package engine

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"xrayrelay/internal/coreversion"
	"xrayrelay/internal/model"
	"xrayrelay/internal/xray"
)

const installRoot = "/opt/xray-relay-panel-node"
const stateRoot = "/var/lib/xray-relay-panel-node"
const unitName = "xray-relay-panel-node.service"
const unitPath = "/etc/systemd/system/" + unitName
const unitMarker = "# Managed by xray-relay-panel; isolated node service."

const serviceUnit = unitMarker + `
[Unit]
Description=Isolated Xray Relay Panel Node
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/xray-relay-panel-node/current/xray run -config /opt/xray-relay-panel-node/current/config.json
WorkingDirectory=/var/lib/xray-relay-panel-node
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=/var/lib/xray-relay-panel-node

[Install]
WantedBy=multi-user.target
`

type nodeRequest struct {
	Operation      string          `json:"operation"`
	Action         string          `json:"action,omitempty"`
	Version        string          `json:"version,omitempty"`
	Architecture   string          `json:"architecture,omitempty"`
	Archive        string          `json:"archive,omitempty"`
	SHA256         string          `json:"sha256,omitempty"`
	Config         json.RawMessage `json:"config,omitempty"`
	RemovedRelayID string          `json:"removed_relay_id,omitempty"`
	Upstream       model.Upstream  `json:"upstream,omitempty"`
}
type nodeResponse struct {
	Inspection *model.NodeInspection `json:"inspection,omitempty"`
	Apply      *model.ApplyResult    `json:"apply,omitempty"`
	Probe      *model.ProbeResult    `json:"probe,omitempty"`
	Logs       string                `json:"logs,omitempty"`
	Error      string                `json:"error,omitempty"`
}
type revisionMetadata struct {
	Revision     string    `json:"revision"`
	CoreVersion  string    `json:"core_version"`
	Architecture string    `json:"architecture"`
	CreatedAt    time.Time `json:"created_at"`
}

func secureDirectories() error {
	if goruntime.GOOS != "linux" {
		return errors.New("node operations require Linux with systemd")
	}
	if os.Geteuid() != 0 {
		return errors.New("node management requires root or passwordless noninteractive sudo (sudo -n)")
	}
	for _, p := range []string{installRoot, stateRoot, filepath.Join(installRoot, "revisions")} {
		if info, err := os.Lstat(p); err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return fmt.Errorf("managed path %s must be a real directory", p)
			}
		} else if !os.IsNotExist(err) {
			return err
		} else if err := os.MkdirAll(p, 0700); err != nil {
			return err
		}
		if err := os.Chmod(p, 0700); err != nil {
			return err
		}
	}
	if data, err := os.ReadFile(unitPath); err == nil {
		if !bytes.HasPrefix(data, []byte(unitMarker+"\n")) {
			return errors.New("refusing to replace an existing unit not owned by this panel")
		}
		if info, e := os.Lstat(unitPath); e != nil || !info.Mode().IsRegular() {
			return errors.New("managed service unit must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}
func invoke(ctx context.Context, command string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, command, args...)
	var out limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return strings.TrimSpace(out.String()), err
}

type limitedBuffer struct{ bytes.Buffer }

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (256 << 10) - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			p = p[:remaining]
		}
		_, _ = b.Buffer.Write(p)
	}
	return n, nil
}
func systemctl(ctx context.Context, args ...string) (string, error) {
	return invoke(ctx, "systemctl", append(args, "--", unitName)...)
}
func unitOwned() error {
	b, err := os.ReadFile(unitPath)
	if err != nil {
		return err
	}
	if !bytes.HasPrefix(b, []byte(unitMarker+"\n")) {
		return errors.New("service is not owned by this panel")
	}
	return nil
}
func coreVersion(ctx context.Context, file string) (string, error) {
	out, err := invoke(ctx, file, "version")
	if err != nil {
		return "", errors.New("could not execute isolated Xray core")
	}
	fields := strings.Fields(out)
	if len(fields) < 2 || fields[0] != "Xray" {
		return "", errors.New("unexpected isolated Xray version response")
	}
	return coreversion.Normalize(fields[1])
}
func randomID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func atomicFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".candidate-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	c := f.Close()
	if err != nil {
		return err
	}
	if c != nil {
		return c
	}
	return os.Rename(name, path)
}

type revisionLinks struct{ root string }

func readRevision(link string) (string, error) {
	return (revisionLinks{root: installRoot}).read(link)
}

func (links revisionLinks) read(link string) (string, error) {
	if link != "current" && link != "previous" {
		return "", errors.New("invalid managed revision link")
	}
	p := filepath.Join(links.root, link)
	target, err := os.Readlink(p)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if filepath.IsAbs(target) {
		return "", errors.New("managed revision link is unexpectedly absolute")
	}
	clean := filepath.Clean(target)
	if filepath.Dir(clean) != "revisions" || !validRevision(filepath.Base(clean)) {
		return "", errors.New("managed revision link escapes revision directory")
	}
	dir := filepath.Join(links.root, clean)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("managed revision is not a real directory")
	}
	return filepath.Base(clean), nil
}
func validRevision(s string) bool {
	if len(s) != 24 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
func switchRevision(link, id string) error {
	return (revisionLinks{root: installRoot}).switchTo(link, id)
}

func (links revisionLinks) switchTo(link, id string) error {
	if link != "current" && link != "previous" {
		return errors.New("invalid managed revision link")
	}
	if !validRevision(id) {
		return errors.New("invalid revision id")
	}
	temporary := filepath.Join(links.root, "."+link+"-"+id)
	_ = os.Remove(temporary)
	if err := os.Symlink(filepath.Join("revisions", id), temporary); err != nil {
		return err
	}
	defer os.Remove(temporary)
	return os.Rename(temporary, filepath.Join(links.root, link))
}

func configHasRelay(config []byte, relayID string) (bool, error) {
	var c struct {
		Inbounds []struct {
			Tag string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(config, &c); err != nil {
		return false, errors.New("invalid relay inbound configuration")
	}
	wanted := xray.RelayInboundTag(relayID)
	for _, inbound := range c.Inbounds {
		if inbound.Tag == wanted {
			return true, nil
		}
	}
	return false, nil
}

func validateDeletedRelayConfig(config []byte, removedRelayID string) error {
	if removedRelayID == "" {
		return nil
	}
	found, err := configHasRelay(config, removedRelayID)
	if err != nil {
		return err
	}
	if found {
		return errors.New("deleted relay is still present in candidate configuration")
	}
	return nil
}

// retainPrevious runs after activation, while applyNode still holds the node lock.
// Only an old current that cannot restore the deleted relay remains reachable.
func (links revisionLinks) retainPrevious(current, removedRelayID string) error {
	if removedRelayID != "" && current != "" {
		if !validRevision(current) {
			return errors.New("invalid revision id")
		}
		path := filepath.Join(links.root, "revisions", current, "config.json")
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return errors.New("managed revision configuration must be a regular file")
		}
		config, err := readPrivateFile(path, maxImportConfig)
		if err != nil {
			return err
		}
		found, err := configHasRelay(config, removedRelayID)
		if err != nil {
			return err
		}
		if found {
			current = ""
		}
	}
	if current != "" {
		return links.switchTo("previous", current)
	}
	if removedRelayID == "" {
		return nil
	}
	// Remove only this fixed symlink, never its target or a revision directory.
	path := filepath.Join(links.root, "previous")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink == 0 {
		return errors.New("managed previous revision link must be a symlink")
	}
	return os.Remove(path)
}

func finishApply(ctx context.Context, links revisionLinks, current, removedRelayID string, enable func(context.Context) error) error {
	if err := links.retainPrevious(current, removedRelayID); err != nil {
		return fmt.Errorf("service applied but could not update previous revision link: %w", err)
	}
	if err := enable(ctx); err != nil {
		return errors.New("service is running but enabling its own boot unit failed")
	}
	return nil
}
func metadata(id string) (revisionMetadata, error) {
	var m revisionMetadata
	if !validRevision(id) {
		return m, errors.New("invalid revision")
	}
	b, err := os.ReadFile(filepath.Join(installRoot, "revisions", id, "metadata.json"))
	if err != nil {
		return m, err
	}
	err = json.Unmarshal(b, &m)
	return m, err
}
func installedVersion() string {
	id, err := readRevision("current")
	if err != nil || id == "" {
		return ""
	}
	m, err := metadata(id)
	if err != nil {
		return ""
	}
	return m.CoreVersion
}
func applyNode(ctx context.Context, req nodeRequest) (model.ApplyResult, error) {
	var result model.ApplyResult
	if err := secureDirectories(); err != nil {
		return result, err
	}
	unlock, err := lockNode(ctx)
	if err != nil {
		return result, err
	}
	defer unlock()
	normalizedVersion, err := coreversion.Normalize(req.Version)
	if err != nil {
		return result, err
	}
	req.Version = normalizedVersion
	if req.Architecture != goruntime.GOARCH {
		return result, errors.New("core architecture does not match node")
	}
	if !json.Valid(req.Config) || len(req.Config) > maxImportConfig {
		return result, errors.New("invalid candidate configuration")
	}
	if err := validateDeletedRelayConfig(req.Config, req.RemovedRelayID); err != nil {
		return result, err
	}
	if err := ensurePortsAvailable(ctx, req.Config); err != nil {
		return result, err
	}
	previous, err := readRevision("current")
	if err != nil {
		return result, err
	}
	id, err := randomID()
	if err != nil {
		return result, err
	}
	stage := filepath.Join(installRoot, "revisions", id)
	if err := os.Mkdir(stage, 0700); err != nil {
		return result, err
	}
	keep := false
	defer func() {
		if !keep {
			os.RemoveAll(stage)
		}
	}()
	core := filepath.Join(stage, "xray")
	reuse := false
	if previous != "" {
		m, e := metadata(previous)
		if e == nil && m.CoreVersion == req.Version && m.Architecture == req.Architecture {
			src := filepath.Join(installRoot, "revisions", previous, "xray")
			if info, e := os.Lstat(src); e == nil && info.Mode().IsRegular() {
				if e = os.Link(src, core); e == nil {
					reuse = true
				} else if e = copyFile(src, core, 0755); e == nil {
					reuse = true
				}
			}
		}
	}
	if !reuse {
		if req.Archive == "" {
			return result, errors.New("requested core is not installed; an official verified release archive is required")
		}
		if err := verifyArchive(req.Archive, req.SHA256); err != nil {
			return result, err
		}
		if err := extractCore(req.Archive, core); err != nil {
			return result, err
		}
	}
	version, err := coreVersion(ctx, core)
	if err != nil {
		return result, err
	}
	if !coreversion.MatchesBinary(req.Version, version) {
		return result, fmt.Errorf("core version mismatch: expected %s, got %s", req.Version, version)
	}
	configPath := filepath.Join(stage, "config.json")
	if err := os.WriteFile(configPath, req.Config, 0600); err != nil {
		return result, err
	}
	testCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	_, err = invoke(testCtx, core, "run", "-test", "-config", configPath)
	cancel()
	if err != nil {
		return result, errors.New("candidate Xray configuration failed core validation; active revision was not changed")
	}
	m := revisionMetadata{Revision: id, CoreVersion: req.Version, Architecture: req.Architecture, CreatedAt: time.Now().UTC()}
	data, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(stage, "metadata.json"), data, 0600); err != nil {
		return result, err
	}
	oldUnit, unitErr := os.ReadFile(unitPath)
	if unitErr != nil && !os.IsNotExist(unitErr) {
		return result, unitErr
	}
	unitExisted := unitErr == nil
	if err := atomicFile(unitPath, []byte(serviceUnit), 0644); err != nil {
		return result, err
	}
	if _, err := invoke(ctx, "systemctl", "daemon-reload"); err != nil {
		return result, errors.New("systemd daemon-reload failed; node must run systemd")
	}
	if err := switchRevision("current", id); err != nil {
		return result, err
	}
	keep = true
	if err := startAndVerify(ctx); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		var restoreErr error
		if previous != "" {
			restoreErr = switchRevision("current", previous)
			if restoreErr == nil {
				restoreErr = startAndVerify(rollbackCtx)
			}
		} else {
			_, _ = systemctl(rollbackCtx, "stop")
			_ = os.Remove(filepath.Join(installRoot, "current"))
		}
		if unitExisted {
			_ = atomicFile(unitPath, oldUnit, 0644)
		} else {
			_ = os.Remove(unitPath)
		}
		_, _ = invoke(rollbackCtx, "systemctl", "daemon-reload")
		if restoreErr != nil {
			return result, fmt.Errorf("new service failed to start and previous revision recovery failed: %w", restoreErr)
		}
		return result, errors.New("new service failed to start; previous binary and configuration restored")
	}
	if err := finishApply(ctx, revisionLinks{root: installRoot}, previous, req.RemovedRelayID, func(ctx context.Context) error {
		_, err := systemctl(ctx, "enable")
		return err
	}); err != nil {
		return result, err
	}
	result = model.ApplyResult{Revision: id, CoreVersion: req.Version, Message: "isolated Xray revision validated and activated"}
	return result, nil
}

const maxImportConfig = 12 << 20

func copyFile(src, dst string, mode os.FileMode) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	defer s.Close()
	d, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = io.Copy(d, s)
	if err == nil {
		err = d.Sync()
	}
	c := d.Close()
	if err != nil {
		return err
	}
	return c
}
func startAndVerify(ctx context.Context) error {
	if _, err := systemctl(ctx, "restart"); err != nil {
		return errors.New("isolated unit restart failed")
	}
	timer := time.NewTimer(900 * time.Millisecond)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	state, err := systemctl(ctx, "is-active")
	if err != nil || state != "active" {
		return errors.New("isolated unit did not stay active")
	}
	return nil
}
func serviceNode(ctx context.Context, action string) error {
	switch action {
	case "start", "stop", "restart", "rollback":
	default:
		return errors.New("service action must be start, stop, restart or rollback")
	}
	if err := secureDirectories(); err != nil {
		return err
	}
	unlock, err := lockNode(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := unitOwned(); err != nil {
		return err
	}
	switch action {
	case "start", "restart":
		if action == "restart" {
			return startAndVerify(ctx)
		}
		_, err := systemctl(ctx, "start")
		return err
	case "stop":
		_, err := systemctl(ctx, "stop")
		return err
	case "rollback":
		prev, err := readRevision("previous")
		if err != nil {
			return err
		}
		if prev == "" {
			return errors.New("there is no previous revision")
		}
		cur, err := readRevision("current")
		if err != nil {
			return err
		}
		if err := switchRevision("current", prev); err != nil {
			return err
		}
		if err := startAndVerify(ctx); err != nil {
			restore, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
			defer cancel()
			if cur != "" {
				_ = switchRevision("current", cur)
				_ = startAndVerify(restore)
			}
			return errors.New("rollback revision could not start; current revision restored")
		}
		if cur != "" {
			return switchRevision("previous", cur)
		}
		return nil
	default:
		return errors.New("service action must be start, stop, restart or rollback")
	}
}
func inspectNode(ctx context.Context) (model.NodeInspection, error) {
	r := model.NodeInspection{OS: goruntime.GOOS, Architecture: goruntime.GOARCH, Ports: []int{}, ServiceState: "not-installed"}
	if goruntime.GOOS != "linux" {
		return r, errors.New("node must run Linux with systemd")
	}
	for _, p := range []string{"/etc/xray", "/usr/local/etc/xray", "/usr/local/bin/xray", "/usr/bin/xray", "/etc/systemd/system/xray.service", "/lib/systemd/system/xray.service", "/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64", "/etc/systemd/system/x-ui.service"} {
		if _, err := os.Lstat(p); err == nil {
			r.ExistingXray = true
		}
	}
	if err := unitOwned(); err == nil {
		state, _ := systemctl(ctx, "is-active")
		r.ServiceState = state
		if r.ServiceState == "" {
			r.ServiceState = "unknown"
		}
	}
	if existingXrayProcess() {
		r.ExistingXray = true
	}
	r.CoreVersion = installedVersion()
	r.Ports = listeningPorts()
	r.Message = "existing Xray installations are left untouched; only the isolated panel unit is managed"
	return r, nil
}
func listeningPorts() []int {
	ports := map[int]bool{}
	for _, p := range []string{"/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(b), "\n") {
			f := strings.Fields(line)
			if len(f) < 4 || (!strings.Contains(p, "udp") && f[3] != "0A") {
				continue
			}
			_, hexport, ok := strings.Cut(f[1], ":")
			if !ok {
				continue
			}
			port, e := strconv.ParseInt(hexport, 16, 32)
			if e == nil && port > 0 {
				ports[int(port)] = true
			}
		}
	}
	result := make([]int, 0, len(ports))
	for p := range ports {
		result = append(result, p)
	}
	sort.Ints(result)
	return result
}
func logsNode(ctx context.Context) (string, error) {
	if err := unitOwned(); err != nil {
		return "", err
	}
	out, err := invoke(ctx, "journalctl", "--unit="+unitName, "--no-pager", "--output=short-iso", "--lines=200")
	if err != nil {
		return "", errors.New("could not read isolated service journal; root or noninteractive sudo is required")
	}
	return out, nil
}
func unusedLoopbackPort() (int, error) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}
