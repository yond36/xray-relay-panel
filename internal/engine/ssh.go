package engine

import (
	"bytes"
	"context"
	"crypto/subtle"
	"debug/elf"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"xrayrelay/internal/model"
)

type trustError struct {
	Fingerprint string
	Mismatch    bool
}

func (e *trustError) Error() string {
	if e.Mismatch {
		return "SSH host key does not match pinned fingerprint; connection refused"
	}
	return "SSH host key requires explicit fingerprint trust"
}
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\"'\"'") + "'" }
func hostKeyCallback(expected string, observed *string) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, key ssh.PublicKey) error {
		fp := ssh.FingerprintSHA256(key)
		*observed = fp
		if expected == "" {
			return &trustError{Fingerprint: fp}
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(fp)) != 1 {
			return &trustError{Fingerprint: fp, Mismatch: true}
		}
		return nil
	}
}
func dialSSH(ctx context.Context, n model.Node) (*ssh.Client, string, error) {
	if n.Host == "" || strings.ContainsAny(n.Host, "\x00\r\n /\\") {
		return nil, "", errors.New("invalid SSH host")
	}
	port := n.SSHPort
	if port == 0 {
		port = 22
	}
	if port < 1 || port > 65535 {
		return nil, "", errors.New("invalid SSH port")
	}
	user := n.Username
	if user == "" {
		user = "root"
	}
	if strings.ContainsAny(user, "\x00\r\n") {
		return nil, "", errors.New("invalid SSH username")
	}
	auth := []ssh.AuthMethod{}
	// Before first trust, abort during key exchange without attempting authentication.
	if n.Fingerprint != "" {
		switch n.AuthMode {
		case "password", "":
			if n.Password == "" {
				return nil, "", errors.New("SSH credential is required")
			}
			auth = append(auth, ssh.Password(n.Password))
		case "privatekey", "publickey", "key":
			var signer ssh.Signer
			var err error
			if n.KeyPassphrase != "" {
				signer, err = ssh.ParsePrivateKeyWithPassphrase([]byte(n.PrivateKey), []byte(n.KeyPassphrase))
			} else {
				signer, err = ssh.ParsePrivateKey([]byte(n.PrivateKey))
			}
			if err != nil {
				return nil, "", errors.New("SSH private key could not be parsed; check key and passphrase")
			}
			auth = append(auth, ssh.PublicKeys(signer))
		default:
			return nil, "", errors.New("SSH auth_mode must be password or privatekey")
		}
	}
	observed := ""
	config := &ssh.ClientConfig{User: user, Auth: auth, HostKeyCallback: hostKeyCallback(n.Fingerprint, &observed), Timeout: 20 * time.Second}
	address := net.JoinHostPort(strings.Trim(n.Host, "[]"), strconv.Itoa(port))
	conn, err := (&net.Dialer{Timeout: 20 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", fmt.Errorf("connect SSH: %w", err)
	}
	deadline := time.Now().Add(25 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)
	sshConn, chans, reqs, err := ssh.NewClientConn(conn, address, config)
	if err != nil {
		conn.Close()
		if observed != "" && n.Fingerprint == "" {
			return nil, observed, &trustError{Fingerprint: observed}
		}
		if observed != "" && observed != n.Fingerprint {
			return nil, observed, &trustError{Fingerprint: observed, Mismatch: true}
		}
		return nil, observed, errors.New("SSH handshake/authentication failed; verify credentials and server SSH policy")
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sshConn, chans, reqs), observed, nil
}
func sshRun(ctx context.Context, client *ssh.Client, args []string, input []byte) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}
	defer session.Close()
	var out, stderr limitedBuffer
	session.Stdout = &out
	session.Stderr = &stderr
	session.Stdin = bytes.NewReader(input)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = shellQuote(a)
	}
	if err := session.Start(strings.Join(quoted, " ")); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- session.Wait() }()
	select {
	case <-ctx.Done():
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		return nil, ctx.Err()
	case err := <-done:
		if err != nil {
			message := strings.ToLower(stderr.String())
			if strings.Contains(message, "sudo") || strings.Contains(message, "permission denied") {
				return nil, errors.New("SSH node requires root or passwordless noninteractive sudo (sudo -n)")
			}
			return nil, errors.New("remote node helper failed; verify executable permissions, Linux architecture and noninteractive sudo")
		}
		return out.Bytes(), nil
	}
}

type target interface {
	Call(context.Context, nodeRequest) (nodeResponse, error)
	UploadArchive(context.Context, release) (string, error)
	Arch() string
	Close() error
}
type localTarget struct{ dataDir string }

func (t *localTarget) Arch() string { return goruntime.GOARCH }
func (t *localTarget) Close() error { return nil }
func (t *localTarget) UploadArchive(_ context.Context, r release) (string, error) {
	return r.Archive, nil
}
func (t *localTarget) Call(ctx context.Context, req nodeRequest) (nodeResponse, error) {
	if os.Geteuid() == 0 {
		return dispatchNode(ctx, req)
	}
	helper, err := helperPath(t.dataDir, goruntime.GOARCH)
	if err != nil {
		if req.Operation == "inspect" {
			i, inspectErr := inspectNode(ctx)
			i.Message += "; privileged helper is unavailable, installed core visibility may be limited"
			return nodeResponse{Inspection: &i}, inspectErr
		}
		return nodeResponse{}, err
	}
	data, _ := json.Marshal(req)
	cmd := exec.CommandContext(ctx, "sudo", "-n", "--", helper, "helper")
	cmd.Stdin = bytes.NewReader(data)
	var out, stderr limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nodeResponse{}, errors.New("local node requires root or passwordless noninteractive sudo (sudo -n)")
	}
	return decodeNodeResponse(out.Bytes())
}

type remoteTarget struct {
	client                               *ssh.Client
	sftp                                 *sftp.Client
	dir, helper, arch, user, fingerprint string
	files                                []string
}

func (t *remoteTarget) Arch() string { return t.arch }
func (t *remoteTarget) Close() error {
	for i := len(t.files) - 1; i >= 0; i-- {
		_ = t.sftp.Remove(t.files[i])
	}
	_ = t.sftp.RemoveDirectory(t.dir)
	_ = t.sftp.Close()
	return t.client.Close()
}
func (t *remoteTarget) Call(ctx context.Context, req nodeRequest) (nodeResponse, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nodeResponse{}, err
	}
	args := []string{t.helper, "helper"}
	if t.user != "root" {
		args = append([]string{"sudo", "-n", "--"}, args...)
	}
	out, err := sshRun(ctx, t.client, args, b)
	if err != nil {
		return nodeResponse{}, err
	}
	return decodeNodeResponse(out)
}
func decodeNodeResponse(data []byte) (nodeResponse, error) {
	var response nodeResponse
	if err := json.Unmarshal(data, &response); err != nil {
		return response, errors.New("invalid node helper response")
	}
	if response.Error != "" {
		return response, errors.New(response.Error)
	}
	return response, nil
}
func (t *remoteTarget) upload(ctx context.Context, src, dst string, mode os.FileMode) error {
	f, err := os.Open(src)
	if err != nil {
		return err
	}
	defer f.Close()
	remote, err := t.sftp.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY)
	if err != nil {
		return err
	}
	t.files = append(t.files, dst)
	if err := remote.Chmod(mode); err != nil {
		remote.Close()
		return err
	}
	done := make(chan error, 1)
	go func() {
		_, err := remote.ReadFromWithConcurrency(f, 16)
		if e := remote.Close(); err == nil {
			err = e
		}
		done <- err
	}()
	select {
	case <-ctx.Done():
		// Closing the transport interrupts pending SFTP writes before Close waits for them.
		_ = t.client.Close()
		_ = remote.Close()
		return ctx.Err()
	case err := <-done:
		return err
	}
}
func (t *remoteTarget) UploadArchive(ctx context.Context, r release) (string, error) {
	p := t.dir + "/core.zip"
	if err := t.upload(ctx, r.Archive, p, 0600); err != nil {
		return "", err
	}
	return p, nil
}
func helperPath(dataDir, arch string) (string, error) {
	candidates := []string{}
	if p := os.Getenv("XRAY_PANEL_NODECTL"); p != "" {
		if !filepath.IsAbs(p) {
			return "", errors.New("XRAY_PANEL_NODECTL must be an absolute path")
		}
		candidates = append(candidates, p)
	}
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, filepath.Join(filepath.Dir(exe), "xray-panel-nodectl"))
	}
	candidates = append(candidates, filepath.Join(dataDir, "helpers", "linux-"+arch, "xray-panel-nodectl"))
	for _, p := range candidates {
		if err := validateHelper(p, arch); err == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("Linux %s nodectl helper not found: set XRAY_PANEL_NODECTL, place xray-panel-nodectl beside panel, or in data/helpers/linux-%s/", arch, arch)
}
func validateHelper(path, arch string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > 100<<20 {
		return errors.New("helper must be a regular project executable")
	}
	f, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if f.Type != elf.ET_EXEC && f.Type != elf.ET_DYN {
		return errors.New("helper is not an executable ELF")
	}
	if (arch == "amd64" && f.Machine != elf.EM_X86_64) || (arch == "arm64" && f.Machine != elf.EM_AARCH64) || (arch != "amd64" && arch != "arm64") {
		return errors.New("helper architecture does not match node")
	}
	return nil
}
func openTarget(ctx context.Context, n model.Node, dataDir string) (target, string, error) {
	if n.Kind == "local" {
		if goruntime.GOOS != "linux" {
			return nil, "", errors.New("local node management requires Linux with systemd; use an SSH Linux node from Windows")
		}
		return &localTarget{dataDir: dataDir}, "", nil
	}
	if n.Kind != "ssh" {
		return nil, "", errors.New("node kind must be local or ssh")
	}
	client, fp, err := dialSSH(ctx, n)
	if err != nil {
		return nil, fp, err
	}
	ok := false
	defer func() {
		if !ok {
			client.Close()
		}
	}()
	osName, err := sshRun(ctx, client, []string{"uname", "-s"}, nil)
	if err != nil {
		return nil, fp, err
	}
	if strings.TrimSpace(string(osName)) != "Linux" {
		return nil, fp, errors.New("SSH node must run Linux with systemd")
	}
	machine, err := sshRun(ctx, client, []string{"uname", "-m"}, nil)
	if err != nil {
		return nil, fp, err
	}
	arch := ""
	switch strings.TrimSpace(string(machine)) {
	case "x86_64", "amd64":
		arch = "amd64"
	case "aarch64", "arm64":
		arch = "arm64"
	default:
		return nil, fp, errors.New("SSH node architecture must be amd64 or arm64")
	}
	helper, err := helperPath(dataDir, arch)
	if err != nil {
		return nil, fp, err
	}
	sf, err := sftp.NewClient(client)
	if err != nil {
		return nil, fp, errors.New("SSH server must provide an SFTP subsystem")
	}
	id, err := randomID()
	if err != nil {
		sf.Close()
		return nil, fp, err
	}
	dir := "/tmp/xray-relay-panel-node-" + id
	if err := sf.Mkdir(dir); err != nil {
		sf.Close()
		return nil, fp, err
	}
	if err := sf.Chmod(dir, 0700); err != nil {
		_ = sf.RemoveDirectory(dir)
		sf.Close()
		return nil, fp, err
	}
	user := n.Username
	if user == "" {
		user = "root"
	}
	t := &remoteTarget{client: client, sftp: sf, dir: dir, helper: dir + "/nodectl", arch: arch, user: user, fingerprint: fp}
	if err := t.upload(ctx, helper, t.helper, 0700); err != nil {
		t.Close()
		return nil, fp, err
	}
	ok = true
	return t, fp, nil
}
