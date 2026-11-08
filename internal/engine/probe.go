package engine

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"xrayrelay/internal/coreversion"
	"xrayrelay/internal/model"
	"xrayrelay/internal/xray"
)

const ipv4Echo = "https://api4.ipify.org"
const ipv6Echo = "https://api6.ipify.org"

func probeHTTPClient(address, user, pass string) (*http.Client, error) {
	if user == "" || pass == "" || len(user) > 255 || len(pass) > 255 {
		return nil, errors.New("probe SOCKS authentication is required")
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, target string) (net.Conn, error) {
		return dialProbeSOCKS(ctx, address, user, pass, target)
	}, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 15 * time.Second, DisableKeepAlives: true}
	return &http.Client{Transport: transport, Timeout: 25 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("IP echo redirects are not allowed") }}, nil
}
func echoIP(ctx context.Context, client *http.Client, address string, family int) (string, int64, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return "", 0, err
	}
	resp, err := client.Do(req)
	elapsed := time.Since(start).Milliseconds()
	if err != nil {
		return "", elapsed, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", elapsed, fmt.Errorf("IP echo returned HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 257))
	if err != nil {
		return "", elapsed, err
	}
	if len(b) > 256 {
		return "", elapsed, errors.New("oversized IP echo response")
	}
	ip := net.ParseIP(strings.TrimSpace(string(b)))
	if ip == nil || (family == 4 && ip.To4() == nil) || (family == 6 && ip.To4() != nil) {
		return "", elapsed, errors.New("IP echo returned an invalid address family")
	}
	return ip.String(), time.Since(start).Milliseconds(), nil
}
func probeNode(ctx context.Context, req nodeRequest) (model.ProbeResult, error) {
	result := model.ProbeResult{UpstreamID: req.Upstream.ID, Status: "failed", CheckedAt: time.Now().UTC()}
	requestedVersion, err := coreversion.Normalize(req.Version)
	if err != nil {
		return result, err
	}
	req.Version = requestedVersion
	if err := xray.ValidateUpstream(req.Upstream); err != nil {
		return result, err
	}
	if err := secureDirectories(); err != nil {
		return result, err
	}
	unlock, err := lockNode(ctx)
	if err != nil {
		return result, err
	}
	defer unlock()
	dir, err := os.MkdirTemp(stateRoot, "probe-")
	if err != nil {
		return result, err
	}
	defer os.RemoveAll(dir)
	core := ""
	if req.Version == installedVersion() {
		id, e := readRevision("current")
		if e == nil && id != "" {
			core = filepath.Join(installRoot, "revisions", id, "xray")
		}
	}
	if core == "" {
		if err := validateVersion(req.Version); err != nil {
			return result, err
		}
		if req.Archive == "" {
			return result, errors.New("probe needs the requested official core release")
		}
		if err := verifyArchive(req.Archive, req.SHA256); err != nil {
			return result, err
		}
		core = filepath.Join(dir, "xray")
		if err := extractCore(req.Archive, core); err != nil {
			return result, err
		}
	}
	version, err := coreVersion(ctx, core)
	if err != nil || !coreversion.MatchesBinary(req.Version, version) {
		return result, errors.New("probe core does not match requested fixed version")
	}
	port, err := unusedLoopbackPort()
	if err != nil {
		return result, err
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return result, err
	}
	credential := base64.RawURLEncoding.EncodeToString(secret)
	config, err := xray.ProbeConfig(req.Upstream, port, "probe", credential)
	if err != nil {
		return result, err
	}
	config, err = xray.ForCoreVersion(config, req.Version)
	if err != nil {
		return result, err
	}
	configPath := filepath.Join(dir, "config.json")
	if err := os.WriteFile(configPath, config, 0600); err != nil {
		return result, err
	}
	testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	_, err = invoke(testCtx, core, "run", "-test", "-config", configPath)
	cancel()
	if err != nil {
		return result, errors.New("probe upstream configuration rejected by pinned Xray core")
	}
	cmd := exec.CommandContext(ctx, core, "run", "-config", configPath)
	cmd.Dir = dir
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return result, errors.New("could not start isolated loopback probe process")
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait(); close(done) }()
	defer func() { // Target only the exact child PID started above.
		_ = cmd.Process.Kill()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
		}
	}()
	address := net.JoinHostPort("127.0.0.1", fmt.Sprint(port))
	ready := time.NewTimer(10 * time.Second)
	defer ready.Stop()
	ticker := time.NewTicker(75 * time.Millisecond)
	defer ticker.Stop()
waitReady:
	for {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		case <-done:
			return result, errors.New("isolated probe core exited before listening")
		case <-ready.C:
			return result, errors.New("isolated loopback probe did not start")
		case <-ticker.C:
			c, e := net.DialTimeout("tcp", address, 200*time.Millisecond)
			if e == nil {
				c.Close()
				break waitReady
			}
		}
	}
	client, err := probeHTTPClient(address, "probe", credential)
	if err != nil {
		return result, err
	}
	defer client.CloseIdleConnections()
	return probeEgress(ctx, client, result)
}

// probeEgress checks both fixed echo endpoints through the isolated probe client.
func probeEgress(ctx context.Context, client *http.Client, result model.ProbeResult) (model.ProbeResult, error) {
	var v4, v6 string
	var latency, latency6 int64
	var err4, err6 error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); v4, latency, err4 = echoIP(ctx, client, ipv4Echo, 4) }()
	go func() { defer wg.Done(); v6, latency6, err6 = echoIP(ctx, client, ipv6Echo, 6) }()
	wg.Wait()
	result.IPv4 = v4
	result.IPv6 = v6
	result.LatencyMS = latency
	result.CheckedAt = time.Now().UTC()
	if err6 != nil {
		result.IPv6Error = "IPv6 proxy egress: " + err6.Error()
	}
	if err4 != nil {
		result.Error = "IPv4 proxy egress: " + err4.Error()
		if v6 != "" {
			result.LatencyMS = latency6
			result.Status = "partial"
			return result, nil
		}
		return result, errors.New(result.Error)
	}
	result.Status = "ok"
	return result, nil
}
