// Command chain verifies the public REALITY entry using a separate real Xray client.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	"golang.org/x/net/proxy"
	"xrayrelay/internal/xray"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	core := flag.String("core", "", "verified Xray executable")
	private := flag.String("secrets", "", "external private integration state")
	output := flag.String("output", ".local/verification/public-chain.json", "sanitized report path")
	debug := flag.Bool("debug", false, "record private client diagnostics")
	flag.Parse()
	data, err := os.ReadFile(*private)
	if err != nil {
		return err
	}
	var state struct {
		ShareURL string `json:"share_url"`
	}
	if err = json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.ShareURL == "" {
		return errors.New("no private relay share URL; run verify_panel.py first")
	}
	upstreams, parseErrors := xray.ParseImports(state.ShareURL)
	if len(parseErrors) > 0 || len(upstreams) != 1 {
		return errors.New("could not parse generated REALITY share URL")
	}
	var outbound map[string]any
	if err = json.Unmarshal(upstreams[0].Outbound, &outbound); err != nil {
		return err
	}
	outbound["tag"] = "relay"
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	config := map[string]any{"log": map[string]any{"loglevel": "warning"}, "inbounds": []any{map[string]any{"tag": "client", "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": "noauth", "udp": false}}}, "outbounds": []any{map[string]any{"tag": "deny", "protocol": "blackhole"}, outbound}, "routing": map[string]any{"rules": []any{map[string]any{"type": "field", "inboundTag": []string{"client"}, "outboundTag": "relay"}}}}
	if *debug {
		config["log"].(map[string]any)["loglevel"] = "debug"
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	base := filepath.Join(".local", "verification")
	if err = os.MkdirAll(base, 0700); err != nil {
		return err
	}
	dir, err := os.MkdirTemp(base, "client-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	configPath, err := filepath.Abs(filepath.Join(dir, "client.json"))
	if err != nil {
		return err
	}
	if err = os.WriteFile(configPath, encoded, 0600); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 70*time.Second)
	defer cancel()
	test := exec.CommandContext(ctx, *core, "run", "-test", "-config", configPath)
	if out, err := test.CombinedOutput(); err != nil {
		return fmt.Errorf("real client configuration rejected: %s", out)
	}
	command := exec.CommandContext(ctx, *core, "run", "-config", configPath)
	logPath := filepath.Join(base, "client-debug.log")
	logs, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer logs.Close()
	command.Stdout = logs
	command.Stderr = logs
	if err = command.Start(); err != nil {
		return err
	}
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	ready := false
	for i := 0; i < 60; i++ {
		conn, e := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if e == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		return errors.New("isolated test client did not listen")
	}
	dialer, err := proxy.SOCKS5("tcp", address, nil, &net.Dialer{Timeout: 15 * time.Second})
	if err != nil {
		return err
	}
	contextual, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return errors.New("SOCKS client does not support cancellation")
	}
	transport := &http.Transport{DialContext: contextual.DialContext, TLSHandshakeTimeout: 15 * time.Second, ResponseHeaderTimeout: 20 * time.Second, DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 40 * time.Second}
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://api4.ipify.org", nil)
	started := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("public REALITY -> relay -> upstream test failed: %w (private diagnostics: %s)", err, logPath)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 128))
	if err != nil {
		return err
	}
	ip := net.ParseIP(string(bytes.TrimSpace(body)))
	if response.StatusCode != 200 || ip == nil || ip.To4() == nil {
		return errors.New("public chain returned no valid IPv4")
	}
	report := map[string]any{"status": "passed", "path": "Windows Xray client -> public VLESS-REALITY entry -> authorized VLESS-REALITY upstream -> HTTPS IP echo", "ipv4": ip.String(), "latency_ms": time.Since(started).Milliseconds(), "checked_at": time.Now().UTC(), "core_version": "v26.10.31"}
	result, _ := json.MarshalIndent(report, "", "  ")
	if err = os.MkdirAll(filepath.Dir(*output), 0700); err != nil {
		return err
	}
	if err = os.WriteFile(*output, result, 0600); err != nil {
		return err
	}
	fmt.Println(string(result))
	return nil
}
