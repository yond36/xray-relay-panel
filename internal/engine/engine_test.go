package engine

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"xrayrelay/internal/model"
	"xrayrelay/internal/xray"
)

func makeZIP(t *testing.T, name string, mode os.FileMode) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "core.zip")
	f, err := os.Create(file)
	if err != nil {
		t.Fatal(err)
	}
	w := zip.NewWriter(f)
	h := &zip.FileHeader{Name: name, Method: zip.Deflate}
	h.SetMode(mode)
	e, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = e.Write([]byte("test-executable"))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return file
}
func TestReleaseChecksumAndSafeExtraction(t *testing.T) {
	file := makeZIP(t, "xray", 0755)
	data, _ := os.ReadFile(file)
	sum := sha256.Sum256(data)
	hexsum := hex.EncodeToString(sum[:])
	got, err := parseChecksum([]byte("MD5= ignored\nSHA2-256= " + hexsum + "\n"))
	if err != nil || got != hexsum {
		t.Fatalf("checksum %s %v", got, err)
	}
	if verifyArchive(file, hexsum) != nil {
		t.Fatal("valid archive rejected")
	}
	if verifyArchive(file, strings.Repeat("0", 64)) == nil {
		t.Fatal("checksum mismatch accepted")
	}
	dst := filepath.Join(t.TempDir(), "xray")
	if err := extractCore(file, dst); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "test-executable" {
		t.Fatal("executable not extracted")
	}
	for _, name := range []string{"../xray", "/xray", "a/../../xray", "a\\xray", "C:/xray"} {
		bad := makeZIP(t, name, 0755)
		if extractCore(bad, filepath.Join(t.TempDir(), "xray")) == nil {
			t.Errorf("unsafe archive entry accepted: %q", name)
		}
	}
	bad := makeZIP(t, "xray", os.ModeSymlink|0777)
	if extractCore(bad, filepath.Join(t.TempDir(), "xray")) == nil {
		t.Fatal("archive symlink accepted")
	}
}
func TestFixedVersionsAndDownloadLimits(t *testing.T) {
	for _, v := range []string{"latest", "v26.10.31/../../", "v1;id", "", "v26.10.31\n"} {
		if validateVersion(v) == nil {
			t.Fatalf("invalid version accepted: %q", v)
		}
	}
	if validateVersion(model.DefaultCoreVersion) != nil {
		t.Fatal("default tag invalid")
	}
	if asset, _ := releaseAsset("amd64"); asset != "Xray-linux-64.zip" {
		t.Fatal(asset)
	}
	if _, e := releaseAsset("386"); e == nil {
		t.Fatal("unsupported architecture accepted")
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "too much content") }))
	defer s.Close()
	if fetchLimited(context.Background(), s.Client(), s.URL, io.Discard, 3) == nil {
		t.Fatal("download limit ignored")
	}
}
func newSSHTestServer(t *testing.T) (string, string, *atomic.Int32) {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(signer)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	requests := new(atomic.Int32)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				c, channels, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					conn.Close()
					return
				}
				defer c.Close()
				go func() {
					for req := range reqs {
						requests.Add(1)
						_ = req.Reply(false, nil)
					}
				}()
				for ch := range channels {
					requests.Add(1)
					_ = ch.Reject(ssh.Prohibited, "test server permits no commands")
				}
			}()
		}
	}()
	return listener.Addr().String(), ssh.FingerprintSHA256(signer.PublicKey()), requests
}
func TestSSHFirstTrustRunsNoCommandsAndMismatchRefused(t *testing.T) {
	address, fp, requests := newSSHTestServer(t)
	host, port, _ := net.SplitHostPort(address)
	p, _ := strconv.Atoi(port)
	n := model.Node{ID: "test", Kind: "ssh", Host: host, SSHPort: p, Username: "test", AuthMode: "password"}
	r := New(Options{DataDir: t.TempDir()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inspection, err := r.Inspect(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	if !inspection.RequiresTrust || inspection.Fingerprint != fp {
		t.Fatalf("first trust response: %+v", inspection)
	}
	if requests.Load() != 0 {
		t.Fatal("first trust executed a remote command")
	}
	n.Fingerprint = "SHA256:wrong"
	n.Password = "test-credential"
	_, _, err = dialSSH(ctx, n)
	var trust *trustError
	if !errors.As(err, &trust) || !trust.Mismatch {
		t.Fatalf("pin mismatch not refused: %v", err)
	}
	if requests.Load() != 0 {
		t.Fatal("pin mismatch executed a remote command")
	}
	n.Fingerprint = fp
	client, _, err := dialSSH(ctx, n)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
}
func TestShellQuoteAndRuntimeLockCancellation(t *testing.T) {
	quoted := shellQuote("a' ; $(touch /tmp/unwanted)\n")
	if quoted != "'a'\"'\"' ; $(touch /tmp/unwanted)\n'" {
		t.Fatal("shell argument escaped incorrectly")
	}
	r := New(Options{})
	n := model.Node{Kind: "ssh", Host: "127.0.0.1", SSHPort: 22}
	unlock, err := r.lock(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.lock(ctx, n); !errors.Is(err, context.Canceled) {
		t.Fatal("node lock ignored cancellation")
	}
	unlock()
	again, err := r.lock(context.Background(), n)
	if err != nil {
		t.Fatal(err)
	}
	again()
}
func TestCLIRejectsUntrustedAndMalformedRequests(t *testing.T) {
	for _, input := range []string{`{"operation":"unknown"}`, `{"operation":"inspect","extra":true}`, `{} {}`} {
		var out, stderr bytes.Buffer
		if code := RunNodeCLI(context.Background(), []string{"helper"}, strings.NewReader(input), &out, &stderr); code != 0 {
			t.Fatal("helper protocol must return structured errors")
		}
		if !strings.Contains(out.String(), `"error"`) {
			t.Fatal("malformed helper request accepted")
		}
	}
	var out, stderr bytes.Buffer
	if RunNodeCLI(context.Background(), []string{"service", "killall"}, strings.NewReader(""), &out, &stderr) == 0 {
		t.Fatal("invalid service action accepted")
	}
	if goruntime.GOOS != "linux" {
		inspection, err := New(Options{}).Inspect(context.Background(), model.Node{Kind: "local"})
		if err == nil || inspection.OS != "" {
			t.Fatal("non-Linux local management was accepted")
		}
	}
}
func TestCandidatePortValidation(t *testing.T) {
	if _, err := candidatePorts([]byte(`{"inbounds":[{"port":12345},{"port":12345}]}`)); err == nil {
		t.Fatal("duplicate port accepted")
	}
	if _, err := candidatePorts([]byte(`{"inbounds":[{"port":0}]}`)); err == nil {
		t.Fatal("zero port accepted")
	}
	ports, err := candidatePorts([]byte(`{"inbounds":[{"port":12345}]}`))
	if err != nil || !ports[12345] {
		t.Fatal("valid port rejected")
	}
}
func TestSOCKSRemoteDNSAndVerifiedHTTPSEcho(t *testing.T) {
	echo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "203.0.113.17") }))
	defer echo.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	target := make(chan string, 1)
	serverErr := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 2)
		if _, err = io.ReadFull(conn, header); err != nil {
			serverErr <- err
			return
		}
		methods := make([]byte, int(header[1]))
		if _, err = io.ReadFull(conn, methods); err != nil {
			serverErr <- err
			return
		}
		if header[0] != 5 || !bytes.Contains(methods, []byte{2}) {
			serverErr <- errors.New("SOCKS authentication was not offered")
			return
		}
		_, _ = conn.Write([]byte{5, 2})
		auth := make([]byte, 2)
		if _, err = io.ReadFull(conn, auth); err != nil {
			serverErr <- err
			return
		}
		user := make([]byte, int(auth[1]))
		_, _ = io.ReadFull(conn, user)
		size := make([]byte, 1)
		_, _ = io.ReadFull(conn, size)
		pass := make([]byte, int(size[0]))
		_, _ = io.ReadFull(conn, pass)
		if string(user) != "probe" || string(pass) != "test-credential" {
			serverErr <- errors.New("incorrect SOCKS authentication")
			return
		}
		_, _ = conn.Write([]byte{1, 0})
		req := make([]byte, 5)
		if _, err = io.ReadFull(conn, req); err != nil {
			serverErr <- err
			return
		}
		if req[3] != 3 {
			serverErr <- errors.New("target was resolved locally instead of SOCKS5h")
			return
		}
		host := make([]byte, int(req[4]))
		_, _ = io.ReadFull(conn, host)
		port := make([]byte, 2)
		_, _ = io.ReadFull(conn, port)
		target <- string(host)
		up, err := net.Dial("tcp", echo.Listener.Addr().String())
		if err != nil {
			serverErr <- err
			return
		}
		defer up.Close()
		_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
		go func() { _, _ = io.Copy(up, conn) }()
		_, err = io.Copy(conn, up)
		serverErr <- err
	}()
	client, err := probeHTTPClient(listener.Addr().String(), "probe", "test-credential")
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(echo.Certificate())
	client.Transport.(*http.Transport).TLSClientConfig = &tls.Config{RootCAs: pool, ServerName: "example.com", MinVersion: tls.VersionTLS12}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ip, _, err := echoIP(ctx, client, "https://unresolvable-proxy-target.invalid:443", 4)
	if err != nil {
		t.Fatal(err)
	}
	if ip != "203.0.113.17" {
		t.Fatal(ip)
	}
	if got := <-target; got != "unresolvable-proxy-target.invalid" {
		t.Fatal("SOCKS hostname was changed")
	}
	client.CloseIdleConnections()
}

type probeEchoTransport func(*http.Request) (*http.Response, error)

func (f probeEchoTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestProbeEgressAggregatesValidatedEchoResponses(t *testing.T) {
	const (
		ipv4Unavailable = "IPv4 proxy egress: IP echo returned HTTP 503"
		ipv6Unavailable = "IPv6 proxy egress: IP echo returned HTTP 503"
		ipv4Invalid     = "IPv4 proxy egress: IP echo returned an invalid address family"
		ipv6Invalid     = "IPv6 proxy egress: IP echo returned an invalid address family"
	)
	for _, test := range []struct {
		name                 string
		code4, code6         int
		body4, body6         string
		status, ipv4, ipv6   string
		ipv4Error, ipv6Error string
		wantErr              bool
	}{
		{name: "dual-stack", code4: 200, code6: 200, body4: "203.0.113.17\n", body6: "2001:db8::17\n", status: "ok", ipv4: "203.0.113.17", ipv6: "2001:db8::17"},
		{name: "IPv4-only", code4: 200, code6: 503, body4: "203.0.113.17", status: "ok", ipv4: "203.0.113.17", ipv6Error: ipv6Unavailable},
		{name: "IPv6-only", code4: 503, code6: 200, body6: "2001:db8::17", status: "partial", ipv6: "2001:db8::17", ipv4Error: ipv4Unavailable},
		{name: "both-unavailable", code4: 503, code6: 503, status: "failed", ipv4Error: ipv4Unavailable, ipv6Error: ipv6Unavailable, wantErr: true},
		{name: "wrong-IPv4-family-with-IPv6", code4: 200, code6: 200, body4: "2001:db8::4", body6: "2001:db8::17", status: "partial", ipv6: "2001:db8::17", ipv4Error: ipv4Invalid},
		{name: "IPv4-fails-and-wrong-IPv6-family", code4: 503, code6: 200, body6: "203.0.113.6", status: "failed", ipv4Error: ipv4Unavailable, ipv6Error: ipv6Invalid, wantErr: true},
		{name: "both-invalid", code4: 200, code6: 200, body4: "not an IP", body6: "not an IP", status: "failed", ipv4Error: ipv4Invalid, ipv6Error: ipv6Invalid, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var hits4, hits6 atomic.Int32
			// Exercise the real echo status/body/family validation and concurrent
			// aggregation without changing targets or contacting an external host.
			client := &http.Client{Transport: probeEchoTransport(func(r *http.Request) (*http.Response, error) {
				if r.Method != http.MethodGet {
					return nil, errors.New("unexpected probe method")
				}
				var code int
				var body string
				switch r.URL.String() {
				case ipv4Echo:
					hits4.Add(1)
					code, body = test.code4, test.body4
				case ipv6Echo:
					hits6.Add(1)
					code, body = test.code6, test.body6
				default:
					return nil, errors.New("unexpected probe target")
				}
				return &http.Response{StatusCode: code, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
			})}
			result, err := probeEgress(context.Background(), client, model.ProbeResult{UpstreamID: "test-upstream", Status: "failed"})
			if (err != nil) != test.wantErr {
				t.Fatalf("probe error = %v, want error %t (result %+v)", err, test.wantErr, result)
			}
			if result.Status != test.status || result.IPv4 != test.ipv4 || result.IPv6 != test.ipv6 {
				t.Fatalf("incorrect aggregate egress: %+v", result)
			}
			if result.Error != test.ipv4Error || result.IPv6Error != test.ipv6Error {
				t.Fatalf("per-family failure diagnostics were lost: %+v", result)
			}
			if hits4.Load() != 1 || hits6.Load() != 1 {
				t.Fatalf("fixed echo endpoints were not both checked: IPv4 %d, IPv6 %d", hits4.Load(), hits6.Load())
			}
		})
	}
}

func TestDeleteRelayRejectsTargetInCandidate(t *testing.T) {
	r := New(Options{DataDir: t.TempDir()})
	for _, tc := range []struct {
		name, removedID string
		relays          []model.Relay
		want            string
	}{
		{name: "missing-id", want: "removed relay id is required"},
		{name: "enabled-target", removedID: "removed", relays: []model.Relay{{ID: "removed", NodeID: "node", Enabled: true}}, want: "still present"},
		{name: "disabled-target", removedID: "removed", relays: []model.Relay{{ID: "removed", NodeID: "node"}}, want: "still present"},
		{name: "target-on-another-node", removedID: "removed", relays: []model.Relay{{ID: "removed", NodeID: "other"}}, want: "still present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := r.DeleteRelay(context.Background(), model.Node{ID: "node", Kind: "invalid"}, nil, tc.relays, tc.removedID)
			if err == nil || !strings.Contains(err.Error(), tc.want) || result.Revision != "" {
				t.Fatalf("invalid deletion accepted: result %+v, error %v", result, err)
			}
		})
	}
}

func TestDeleteRelaySharesApplyNodeLock(t *testing.T) {
	r := New(Options{DataDir: t.TempDir()})
	node := model.Node{ID: "node", Kind: "local"}
	unlock, err := r.lock(context.Background(), node)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	for _, action := range []string{"apply", "delete-relay"} {
		t.Run(action, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
			defer cancel()
			var result model.ApplyResult
			var err error
			if action == "apply" {
				result, err = r.Apply(ctx, node, nil, nil)
			} else {
				result, err = r.DeleteRelay(ctx, node, nil, nil, "removed")
			}
			if !errors.Is(err, context.DeadlineExceeded) || result.Revision != "" {
				t.Fatalf("operation bypassed the shared node lock: result %+v, error %v", result, err)
			}
		})
	}
}

func deleteRelayConfig(t *testing.T, relayIDs ...string) []byte {
	t.Helper()
	upstreams, errs := xray.ParseImports("socks5://127.0.0.1:1080")
	if len(errs) != 0 || len(upstreams) != 1 {
		t.Fatalf("upstream fixture: %v", errs)
	}
	upstreams[0].ID = "upstream"
	relays := make([]model.Relay, 0, len(relayIDs))
	for i, id := range relayIDs {
		relay := model.Relay{ID: id, NodeID: "node", UpstreamID: "upstream", Enabled: true, Protocol: "socks", Listen: "127.0.0.1", Port: 31000 + i, Password: "relay-test-secret"}
		if err := xray.PrepareRelay(&relay); err != nil {
			t.Fatal(err)
		}
		relays = append(relays, relay)
	}
	config, err := xray.Generate(model.Node{ID: "node"}, upstreams, relays)
	if err != nil {
		t.Fatal(err)
	}
	return config
}

func TestDeleteRelayHelperRejectsCandidateWithTarget(t *testing.T) {
	for _, tc := range []struct {
		name   string
		config []byte
		bad    bool
	}{
		{name: "target", config: deleteRelayConfig(t, "removed"), bad: true},
		{name: "target-among-others", config: deleteRelayConfig(t, "kept", "removed"), bad: true},
		{name: "other-relay", config: deleteRelayConfig(t, "kept")},
		{name: "empty", config: deleteRelayConfig(t)},
		{name: "malformed", config: []byte(`{"inbounds":`), bad: true},
		{name: "invalid-tag", config: []byte(`{"inbounds":[{"tag":false}]}`), bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := validateDeletedRelayConfig(tc.config, "removed"); (err != nil) != tc.bad {
				t.Fatalf("candidate validation error = %v, want rejection %t", err, tc.bad)
			}
		})
	}
}

func revisionFixture(t *testing.T) revisionLinks {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "revisions"), 0700); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(root, ".symlink-probe")
	if err := os.Symlink("revisions", probe); err != nil {
		if goruntime.GOOS == "windows" && (errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "privilege")) {
			t.Skipf("revision fixtures need symlink permission: %v", err)
		}
		t.Fatal(err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	return revisionLinks{root: root}
}

func writeRevisionFixture(t *testing.T, links revisionLinks, id string, config []byte) {
	t.Helper()
	path := filepath.Join(links.root, "revisions", id)
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "config.json"), config, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestDeleteRelayUpdatesActualRollbackHistory(t *testing.T) {
	const current, previous, activated = "aaaaaaaaaaaaaaaaaaaaaaaa", "bbbbbbbbbbbbbbbbbbbbbbbb", "cccccccccccccccccccccccc"
	for _, tc := range []struct {
		name       string
		oldCurrent []byte
		removedID  string
		want       string
	}{
		{name: "current-contains-target", oldCurrent: deleteRelayConfig(t, "removed"), removedID: "removed"},
		{name: "only-previous-contains-target", oldCurrent: deleteRelayConfig(t, "kept"), removedID: "removed", want: current},
		{name: "empty-current-is-safe", oldCurrent: deleteRelayConfig(t), removedID: "removed", want: current},
		{name: "no-current-clears-previous", removedID: "removed"},
		{name: "ordinary-apply-keeps-current", oldCurrent: deleteRelayConfig(t, "removed"), want: current},
	} {
		t.Run(tc.name, func(t *testing.T) {
			links := revisionFixture(t)
			old := ""
			if tc.oldCurrent != nil {
				writeRevisionFixture(t, links, current, tc.oldCurrent)
				old = current
			}
			writeRevisionFixture(t, links, previous, deleteRelayConfig(t, "removed"))
			writeRevisionFixture(t, links, activated, deleteRelayConfig(t))
			if err := links.switchTo("current", activated); err != nil {
				t.Fatal(err)
			}
			if err := links.switchTo("previous", previous); err != nil {
				t.Fatal(err)
			}
			enabled := false
			err := finishApply(context.Background(), links, old, tc.removedID, func(context.Context) error {
				enabled = true
				got, err := links.read("previous")
				if err != nil || got != tc.want {
					t.Fatalf("unsafe rollback still reachable before enable: revision %q, error %v", got, err)
				}
				return nil
			})
			if err != nil || !enabled {
				t.Fatalf("apply finalization failed: enable %t, error %v", enabled, err)
			}
			got, err := links.read("current")
			if err != nil || got != activated {
				t.Fatalf("active revision changed during history update: %q, %v", got, err)
			}
			if tc.want == "" {
				if _, err := os.Lstat(filepath.Join(links.root, "previous")); !os.IsNotExist(err) {
					t.Fatalf("rollback should find no previous revision, got %v", err)
				}
			} else if tc.removedID != "" {
				config, err := os.ReadFile(filepath.Join(links.root, "revisions", tc.want, "config.json"))
				if err != nil {
					t.Fatal(err)
				}
				if err := validateDeletedRelayConfig(config, tc.removedID); err != nil {
					t.Fatalf("rollback could restore deleted relay: %v", err)
				}
			}
			if _, err := os.Stat(filepath.Join(links.root, "revisions", previous, "config.json")); err != nil {
				t.Fatalf("unlinked backup revision was deleted: %v", err)
			}
		})
	}
}

func TestDeleteRelayHistoryFailuresReturnError(t *testing.T) {
	const current = "aaaaaaaaaaaaaaaaaaaaaaaa"
	for _, tc := range []string{"previous-is-directory", "invalid-current-config", "missing-current-config", "enable-fails"} {
		t.Run(tc, func(t *testing.T) {
			links := revisionFixture(t)
			config := deleteRelayConfig(t, "removed")
			if tc == "invalid-current-config" {
				config = []byte(`{"inbounds":false}`)
			}
			writeRevisionFixture(t, links, current, config)
			if tc == "missing-current-config" {
				if err := os.Remove(filepath.Join(links.root, "revisions", current, "config.json")); err != nil {
					t.Fatal(err)
				}
			}
			if tc == "previous-is-directory" {
				path := filepath.Join(links.root, "previous")
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, "sentinel"), []byte("keep"), 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := links.switchTo("previous", current); err != nil {
				t.Fatal(err)
			}
			var enabled bool
			err := finishApply(context.Background(), links, current, "removed", func(context.Context) error {
				enabled = true
				return errors.New("test enable failed")
			})
			if err == nil {
				t.Fatal("failed apply finalization was reported as success")
			}
			if enabled != (tc == "enable-fails") {
				t.Fatalf("enable ran before rollback history was safe: %t, %v", enabled, err)
			}
			if tc == "previous-is-directory" {
				if data, err := os.ReadFile(filepath.Join(links.root, "previous", "sentinel")); err != nil || string(data) != "keep" {
					t.Fatalf("non-symlink previous path was modified: %q, %v", data, err)
				}
			}
			if tc == "enable-fails" {
				if previous, err := links.read("previous"); err != nil || previous != "" {
					t.Fatalf("unsafe rollback remained after enable failure: %q, %v", previous, err)
				}
			}
		})
	}
}

func TestDeleteRelayOnlyUnlinksFixedPreviousPath(t *testing.T) {
	links := revisionFixture(t)
	outside := t.TempDir()
	sentinel := filepath.Join(outside, "sentinel")
	if err := os.WriteFile(sentinel, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(links.root, "previous")); err != nil {
		t.Fatal(err)
	}
	if err := links.retainPrevious("", "removed"); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(sentinel); err != nil || string(data) != "keep" {
		t.Fatalf("cleanup followed an untrusted previous target: %q, %v", data, err)
	}
	for _, link := range []string{"../outside", "/tmp/previous", "revisions"} {
		if err := links.switchTo(link, strings.Repeat("a", 24)); err == nil {
			t.Fatalf("untrusted link path accepted: %q", link)
		}
		if _, err := links.read(link); err == nil {
			t.Fatalf("untrusted link path read: %q", link)
		}
	}
}

func TestSOCKSFailureNeverFallsBackToDirect(t *testing.T) {
	var requests atomic.Int32
	echo := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = io.WriteString(w, "203.0.113.1") }))
	defer echo.Close()
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	listener.Close()
	client, err := probeHTTPClient(address, "probe", "test-credential")
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, _, err := echoIP(ctx, client, echo.URL, 4); err == nil {
		t.Fatal("failed SOCKS unexpectedly succeeded")
	}
	if requests.Load() != 0 {
		t.Fatal("failed proxy leaked a direct request")
	}
}
