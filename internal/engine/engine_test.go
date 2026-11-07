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
