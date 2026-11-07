package xray

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xrayrelay/internal/model"
)

func testCertificate(t *testing.T) (string, string) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "relay.example"}, DNSNames: []string{"relay.example"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
}
func runCoreTest(t *testing.T, config []byte) {
	t.Helper()
	core := os.Getenv("XRAY_TEST_CORE")
	if core == "" {
		return
	}
	core, err := filepath.Abs(core)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, config, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, core, "run", "-test", "-config", file)
	cmd.Dir, _ = filepath.Abs("../..")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("official core rejected generated configuration: %v\n%s", err, out)
	}
}
func TestRelayProtocolMatrixAndCore(t *testing.T) {
	cert, key := testCertificate(t)
	cases := []struct{ protocol, network, security, cipher string }{
		{"vless", "raw", "reality", ""}, {"vless", "raw", "tls", ""}, {"vless", "raw", "none", ""}, {"vless", "ws", "tls", ""}, {"vless", "grpc", "tls", ""}, {"vless", "xhttp", "tls", ""},
		{"vmess", "raw", "none", ""}, {"vmess", "raw", "tls", ""}, {"vmess", "ws", "tls", ""}, {"vmess", "grpc", "tls", ""}, {"vmess", "xhttp", "tls", ""},
		{"trojan", "raw", "tls", ""}, {"trojan", "ws", "tls", ""}, {"trojan", "grpc", "tls", ""}, {"trojan", "xhttp", "tls", ""},
		{"shadowsocks", "raw", "none", "aes-128-gcm"}, {"shadowsocks", "raw", "none", "2022-blake3-aes-128-gcm"}, {"shadowsocks", "raw", "none", "2022-blake3-aes-256-gcm"},
		{"socks", "raw", "none", ""}, {"http", "raw", "none", ""}, {"socks", "raw", "tls", ""}, {"http", "raw", "tls", ""},
	}
	up := testUpstream(t)
	for _, tc := range cases {
		t.Run(tc.protocol+"_"+tc.network+"_"+tc.security+tc.cipher, func(t *testing.T) {
			r := model.Relay{ID: "relay", NodeID: "node", UpstreamID: up.ID, Enabled: true, Protocol: tc.protocol, Network: tc.network, Security: tc.security, Cipher: tc.cipher, PublicHost: "relay.example", ServerName: "relay.example", Port: 34443, Name: "protocol fixture"}
			if tc.security == "tls" {
				r.Certificate = cert
				r.CertificateKey = key
			}
			if err := PrepareRelay(&r); err != nil {
				t.Fatal(err)
			}
			if !relayPrepared(r) {
				t.Fatal("prepared relay missing protocol credentials")
			}
			if tc.security != "reality" && r.RealityPrivateKey != "" {
				t.Fatal("non-REALITY entrypoint generated REALITY secrets")
			}
			config, err := Generate(model.Node{ID: "node"}, []model.Upstream{up}, []model.Relay{r})
			if err != nil {
				t.Fatal(err)
			}
			share, err := ShareURL(r)
			if err != nil {
				t.Fatal(err)
			}
			imports, errs := ParseImports(share)
			if len(errs) != 0 || len(imports) != 1 {
				t.Fatalf("share cannot reimport: %v", errs)
			}
			if imports[0].Protocol != tc.protocol {
				t.Fatal("share changed protocol")
			}
			runCoreTest(t, config)
			probe, err := ProbeConfig(imports[0], 31337, "probe", "test-credential")
			if err != nil {
				t.Fatal(err)
			}
			runCoreTest(t, probe)
		})
	}
}
func TestProtocolMatrixRejectsInvalidCombinations(t *testing.T) {
	for _, r := range []model.Relay{{Protocol: "trojan", Security: "none", Port: 34443}, {Protocol: "vmess", Security: "reality", Port: 34443}, {Protocol: "shadowsocks", Security: "tls", Port: 34443}, {Protocol: "socks", Network: "ws", Security: "none", Port: 34443}, {Protocol: "vless", Network: "ws", Security: "tls", Port: 34443}, {Protocol: "vless", Network: "quic", Port: 34443}} {
		if PrepareRelay(&r) == nil {
			t.Fatalf("invalid matrix combination accepted: %s %s %s", r.Protocol, r.Network, r.Security)
		}
	}
	cert, key := testCertificate(t)
	r := model.Relay{Protocol: "trojan", Port: 34443, Certificate: cert, CertificateKey: key}
	if err := PrepareRelay(&r); err != nil {
		t.Fatal(err)
	}
	r.CertificateKey = "invalid"
	if PrepareRelay(&r) == nil {
		t.Fatal("invalid PEM key accepted")
	}
	if strings.Contains(r.ShareURL, "PRIVATE KEY") {
		t.Fatal("private key leaked into share URL")
	}
}
