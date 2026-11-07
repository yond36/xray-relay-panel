package xray

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"xrayrelay/internal/model"
)

const testUUID = "f3e07162-b419-4cad-96d3-fef130bf6260"

func testRelay(t *testing.T, node, id string) model.Relay {
	t.Helper()
	r := model.Relay{ID: id, NodeID: node, UpstreamID: "up", Enabled: true, Port: 34443, PublicHost: "relay.example", Name: "中转节点"}
	if err := PrepareRelay(&r); err != nil {
		t.Fatal(err)
	}
	return r
}
func testUpstream(t *testing.T) model.Upstream {
	t.Helper()
	u, e := ParseImports("vless://" + testUUID + "@upstream.example:443?encryption=none&security=tls&sni=upstream.example&type=tcp#Upstream")
	if len(e) != 0 || len(u) != 1 {
		t.Fatalf("parse: %v", e)
	}
	u[0].ID = "up"
	return u[0]
}
func TestPrepareRelayAndShareRoundTrip(t *testing.T) {
	r := testRelay(t, "n", "r")
	privBytes, _ := decodeKey(r.RealityPrivateKey)
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes()) != r.RealityPublicKey {
		t.Fatal("key pair does not match")
	}
	original := r
	if err := PrepareRelay(&r); err != nil {
		t.Fatal(err)
	}
	if r.UUID != original.UUID || r.RealityPrivateKey != original.RealityPrivateKey || r.ShortID != original.ShortID {
		t.Fatal("prepare regenerated saved secrets")
	}
	share, err := ShareURL(r)
	if err != nil {
		t.Fatal(err)
	}
	parsed, _ := url.Parse(share)
	if parsed.Query().Get("type") != "tcp" || parsed.Query().Get("flow") != "xtls-rprx-vision" {
		t.Fatal("missing client compatibility parameters")
	}
	imports, errs := ParseImports(share)
	if len(errs) != 0 || len(imports) != 1 {
		t.Fatalf("share roundtrip: %v", errs)
	}
	var out map[string]any
	_ = json.Unmarshal(imports[0].Outbound, &out)
	reality := out["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)
	if reality["publicKey"] != r.RealityPublicKey {
		t.Fatal("pinned core requires publicKey field")
	}
	if _, ok := reality[passwordField]; ok {
		t.Fatal("incompatible REALITY client key field")
	}
}
func TestParseImportProtocolsAndSubscription(t *testing.T) {
	vmess, _ := json.Marshal(map[string]any{"v": "2", "ps": "vmess", "add": "vmess.example", "port": "443", "id": testUUID, "aid": "0", "net": "ws", "tls": "tls", "path": "/ws", "host": "vmess.example"})
	ss := base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:test-credential"))
	links := []string{"vless://" + testUUID + "@vless.example:443?security=tls", "vmess://" + base64.StdEncoding.EncodeToString(vmess), "trojan://test-credential@trojan.example:443?sni=trojan.example", "ss://" + ss + "@ss.example:8388#ss", "socks5://user:test-credential@socks.example:1080", "https://user:test-credential@http.example:443"}
	sub := base64.StdEncoding.EncodeToString([]byte(strings.Join(links, "\n")))
	upstreams, errs := ParseImports(sub)
	if len(errs) != 0 || len(upstreams) != len(links) {
		t.Fatalf("imports=%d errors=%v", len(upstreams), errs)
	}
	for _, u := range upstreams {
		if err := ValidateUpstream(u); err != nil {
			t.Fatal(err)
		}
	}
	out, _ := DecodeOutbound(upstreams[2])
	server := out["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
	if server[passwordField] != "test-credential" {
		t.Fatal("Trojan core credential field missing")
	}
}
func TestLegacyAndInvalidImportsAreRejected(t *testing.T) {
	for _, link := range []string{"vless://" + testUUID + "@a.example:443?security=tls&allowInsecure=1", "vless://" + testUUID + "@a.example:443?type=h2", "vless://" + testUUID + "@a.example:443?type=quic", "vless://" + testUUID + "@a.example:443?security=xtls", "ss://YWVzLTEyOC1nY206cGFzcw@a.example:8388?plugin=obfs-local", "vless://" + strings.Repeat("x", 31) + "@a.example:443"} {
		u, e := ParseImports(link)
		if len(u) != 0 || len(e) == 0 {
			t.Errorf("invalid import accepted: %s", link)
		}
	}
	u := testUpstream(t)
	out, _ := DecodeOutbound(u)
	out["streamSettings"].(map[string]any)["tlsSettings"].(map[string]any)["allowInsecure"] = true
	u.Outbound, _ = json.Marshal(out)
	if ValidateUpstream(u) == nil {
		t.Fatal("insecure advanced TLS accepted")
	}
	u.Outbound = json.RawMessage(`{"protocol":"freedom","settings":{}}`)
	u.Protocol = "freedom"
	if ValidateUpstream(u) == nil {
		t.Fatal("direct outbound must not become upstream")
	}
}
func TestGenerateNodeIsolationProbeAndDefaultDeny(t *testing.T) {
	u := testUpstream(t)
	r := testRelay(t, "node-a", "relay-a")
	other := testRelay(t, "node-b", "relay-b")
	other.UpstreamID = "missing-on-purpose"
	disabled := r
	disabled.ID = "disabled"
	disabled.Enabled = false
	config, err := Generate(model.Node{ID: "node-a"}, []model.Upstream{u}, []model.Relay{r, other, disabled})
	if err != nil {
		t.Fatal(err)
	}
	var c map[string]any
	if err := json.Unmarshal(config, &c); err != nil {
		t.Fatal(err)
	}
	outs := c["outbounds"].([]any)
	if len(outs) != 2 || outs[0].(map[string]any)["protocol"] != "blackhole" {
		t.Fatal("default outbound must be blackhole")
	}
	ins := c["inbounds"].([]any)
	if len(ins) != 1 {
		t.Fatal("only this node's enabled relay should bind a permanent port")
	}
	relay := ins[0].(map[string]any)
	if relay["streamSettings"].(map[string]any)["network"] != "raw" {
		t.Fatal("entrypoint is not RAW")
	}
	rules := c["routing"].(map[string]any)["rules"].([]any)
	if len(rules) != 1 || rules[0].(map[string]any)["outboundTag"] != outs[1].(map[string]any)["tag"] {
		t.Fatal("relay does not explicitly select its upstream")
	}
	probeData, err := ProbeConfig(u, 30001, "probe", "isolated-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	var pc map[string]any
	if err := json.Unmarshal(probeData, &pc); err != nil {
		t.Fatal(err)
	}
	probe := pc["inbounds"].([]any)[0].(map[string]any)
	if probe["listen"] != "127.0.0.1" || probe["settings"].(map[string]any)["auth"] != passwordField {
		t.Fatal("temporary probe is not loopback authenticated SOCKS")
	}
	probeOuts := pc["outbounds"].([]any)
	probeRules := pc["routing"].(map[string]any)["rules"].([]any)
	if probeOuts[0].(map[string]any)["protocol"] != "blackhole" || len(probeRules) != 1 || probeRules[0].(map[string]any)["outboundTag"] != probeOuts[1].(map[string]any)["tag"] {
		t.Fatal("temporary probe must explicitly route to its upstream without direct fallback")
	}
	mainOut, probeOut := outs[1].(map[string]any), probeOuts[1].(map[string]any)
	delete(mainOut, "tag")
	delete(probeOut, "tag")
	mainJSON, _ := json.Marshal(mainOut)
	probeJSON, _ := json.Marshal(probeOut)
	if string(mainJSON) != string(probeJSON) {
		t.Fatal("business entry and temporary probe use different upstream configuration")
	}
	after, _ := DecodeOutbound(u)
	if _, ok := after["tag"]; ok {
		t.Fatal("generator mutated stored outbound")
	}
}
func TestGenerateConflictsAndUnknownReferences(t *testing.T) {
	u := testUpstream(t)
	r := testRelay(t, "n", "r")
	r2 := r
	r2.ID = "r2"
	if _, err := Generate(model.Node{ID: "n"}, []model.Upstream{u}, []model.Relay{r, r2}); err == nil {
		t.Fatal("duplicate port accepted")
	}
	r.UpstreamID = "gone"
	if _, err := Generate(model.Node{ID: "n"}, []model.Upstream{u}, []model.Relay{r}); err == nil {
		t.Fatal("missing upstream accepted")
	}
	bad := r
	bad.Security = "tls"
	if PrepareRelay(&bad) == nil {
		t.Fatal("unsupported TLS entrypoint accepted")
	}
	bad = r
	bad.RealityPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if PrepareRelay(&bad) == nil {
		t.Fatal("mismatched key accepted")
	}
}
func TestAdvancedOutboundAndProbeConfig(t *testing.T) {
	raw := `{"protocol":"wireguard","settings":{"secretKey":"example","peers":[{"publicKey":"example","endpoint":"wireguard.example:51820"}]}}`
	u, e := ParseImports(raw)
	if len(e) != 0 || len(u) != 1 {
		t.Fatalf("advanced outbound: %v", e)
	}
	cfg, err := ProbeConfig(u[0], 31000, "probe", "credential")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cfg), `"blackhole"`) || !strings.Contains(string(cfg), `"wireguard"`) {
		t.Fatal("probe lost advanced outbound or fail-closed default")
	}
}
