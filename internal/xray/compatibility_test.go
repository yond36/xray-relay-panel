package xray

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLegacyAliasesPreserveProxyRouting(t *testing.T) {
	input := []byte(`{"inbounds":[{"tag":"entry","streamSettings":{"network":"raw","security":"reality","realitySettings":{"target":"example.com:443","privateKey":"test"}}}],"outbounds":[{"tag":"proxy","streamSettings":{"network":"raw","security":"reality","realitySettings":{"publicKey":"test"}}}],"routing":{"rules":[{"inboundTag":["entry"],"outboundTag":"proxy"}]}}`)
	converted, err := ForCoreVersion(input, "1.8.24")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err = json.Unmarshal(converted, &got); err != nil {
		t.Fatal(err)
	}
	stream := got["inbounds"].([]any)[0].(map[string]any)["streamSettings"].(map[string]any)
	if stream["network"] != "tcp" || stream["realitySettings"].(map[string]any)["dest"] != "example.com:443" {
		t.Fatal("legacy aliases missing")
	}
	if !strings.Contains(string(input), `"target"`) || !strings.Contains(string(input), `"raw"`) {
		t.Fatal("compatibility conversion mutated source")
	}
	current, err := ForCoreVersion(input, "v26.10.31")
	if err != nil || string(current) != string(input) {
		t.Fatal("current configuration was changed")
	}
	rule := got["routing"].(map[string]any)["rules"].([]any)[0].(map[string]any)
	if rule["outboundTag"] != "proxy" {
		t.Fatal("compatibility conversion changed upstream routing")
	}
}
