package xray

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpstreamCustomUserIDs(t *testing.T) {
	reality := testRelay(t, "node", "relay")
	cases := []struct {
		name, id string
		valid    bool
	}{
		{"numeric", "1234567890", true},
		{"named", "not-a-uuid", true},
		{"thirty-bytes", strings.Repeat("a", 30), true},
		{"unicode-thirty-bytes", strings.Repeat("中", 10), true},
		{"uuid", testUUID, true},
		{"compact-uuid", strings.ReplaceAll(testUUID, "-", ""), true},
		{"empty", "", false},
		{"thirty-one-bytes", strings.Repeat("a", 31), false},
		{"nonhex-thirty-two-bytes", strings.Repeat("z", 32), false},
		{"unicode-over-limit", strings.Repeat("中", 11), false},
		{"malformed-uuid", "z" + testUUID[1:], false},
		{"braced-uuid", "{" + testUUID + "}", false},
	}
	for _, protocol := range []string{"vless", "vmess"} {
		for _, tc := range cases {
			t.Run(protocol+"/"+tc.name, func(t *testing.T) {
				var link string
				if protocol == "vless" {
					query := url.Values{"encryption": {"none"}, "flow": {"xtls-rprx-vision"}, "security": {"reality"}, "sni": {"www.example.com"}, "fp": {"chrome"}, "pbk": {reality.RealityPublicKey}, "sid": {"aabbccdd"}, "spx": {"/"}, "type": {"tcp"}, "headerType": {"none"}}
					u := url.URL{Scheme: "vless", User: url.User(tc.id), Host: "proxy.example:443", RawQuery: query.Encode(), Fragment: "Custom-ID"}
					link = u.String()
				} else {
					encoded, _ := json.Marshal(map[string]any{"v": "2", "ps": "Custom-ID", "add": "proxy.example", "port": "443", "id": tc.id, "aid": "0", "net": "tcp"})
					link = "vmess://" + base64.StdEncoding.EncodeToString(encoded)
				}
				parsed, errs := ParseImports(link)
				if !tc.valid {
					if len(parsed) != 0 || len(errs) == 0 {
						t.Fatal("invalid user ID was accepted")
					}
					return
				}
				if len(parsed) != 1 || len(errs) != 0 {
					t.Fatalf("supported user ID was rejected: %v", errs)
				}
				out, err := DecodeOutbound(parsed[0])
				if err != nil {
					t.Fatal(err)
				}
				user := out["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["users"].([]any)[0].(map[string]any)
				if user["id"] != tc.id {
					t.Fatal("original user ID was rewritten")
				}
				config, err := ProbeConfig(parsed[0], 31337, "probe", "fixture-credential")
				if err != nil {
					t.Fatal(err)
				}
				runCoreTest(t, config)
				if core := os.Getenv("XRAY_TEST_LEGACY_CORE"); core != "" {
					config, err = ForCoreVersion(config, "v1.8.24")
					if err != nil {
						t.Fatal(err)
					}
					path := filepath.Join(t.TempDir(), "config.json")
					if err = os.WriteFile(path, config, 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					if output, err := exec.CommandContext(ctx, core, "run", "-test", "-config", path).CombinedOutput(); err != nil {
						t.Fatalf("legacy core rejected user ID: %v\n%s", err, output)
					}
				}
			})
		}
	}
}
