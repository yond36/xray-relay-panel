package xray

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"xrayrelay/internal/model"
)

func TestLegacyCoreRealityCompatibility(t *testing.T) {
	core := os.Getenv("XRAY_TEST_LEGACY_CORE")
	if core == "" {
		t.Skip("set XRAY_TEST_LEGACY_CORE to a verified v1.8.24 executable")
	}
	upstream := testUpstream(t)
	relay := testRelay(t, "legacy-node", "legacy-relay")
	main, err := Generate(model.Node{ID: "legacy-node"}, []model.Upstream{upstream}, []model.Relay{relay})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := ProbeConfig(upstream, 30005, "probe", "legacy-test-secret")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"relay": main, "probe": probe} {
		compatible, err := ForCoreVersion(data, "v1.8.24")
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(t.TempDir(), "config.json")
		if err = os.WriteFile(path, compatible, 0600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(core, "run", "-test", "-config", path)
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("legacy %s config rejected: %v\n%s", name, err, output)
		}
	}
}
