package xray

import (
	"encoding/json"
	"xrayrelay/internal/coreversion"
)

// ForCoreVersion uses equivalent legacy aliases; unsupported features still fail core validation.
func ForCoreVersion(config []byte, version string) ([]byte, error) {
	if _, err := coreversion.Normalize(version); err != nil {
		return nil, err
	}
	if !coreversion.LegacyAliases(version) {
		return config, nil
	}
	var value map[string]any
	if err := json.Unmarshal(config, &value); err != nil {
		return nil, err
	}
	var walk func(any)
	walk = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if stream, ok := v["streamSettings"].(map[string]any); ok {
				if stream["network"] == "raw" {
					stream["network"] = "tcp"
				}
				if reality, ok := stream["realitySettings"].(map[string]any); ok {
					if target, exists := reality["target"]; exists {
						reality["dest"] = target
						delete(reality, "target")
					}
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(value)
	return json.MarshalIndent(value, "", "  ")
}
