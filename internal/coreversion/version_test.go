package coreversion

import "testing"

func TestNormalizeExplicitTags(t *testing.T) {
	for in, want := range map[string]string{"1.8.24": "v1.8.24", " v26.10.31 ": "v26.10.31", "V26.10.31-rc.1": "v26.10.31-rc.1", "v1.2.123": "v1.2.123", "v26.11.1-beta.2+build.1": "v26.11.1-beta.2+build.1"} {
		got, err := Normalize(in)
		if err != nil || got != want {
			t.Fatalf("Normalize(%q)=%q,%v", in, got, err)
		}
	}
	for _, in := range []string{"", "latest", "v1.2", "v1.2.3/../../etc", "v1.2.3;id", "https://example.com/core", "v1.2.3\nnext", "v1.2.3-rc..1"} {
		if _, err := Normalize(in); err == nil {
			t.Fatalf("unsafe or ambiguous tag accepted: %q", in)
		}
	}
}
func TestBinaryVersionMatchesOfficialTaggedAsset(t *testing.T) {
	for _, pair := range [][2]string{{"v1.8.24", "1.8.24"}, {"v26.10.31-rc.1", "26.10.31"}, {"v26.10.31-rc.1", "v26.10.31-rc.1"}} {
		if !MatchesBinary(pair[0], pair[1]) {
			t.Fatalf("valid reported version rejected: %v", pair)
		}
	}
	for _, pair := range [][2]string{{"v26.10.31", "v26.10.30"}, {"v26.10.31", "v26.10.31-rc.1"}, {"v26.10.31-rc.1", "v26.10.31-rc.2"}, {"latest", "v26.10.31"}} {
		if MatchesBinary(pair[0], pair[1]) {
			t.Fatalf("mismatched reported version accepted: %v", pair)
		}
	}
}
