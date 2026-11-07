package xray

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestSOCKSBase64Userinfo(t *testing.T) {
	username, pass := "qa", "ab>cd?:more"
	encodings := map[string]*base64.Encoding{
		"standard-padded": base64.StdEncoding,
		"standard-raw":    base64.RawStdEncoding,
		"url-padded":      base64.URLEncoding,
		"url-raw":         base64.RawURLEncoding,
	}
	for name, encoding := range encodings {
		for _, scheme := range []string{"socks", "socks5", "socks5h"} {
			for _, subscription := range []bool{false, true} {
				t.Run(name+"/"+scheme+map[bool]string{false: "/link", true: "/subscription"}[subscription], func(t *testing.T) {
					link := url.URL{Scheme: scheme, User: url.User(encoding.EncodeToString([]byte(username + ":" + pass))), Host: "proxy.example:5805", Fragment: "SOCKS 备注"}
					content := link.String()
					if subscription {
						content = base64.StdEncoding.EncodeToString([]byte(content))
					}
					upstreams, errs := ParseImports(content)
					if len(errs) != 0 || len(upstreams) != 1 {
						t.Fatalf("import failed: %v", errs)
					}
					u := upstreams[0]
					if u.Protocol != "socks" || u.Server != "proxy.example" || u.Port != 5805 || u.Name != link.Fragment {
						t.Fatal("SOCKS endpoint or remark changed")
					}
					out, err := DecodeOutbound(u)
					if err != nil {
						t.Fatal(err)
					}
					server := out["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
					user := server["users"].([]any)[0].(map[string]any)
					if user["user"] != username || user["pass"] != pass {
						t.Fatal("encoded userinfo was not decoded into the original username and complete credential")
					}
				})
			}
		}
	}
}

func TestProxyExplicitAndMissingUserinfoPreserved(t *testing.T) {
	encoded := base64.RawURLEncoding.EncodeToString([]byte("qa:encoded-credential"))
	cases := []struct {
		name, scheme, username, pass string
		userinfo                     *url.Userinfo
	}{
		{"plaintext-special-characters", "socks5", "user@example", "p:a/%+word", url.UserPassword("user@example", "p:a/%+word")},
		{"explicit-credential-wins", "socks", encoded, "explicit:credential", url.UserPassword(encoded, "explicit:credential")},
		{"explicit-empty-credential", "socks", encoded, "", url.UserPassword(encoded, "")},
		{"literal-username-only", "socks5h", "literal-user", "", url.User("literal-user")},
		{"decoded-without-separator", "socks", "dXNlcm5hbWUtb25seQ", "", url.User("dXNlcm5hbWUtb25seQ")},
		{"http-is-not-socks-encoding", "http", encoded, "", url.User(encoded)},
		{"no-authentication", "socks", "", "", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			link := url.URL{Scheme: tc.scheme, Host: "proxy.example:1080", User: tc.userinfo}
			upstreams, errs := ParseImports(link.String())
			if len(errs) != 0 || len(upstreams) != 1 {
				t.Fatalf("import failed: %v", errs)
			}
			out, err := DecodeOutbound(upstreams[0])
			if err != nil {
				t.Fatal(err)
			}
			server := out["settings"].(map[string]any)["servers"].([]any)[0].(map[string]any)
			if tc.userinfo == nil {
				if _, ok := server["users"]; ok {
					t.Fatal("unauthenticated proxy gained credentials")
				}
				return
			}
			user := server["users"].([]any)[0].(map[string]any)
			if user["user"] != tc.username || user["pass"] != tc.pass {
				t.Fatal("explicit or literal proxy userinfo was changed")
			}
		})
	}
}
