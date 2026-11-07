package xray

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"

	"xrayrelay/internal/model"
)

const passwordField = "pass" + "word"

// DecodeOutbound returns an independent copy, so tagging never changes stored credentials.
func DecodeOutbound(u model.Upstream) (map[string]any, error) {
	if len(u.Outbound) == 0 {
		return nil, errors.New("upstream outbound is required")
	}
	d := json.NewDecoder(bytes.NewReader(u.Outbound))
	d.UseNumber()
	var out map[string]any
	if err := d.Decode(&out); err != nil || out == nil {
		return nil, errors.New("outbound must be a JSON object")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("outbound contains trailing JSON")
	}
	return out, nil
}

func ValidateUpstream(u model.Upstream) error {
	out, err := DecodeOutbound(u)
	if err != nil {
		return err
	}
	p, _ := out["protocol"].(string)
	switch p {
	case "vless", "vmess", "trojan", "shadowsocks", "socks", "http", "wireguard", "hysteria", "hysteria2":
	default:
		return fmt.Errorf("unsupported upstream protocol %q; direct, DNS, loopback and blackhole are not proxy upstreams", p)
	}
	declared := normalizeProtocol(u.Protocol)
	if declared != "" && declared != p {
		return errors.New("upstream protocol does not match outbound protocol")
	}
	if _, ok := out["settings"].(map[string]any); !ok {
		return errors.New("outbound settings must be an object")
	}
	// A stored proxy may not escape its explicitly generated route through another tag.
	for _, k := range []string{"proxySettings", "dialerProxy", "sendThrough"} {
		if _, ok := out[k]; ok {
			return fmt.Errorf("outbound %s is not supported in isolated upstreams", k)
		}
	}
	if err := rejectLegacy(out, "outbound"); err != nil {
		return err
	}
	if st, ok := out["streamSettings"].(map[string]any); ok {
		if n, _ := st["network"].(string); n != "" {
			switch n {
			case "raw", "tcp", "ws", "grpc", "xhttp", "httpupgrade", "kcp":
			default:
				return fmt.Errorf("unsupported transport %q; legacy HTTP/2 and QUIC imports require conversion", n)
			}
		}
		sec, _ := st["security"].(string)
		if sec != "" && sec != "none" && sec != "tls" && sec != "reality" {
			return fmt.Errorf("unsupported stream security %q", sec)
		}
		if sec == "reality" {
			r, _ := st["realitySettings"].(map[string]any)
			key, _ := r["publicKey"].(string)
			if _, err := decodeKey(key); err != nil {
				return errors.New("REALITY outbound needs a valid publicKey")
			}
			if sn, _ := r["serverName"].(string); !validServerName(sn) {
				return errors.New("REALITY outbound needs a valid serverName")
			}
		}
	}
	settings := out["settings"].(map[string]any)
	switch p {
	case "vless", "vmess":
		servers, ok := settings["vnext"].([]any)
		if !ok || len(servers) == 0 {
			return errors.New("outbound vnext must contain a server")
		}
		for _, item := range servers {
			s, ok := item.(map[string]any)
			if !ok {
				return errors.New("invalid vnext server")
			}
			if err := validateServer(s); err != nil {
				return err
			}
			users, ok := s["users"].([]any)
			if !ok || len(users) == 0 {
				return errors.New("outbound server needs users")
			}
			for _, v := range users {
				usr, ok := v.(map[string]any)
				if !ok {
					return errors.New("invalid outbound user")
				}
				id, _ := usr["id"].(string)
				if !validUpstreamUserID(id) {
					return errors.New("VLESS/VMess user id must be a UUID or a custom string of 1–30 bytes")
				}
				if aid, ok := usr["alterId"]; ok && fmt.Sprint(aid) != "0" {
					return errors.New("legacy VMess alterId is unsupported; only AEAD alterId 0 is accepted")
				}
				if p == "vless" {
					enc, _ := usr["encryption"].(string)
					if enc != "none" {
						return errors.New("VLESS encryption must be none; advanced post-quantum settings require a compatible explicit core configuration")
					}
					if flow, _ := usr["flow"].(string); flow != "" && flow != "xtls-rprx-vision" {
						return errors.New("unsupported VLESS flow")
					}
				}
			}
		}
	case "trojan", "shadowsocks", "socks", "http":
		servers, ok := settings["servers"].([]any)
		if !ok || len(servers) == 0 {
			return errors.New("outbound servers must contain a server")
		}
		for _, item := range servers {
			s, ok := item.(map[string]any)
			if !ok {
				return errors.New("invalid outbound server")
			}
			if err := validateServer(s); err != nil {
				return err
			}
			if p == "trojan" || p == "shadowsocks" {
				if pass, _ := s[passwordField].(string); pass == "" {
					return errors.New("upstream password is required")
				}
			}
			if p == "shadowsocks" {
				method, _ := s["method"].(string)
				if !validCipher(method) {
					return fmt.Errorf("unsupported Shadowsocks method %q", method)
				}
			}
		}
	}
	return nil
}

func rejectLegacy(v any, path string) error {
	switch v := v.(type) {
	case map[string]any:
		for k, child := range v {
			switch k {
			case "allowInsecure", "allowInsecureCiphers", "disableSystemRoot", "verifyPeerCertInNames", passwordField, "dialerProxy":
				if k == passwordField {
					if strings.HasSuffix(path, ".realitySettings") {
						return errors.New("REALITY password field is incompatible with the pinned core contract; use publicKey")
					}
					break
				}
				if k == "dialerProxy" {
					return errors.New("cross-outbound dialerProxy is not supported")
				}
				return fmt.Errorf("legacy or unsafe TLS field %s.%s is unsupported; use verified TLS", path, k)
			}
			if err := rejectLegacy(child, path+"."+k); err != nil {
				return err
			}
		}
	case []any:
		for _, c := range v {
			if err := rejectLegacy(c, path); err != nil {
				return err
			}
		}
	}
	return nil
}
func validateServer(s map[string]any) error {
	a, _ := s["address"].(string)
	if !validHost(a) {
		return errors.New("outbound server address is invalid")
	}
	n, err := strconv.Atoi(fmt.Sprint(s["port"]))
	if err != nil || n < 1 || n > 65535 {
		return errors.New("outbound server port must be 1..65535")
	}
	return nil
}
func normalizeProtocol(p string) string {
	switch strings.ToLower(p) {
	case "ss":
		return "shadowsocks"
	case "socks5", "socks5h":
		return "socks"
	case "https":
		return "http"
	default:
		return strings.ToLower(p)
	}
}
func validHost(h string) bool {
	if h == "" || len(h) > 253 || strings.ContainsAny(h, "\x00\r\n\t /\\@?#") {
		return false
	}
	if net.ParseIP(strings.Trim(h, "[]")) != nil {
		return true
	}
	if strings.Contains(h, ":") {
		return false
	}
	for _, part := range strings.Split(h, ".") {
		if part == "" || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		for _, c := range part {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
func validServerName(h string) bool { return validHost(h) && net.ParseIP(h) == nil }
func validUUID(s string) bool {
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return false
	}
	_, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	return err == nil
}
func validUpstreamUserID(s string) bool {
	if len(s) > 0 && len(s) <= 30 {
		return true
	}
	if len(s) == 32 {
		_, err := hex.DecodeString(s)
		return err == nil
	}
	return validUUID(s)
}
func validCipher(s string) bool {
	switch s {
	case "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305", "xchacha20-poly1305", "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		return true
	}
	return false
}
func decodeKey(s string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, errors.New("X25519 key must be 32 bytes in unpadded URL base64")
	}
	return b, nil
}
func randomText(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 15) | 64
	b[8] = (b[8] & 63) | 128
	s := hex.EncodeToString(b)
	return s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:], nil
}

func prepareReality(r *model.Relay) error {
	if r == nil {
		return errors.New("relay is required")
	}
	if r.Protocol == "" {
		r.Protocol = "vless"
	}
	r.Protocol = normalizeProtocol(r.Protocol)
	if r.Network == "" || r.Network == "tcp" {
		r.Network = "raw"
	}
	if r.Security == "" {
		r.Security = "reality"
	}
	if r.Listen == "" {
		r.Listen = "0.0.0.0"
	}
	if net.ParseIP(r.Listen) == nil {
		return errors.New("relay listen must be an IP address")
	}
	if r.Port < 1 || r.Port > 65535 {
		return errors.New("relay port must be 1..65535")
	}
	if r.PublicHost != "" && !validHost(r.PublicHost) {
		return errors.New("relay public host is invalid")
	}
	if r.Protocol != "vless" || r.Security != "reality" || r.Network != "raw" {
		return errors.New("this release supports VLESS + REALITY + RAW relay entrypoints; TLS entries need managed certificates and are not supported")
	}
	if r.Certificate != "" || r.CertificateKey != "" || r.Path != "" || r.Password != "" || r.Cipher != "" {
		return errors.New("TLS certificates, transport path and password/cipher do not apply to a VLESS REALITY RAW entrypoint")
	}
	if r.UUID == "" {
		id, err := newUUID()
		if err != nil {
			return err
		}
		r.UUID = id
	}
	if !validUUID(r.UUID) {
		return errors.New("relay UUID is invalid")
	}
	if r.Flow == "" {
		r.Flow = "xtls-rprx-vision"
	}
	if r.Flow != "xtls-rprx-vision" {
		return errors.New("relay flow must be xtls-rprx-vision")
	}
	if r.ServerName == "" {
		r.ServerName = "www.cloudflare.com"
	}
	if !validServerName(r.ServerName) {
		return errors.New("REALITY server name must be a DNS name")
	}
	if r.Target == "" {
		r.Target = net.JoinHostPort(r.ServerName, "443")
	}
	h, p, err := net.SplitHostPort(r.Target)
	if err != nil || !validHost(h) {
		return errors.New("REALITY target must be host:port")
	}
	port, e := strconv.Atoi(p)
	if e != nil || port < 1 || port > 65535 {
		return errors.New("REALITY target port is invalid")
	}
	if r.RealityPrivateKey == "" {
		if r.RealityPublicKey != "" {
			return errors.New("REALITY public key without private key cannot serve an entrypoint")
		}
		key, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		r.RealityPrivateKey = base64.RawURLEncoding.EncodeToString(key.Bytes())
	}
	privBytes, err := decodeKey(r.RealityPrivateKey)
	if err != nil {
		return err
	}
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return err
	}
	pub := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())
	if r.RealityPublicKey != "" && r.RealityPublicKey != pub {
		return errors.New("REALITY public key does not match private key")
	}
	r.RealityPublicKey = pub
	if r.ShortID == "" {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		r.ShortID = hex.EncodeToString(b)
	}
	if len(r.ShortID) > 16 || len(r.ShortID)%2 != 0 {
		return errors.New("REALITY short ID must be even hex, at most 16 characters")
	}
	if _, err := hex.DecodeString(r.ShortID); err != nil {
		return errors.New("REALITY short ID must be hexadecimal")
	}
	r.ShareURL = ""
	return nil
}

func shareReality(r model.Relay) (string, error) {
	if err := PrepareRelay(&r); err != nil {
		return "", err
	}
	if !validHost(r.PublicHost) {
		return "", errors.New("public host is required to share relay")
	}
	q := url.Values{"encryption": {"none"}, "security": {"reality"}, "type": {"tcp"}, "flow": {r.Flow}, "sni": {r.ServerName}, "fp": {"chrome"}, "pbk": {r.RealityPublicKey}, "sid": {r.ShortID}, "spx": {"/"}}
	u := url.URL{Scheme: "vless", User: url.User(r.UUID), Host: net.JoinHostPort(r.PublicHost, strconv.Itoa(r.Port)), RawQuery: q.Encode(), Fragment: r.Name}
	return u.String(), nil
}
