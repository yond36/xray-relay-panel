package xray

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"xrayrelay/internal/model"
)

// PrepareRelay fills credentials once, and validates the actual entrypoint matrix.
func PrepareRelay(r *model.Relay) error {
	if r == nil {
		return errors.New("relay is required")
	}
	r.Protocol = normalizeProtocol(defaultString(r.Protocol, "vless"))
	if r.Network == "" || r.Network == "tcp" {
		r.Network = "raw"
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
	switch r.Protocol {
	case "vless", "vmess", "trojan":
		switch r.Network {
		case "raw", "ws", "grpc", "xhttp":
		default:
			return errors.New("VLESS/VMess/Trojan entrypoints support RAW, WS, gRPC or XHTTP")
		}
	case "shadowsocks", "socks", "http":
		if r.Network != "raw" {
			return errors.New("Shadowsocks/SOCKS/HTTP entrypoints support RAW transport only")
		}
	default:
		return fmt.Errorf("unsupported relay protocol %q", r.Protocol)
	}
	if r.Security == "" {
		switch {
		case r.Protocol == "vless" && r.Network == "raw":
			r.Security = "reality"
		case r.Protocol == "trojan" || r.Protocol == "vless":
			r.Security = "tls"
		default:
			r.Security = "none"
		}
	}
	if r.Security == "reality" {
		return prepareReality(r)
	}
	if r.Security != "none" && r.Security != "tls" {
		return errors.New("entrypoint security must be none, tls or reality")
	}
	if r.Protocol == "trojan" && r.Security != "tls" {
		return errors.New("Trojan entrypoints require TLS with a PEM certificate and key")
	}
	if r.Protocol == "shadowsocks" && r.Security != "none" {
		return errors.New("Shadowsocks entrypoints use native encryption and security=none")
	}
	if r.Security == "tls" {
		if r.Certificate == "" || r.CertificateKey == "" {
			return errors.New("TLS entrypoints require PEM certificate and private key contents")
		}
		if _, err := tls.X509KeyPair([]byte(r.Certificate), []byte(r.CertificateKey)); err != nil {
			return errors.New("TLS certificate and private key are invalid or do not match")
		}
		if r.ServerName == "" {
			r.ServerName = r.PublicHost
		}
		if r.ServerName != "" && !validHost(r.ServerName) {
			return errors.New("TLS server name is invalid")
		}
	} else if r.Certificate != "" || r.CertificateKey != "" {
		return errors.New("PEM certificate fields require security=tls")
	}
	if r.Protocol == "vless" || r.Protocol == "vmess" {
		if r.UUID == "" {
			id, err := newUUID()
			if err != nil {
				return err
			}
			r.UUID = id
		}
		if !validUUID(r.UUID) {
			return errors.New("VLESS/VMess entrypoint needs a valid UUID")
		}
	}
	if r.Protocol == "vless" {
		if r.Flow != "" && (r.Flow != "xtls-rprx-vision" || r.Network != "raw" || r.Security != "tls") {
			return errors.New("Vision flow requires VLESS RAW with TLS or REALITY")
		}
	} else if r.Flow != "" {
		return errors.New("flow is only valid for VLESS")
	}
	if r.Protocol == "shadowsocks" {
		if r.Cipher == "" {
			r.Cipher = "aes-128-gcm"
		}
		if !validCipher(r.Cipher) {
			return errors.New("unsupported Shadowsocks cipher")
		}
		if r.Password == "" {
			length := 24
			if strings.HasPrefix(r.Cipher, "2022-") {
				length = 32
				if r.Cipher == "2022-blake3-aes-128-gcm" {
					length = 16
				}
			}
			b := make([]byte, length)
			if _, err := rand.Read(b); err != nil {
				return err
			}
			r.Password = base64.StdEncoding.EncodeToString(b)
		}
		if strings.HasPrefix(r.Cipher, "2022-") {
			key, err := base64.StdEncoding.DecodeString(r.Password)
			expected := 32
			if r.Cipher == "2022-blake3-aes-128-gcm" {
				expected = 16
			}
			if err != nil || len(key) != expected {
				return fmt.Errorf("Shadowsocks %s needs a base64 %d-byte key", r.Cipher, expected)
			}
		}
	}
	if r.Protocol == "trojan" || r.Protocol == "socks" || r.Protocol == "http" {
		if r.Password == "" {
			p, err := randomText(24)
			if err != nil {
				return err
			}
			r.Password = p
		}
		if r.Protocol == "socks" || r.Protocol == "http" {
			if r.UUID == "" {
				r.UUID = "relay"
			}
			if len(r.UUID) > 255 || len(r.Password) > 255 || strings.ContainsAny(r.UUID, "\x00\r\n") {
				return errors.New("SOCKS/HTTP username and credential must fit 255 bytes")
			}
		}
	}
	if r.Network == "raw" && r.Path != "" {
		return errors.New("RAW entrypoints do not have a transport path")
	}
	if r.Network != "raw" {
		if r.Path == "" {
			if r.Network == "grpc" {
				r.Path = "relay"
			} else {
				r.Path = "/relay"
			}
		}
		if strings.ContainsAny(r.Path, "\x00\r\n") {
			return errors.New("transport path contains control characters")
		}
		if (r.Network == "ws" || r.Network == "xhttp") && !strings.HasPrefix(r.Path, "/") {
			return errors.New("WS/XHTTP path must start with /")
		}
	}
	r.ShareURL = ""
	return nil
}
func relayPrepared(r model.Relay) bool {
	switch normalizeProtocol(r.Protocol) {
	case "vless", "vmess":
		if r.UUID == "" {
			return false
		}
	case "trojan", "shadowsocks", "socks", "http":
		if r.Password == "" {
			return false
		}
	default:
		return false
	}
	return r.Security != "reality" || (r.RealityPrivateKey != "" && r.ShortID != "")
}
func relayInbound(r model.Relay, t string) map[string]any {
	settings := map[string]any{}
	switch r.Protocol {
	case "vless":
		user := map[string]any{"id": r.UUID}
		if r.Flow != "" {
			user["flow"] = r.Flow
		}
		settings = map[string]any{"clients": []any{user}, "decryption": "none"}
	case "vmess":
		settings = map[string]any{"clients": []any{map[string]any{"id": r.UUID, "alterId": 0}}}
	case "trojan":
		settings = map[string]any{"clients": []any{map[string]any{passwordField: r.Password}}}
	case "shadowsocks":
		settings = map[string]any{"method": r.Cipher, passwordField: r.Password, "network": "tcp,udp"}
	case "socks":
		settings = map[string]any{"auth": passwordField, "accounts": []any{map[string]any{"user": r.UUID, "pass": r.Password}}, "udp": false}
	case "http":
		settings = map[string]any{"accounts": []any{map[string]any{"user": r.UUID, "pass": r.Password}}, "allowTransparent": false}
	}
	stream := map[string]any{"network": r.Network, "security": r.Security}
	if r.Security == "reality" {
		stream["realitySettings"] = map[string]any{"show": false, "target": r.Target, "xver": 0, "serverNames": []string{r.ServerName}, "privateKey": r.RealityPrivateKey, "shortIds": []string{r.ShortID}}
	}
	if r.Security == "tls" {
		stream["tlsSettings"] = map[string]any{"minVersion": "1.2", "certificates": []any{map[string]any{"certificate": strings.Split(strings.TrimSpace(r.Certificate), "\n"), "key": strings.Split(strings.TrimSpace(r.CertificateKey), "\n")}}}
	}
	switch r.Network {
	case "ws":
		stream["wsSettings"] = map[string]any{"path": r.Path}
	case "grpc":
		stream["grpcSettings"] = map[string]any{"serviceName": strings.TrimPrefix(r.Path, "/")}
	case "xhttp":
		stream["xhttpSettings"] = map[string]any{"path": r.Path, "mode": "auto"}
	}
	return map[string]any{"tag": t, "listen": r.Listen, "port": r.Port, "protocol": r.Protocol, "settings": settings, "streamSettings": stream}
}
func ShareURL(r model.Relay) (string, error) {
	if !relayPrepared(r) {
		return "", errors.New("relay must be prepared and saved before sharing")
	}
	if err := PrepareRelay(&r); err != nil {
		return "", err
	}
	if !validHost(r.PublicHost) {
		return "", errors.New("public host is required to share relay")
	}
	if r.Security == "reality" {
		return shareReality(r)
	}
	network := r.Network
	if network == "raw" {
		network = "tcp"
	}
	q := url.Values{"type": {network}, "security": {r.Security}}
	if r.Security == "tls" {
		q.Set("sni", defaultString(r.ServerName, r.PublicHost))
		q.Set("fp", "chrome")
	}
	if r.Network == "ws" || r.Network == "xhttp" {
		q.Set("path", r.Path)
	}
	if r.Network == "grpc" {
		q.Set("serviceName", strings.TrimPrefix(r.Path, "/"))
	}
	u := url.URL{Host: net.JoinHostPort(r.PublicHost, strconv.Itoa(r.Port)), Fragment: r.Name, RawQuery: q.Encode()}
	switch r.Protocol {
	case "vless":
		u.Scheme = "vless"
		u.User = url.User(r.UUID)
		q.Set("encryption", "none")
		if r.Flow != "" {
			q.Set("flow", r.Flow)
		}
		u.RawQuery = q.Encode()
	case "vmess":
		v := map[string]any{"v": "2", "ps": r.Name, "add": r.PublicHost, "port": strconv.Itoa(r.Port), "id": r.UUID, "aid": "0", "scy": "auto", "net": network, "type": "none", "host": "", "path": r.Path, "tls": "", "sni": r.ServerName}
		if r.Network == "grpc" {
			v["path"] = strings.TrimPrefix(r.Path, "/")
		}
		if r.Security == "tls" {
			v["tls"] = "tls"
		}
		b, _ := json.Marshal(v)
		return "vmess://" + base64.StdEncoding.EncodeToString(b), nil
	case "trojan":
		u.Scheme = "trojan"
		u.User = url.User(r.Password)
	case "shadowsocks":
		u.Scheme = "ss"
		u.RawQuery = ""
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(r.Cipher + ":" + r.Password)))
	case "socks":
		u.Scheme = "socks5"
		u.User = url.UserPassword(r.UUID, r.Password)
	case "http":
		u.Scheme = "http"
		if r.Security == "tls" {
			u.Scheme = "https"
		}
		u.User = url.UserPassword(r.UUID, r.Password)
	}
	return u.String(), nil
}
