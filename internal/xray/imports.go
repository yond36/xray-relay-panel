package xray

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"xrayrelay/internal/model"
)

const maxImportSize = 8 << 20

// ParseImports accepts URI lists, base64 subscriptions, and explicit Xray outbound JSON.
// It performs no network access and reports errors without echoing credentials.
func ParseImports(content string) ([]model.Upstream, []string) {
	result := []model.Upstream{}
	errs := []string{}
	if len(content) > maxImportSize {
		return result, []string{"import exceeds 8 MiB"}
	}
	content = strings.TrimSpace(strings.TrimPrefix(content, "\ufeff"))
	if content == "" {
		return result, []string{"import is empty"}
	}
	if !strings.Contains(content, "://") && !strings.HasPrefix(content, "{") && !strings.HasPrefix(content, "[") {
		if b, err := decodeBase64(content); err == nil {
			content = strings.TrimSpace(string(b))
		}
	}
	if strings.HasPrefix(content, "{") || strings.HasPrefix(content, "[") {
		var value any
		d := json.NewDecoder(strings.NewReader(content))
		d.UseNumber()
		if err := d.Decode(&value); err != nil {
			return result, []string{"invalid outbound JSON"}
		}
		if err := d.Decode(new(any)); err != io.EOF {
			return result, []string{"outbound import contains trailing JSON"}
		}
		var list []any
		switch v := value.(type) {
		case []any:
			list = v
		case map[string]any:
			if a, ok := v["outbounds"].([]any); ok {
				list = a
			} else {
				list = []any{v}
			}
		default:
			return result, []string{"expected Xray outbound JSON object or array"}
		}
		if len(list) > 2000 {
			return result, []string{"too many imported outbounds"}
		}
		for i, item := range list {
			m, ok := item.(map[string]any)
			if !ok {
				errs = append(errs, fmt.Sprintf("outbound %d: expected object", i+1))
				continue
			}
			b, _ := json.Marshal(m)
			p, _ := m["protocol"].(string)
			name, _ := m["tag"].(string)
			u := model.Upstream{Name: name, Protocol: p, Outbound: b}
			deriveEndpoint(&u, m)
			finishImport(&u, i+1, &result, &errs)
		}
		return result, errs
	}
	lines := strings.FieldsFunc(content, func(r rune) bool { return r == '\n' || r == '\r' })
	if len(lines) > 2000 {
		return result, []string{"too many imported links"}
	}
	for i, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		u, err := parseURI(line)
		if err != nil {
			errs = append(errs, fmt.Sprintf("line %d: %s", i+1, err))
			continue
		}
		finishImport(&u, i+1, &result, &errs)
	}
	if len(result) == 0 && len(errs) == 0 {
		errs = append(errs, "import contains no links")
	}
	return result, errs
}
func finishImport(u *model.Upstream, index int, result *[]model.Upstream, errs *[]string) {
	if err := ValidateUpstream(*u); err != nil {
		*errs = append(*errs, fmt.Sprintf("item %d: %s", index, err))
		return
	}
	id, err := randomText(12)
	if err != nil {
		*errs = append(*errs, "secure random generation failed")
		return
	}
	u.ID = id
	if u.Name == "" {
		u.Name = u.Protocol + " " + net.JoinHostPort(u.Server, strconv.Itoa(u.Port))
	}
	u.CreatedAt = time.Now().UTC()
	u.UpdatedAt = u.CreatedAt
	*result = append(*result, *u)
}
func deriveEndpoint(u *model.Upstream, out map[string]any) {
	s, _ := out["settings"].(map[string]any)
	for _, key := range []string{"vnext", "servers"} {
		if a, ok := s[key].([]any); ok && len(a) > 0 {
			if e, ok := a[0].(map[string]any); ok {
				u.Server, _ = e["address"].(string)
				u.Port, _ = strconv.Atoi(fmt.Sprint(e["port"]))
				return
			}
		}
	}
}
func decodeBase64(s string) ([]byte, error) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, fmt.Errorf("invalid base64")
}
func parseURI(raw string) (model.Upstream, error) {
	var u model.Upstream
	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		return parseVMess(raw)
	}
	if strings.HasPrefix(strings.ToLower(raw), "ss://") {
		return parseSS(raw)
	}
	link, err := url.Parse(raw)
	if err != nil {
		return u, fmt.Errorf("invalid proxy URI")
	}
	u.Protocol = normalizeProtocol(link.Scheme)
	u.Server = link.Hostname()
	u.Port, err = strconv.Atoi(link.Port())
	if err != nil || u.Port < 1 || u.Port > 65535 || !validHost(u.Server) {
		return u, fmt.Errorf("proxy URI needs a valid host and explicit port")
	}
	u.Name = link.Fragment
	q := link.Query()
	for _, k := range []string{"allowInsecure", "insecure", "skip-cert-verify", "skipCertVerify", "allow_insecure", "tlsAllowInsecure"} {
		if _, ok := q[k]; ok {
			return u, fmt.Errorf("legacy/insecure TLS query %s is unsupported", k)
		}
	}
	out := map[string]any{"protocol": u.Protocol}
	auth := ""
	if link.User != nil {
		auth = link.User.Username()
	}
	switch u.Protocol {
	case "vless":
		if auth == "" {
			return u, fmt.Errorf("VLESS user id is required")
		}
		encryption := q.Get("encryption")
		if encryption == "" {
			encryption = "none"
		}
		user := map[string]any{"id": auth, "encryption": encryption}
		if flow := q.Get("flow"); flow != "" {
			user["flow"] = flow
		}
		out["settings"] = map[string]any{"vnext": []any{map[string]any{"address": u.Server, "port": u.Port, "users": []any{user}}}}
	case "trojan":
		if auth == "" {
			return u, fmt.Errorf("Trojan credential is required")
		}
		out["settings"] = map[string]any{"servers": []any{map[string]any{"address": u.Server, "port": u.Port, passwordField: auth}}}
		if q.Get("security") == "" {
			q.Set("security", "tls")
		}
	case "socks", "http":
		s := map[string]any{"address": u.Server, "port": u.Port}
		if link.User != nil {
			pass, explicit := link.User.Password()
			if u.Protocol == "socks" && !explicit {
				if decoded, err := decodeBase64(auth); err == nil {
					if username, credential, ok := strings.Cut(string(decoded), ":"); ok {
						auth, pass = username, credential
					}
				}
			}
			s["users"] = []any{map[string]any{"user": auth, "pass": pass}}
		}
		out["settings"] = map[string]any{"servers": []any{s}}
		if strings.EqualFold(link.Scheme, "https") {
			q.Set("security", "tls")
		}
	default:
		return u, fmt.Errorf("unsupported URI scheme; use explicit Xray outbound JSON for advanced protocols")
	}
	stream, err := streamFromQuery(q, u.Server)
	if err != nil {
		return u, err
	}
	out["streamSettings"] = stream
	u.Outbound, _ = json.Marshal(out)
	return u, nil
}
func streamFromQuery(q url.Values, server string) (map[string]any, error) {
	network := q.Get("type")
	if network == "" {
		network = q.Get("network")
	}
	if network == "" || network == "tcp" {
		network = "raw"
	}
	sec := q.Get("security")
	if sec == "" {
		sec = "none"
	}
	s := map[string]any{"network": network, "security": sec}
	if h := q.Get("headerType"); h != "" && h != "none" {
		return nil, fmt.Errorf("legacy transport headerType is unsupported")
	}
	switch network {
	case "raw":
	case "ws":
		ws := map[string]any{"path": defaultString(q.Get("path"), "/")}
		if h := q.Get("host"); h != "" {
			ws["headers"] = map[string]any{"Host": h}
		}
		s["wsSettings"] = ws
	case "grpc":
		g := map[string]any{"serviceName": q.Get("serviceName")}
		if a := q.Get("authority"); a != "" {
			g["authority"] = a
		}
		if mode := q.Get("mode"); mode != "" && mode != "gun" && mode != "multi" {
			return nil, fmt.Errorf("unsupported gRPC mode")
		} else if mode == "multi" {
			g["multiMode"] = true
		}
		s["grpcSettings"] = g
	case "xhttp":
		x := map[string]any{"path": defaultString(q.Get("path"), "/"), "host": q.Get("host"), "mode": defaultString(q.Get("mode"), "auto")}
		if extra := q.Get("extra"); extra != "" {
			var v map[string]any
			if json.Unmarshal([]byte(extra), &v) != nil {
				return nil, fmt.Errorf("invalid XHTTP extra JSON")
			}
			x["extra"] = v
		}
		s["xhttpSettings"] = x
	case "httpupgrade":
		s["httpupgradeSettings"] = map[string]any{"path": defaultString(q.Get("path"), "/"), "host": q.Get("host")}
	default:
		return nil, fmt.Errorf("unsupported/legacy transport %q; use RAW, WS, gRPC, XHTTP or HTTPUpgrade", network)
	}
	sn := defaultString(q.Get("sni"), defaultString(q.Get("serverName"), server))
	fp := defaultString(q.Get("fp"), "chrome")
	switch sec {
	case "none":
	case "tls":
		tls := map[string]any{"serverName": sn, "fingerprint": fp}
		if alpn := q.Get("alpn"); alpn != "" {
			tls["alpn"] = strings.Split(alpn, ",")
		}
		s["tlsSettings"] = tls
	case "reality":
		s["realitySettings"] = map[string]any{"serverName": sn, "fingerprint": fp, "publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": defaultString(q.Get("spx"), "/")}
	default:
		return nil, fmt.Errorf("unsupported stream security %q", sec)
	}
	return s, nil
}
func defaultString(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
func parseVMess(raw string) (model.Upstream, error) {
	var u model.Upstream
	b, err := decodeBase64(raw[len("vmess://"):])
	if err != nil {
		return u, fmt.Errorf("invalid VMess base64")
	}
	var v map[string]any
	if json.Unmarshal(b, &v) != nil {
		return u, fmt.Errorf("invalid VMess JSON")
	}
	str := func(k string) string {
		if x, ok := v[k]; ok {
			return fmt.Sprint(x)
		}
		return ""
	}
	for _, k := range []string{"allowInsecure", "insecure", "skip-cert-verify"} {
		if _, ok := v[k]; ok {
			return u, fmt.Errorf("VMess insecure TLS setting is unsupported")
		}
	}
	if aid := str("aid"); aid != "" && aid != "0" {
		return u, fmt.Errorf("legacy VMess alterId is unsupported")
	}
	u.Protocol = "vmess"
	u.Name = str("ps")
	u.Server = str("add")
	u.Port, _ = strconv.Atoi(str("port"))
	q := url.Values{"type": {str("net")}, "security": {defaultString(str("tls"), "none")}, "path": {str("path")}, "host": {str("host")}, "sni": {str("sni")}, "alpn": {str("alpn")}, "fp": {str("fp")}, "headerType": {str("type")}}
	if str("net") == "grpc" {
		q.Set("serviceName", str("path"))
	}
	s, err := streamFromQuery(q, u.Server)
	if err != nil {
		return u, err
	}
	out := map[string]any{"protocol": "vmess", "settings": map[string]any{"vnext": []any{map[string]any{"address": u.Server, "port": u.Port, "users": []any{map[string]any{"id": str("id"), "alterId": 0, "security": defaultString(str("scy"), "auto")}}}}}, "streamSettings": s}
	u.Outbound, _ = json.Marshal(out)
	return u, nil
}
func parseSS(raw string) (model.Upstream, error) {
	var u model.Upstream
	// SIP002 encodes userinfo only; the older format encodes the entire authority.
	rest := raw[len("ss://"):]
	frag := ""
	if i := strings.Index(rest, "#"); i >= 0 {
		frag = rest[i:]
		rest = rest[:i]
	}
	if !strings.Contains(rest, "@") {
		b, err := decodeBase64(strings.TrimSuffix(rest, "/"))
		if err != nil {
			return u, fmt.Errorf("invalid Shadowsocks base64")
		}
		rest = string(b)
	}
	link, err := url.Parse("ss://" + rest + frag)
	if err != nil || link.User == nil {
		return u, fmt.Errorf("invalid Shadowsocks URI")
	}
	if link.Query().Get("plugin") != "" {
		return u, fmt.Errorf("Shadowsocks SIP003 plugins are unsupported; use a native compatible outbound")
	}
	user := link.User.Username()
	pass, hasPass := link.User.Password()
	method := user
	if !hasPass {
		b, err := decodeBase64(user)
		if err != nil {
			return u, fmt.Errorf("invalid Shadowsocks userinfo")
		}
		parts := strings.SplitN(string(b), ":", 2)
		if len(parts) != 2 {
			return u, fmt.Errorf("Shadowsocks userinfo needs method and credential")
		}
		method, pass = parts[0], parts[1]
	}
	u.Protocol = "shadowsocks"
	u.Server = link.Hostname()
	u.Port, _ = strconv.Atoi(link.Port())
	u.Name = link.Fragment
	out := map[string]any{"protocol": u.Protocol, "settings": map[string]any{"servers": []any{map[string]any{"address": u.Server, "port": u.Port, "method": method, passwordField: pass}}}}
	u.Outbound, _ = json.Marshal(out)
	return u, nil
}
