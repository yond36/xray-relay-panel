package xray

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"xrayrelay/internal/model"
)

func tag(prefix, id string) string {
	b := sha256.Sum256([]byte(id))
	return prefix + hex.EncodeToString(b[:12])
}
func blackhole() map[string]any {
	return map[string]any{"tag": "default-deny", "protocol": "blackhole", "settings": map[string]any{}}
}
func baseConfig() map[string]any {
	return map[string]any{"log": map[string]any{"access": "none", "loglevel": "warning"}, "inbounds": []any{}, "outbounds": []any{blackhole()}, "routing": map[string]any{"domainStrategy": "AsIs", "rules": []any{}}}
}
func probeInbound(t string, port int, user, pass string) map[string]any {
	return map[string]any{"tag": t, "listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": map[string]any{"auth": passwordField, "accounts": []any{map[string]any{"user": user, "pass": pass}}, "udp": false}}
}
func route(in, out string) map[string]any {
	return map[string]any{"type": "field", "inboundTag": []string{in}, "outboundTag": out}
}

func Generate(n model.Node, upstreams []model.Upstream, relays []model.Relay) ([]byte, error) {
	if n.ID == "" {
		return nil, errors.New("node id is required")
	}
	cfg := baseConfig()
	inbounds := []any{}
	outbounds := []any{blackhole()}
	rules := []any{}
	available := map[string]model.Upstream{}
	for _, u := range upstreams {
		if u.ID == "" {
			return nil, errors.New("upstream id is required")
		}
		if _, ok := available[u.ID]; ok {
			return nil, errors.New("duplicate upstream id")
		}
		available[u.ID] = u
	}
	used := map[string]bool{}
	ports := map[int]bool{}
	seenIDs := map[string]bool{}
	for _, r := range relays {
		if r.NodeID != n.ID || !r.Enabled {
			continue
		}
		if r.ID == "" || seenIDs[r.ID] {
			return nil, errors.New("relay id must be nonempty and unique on node")
		}
		seenIDs[r.ID] = true
		if !relayPrepared(r) {
			return nil, fmt.Errorf("relay %q has not been prepared", r.ID)
		}
		if err := PrepareRelay(&r); err != nil {
			return nil, fmt.Errorf("relay %q: %w", r.ID, err)
		}
		if ports[r.Port] {
			return nil, fmt.Errorf("relay port %d conflicts on node", r.Port)
		}
		ports[r.Port] = true
		if _, ok := available[r.UpstreamID]; !ok {
			return nil, fmt.Errorf("relay %q references missing upstream", r.ID)
		}
		used[r.UpstreamID] = true
		it := tag("relay-", r.ID)
		ot := tag("upstream-", r.UpstreamID)
		inbound := relayInbound(r, it)
		inbounds = append(inbounds, inbound)
		rules = append(rules, route(it, ot))
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		u := available[id]
		if err := ValidateUpstream(u); err != nil {
			return nil, fmt.Errorf("upstream %q: %w", id, err)
		}
		out, _ := DecodeOutbound(u)
		out["tag"] = tag("upstream-", id)
		outbounds = append(outbounds, out)
	}
	cfg["inbounds"] = inbounds
	cfg["outbounds"] = outbounds
	cfg["routing"].(map[string]any)["rules"] = rules
	return json.MarshalIndent(cfg, "", "  ")
}

// ProbeConfig builds a loopback-only process with precisely the requested outbound.
func ProbeConfig(u model.Upstream, port int, user, pass string) ([]byte, error) {
	if port < 1 || port > 65535 || user == "" || pass == "" {
		return nil, errors.New("probe needs a valid port and authentication")
	}
	if err := ValidateUpstream(u); err != nil {
		return nil, err
	}
	out, _ := DecodeOutbound(u)
	out["tag"] = "probe-upstream"
	cfg := baseConfig()
	cfg["inbounds"] = []any{probeInbound("probe-in", port, user, pass)}
	cfg["outbounds"] = []any{blackhole(), out}
	cfg["routing"].(map[string]any)["rules"] = []any{route("probe-in", "probe-upstream")}
	return json.MarshalIndent(cfg, "", "  ")
}
