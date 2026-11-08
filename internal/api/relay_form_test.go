package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"xrayrelay/internal/model"
)

type relayFormRuntime struct {
	fakeRuntime
	serviceCalls atomic.Int32
}

func (f *relayFormRuntime) Service(context.Context, model.Node, string) error {
	f.serviceCalls.Add(1)
	return nil
}

func TestRelayFormJSONContract(t *testing.T) {
	runtime := &relayFormRuntime{}
	s, cookie := fixture(t, runtime)
	node := decodeResponse[model.Node](t, request(t, s, http.MethodPost, "/api/nodes", model.Node{
		Name: "Default relay entry", Kind: "local", PublicHost: "relay.example.test",
	}, cookie), http.StatusCreated)
	upstream := decodeResponse[model.Upstream](t, request(t, s, http.MethodPost, "/api/upstreams", testUpstream(t), cookie), http.StatusCreated)
	if node.OwnerID == "" || node.OwnerID != upstream.OwnerID {
		t.Fatal("entry node and upstream must have the same owner")
	}

	data, err := os.ReadFile(filepath.Join("..", "..", "tests", "fixtures", "default-relay-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	// Keep the browser's JSON shape: marshaling model.Relay would add timestamps.
	var input map[string]any
	if err := json.Unmarshal(data, &input); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"created_at", "updated_at"} {
		if _, present := input[field]; present {
			t.Fatalf("default form request must omit %s", field)
		}
	}
	for _, field := range []string{"id", "uuid", "reality_private_key", "reality_public_key", "short_id"} {
		if input[field] != "" {
			t.Fatalf("default form must leave %s for the server to generate", field)
		}
	}
	input["node_id"], input["upstream_id"] = node.ID, upstream.ID

	assertConfigOnly := func(t *testing.T, want model.Relay) {
		t.Helper()
		state := decodeResponse[model.State](t, request(t, s, http.MethodGet, "/api/state", nil, cookie), http.StatusOK)
		if len(state.Relays) != 1 || state.Relays[0] != want {
			t.Fatal("saved relay does not match the response or rejected requests changed it")
		}
		if len(state.Nodes) != 1 || len(state.Upstreams) != 1 || len(state.Jobs) != 0 || len(state.Probes) != 0 || state.Nodes[0].Status != "pending" || state.Nodes[0].AppliedRevision != "" {
			t.Fatal("saving relay configuration must only mark the node pending, without runtime tasks")
		}
		runtime.mu.Lock()
		defer runtime.mu.Unlock()
		if runtime.inspected.ID != "" || runtime.appliedNode.ID != "" || len(runtime.active) != 0 || runtime.serviceCalls.Load() != 0 {
			t.Fatal("saving relay configuration must not inspect, apply or operate a service")
		}
	}

	var created model.Relay
	if !t.Run("create", func(t *testing.T) {
		created = decodeResponse[model.Relay](t, request(t, s, http.MethodPost, "/api/relays", input, cookie), http.StatusCreated)
		if created.ID == "" || created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() || created.UUID == "" || created.RealityPrivateKey == "" || created.RealityPublicKey == "" || created.ShortID == "" {
			t.Fatal("server did not generate relay ID, timestamps, UUID and REALITY credentials")
		}
		if created.OwnerID != node.OwnerID || created.NodeID != node.ID || created.UpstreamID != upstream.ID {
			t.Fatal("relay lost its owner or resource references")
		}
		// The API normalizes the form's TCP transport to Xray's RAW name.
		if !created.Enabled || created.Port != 443 || created.Protocol != "vless" || created.Security != "reality" || created.Flow != "xtls-rprx-vision" || created.Network != "raw" || created.Listen != "0.0.0.0" {
			t.Fatal("default form's enabled 443/VLESS/REALITY/Vision configuration changed")
		}
		assertConfigOnly(t, created)
	}) {
		return
	}

	var updated model.Relay
	if !t.Run("update_without_timestamps", func(t *testing.T) {
		// The generated credentials are still empty in input, as on the default form.
		input["enabled"] = false
		updated = decodeResponse[model.Relay](t, request(t, s, http.MethodPut, "/api/relays/"+created.ID, input, cookie), http.StatusOK)
		want := created
		want.Enabled, want.UpdatedAt = false, updated.UpdatedAt
		if updated != want || updated.UpdatedAt.Before(created.UpdatedAt) {
			t.Fatal("update must disable the relay while preserving CreatedAt, credentials and other configuration")
		}
		assertConfigOnly(t, updated)
	}) {
		return
	}

	for _, method := range []string{http.MethodPost, http.MethodPut} {
		path := "/api/relays"
		if method == http.MethodPut {
			path += "/" + created.ID
		}
		for _, tc := range []struct {
			name   string
			fields map[string]any
		}{
			{"unknown_field", map[string]any{"unknown_field": true}},
			{"empty_created_at", map[string]any{"created_at": ""}},
			{"empty_updated_at", map[string]any{"updated_at": ""}},
			{"both_timestamps_empty", map[string]any{"created_at": "", "updated_at": ""}},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				invalid := make(map[string]any, len(input)+len(tc.fields))
				for key, value := range input {
					invalid[key] = value
				}
				for key, value := range tc.fields {
					invalid[key] = value
				}
				decodeResponse[map[string]string](t, request(t, s, method, path, invalid, cookie), http.StatusBadRequest)
			})
		}
	}
	assertConfigOnly(t, updated)
}
