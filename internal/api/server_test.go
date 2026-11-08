package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
)

type fakeRuntime struct {
	mu               sync.Mutex
	active           map[string]int
	maxActive        map[string]int
	started          chan string
	release          chan struct{}
	applyError       error
	applyFunc        func(context.Context, model.Node, []model.Upstream, []model.Relay) (model.ApplyResult, error)
	deleteRelayID    string
	serviceActions   []string
	probe            model.ProbeResult
	probeError       error
	probeFunc        func(context.Context, model.Node, model.Upstream) (model.ProbeResult, error)
	inspected        model.Node
	appliedNode      model.Node
	appliedUpstreams []model.Upstream
	appliedRelays    []model.Relay
}

func (f *fakeRuntime) Inspect(ctx context.Context, node model.Node) (model.NodeInspection, error) {
	f.mu.Lock()
	f.inspected = node
	f.mu.Unlock()
	return model.NodeInspection{Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), RequiresTrust: node.Fingerprint == "", Ports: []int{}}, nil
}

func (f *fakeRuntime) Apply(ctx context.Context, node model.Node, upstreams []model.Upstream, relays []model.Relay) (model.ApplyResult, error) {
	f.mu.Lock()
	f.appliedNode = node
	f.appliedUpstreams = append([]model.Upstream{}, upstreams...)
	f.appliedRelays = append([]model.Relay{}, relays...)
	if f.active == nil {
		f.active, f.maxActive = make(map[string]int), make(map[string]int)
	}
	f.active[node.ID]++
	if f.active[node.ID] > f.maxActive[node.ID] {
		f.maxActive[node.ID] = f.active[node.ID]
	}
	f.mu.Unlock()
	defer func() { f.mu.Lock(); f.active[node.ID]--; f.mu.Unlock() }()
	if f.started != nil {
		f.started <- node.ID
	}
	if f.release != nil {
		select {
		case <-ctx.Done():
			return model.ApplyResult{}, ctx.Err()
		case <-f.release:
		}
	}
	if f.applyFunc != nil {
		return f.applyFunc(ctx, node, upstreams, relays)
	}
	if f.applyError != nil {
		return model.ApplyResult{}, f.applyError
	}
	return model.ApplyResult{Revision: "revision-" + node.ID, CoreVersion: model.DefaultCoreVersion}, nil
}

func (f *fakeRuntime) DeleteRelay(ctx context.Context, node model.Node, upstreams []model.Upstream, relays []model.Relay, relayID string) (model.ApplyResult, error) {
	f.mu.Lock()
	f.deleteRelayID = relayID
	f.mu.Unlock()
	return f.Apply(ctx, node, upstreams, relays)
}

func (f *fakeRuntime) Probe(ctx context.Context, node model.Node, upstream model.Upstream) (model.ProbeResult, error) {
	if f.probeFunc != nil {
		return f.probeFunc(ctx, node, upstream)
	}
	return f.probe, f.probeError
}
func (f *fakeRuntime) Service(_ context.Context, _ model.Node, action string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.serviceActions = append(f.serviceActions, action)
	return nil
}
func (f *fakeRuntime) Logs(context.Context, model.Node) (string, error) { return "service log", nil }

func request(t *testing.T, server *Server, method, path string, input any, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			t.Fatal(err)
		}
		body = bytes.NewReader(data)
	}
	r := httptest.NewRequest(method, "http://panel.test"+path, body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "http://panel.test")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func decodeResponse[T any](t *testing.T, response *httptest.ResponseRecorder, status int) T {
	t.Helper()
	if response.Code != status {
		t.Fatalf("unexpected HTTP status: got %d, want %d (message %s)", response.Code, status, response.Body.String())
	}
	var value T
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func fixture(t *testing.T, runtime model.Runtime) (*Server, *http.Cookie) {
	t.Helper()
	return fixtureIn(t, t.TempDir(), runtime)
}

func fixtureIn(t *testing.T, directory string, runtime model.Runtime) (*Server, *http.Cookie) {
	t.Helper()
	s, err := New(Config{DataDir: directory, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	account := store.Account{ID: "fixture-admin", Username: "admin", Role: model.RoleAdmin, Hash: token}
	if err := s.store.Setup(context.Background(), account, store.Session{AccountID: account.ID, Hash: auth.TokenHash(token), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return s, &http.Cookie{Name: cookieName, Value: token}
}

func testUpstream(t *testing.T) model.Upstream {
	t.Helper()
	user, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	pass, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	outbound, err := json.Marshal(map[string]any{"protocol": "socks", "settings": map[string]any{"servers": []any{map[string]any{"address": "proxy.example.test", "port": 1080, "users": []any{map[string]any{"user": user, "pass": pass}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	return model.Upstream{Name: "SOCKS upstream", Protocol: "socks", Server: "proxy.example.test", Port: 1080, Outbound: outbound}
}

func TestConcurrentSetupOriginAndSessionRevocation(t *testing.T) {
	s, err := New(Config{DataDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	secret, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"username": "owner", "password": secret}
	var wait sync.WaitGroup
	responses := make(chan *httptest.ResponseRecorder, 4)
	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() { defer wait.Done(); responses <- request(t, s, "POST", "/api/auth/setup", input, nil) }()
	}
	wait.Wait()
	close(responses)
	created := 0
	var cookie *http.Cookie
	for response := range responses {
		if response.Code == http.StatusCreated {
			created++
			cookie = response.Result().Cookies()[0]
		} else if response.Code != http.StatusConflict {
			t.Fatalf("unexpected setup response %d", response.Code)
		}
	}
	if created != 1 || cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal("setup was not singleton or cookie protections are missing")
	}
	stateResponse := request(t, s, "GET", "/api/state", nil, cookie)
	decodeResponse[model.State](t, stateResponse, http.StatusOK)
	for _, key := range []string{"nodes", "upstreams", "relays", "jobs", "probes", "subscriptions"} {
		if !bytes.Contains(stateResponse.Body.Bytes(), []byte(`"`+key+`":[]`)) {
			t.Fatalf("empty %s must be an array", key)
		}
	}
	r := httptest.NewRequest("POST", "http://panel.test/api/settings/rotate-token", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", "https://attacker.test")
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("cross-origin mutation was accepted")
	}
	r = httptest.NewRequest("POST", "http://panel.test/api/settings/rotate-token", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatal("cookie mutation without a verifiable origin was accepted")
	}
	decodeResponse[map[string]bool](t, request(t, s, "POST", "/api/auth/logout", nil, cookie), http.StatusOK)
	if response := request(t, s, "GET", "/api/state", nil, cookie); response.Code != http.StatusUnauthorized {
		t.Fatal("logged-out cookie remained authenticated")
	}
	login := request(t, s, "POST", "/api/auth/login", input, nil)
	decodeResponse[map[string]any](t, login, http.StatusOK)
}

func TestCRUDMasksSecretsPreservesEmptyCredentialsAndPendingRules(t *testing.T) {
	runtime := &fakeRuntime{}
	s, cookie := fixture(t, runtime)
	secret, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	node := model.Node{Name: "Remote", Kind: "ssh", Host: "node.example.test", SSHPort: 22, Username: "root", AuthMode: "password", Password: secret, PublicHost: "relay.example.test"}
	inspection := decodeResponse[model.NodeInspection](t, request(t, s, "POST", "/api/nodes/test", node, cookie), http.StatusOK)
	if !inspection.RequiresTrust || inspection.Fingerprint == "" {
		t.Fatal("first-use inspection did not require explicit fingerprint trust")
	}
	if response := request(t, s, "POST", "/api/nodes", node, cookie); response.Code != http.StatusBadRequest {
		t.Fatal("node was saved without trusted fingerprint")
	}
	node.Fingerprint = inspection.Fingerprint
	node = decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", node, cookie), http.StatusCreated)
	if node.Password != "" || !node.HasCredentials {
		t.Fatal("SSH credentials leaked in node response")
	}
	node.Name = "Renamed remote"
	node = decodeResponse[model.Node](t, request(t, s, "PUT", "/api/nodes/"+node.ID, node, cookie), http.StatusOK)
	s.mu.Lock()
	stored, err := s.store.State(context.Background())
	s.mu.Unlock()
	if err != nil || stored.Nodes[0].Password != secret {
		t.Fatal("empty update cleared the existing SSH credential")
	}
	upstream := decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", testUpstream(t), cookie), http.StatusCreated)
	if len(upstream.Outbound) != 0 {
		t.Fatal("upstream create leaked outbound")
	}
	upstream = decodeResponse[model.Upstream](t, request(t, s, "PUT", "/api/upstreams/"+upstream.ID, map[string]string{"name": "Renamed"}, cookie), http.StatusOK)
	detail := decodeResponse[model.Upstream](t, request(t, s, "GET", "/api/upstreams/"+upstream.ID, nil, cookie), http.StatusOK)
	if len(detail.Outbound) == 0 || detail.Server != "proxy.example.test" || detail.Port != 1080 || detail.Protocol != "socks" {
		t.Fatal("name-only upstream update cleared fields")
	}
	relay := model.Relay{Name: "Entry", NodeID: node.ID, UpstreamID: upstream.ID, Enabled: true, Port: 24443, ServerName: "www.example.com", Target: "www.example.com:443"}
	relay = decodeResponse[model.Relay](t, request(t, s, "POST", "/api/relays", relay, cookie), http.StatusCreated)
	if relay.UUID == "" || relay.RealityPrivateKey == "" {
		t.Fatal("relay secrets were not generated")
	}
	state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	if state.Nodes[0].Status != "pending" || state.Nodes[0].Password != "" || len(state.Upstreams[0].Outbound) != 0 {
		t.Fatal("state leaked credentials or did not mark relay pending")
	}
	conflict := relay
	conflict.ID, conflict.Name = "", "Conflicting entry"
	if response := request(t, s, "POST", "/api/relays", conflict, cookie); response.Code != http.StatusConflict {
		t.Fatal("per-node port conflict was not rejected")
	}
	job := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, job.ID, "succeeded")
	waitNodeIdle(t, s, node.ID)
	job = decodeResponse[model.Job](t, request(t, s, "DELETE", "/api/relays/"+relay.ID, nil, cookie), http.StatusAccepted)
	if job.Action != "delete-relay" || job.RelayID != relay.ID || job.OwnerID != node.OwnerID {
		t.Fatalf("applied deletion lost its task target: %+v", job)
	}
	waitJob(t, s, cookie, job.ID, "succeeded")
	state = decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	if len(state.Relays) != 0 || state.Nodes[0].Status != "ready" {
		t.Fatal("deleting the last enabled relay did not apply an empty configuration")
	}
	if response := request(t, s, "POST", "/api/nodes/"+node.ID+"/service", map[string]string{"action": "rollback"}, cookie); response.Code != http.StatusConflict {
		t.Fatal("rollback could resurrect the deleted relay")
	}
}

func seedAppliedGraph(t *testing.T, s *Server, cookie *http.Cookie, name string) ownedGraph {
	t.Helper()
	graph := graphFixture(t, s, cookie, name)
	state, err := s.store.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	graph.node, _ = nodeByID(state, graph.node.ID)
	graph.upstream, _ = upstreamByID(state, graph.upstream.ID)
	graph.node.AppliedRevision, graph.node.Status = "confirmed-current", "ready"
	applied := deploymentSnapshot(graph.node.ID, graph.node.AppliedRevision, state.Relays)
	applied.ConfigHash = desiredConfigHash(graph.node, state)
	applied.Previous = &store.Applied{Revision: "confirmed-previous", RelayIDs: []string{}, UpstreamIDs: []string{}}
	if err := s.store.Commit(context.Background(), store.Changes{Nodes: []model.Node{graph.node}, Applied: map[string]store.Applied{graph.node.ID: applied}}); err != nil {
		t.Fatal(err)
	}
	return graph
}

func waitNodeIdle(t *testing.T, s *Server, nodeID string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		s.mu.Lock()
		busy := s.busy[nodeID]
		s.mu.Unlock()
		if busy == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("node did not finish its queued tasks")
}

func TestDeleteAppliedRelayKeepsOtherRulesAndPersistsTarget(t *testing.T) {
	runtime := &fakeRuntime{started: make(chan string, 1), release: make(chan struct{}, 1)}
	directory := t.TempDir()
	s, cookie := fixtureIn(t, directory, runtime)
	graph := seedAppliedGraph(t, s, cookie, "delete")
	survivor := graph.relay
	survivor.ID, survivor.Name, survivor.Port = "", "Keep this entry", 24444
	survivor = decodeResponse[model.Relay](t, request(t, s, "POST", "/api/relays", survivor, cookie), http.StatusCreated)
	other := graphFixture(t, s, cookie, "other")
	before, err := s.store.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie)
	job := decodeResponse[model.Job](t, response, http.StatusAccepted)
	if job.Action != "delete-relay" || job.RelayID != graph.relay.ID || job.OwnerID != graph.node.OwnerID || job.NodeID != graph.node.ID || job.Status != "queued" || decodeResponse[map[string]any](t, response, http.StatusAccepted)["relay_id"] != graph.relay.ID {
		t.Fatalf("accepted delete did not identify its persisted target: %+v", job)
	}
	select {
	case <-runtime.started:
	case <-time.After(3 * time.Second):
		t.Fatal("delete never reached the runtime")
	}
	pending, err := s.store.Applied(context.Background(), graph.node.ID)
	if err != nil || pending.PendingDeleteRelayID != graph.relay.ID || pending.Revision != "confirmed-current" {
		t.Fatalf("remote deletion started without durable intent: %+v, %v", pending, err)
	}
	during, err := s.store.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	target, found := relayByID(during, graph.relay.ID)
	if !found || !reflect.DeepEqual(target, graph.relay) {
		t.Fatal("delete modified the target or its credentials before runtime success")
	}
	runtime.mu.Lock()
	appliedNode, upstreams, relays, deletedID := runtime.appliedNode, runtime.appliedUpstreams, runtime.appliedRelays, runtime.deleteRelayID
	runtime.mu.Unlock()
	if appliedNode.Password != graph.node.Password || deletedID != graph.relay.ID || len(relays) != len(before.Relays)-1 || !reflect.DeepEqual(upstreams, before.Upstreams) {
		t.Fatal("delete lost runtime credentials, upstreams, or safe deletion target")
	}
	for _, relay := range relays {
		original, exists := relayByID(before, relay.ID)
		if !exists || relay.ID == graph.relay.ID || !reflect.DeepEqual(original, relay) {
			t.Fatal("delete applied a changed or unwanted relay")
		}
	}
	if _, found := relayByID(model.State{Relays: relays}, survivor.ID); !found {
		t.Fatal("delete omitted another enabled relay on the same node")
	}
	if _, found := relayByID(model.State{Relays: relays}, other.relay.ID); !found {
		t.Fatal("delete did not preserve the complete desired state")
	}
	if response := request(t, s, "POST", "/api/nodes/"+graph.node.ID+"/service", map[string]string{"action": "rollback"}, cookie); response.Code != http.StatusConflict {
		t.Fatal("rollback was accepted while deletion was unconfirmed")
	}
	if response := request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie); response.Code != http.StatusConflict {
		t.Fatal("another deletion was accepted while the node was busy")
	}
	runtime.release <- struct{}{}
	finished := waitJob(t, s, cookie, job.ID, "succeeded")
	waitNodeIdle(t, s, graph.node.ID)
	applied, err := s.store.Applied(context.Background(), graph.node.ID)
	if err != nil || applied.PendingDeleteRelayID != "" || applied.ReferencesRelay(graph.relay.ID) || applied.Previous != nil || !applied.ReferencesRelay(survivor.ID) || applied.Revision != finished.Revision {
		t.Fatalf("successful deletion left stale deployment metadata: %+v, %v", applied, err)
	}
	after, err := s.store.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, found := relayByID(after, graph.relay.ID); found || len(after.Relays) != len(before.Relays)-1 {
		t.Fatal("successful runtime deletion did not delete exactly the target")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Config{DataDir: directory, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	persisted := waitJob(t, reopened, cookie, job.ID, "succeeded")
	if persisted.RelayID != graph.relay.ID || persisted.Revision != finished.Revision {
		t.Fatal("delete task lost its relay correlation across restart")
	}
	select {
	case <-runtime.started:
		t.Fatal("completed delete was replayed after restart")
	default:
	}
}

func TestDeleteRelayReferencedOnlyByPreviousKeepsSafeCurrent(t *testing.T) {
	runtime := &fakeRuntime{}
	s, cookie := fixture(t, runtime)
	graph := seedAppliedGraph(t, s, cookie, "previous")
	old, err := s.store.Applied(context.Background(), graph.node.ID)
	if err != nil {
		t.Fatal(err)
	}
	graph.relay.Enabled = false
	graph.relay = decodeResponse[model.Relay](t, request(t, s, "PUT", "/api/relays/"+graph.relay.ID, graph.relay, cookie), http.StatusOK)
	old.Previous = nil
	current := store.Applied{Revision: "confirmed-without-target", Previous: &old, RelayIDs: []string{}, UpstreamIDs: []string{}}
	if err := s.store.Commit(context.Background(), store.Changes{Applied: map[string]store.Applied{graph.node.ID: current}}); err != nil {
		t.Fatal(err)
	}
	job := decodeResponse[model.Job](t, request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, job.ID, "succeeded")
	waitNodeIdle(t, s, graph.node.ID)
	applied, err := s.store.Applied(context.Background(), graph.node.ID)
	if err != nil || applied.ReferencesRelay(graph.relay.ID) || applied.Previous == nil || applied.Previous.Revision != current.Revision || applied.Previous.Previous != nil {
		t.Fatalf("deleting a previous-only relay did not retain just the safe current: %+v, %v", applied, err)
	}
	rollback := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+graph.node.ID+"/service", map[string]string{"action": "rollback"}, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, rollback.ID, "succeeded")
	applied, err = s.store.Applied(context.Background(), graph.node.ID)
	if err != nil || applied.ReferencesRelay(graph.relay.ID) {
		t.Fatal("safe rollback resurrected a deleted relay reference")
	}
}

func TestDeleteUndeployedRelayRemainsImmediateWithoutRuntime(t *testing.T) {
	s, cookie := fixture(t, nil)
	graph := graphFixture(t, s, cookie, "undeployed")
	deleted := decodeResponse[map[string]bool](t, request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie), http.StatusOK)
	if !deleted["deleted"] || !deleted["pending_apply"] {
		t.Fatal("immediate deletion changed its existing response contract")
	}
	state, err := s.store.State(context.Background())
	if err != nil || len(state.Relays) != 0 || len(state.Jobs) != 1 || state.Jobs[0].Action == "delete-relay" {
		t.Fatal("undeployed deletion scheduled runtime work or retained the rule")
	}
}

func assertUnconfirmedDelete(t *testing.T, s *Server, graph ownedGraph, jobID, status string) {
	t.Helper()
	state, err := s.store.State(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	relay, found := relayByID(state, graph.relay.ID)
	if !found || !reflect.DeepEqual(relay, graph.relay) {
		t.Fatal("unconfirmed deletion lost the original relay or credentials")
	}
	node, found := nodeByID(state, graph.node.ID)
	if !found || node.Password != graph.node.Password || node.AppliedRevision != graph.node.AppliedRevision || node.CoreVersion != graph.node.CoreVersion || node.LastError == "" || (node.Status != "error" && node.Status != "interrupted") {
		t.Fatalf("unconfirmed deletion reported a new revision or lost node credentials: %+v", maskNode(node))
	}
	upstream, found := upstreamByID(state, graph.upstream.ID)
	if !found || !bytes.Equal(upstream.Outbound, graph.upstream.Outbound) {
		t.Fatal("unconfirmed deletion lost upstream credentials")
	}
	applied, err := s.store.Applied(context.Background(), graph.node.ID)
	if err != nil || applied.PendingDeleteRelayID != graph.relay.ID || applied.Revision != graph.node.AppliedRevision || applied.Previous == nil {
		t.Fatalf("unconfirmed deletion cleared intent or replaced confirmed snapshots: %+v, %v", applied, err)
	}
	for _, job := range state.Jobs {
		if job.ID == jobID {
			if job.Status != status || job.RelayID != graph.relay.ID || job.Revision != "" || job.Error == "" || job.FinishedAt == nil {
				t.Fatalf("unconfirmed delete task reported success or lost its target: %+v", job)
			}
			return
		}
	}
	t.Fatal("unconfirmed delete task was not persisted")
}

func TestFailedAndInterruptedRelayDeletionRetainsCredentialsAcrossRestart(t *testing.T) {
	for _, scenario := range []string{"apply-error", "runtime-canceled", "runtime-panic", "missing-revision", "shutdown"} {
		t.Run(scenario, func(t *testing.T) {
			runtime := &fakeRuntime{started: make(chan string, 1)}
			directory := t.TempDir()
			s, cookie := fixtureIn(t, directory, runtime)
			graph := seedAppliedGraph(t, s, cookie, "failed-delete")
			switch scenario {
			case "apply-error":
				runtime.applyError = errors.New("deliberate deletion failure: " + graph.relay.RealityPrivateKey)
			case "runtime-canceled":
				runtime.applyError = context.Canceled
			case "runtime-panic":
				runtime.applyFunc = func(context.Context, model.Node, []model.Upstream, []model.Relay) (model.ApplyResult, error) {
					panic(graph.relay.RealityPrivateKey)
				}
			case "missing-revision":
				runtime.applyFunc = func(context.Context, model.Node, []model.Upstream, []model.Relay) (model.ApplyResult, error) {
					return model.ApplyResult{}, nil
				}
			case "shutdown":
				runtime.release = make(chan struct{})
			}
			job := decodeResponse[model.Job](t, request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie), http.StatusAccepted)
			select {
			case <-runtime.started:
			case <-time.After(3 * time.Second):
				t.Fatal("delete never reached the runtime")
			}
			status := "failed"
			if scenario == "shutdown" {
				status = "interrupted"
			} else {
				finished := waitJob(t, s, cookie, job.ID, status)
				waitNodeIdle(t, s, graph.node.ID)
				if strings.Contains(finished.Error, graph.relay.RealityPrivateKey) {
					t.Fatal("delete failure leaked the excluded relay's secret")
				}
				assertUnconfirmedDelete(t, s, graph, job.ID, status)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			restartedRuntime := &fakeRuntime{started: make(chan string, 1)}
			reopened, err := New(Config{DataDir: directory, Runtime: restartedRuntime})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			assertUnconfirmedDelete(t, reopened, graph, job.ID, status)
			if response := request(t, reopened, "POST", "/api/nodes/"+graph.node.ID+"/service", map[string]string{"action": "rollback"}, cookie); response.Code != http.StatusConflict {
				t.Fatal("restart allowed rollback using unconfirmed deletion metadata")
			}
			select {
			case <-restartedRuntime.started:
				t.Fatal("unfinished deletion was replayed after restart")
			default:
			}
		})
	}
}

func TestDeleteRelayCommitFailureStaysUnknownUntilExplicitReconciliation(t *testing.T) {
	for _, recovery := range []string{"retry-delete", "apply", "delete-other-relay"} {
		t.Run(recovery, func(t *testing.T) {
			runtime := &fakeRuntime{applyFunc: func(context.Context, model.Node, []model.Upstream, []model.Relay) (model.ApplyResult, error) {
				return model.ApplyResult{Revision: "remote-new-revision", CoreVersion: "v26.10.32"}, nil
			}}
			directory := t.TempDir()
			s, cookie := fixtureIn(t, directory, runtime)
			graph := seedAppliedGraph(t, s, cookie, "commit-failure")
			newRelay := graph.relay
			newRelay.ID, newRelay.Name, newRelay.Port = "", "Not in confirmed snapshot", 24444
			newRelay = decodeResponse[model.Relay](t, request(t, s, "POST", "/api/relays", newRelay, cookie), http.StatusCreated)
			other := graphFixture(t, s, cookie, "move-target")
			db, err := sql.Open("sqlite", filepath.Join(directory, "panel.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			// Fail after Commit has attempted node, job and Applied updates, so
			// the transaction must roll back every part of the success result.
			if _, err := db.Exec(`CREATE TRIGGER fail_relay_delete BEFORE DELETE ON relays BEGIN SELECT RAISE(ABORT, 'deliberate deletion commit failure'); END`); err != nil {
				t.Fatal(err)
			}
			job := decodeResponse[model.Job](t, request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie), http.StatusAccepted)
			finished := waitJob(t, s, cookie, job.ID, "failed")
			waitNodeIdle(t, s, graph.node.ID)
			if !strings.Contains(finished.Error, "远端状态未知") {
				t.Fatal("commit failure was not reported as an unknown remote state")
			}
			assertUnconfirmedDelete(t, s, graph, job.ID, "failed")
			if response := request(t, s, "POST", "/api/nodes/"+graph.node.ID+"/service", map[string]string{"action": "rollback"}, cookie); response.Code != http.StatusConflict {
				t.Fatal("commit failure permitted rollback of stale snapshots")
			}
			moved := newRelay
			moved.NodeID = other.node.ID
			if response := request(t, s, "PUT", "/api/relays/"+newRelay.ID, moved, cookie); response.Code != http.StatusConflict {
				t.Fatal("unconfirmed deployment let a newly deployed rule move and become orphaned")
			}
			if _, err := db.Exec("DROP TRIGGER fail_relay_delete"); err != nil {
				t.Fatal(err)
			}
			path, method, targetID := "/api/relays/"+graph.relay.ID, "DELETE", graph.relay.ID
			if recovery == "apply" {
				path, method = "/api/nodes/"+graph.node.ID+"/apply", "POST"
			} else if recovery == "delete-other-relay" {
				path, targetID = "/api/relays/"+newRelay.ID, newRelay.ID
			}
			retry := decodeResponse[model.Job](t, request(t, s, method, path, nil, cookie), http.StatusAccepted)
			waitJob(t, s, cookie, retry.ID, "succeeded")
			waitNodeIdle(t, s, graph.node.ID)
			applied, err := s.store.Applied(context.Background(), graph.node.ID)
			if err != nil || applied.PendingDeleteRelayID != "" || applied.Revision != "remote-new-revision" || applied.Previous != nil {
				t.Fatalf("explicit reconciliation retained an unknown rollback snapshot: %+v, %v", applied, err)
			}
			state, err := s.store.State(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			_, present := relayByID(state, targetID)
			if present != (recovery == "apply") {
				t.Fatal("reconciliation did not preserve or delete the intended relay")
			}
			if recovery != "retry-delete" {
				if _, found := relayByID(state, graph.relay.ID); !found {
					t.Fatal("reconciliation lost the first failed deletion's original rule")
				}
			}
		})
	}
}

func TestQueuedRollbackRevalidatesAfterRelayDeletion(t *testing.T) {
	for _, failDeletion := range []bool{false, true} {
		t.Run(fmt.Sprintf("delete-failed=%t", failDeletion), func(t *testing.T) {
			runtime := &fakeRuntime{}
			if failDeletion {
				runtime.applyError = errors.New("deliberate deletion failure")
			}
			s, cookie := fixture(t, runtime)
			graph := seedAppliedGraph(t, s, cookie, "queued-rollback")
			// Pause dispatch so rollback is accepted against the old snapshots,
			// immediately behind the already queued deletion.
			queue := make(chan task, 16)
			s.workers[graph.node.ID] = queue
			deleted := decodeResponse[model.Job](t, request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie), http.StatusAccepted)
			rollback := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+graph.node.ID+"/service", map[string]string{"action": "rollback"}, cookie), http.StatusAccepted)
			s.execute(<-queue)
			s.execute(<-queue)
			deleteStatus := "succeeded"
			if failDeletion {
				deleteStatus = "failed"
			}
			waitJob(t, s, cookie, deleted.ID, deleteStatus)
			waitJob(t, s, cookie, rollback.ID, "failed")
			runtime.mu.Lock()
			serviceCalls := len(runtime.serviceActions)
			runtime.mu.Unlock()
			if serviceCalls != 0 {
				t.Fatal("queued rollback reached runtime after deletion invalidated its snapshots")
			}
		})
	}
}

type runtimeWithoutRelayDeletion struct{ model.Runtime }

func TestDeleteAppliedRelayRejectsUnauthorizedOrUnsupportedOperations(t *testing.T) {
	for _, scenario := range []string{"anonymous", "cross-owner", "local-owner", "node-owner-mismatch", "unsupported-runtime"} {
		t.Run(scenario, func(t *testing.T) {
			runtime := &fakeRuntime{}
			s, _ := fixture(t, runtime)
			_, cookie := userFixture(t, s, "owner")
			_, otherCookie := userFixture(t, s, "other")
			graph := seedAppliedGraph(t, s, cookie, "permissions")
			status := http.StatusNotFound
			switch scenario {
			case "anonymous":
				cookie, status = nil, http.StatusUnauthorized
			case "cross-owner":
				cookie = otherCookie
			case "local-owner":
				graph.node.Kind, status = "local", http.StatusForbidden
				if err := s.store.Commit(context.Background(), store.Changes{Nodes: []model.Node{graph.node}}); err != nil {
					t.Fatal(err)
				}
			case "node-owner-mismatch":
				other := graphFixture(t, s, otherCookie, "other-owner")
				graph.relay.NodeID = other.node.ID
				if err := s.store.Commit(context.Background(), store.Changes{Relays: []model.Relay{graph.relay}}); err != nil {
					t.Fatal(err)
				}
			case "unsupported-runtime":
				s.runtime, status = runtimeWithoutRelayDeletion{runtime}, http.StatusServiceUnavailable
			}
			if response := request(t, s, "DELETE", "/api/relays/"+graph.relay.ID, nil, cookie); response.Code != status {
				t.Fatalf("unauthorized/unsupported delete returned %d, want %d: %s", response.Code, status, response.Body.String())
			}
			state, err := s.store.State(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if _, found := relayByID(state, graph.relay.ID); !found {
				t.Fatal("rejected delete removed the target")
			}
			for _, job := range state.Jobs {
				if job.Action == "delete-relay" {
					t.Fatal("rejected delete persisted a runtime job")
				}
			}
		})
	}
}

func waitJob(t *testing.T, s *Server, cookie *http.Cookie, id, expected string) model.Job {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
		for _, job := range state.Jobs {
			if job.ID == id && job.Status != "queued" && job.Status != "running" {
				if job.Status != expected {
					t.Fatalf("job ended as %s, want %s: %s", job.Status, expected, job.Error)
				}
				return job
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("task did not reach %s", expected)
	return model.Job{}
}

func TestJobsSerializePerNodeAndPersistFailuresAndPartialProbes(t *testing.T) {
	runtime := &fakeRuntime{started: make(chan string, 8), release: make(chan struct{}, 8)}
	s, cookie := fixture(t, runtime)
	node := decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", model.Node{Name: "Local", Kind: "local"}, cookie), http.StatusCreated)
	upstream := decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", testUpstream(t), cookie), http.StatusCreated)
	first := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	select {
	case <-runtime.started:
	case <-time.After(3 * time.Second):
		t.Fatal("first job did not start")
	}
	second := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	select {
	case <-runtime.started:
		t.Fatal("two runtime tasks ran simultaneously on one node")
	case <-time.After(75 * time.Millisecond):
	}
	if response := request(t, s, "PUT", "/api/nodes/"+node.ID, node, cookie); response.Code != http.StatusConflict {
		t.Fatal("configuration was edited during deployment")
	}
	runtime.release <- struct{}{}
	waitJob(t, s, cookie, first.ID, "succeeded")
	select {
	case <-runtime.started:
	case <-time.After(3 * time.Second):
		t.Fatal("second job never started")
	}
	runtime.release <- struct{}{}
	waitJob(t, s, cookie, second.ID, "succeeded")
	runtime.mu.Lock()
	maximum := runtime.maxActive[node.ID]
	runtime.mu.Unlock()
	if maximum != 1 {
		t.Fatal("node jobs were not serialized")
	}
	runtime.applyError = errors.New("deliberate runtime failure")
	failed := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	runtime.release <- struct{}{}
	waitJob(t, s, cookie, failed.ID, "failed")
	runtime.probe = model.ProbeResult{Status: "partial", IPv6: "2001:db8::1", Error: "IPv4 unavailable"}
	partial := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/probe", map[string]string{"upstream_id": upstream.ID}, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, partial.ID, "succeeded")
	state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	if len(state.Probes) != 1 || state.Probes[0].Status != "partial" || state.Probes[0].IPv6 == "" || state.Probes[0].Error == "" {
		t.Fatal("partial IPv6 success was not persisted accurately")
	}
	runtime.probeError = errors.New("deliberate probe failure")
	failed = decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/probe", map[string]string{"upstream_id": upstream.ID}, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, failed.ID, "failed")
	state = decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	if len(state.Probes) != 2 || state.Probes[0].Status != "failed" || state.Probes[0].Error == "" {
		t.Fatal("failed probe was not persisted")
	}
}

func TestProbeJobsPersistCorrelationAcrossQueueAndRestart(t *testing.T) {
	runtime := &fakeRuntime{
		started: make(chan string, 1), release: make(chan struct{}, 1),
		probe: model.ProbeResult{
			ID: "runtime-result", JobID: "runtime-job", OwnerID: "runtime-owner", NodeID: "runtime-node", UpstreamID: "runtime-upstream",
			Status: "partial", IPv6: "2001:db8::17", Error: "IPv4 unavailable",
		},
	}
	directory := t.TempDir()
	s, cookie := fixtureIn(t, directory, runtime)
	node := decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", model.Node{Name: "Local", Kind: "local"}, cookie), http.StatusCreated)
	upstreams := []model.Upstream{
		decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", testUpstream(t), cookie), http.StatusCreated),
		decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", testUpstream(t), cookie), http.StatusCreated),
	}
	response := request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie)
	apply := decodeResponse[model.Job](t, response, http.StatusAccepted)
	if _, present := decodeResponse[map[string]any](t, response, http.StatusAccepted)["upstream_id"]; present {
		t.Fatal("non-probe task exposed upstream_id")
	}
	select {
	case <-runtime.started:
	case <-time.After(3 * time.Second):
		t.Fatal("blocking apply did not start")
	}

	// Repeating one target and interleaving another catches matching by node,
	// upstream or recency instead of the exact task that produced each result.
	expected := make(map[string]string)
	for _, upstream := range []model.Upstream{upstreams[0], upstreams[1], upstreams[0]} {
		response := request(t, s, "POST", "/api/nodes/"+node.ID+"/probe", map[string]string{"upstream_id": upstream.ID}, cookie)
		job := decodeResponse[model.Job](t, response, http.StatusAccepted)
		if decodeResponse[map[string]any](t, response, http.StatusAccepted)["upstream_id"] != upstream.ID {
			t.Fatal("accepted probe omitted its target from the JSON response")
		}
		expected[job.ID] = upstream.ID
	}
	queued := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	queuedCount := 0
	for _, job := range queued.Jobs {
		if target, found := expected[job.ID]; found {
			queuedCount++
			if job.Status != "queued" || job.UpstreamID != target {
				t.Fatalf("queued probe lost its persisted target: %+v", job)
			}
		}
	}
	if queuedCount != len(expected) || len(queued.Probes) != 0 {
		t.Fatal("queued probes were not durably recorded behind the active apply")
	}
	runtime.release <- struct{}{}
	waitJob(t, s, cookie, apply.ID, "succeeded")
	for id := range expected {
		waitJob(t, s, cookie, id, "succeeded")
	}

	checkHistory := func(server *Server) {
		t.Helper()
		response := request(t, server, "GET", "/api/state", nil, cookie)
		state := decodeResponse[model.State](t, response, http.StatusOK)
		if len(state.Probes) != len(expected) {
			t.Fatalf("got %d results for %d probe tasks", len(state.Probes), len(expected))
		}
		seenJobs, seenResults := make(map[string]bool), make(map[string]bool)
		for _, probe := range state.Probes {
			target, found := expected[probe.JobID]
			if !found || seenJobs[probe.JobID] || probe.ID == "" || probe.ID == "runtime-result" || seenResults[probe.ID] || probe.UpstreamID != target || probe.NodeID != node.ID || probe.OwnerID != node.OwnerID {
				t.Fatalf("result was not uniquely bound to its server-owned task: %+v", probe)
			}
			if probe.Status != "partial" || probe.IPv6 != "2001:db8::17" || probe.Error != "IPv4 unavailable" {
				t.Fatalf("IPv6-only success lost its IPv4 diagnostics: %+v", probe)
			}
			seenJobs[probe.JobID], seenResults[probe.ID] = true, true
		}
		completedCount := 0
		for _, job := range state.Jobs {
			if target, found := expected[job.ID]; found {
				completedCount++
				if job.UpstreamID != target || job.Status != "succeeded" || job.Error != "" || job.FinishedAt == nil {
					t.Fatalf("completed probe task lost its target or success: %+v", job)
				}
			}
		}
		if completedCount != len(expected) {
			t.Fatal("completed probe tasks were missing from persisted history")
		}
		wire := decodeResponse[struct {
			Probes []map[string]any `json:"probes"`
		}](t, response, http.StatusOK)
		for _, probe := range wire.Probes {
			if id, ok := probe["job_id"].(string); !ok || expected[id] != probe["upstream_id"] {
				t.Fatal("probe JSON did not expose the exact job_id correlation")
			}
		}
	}
	checkHistory(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(Config{DataDir: directory, Runtime: runtime})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := reopened.Close(); err != nil {
			t.Error(err)
		}
	})
	checkHistory(reopened)
}

func TestFailedAndInterruptedProbesKeepPersistedTarget(t *testing.T) {
	for _, test := range []struct {
		name, message string
		panicRuntime  bool
		deleteTarget  bool
		shutdown      bool
		wantResult    bool
	}{
		{name: "validation", message: "invalid upstream configuration", wantResult: true},
		{name: "core-preparation", message: "requested fixed core preparation failed", wantResult: true},
		{name: "runtime-panic", message: "节点运行时意外终止", panicRuntime: true},
		{name: "missing-upstream", message: "探测上游已不存在", deleteTarget: true},
		{name: "queued-shutdown", message: "任务因服务关闭或重启中断", shutdown: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := make(chan string, 1)
			runtime := &fakeRuntime{started: make(chan string, 1), release: make(chan struct{}, 1)}
			runtime.probeFunc = func(_ context.Context, _ model.Node, upstream model.Upstream) (model.ProbeResult, error) {
				calls <- upstream.ID
				if test.panicRuntime {
					panic("deliberate runtime panic")
				}
				return model.ProbeResult{JobID: "runtime-job"}, errors.New(test.message)
			}
			directory := t.TempDir()
			s, cookie := fixtureIn(t, directory, runtime)
			node := decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", model.Node{Name: "Local", Kind: "local"}, cookie), http.StatusCreated)
			upstream := decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", testUpstream(t), cookie), http.StatusCreated)
			apply := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
			select {
			case <-runtime.started:
			case <-time.After(3 * time.Second):
				t.Fatal("blocking apply did not start")
			}
			job := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/probe", map[string]string{"upstream_id": upstream.ID}, cookie), http.StatusAccepted)
			if test.deleteTarget {
				// Simulate a stale queued reference through the store, without
				// weakening the HTTP guards against deleting busy resources.
				s.mu.Lock()
				err := s.store.Commit(context.Background(), store.Changes{DeleteUpstreams: []string{upstream.ID}})
				s.mu.Unlock()
				if err != nil {
					t.Fatal(err)
				}
			}
			status := "failed"
			if test.shutdown {
				status = "interrupted"
			} else {
				runtime.release <- struct{}{}
				waitJob(t, s, cookie, apply.ID, "succeeded")
				waitJob(t, s, cookie, job.ID, status)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := New(Config{DataDir: directory, Runtime: runtime})
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			finished := waitJob(t, reopened, cookie, job.ID, status)
			if finished.UpstreamID != upstream.ID || finished.OwnerID != node.OwnerID || finished.FinishedAt == nil || !strings.Contains(finished.Error, test.message) {
				t.Fatalf("failed probe could not be located by its persisted target after restart: %+v", finished)
			}
			state := decodeResponse[model.State](t, request(t, reopened, "GET", "/api/state", nil, cookie), http.StatusOK)
			if test.wantResult {
				if len(state.Probes) != 1 || state.Probes[0].JobID != job.ID || state.Probes[0].UpstreamID != upstream.ID || state.Probes[0].OwnerID != node.OwnerID || state.Probes[0].Status != "failed" || state.Probes[0].Error != finished.Error {
					t.Fatalf("runtime preparation failure lost its result correlation: %+v", state.Probes)
				}
			} else if len(state.Probes) != 0 {
				t.Fatal("task with no runtime result created a probe record")
			}
			select {
			case target := <-calls:
				if test.deleteTarget || test.shutdown || target != upstream.ID {
					t.Fatal("runtime executed an unavailable or interrupted probe target")
				}
			default:
				if !test.deleteTarget && !test.shutdown {
					t.Fatal("failure scenario did not reach the probe runtime")
				}
			}
		})
	}
}

func TestImportsReturnPartialErrorsAndOutboundRemainsHidden(t *testing.T) {
	s, cookie := fixture(t, nil)
	identifier := make([]byte, 16)
	if _, err := rand.Read(identifier); err != nil {
		t.Fatal(err)
	}
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x", identifier[:4], identifier[4:6], identifier[6:8], identifier[8:10], identifier[10:])
	content := "vless://" + uuid + "@proxy.example.test:443?encryption=none&security=tls&type=tcp#Imported\ninvalid://broken"
	response := request(t, s, "POST", "/api/upstreams/import", map[string]string{"content": content}, cookie)
	result := decodeResponse[struct {
		Upstreams []model.Upstream `json:"upstreams"`
		Errors    []string         `json:"errors"`
	}](t, response, http.StatusOK)
	if len(result.Upstreams) != 1 || len(result.Errors) == 0 || len(result.Upstreams[0].Outbound) != 0 {
		t.Fatal("partial import did not return a safe result")
	}
	if strings.Contains(response.Body.String(), uuid) {
		t.Fatal("import response exposed a URI credential")
	}
}
