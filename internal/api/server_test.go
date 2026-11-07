package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
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
	probe            model.ProbeResult
	probeError       error
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
	if f.applyError != nil {
		return model.ApplyResult{}, f.applyError
	}
	return model.ApplyResult{Revision: "revision-" + node.ID, CoreVersion: model.DefaultCoreVersion}, nil
}

func (f *fakeRuntime) Probe(context.Context, model.Node, model.Upstream) (model.ProbeResult, error) {
	return f.probe, f.probeError
}
func (f *fakeRuntime) Service(context.Context, model.Node, string) error { return nil }
func (f *fakeRuntime) Logs(context.Context, model.Node) (string, error)  { return "service log", nil }

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
	s, err := New(Config{DataDir: t.TempDir(), Runtime: runtime})
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
	if response := request(t, s, "DELETE", "/api/relays/"+relay.ID, nil, cookie); response.Code != http.StatusConflict {
		t.Fatal("active applied relay was deleted")
	}
	relay.Enabled = false
	decodeResponse[model.Relay](t, request(t, s, "PUT", "/api/relays/"+relay.ID, relay, cookie), http.StatusOK)
	job = decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, job.ID, "succeeded")
	if response := request(t, s, "DELETE", "/api/relays/"+relay.ID, nil, cookie); response.Code != http.StatusConflict {
		t.Fatal("relay used by the previous applied snapshot was deleted")
	}
	job = decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/apply", nil, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, job.ID, "succeeded")
	decodeResponse[map[string]any](t, request(t, s, "DELETE", "/api/relays/"+relay.ID, nil, cookie), http.StatusOK)
	job = decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/service", map[string]string{"action": "rollback"}, cookie), http.StatusAccepted)
	waitJob(t, s, cookie, job.ID, "succeeded")
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
