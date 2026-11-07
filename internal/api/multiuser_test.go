package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

func userFixture(t *testing.T, s *Server, username string) (model.User, *http.Cookie) {
	t.Helper()
	account, err := newAccount(username, "fixture-hash", model.RoleUser)
	if err != nil {
		t.Fatal(err)
	}
	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	session := store.Session{AccountID: account.ID, Hash: auth.TokenHash(token), ExpiresAt: time.Now().Add(time.Hour)}
	if err := s.store.CreateAccount(context.Background(), account, &session, false); err != nil {
		t.Fatal(err)
	}
	return account.Public(), &http.Cookie{Name: cookieName, Value: token}
}

type ownedGraph struct {
	node     model.Node
	upstream model.Upstream
	relay    model.Relay
	sub      model.Subscription
}

func graphFixture(t *testing.T, s *Server, cookie *http.Cookie, name string) ownedGraph {
	t.Helper()
	secret, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	node := decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", model.Node{OwnerID: "injected-owner", Name: name, Kind: "ssh", Host: name + ".example.test", SSHPort: 22, Username: "root", AuthMode: "password", Password: secret, Fingerprint: "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), PublicHost: name + ".public.example.test"}, cookie), http.StatusCreated)
	upstream := testUpstream(t)
	upstream.OwnerID = "injected-owner"
	upstream = decodeResponse[model.Upstream](t, request(t, s, "POST", "/api/upstreams", upstream, cookie), http.StatusCreated)
	relay := decodeResponse[model.Relay](t, request(t, s, "POST", "/api/relays", model.Relay{OwnerID: "injected-owner", Name: name + " entry", NodeID: node.ID, UpstreamID: upstream.ID, Enabled: true, Port: 24443, ServerName: "www.example.com", Target: "www.example.com:443"}, cookie), http.StatusCreated)
	sub := model.Subscription{ID: name + "-subscription", OwnerID: node.OwnerID, Name: name + " source", URL: "https://source.example.test/" + name, UpdatedAt: time.Now().UTC()}
	if node.OwnerID == "injected-owner" || upstream.OwnerID != node.OwnerID || relay.OwnerID != node.OwnerID {
		t.Fatal("creation trusted body ownership")
	}
	if err := s.store.Commit(context.Background(), store.Changes{
		Subscriptions: []model.Subscription{sub},
		Jobs:          []model.Job{{ID: name + "-job", OwnerID: node.OwnerID, NodeID: node.ID, Action: "apply", Status: "succeeded", CreatedAt: time.Now().UTC()}},
		Probes:        []model.ProbeResult{{ID: name + "-probe", OwnerID: node.OwnerID, NodeID: node.ID, UpstreamID: upstream.ID, Status: "ok", IPv4: "203.0.113.1", CheckedAt: time.Now().UTC()}},
	}); err != nil {
		t.Fatal(err)
	}
	return ownedGraph{node: node, upstream: upstream, relay: relay, sub: sub}
}

func TestRegistrationAndAdminUserCreationRespectPublicContract(t *testing.T) {
	s, adminCookie := fixture(t, nil)
	password, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	input := map[string]string{"username": " Alice ", "password": password}
	bootstrap := decodeResponse[struct {
		RegistrationOpen bool        `json:"registration_open"`
		User             *model.User `json:"user"`
	}](t, request(t, s, "GET", "/api/bootstrap", nil, adminCookie), http.StatusOK)
	if bootstrap.RegistrationOpen || bootstrap.User == nil || bootstrap.User.Role != model.RoleAdmin {
		t.Fatal("bootstrap did not describe the initial administrator and closed registration")
	}
	if response := request(t, s, "POST", "/api/auth/register", input, nil); response.Code != http.StatusForbidden {
		t.Fatal("closed registration accepted an account")
	}
	settings := decodeResponse[model.Settings](t, request(t, s, "GET", "/api/settings", nil, adminCookie), http.StatusOK)
	settings.RegistrationOpen = true
	settings.CoreVersion = "26.10.31-rc.1"
	settings = decodeResponse[model.Settings](t, request(t, s, "PUT", "/api/settings", settings, adminCookie), http.StatusOK)
	if settings.CoreVersion != "v26.10.31-rc.1" {
		t.Fatal("settings did not normalize the shared version tag")
	}
	for _, field := range []string{"role", "owner_id", "id"} {
		injected := map[string]string{"username": "malicious", "password": password, field: "admin"}
		if response := request(t, s, "POST", "/api/auth/register", injected, nil); response.Code != http.StatusBadRequest {
			t.Fatalf("register accepted %s injection", field)
		}
	}
	registered := request(t, s, "POST", "/api/auth/register", input, nil)
	result := decodeResponse[struct {
		Authenticated bool       `json:"authenticated"`
		User          model.User `json:"user"`
	}](t, registered, http.StatusCreated)
	if !result.Authenticated || result.User.ID == "" || result.User.Username != "alice" || result.User.Role != model.RoleUser || len(registered.Result().Cookies()) != 1 {
		t.Fatal("registration did not create a canonical user session")
	}
	cookie := registered.Result().Cookies()[0]
	state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
	if state.CurrentUser == nil || state.CurrentUser.ID != result.User.ID || len(state.Users) != 1 || state.Users[0].ID != result.User.ID {
		t.Fatal("registration cookie authenticated a different account")
	}
	login := request(t, s, "POST", "/api/auth/login", map[string]string{"username": "ALICE", "password": password}, nil)
	decodeResponse[map[string]any](t, login, http.StatusOK)
	input["username"] = "ALICE"
	if response := request(t, s, "POST", "/api/auth/register", input, nil); response.Code != http.StatusConflict {
		t.Fatal("case-insensitive username conflict was accepted")
	}
	settings.RegistrationOpen = false
	decodeResponse[model.Settings](t, request(t, s, "PUT", "/api/settings", settings, adminCookie), http.StatusOK)
	input["username"] = "bob"
	if response := request(t, s, "POST", "/api/auth/register", input, nil); response.Code != http.StatusForbidden {
		t.Fatal("registration remained open after closure")
	}
	managed := decodeResponse[model.User](t, request(t, s, "POST", "/api/users", input, adminCookie), http.StatusCreated)
	if managed.Role != model.RoleUser || managed.Username != "bob" {
		t.Fatal("administrator creation default role was not user")
	}
	input["username"], input["role"] = "second-admin", model.RoleAdmin
	managedAdmin := decodeResponse[model.User](t, request(t, s, "POST", "/api/users", input, adminCookie), http.StatusCreated)
	if managedAdmin.Role != model.RoleAdmin {
		t.Fatal("administrator could not create another administrator while registration was closed")
	}
	input["username"], input["role"] = "invalid", "root"
	if response := request(t, s, "POST", "/api/users", input, adminCookie); response.Code != http.StatusBadRequest {
		t.Fatal("unknown account role was accepted")
	}
	usersResponse := request(t, s, "GET", "/api/users", nil, adminCookie)
	users := decodeResponse[[]map[string]any](t, usersResponse, http.StatusOK)
	if len(users) != 4 {
		t.Fatal("administrator did not see all public identities")
	}
	for _, user := range users {
		if len(user) != 3 || user["id"] == nil || user["username"] == nil || user["role"] == nil {
			t.Fatal("user listing leaked credentials or omitted identity fields")
		}
	}
	for _, method := range []string{"GET", "POST"} {
		if response := request(t, s, method, "/api/users", input, cookie); response.Code != http.StatusForbidden {
			t.Fatal("normal user accessed global user management")
		}
	}
	if response := request(t, s, "PUT", "/api/settings", settings, cookie); response.Code != http.StatusForbidden {
		t.Fatal("normal user modified global settings")
	}
}

func TestOwnershipFiltersViewsAndRejectsEveryCrossAccountObjectAction(t *testing.T) {
	s, adminCookie := fixture(t, &fakeRuntime{})
	alice, aliceCookie := userFixture(t, s, "alice")
	bob, bobCookie := userFixture(t, s, "bob")
	adminGraph := graphFixture(t, s, adminCookie, "admin")
	a := graphFixture(t, s, aliceCookie, "alice")
	b := graphFixture(t, s, bobCookie, "bob")
	if a.node.OwnerID != alice.ID || b.node.OwnerID != bob.ID || adminGraph.node.OwnerID != "fixture-admin" {
		t.Fatal("server did not assign actor ownership")
	}
	for _, entry := range []struct {
		user   model.User
		cookie *http.Cookie
		graph  ownedGraph
	}{{alice, aliceCookie, a}, {bob, bobCookie, b}} {
		response := request(t, s, "GET", "/api/state", nil, entry.cookie)
		state := decodeResponse[model.State](t, response, http.StatusOK)
		if state.CurrentUser == nil || state.CurrentUser.ID != entry.user.ID || len(state.Nodes) != 1 || len(state.Upstreams) != 1 || len(state.Relays) != 1 || len(state.Jobs) != 1 || len(state.Probes) != 1 || len(state.Subscriptions) != 1 || state.Nodes[0].ID != entry.graph.node.ID {
			t.Fatal("normal state exposed another owner's resources")
		}
		if state.Nodes[0].Password != "" || len(state.Upstreams[0].Outbound) != 0 {
			t.Fatal("filtered state lost credential masking")
		}
		if len(decodeResponse[[]model.Node](t, request(t, s, "GET", "/api/nodes", nil, entry.cookie), http.StatusOK)) != 1 || len(decodeResponse[[]model.Upstream](t, request(t, s, "GET", "/api/upstreams", nil, entry.cookie), http.StatusOK)) != 1 || len(decodeResponse[[]model.Relay](t, request(t, s, "GET", "/api/relays", nil, entry.cookie), http.StatusOK)) != 1 {
			t.Fatal("standalone resource list was not owner filtered")
		}
	}
	adminState := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, adminCookie), http.StatusOK)
	if len(adminState.Nodes) != 3 || len(adminState.Upstreams) != 3 || len(adminState.Relays) != 3 || len(adminState.Users) != 3 || len(adminState.Probes) != 3 || len(adminState.Jobs) != 3 || len(adminState.Subscriptions) != 3 {
		t.Fatal("administrator view was filtered")
	}
	var fetched atomic.Int32
	s.fetchSource = func(context.Context, string) (string, error) { fetched.Add(1); return "", nil }
	for _, pair := range []struct {
		cookie *http.Cookie
		target ownedGraph
		own    ownedGraph
	}{{aliceCookie, b, a}, {bobCookie, a, b}} {
		for _, test := range []struct {
			method, path string
			input        any
		}{
			{"GET", "/api/upstreams/" + pair.target.upstream.ID, nil},
			{"PUT", "/api/upstreams/" + pair.target.upstream.ID, pair.target.upstream},
			{"DELETE", "/api/upstreams/" + pair.target.upstream.ID, nil},
			{"PUT", "/api/nodes/" + pair.target.node.ID, pair.target.node},
			{"DELETE", "/api/nodes/" + pair.target.node.ID, nil},
			{"POST", "/api/nodes/test", pair.target.node},
			{"POST", "/api/nodes/" + pair.target.node.ID + "/apply", nil},
			{"POST", "/api/nodes/" + pair.target.node.ID + "/probe", map[string]string{"upstream_id": pair.own.upstream.ID}},
			{"POST", "/api/nodes/" + pair.target.node.ID + "/service", map[string]string{"action": "stop"}},
			{"GET", "/api/nodes/" + pair.target.node.ID + "/logs", nil},
			{"PUT", "/api/relays/" + pair.target.relay.ID, pair.target.relay},
			{"DELETE", "/api/relays/" + pair.target.relay.ID, nil},
			{"GET", "/api/relays/" + pair.target.relay.ID + "/share", nil},
			{"POST", "/api/subscriptions/" + pair.target.sub.ID + "/refresh", nil},
			{"DELETE", "/api/subscriptions/" + pair.target.sub.ID, nil},
			{"POST", "/api/nodes/" + pair.own.node.ID + "/probe", map[string]string{"upstream_id": pair.target.upstream.ID}},
		} {
			response := request(t, s, test.method, test.path, test.input, pair.cookie)
			if response.Code != http.StatusNotFound {
				t.Fatalf("cross-owner %s %s returned %d: %s", test.method, test.path, response.Code, response.Body.String())
			}
		}
	}
	if fetched.Load() != 0 {
		t.Fatal("unauthorized subscription refresh performed a network fetch")
	}
	for _, path := range []string{"/api/nodes", "/api/nodes/test"} {
		if response := request(t, s, "POST", path, model.Node{Name: "Local", Kind: "local"}, aliceCookie); response.Code != http.StatusForbidden {
			t.Fatal("normal user accessed the privileged local runtime")
		}
	}
	duplicate := b.node
	duplicate.ID, duplicate.Password = "", "new-password-for-test"
	if response := request(t, s, "POST", "/api/nodes", duplicate, aliceCookie); response.Code != http.StatusConflict {
		t.Fatal("node duplicate check used the filtered HTTP view")
	}
	if response := request(t, s, "POST", "/api/nodes/test", duplicate, aliceCookie); response.Code != http.StatusForbidden {
		t.Fatal("node test reached another owner's endpoint without its ID")
	}
	decodeResponse[model.Upstream](t, request(t, s, "GET", "/api/upstreams/"+b.upstream.ID, nil, adminCookie), http.StatusOK)
	decodeResponse[map[string]string](t, request(t, s, "GET", "/api/relays/"+b.relay.ID+"/share", nil, adminCookie), http.StatusOK)
	decodeResponse[map[string]any](t, request(t, s, "GET", "/api/nodes/"+b.node.ID+"/logs", nil, adminCookie), http.StatusOK)
	// Updates keep the stored owner even when an administrator or owner sends
	// a different owner_id in an otherwise valid resource body.
	for _, cookie := range []*http.Cookie{aliceCookie, adminCookie} {
		a.node.OwnerID = bob.ID
		updatedNode := decodeResponse[model.Node](t, request(t, s, "PUT", "/api/nodes/"+a.node.ID, a.node, cookie), http.StatusOK)
		if updatedNode.OwnerID != alice.ID {
			t.Fatal("node update transferred ownership")
		}
		updatedUpstream := decodeResponse[model.Upstream](t, request(t, s, "PUT", "/api/upstreams/"+a.upstream.ID, map[string]string{"name": "Renamed", "owner_id": bob.ID}, cookie), http.StatusOK)
		if updatedUpstream.OwnerID != alice.ID {
			t.Fatal("upstream update transferred ownership")
		}
		a.relay.OwnerID = bob.ID
		updatedRelay := decodeResponse[model.Relay](t, request(t, s, "PUT", "/api/relays/"+a.relay.ID, a.relay, cookie), http.StatusOK)
		if updatedRelay.OwnerID != alice.ID {
			t.Fatal("relay update transferred ownership")
		}
	}
	mismatch := a.relay
	mismatch.NodeID, mismatch.UpstreamID = b.node.ID, b.upstream.ID
	if response := request(t, s, "PUT", "/api/relays/"+a.relay.ID, mismatch, adminCookie); response.Code != http.StatusBadRequest {
		t.Fatal("administrator attached a relay across owners")
	}
	if response := request(t, s, "PUT", "/api/relays/"+a.relay.ID, mismatch, aliceCookie); response.Code != http.StatusNotFound {
		t.Fatal("regular user attached another owner's infrastructure")
	}
	if response := request(t, s, "POST", "/api/nodes/"+a.node.ID+"/probe", map[string]string{"upstream_id": b.upstream.ID}, adminCookie); response.Code != http.StatusBadRequest {
		t.Fatal("administrator probe crossed private node ownership")
	}
}

func TestPersonalSubscriptionTokensAndRotationDoNotExpandAdminFeed(t *testing.T) {
	s, adminCookie := fixture(t, nil)
	_, aliceCookie := userFixture(t, s, "alice")
	_, bobCookie := userFixture(t, s, "bob")
	admin := graphFixture(t, s, adminCookie, "admin")
	alice := graphFixture(t, s, aliceCookie, "alice")
	bob := graphFixture(t, s, bobCookie, "bob")
	cookies := []*http.Cookie{adminCookie, aliceCookie, bobCookie}
	graphs := []ownedGraph{admin, alice, bob}
	disabled := alice.relay
	disabled.Name, disabled.Enabled, disabled.Port = "Disabled private entry", false, 24444
	decodeResponse[model.Relay](t, request(t, s, "POST", "/api/relays", disabled, aliceCookie), http.StatusCreated)
	tokens := make([]string, 0, 3)
	for i, cookie := range cookies {
		settings := decodeResponse[model.Settings](t, request(t, s, "GET", "/api/settings", nil, cookie), http.StatusOK)
		state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, cookie), http.StatusOK)
		if !auth.ValidToken(settings.SubscriptionToken) || settings.SubscriptionToken != state.Settings.SubscriptionToken {
			t.Fatal("settings/state returned a nonpersonal subscription token")
		}
		for _, token := range tokens {
			if token == settings.SubscriptionToken {
				t.Fatal("users share a token")
			}
		}
		tokens = append(tokens, settings.SubscriptionToken)
		feed := request(t, s, "GET", "/sub/"+settings.SubscriptionToken, nil, nil)
		if feed.Code != http.StatusOK {
			t.Fatalf("personal feed failed: %s", feed.Body.String())
		}
		content, err := base64.StdEncoding.DecodeString(feed.Body.String())
		if err != nil || strings.TrimSpace(string(content)) != graphs[i].relay.ShareURL {
			t.Fatal("personal feed included another owner's relay (including the admin feed)")
		}
	}
	rotated := decodeResponse[model.Settings](t, request(t, s, "POST", "/api/settings/rotate-token", map[string]string{"owner_id": bob.node.OwnerID, "user_id": admin.node.OwnerID}, aliceCookie), http.StatusOK)
	if rotated.SubscriptionToken == tokens[1] {
		t.Fatal("rotation did not change the caller's token")
	}
	if response := request(t, s, "GET", "/sub/"+tokens[1], nil, nil); response.Code != http.StatusNotFound {
		t.Fatal("old personal token was still accepted")
	}
	for _, i := range []int{0, 2} {
		settings := decodeResponse[model.Settings](t, request(t, s, "GET", "/api/settings", nil, cookies[i]), http.StatusOK)
		if settings.SubscriptionToken != tokens[i] {
			t.Fatal("rotating Alice's token changed another account's token")
		}
	}
	global, err := s.store.Settings(context.Background())
	if err != nil || global.SubscriptionToken != "" {
		t.Fatal("personal token was stored in global settings")
	}
}

func TestAdminSubscriptionRefreshRetainsOriginalOwnerAndPreviousReferences(t *testing.T) {
	s, adminCookie := fixture(t, nil)
	alice, aliceCookie := userFixture(t, s, "alice")
	_, bobCookie := userFixture(t, s, "bob")
	var fetches atomic.Int32
	content := "vless://00112233-4455-4677-8899-aabbccddeeff@proxy.example.test:443?encryption=none&security=tls&type=tcp#First"
	s.fetchSource = func(context.Context, string) (string, error) { fetches.Add(1); return content, nil }
	created := decodeResponse[struct {
		Subscription model.Subscription `json:"subscription"`
		Upstreams    []model.Upstream   `json:"upstreams"`
	}](t, request(t, s, "POST", "/api/subscriptions", map[string]string{"name": "Alice source", "url": "https://source.example.test/list"}, aliceCookie), http.StatusCreated)
	if created.Subscription.OwnerID != alice.ID || len(created.Upstreams) != 1 || created.Upstreams[0].OwnerID != alice.ID {
		t.Fatal("subscription import did not use the actor owner")
	}
	if response := request(t, s, "POST", "/api/subscriptions/"+created.Subscription.ID+"/refresh", nil, bobCookie); response.Code != http.StatusNotFound || fetches.Load() != 1 {
		t.Fatal("cross-owner refresh fetched the source")
	}
	content = "vless://00112233-4455-4677-8899-aabbccddeeff@replacement.example.test:443?encryption=none&security=tls&type=tcp#Second"
	refreshed := decodeResponse[struct {
		Subscription model.Subscription `json:"subscription"`
		Upstreams    []model.Upstream   `json:"upstreams"`
	}](t, request(t, s, "POST", "/api/subscriptions/"+created.Subscription.ID+"/refresh", nil, adminCookie), http.StatusOK)
	if refreshed.Subscription.OwnerID != alice.ID || len(refreshed.Upstreams) != 1 || refreshed.Upstreams[0].OwnerID != alice.ID {
		t.Fatal("administrator refresh stole imported upstream ownership")
	}
	node := decodeResponse[model.Node](t, request(t, s, "POST", "/api/nodes", model.Node{Name: "Admin local", Kind: "local"}, adminCookie), http.StatusCreated)
	previous := store.Applied{Revision: "previous", UpstreamIDs: []string{refreshed.Upstreams[0].ID}}
	if err := s.store.Commit(context.Background(), store.Changes{Applied: map[string]store.Applied{node.ID: {Revision: "current", Previous: &previous}}}); err != nil {
		t.Fatal(err)
	}
	content = "vless://00112233-4455-4677-8899-aabbccddeeff@third.example.test:443?encryption=none&security=tls&type=tcp#Third"
	if response := request(t, s, "POST", "/api/subscriptions/"+created.Subscription.ID+"/refresh", nil, aliceCookie); response.Code != http.StatusConflict {
		t.Fatal("subscription refresh missed a hidden node's previous applied reference")
	}
	if response := request(t, s, "DELETE", "/api/upstreams/"+refreshed.Upstreams[0].ID, nil, aliceCookie); response.Code != http.StatusConflict {
		t.Fatal("upstream deletion missed the global previous applied reference")
	}
}

func TestWorkersReadCompleteStoreAndOwnershipDoesNotAlterAppliedHash(t *testing.T) {
	runtime := &fakeRuntime{}
	s, adminCookie := fixture(t, runtime)
	_, aliceCookie := userFixture(t, s, "alice")
	_, bobCookie := userFixture(t, s, "bob")
	graphFixture(t, s, adminCookie, "admin")
	alice := graphFixture(t, s, aliceCookie, "alice")
	graphFixture(t, s, bobCookie, "bob")
	job := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+alice.node.ID+"/apply", nil, aliceCookie), http.StatusAccepted)
	if job.OwnerID != alice.node.OwnerID {
		t.Fatal("node job was not bound to its resource owner")
	}
	waitJob(t, s, aliceCookie, job.ID, "succeeded")
	runtime.mu.Lock()
	node, upstreams, relays := runtime.appliedNode, runtime.appliedUpstreams, runtime.appliedRelays
	runtime.mu.Unlock()
	if node.ID != alice.node.ID || len(upstreams) != 3 || len(relays) != 3 {
		t.Fatal("worker received the HTTP user's filtered view instead of the complete desired state")
	}
	generated, err := xray.Generate(node, upstreams, relays)
	if err != nil {
		t.Fatal(err)
	}
	var config struct {
		Inbounds []any `json:"inbounds"`
	}
	if err := json.Unmarshal(generated, &config); err != nil || len(config.Inbounds) != 1 {
		t.Fatal("full-state generation did not isolate the target node")
	}
	state := model.State{Upstreams: upstreams, Relays: relays}
	before := desiredConfigHash(node, state)
	for i := range state.Relays {
		state.Relays[i].OwnerID = "metadata-only-change"
	}
	for i := range state.Upstreams {
		state.Upstreams[i].OwnerID = "metadata-only-change"
	}
	node.OwnerID = "metadata-only-change"
	if desiredConfigHash(node, state) != before {
		t.Fatal("ownership metadata changed the applied configuration hash")
	}
	afterConfig, err := xray.Generate(node, state.Upstreams, state.Relays)
	if err != nil || !bytes.Equal(generated, afterConfig) {
		t.Fatal("ownership metadata changed runtime configuration")
	}
	// Independently reconstruct the old hash input with the original JSON field
	// sequence and no owner fields, to preserve already-applied v1 comparisons.
	legacyRelays := []model.Relay{}
	legacyUpstreams := []model.Upstream{}
	for _, relay := range relays {
		if relay.NodeID == node.ID && relay.Enabled {
			relay.OwnerID, relay.Name, relay.ShareURL = "", "", ""
			relay.CreatedAt, relay.UpdatedAt = time.Time{}, time.Time{}
			legacyRelays = append(legacyRelays, relay)
		}
	}
	for _, upstream := range upstreams {
		if upstream.ID == alice.upstream.ID {
			upstream.OwnerID, upstream.Name, upstream.SourceID, upstream.Server, upstream.Protocol = "", "", "", "", ""
			upstream.Port = 0
			upstream.CreatedAt, upstream.UpdatedAt = time.Time{}, time.Time{}
			legacyUpstreams = append(legacyUpstreams, upstream)
		}
	}
	legacyJSON, err := json.Marshal(struct {
		Version   string           `json:"version"`
		Relays    []model.Relay    `json:"relays"`
		Upstreams []model.Upstream `json:"upstreams"`
	}{node.CoreVersion, legacyRelays, legacyUpstreams})
	if err != nil {
		t.Fatal(err)
	}
	legacyHash := sha256.Sum256(legacyJSON)
	if before != hex.EncodeToString(legacyHash[:]) {
		t.Fatal("new owner field broke a pre-migration applied hash")
	}
	applied, err := s.store.Applied(context.Background(), node.ID)
	if err != nil || applied.ConfigHash != before || !applied.ReferencesRelay(alice.relay.ID) || !applied.ReferencesUpstream(alice.upstream.ID) {
		t.Fatal("applied snapshot lost hash or object references")
	}
}
