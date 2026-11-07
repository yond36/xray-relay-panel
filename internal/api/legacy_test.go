package api

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/credentials"
	"xrayrelay/internal/model"
	"xrayrelay/internal/store"
	"xrayrelay/internal/xray"
)

func TestV1HTTPMigrationKeepsOldLoginSessionSubscriptionAndAppliedStatus(t *testing.T) {
	directory := t.TempDir()
	crypt, err := credentials.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(directory, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	// Build the old singleton schema directly, before opening the new server.
	for _, statement := range []string{
		`CREATE TABLE accounts (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`,
		`CREATE TABLE sessions (hash BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE INDEX sessions_expiry ON sessions(expires_at)`,
		`CREATE TABLE nodes (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE subscriptions (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE upstreams (id TEXT PRIMARY KEY, source_id TEXT NOT NULL DEFAULT '', data BLOB NOT NULL)`,
		`CREATE TABLE relays (id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT, upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE RESTRICT, data BLOB NOT NULL)`,
		`CREATE TABLE jobs (id TEXT PRIMARY KEY, node_id TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, data BLOB NOT NULL)`,
		`CREATE TABLE probes (id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE, checked_at INTEGER NOT NULL, data BLOB NOT NULL)`,
		`CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`,
		`CREATE TABLE applied (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, data BLOB NOT NULL)`,
		`PRAGMA user_version=1`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	password, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	legacySession, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	legacyToken, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	node := model.Node{ID: "legacy-node", Name: "Legacy local", Kind: "local", Host: "127.0.0.1", PublicHost: "legacy.example.test", CoreVersion: model.DefaultCoreVersion, Status: "ready", AppliedRevision: "legacy-revision", CreatedAt: now, UpdatedAt: now}
	upstream := testUpstream(t)
	upstream.ID, upstream.CreatedAt, upstream.UpdatedAt = "legacy-upstream", now, now
	relay := model.Relay{ID: "legacy-relay", Name: "Legacy entry", NodeID: node.ID, UpstreamID: upstream.ID, Enabled: true, Protocol: "shadowsocks", Listen: "0.0.0.0", PublicHost: node.PublicHost, Port: 24443, Network: "tcp", Security: "none", Cipher: "aes-128-gcm", Password: password, CreatedAt: now, UpdatedAt: now}
	if err := xray.PrepareRelay(&relay); err != nil {
		t.Fatal(err)
	}
	link, err := xray.ShareURL(relay)
	if err != nil {
		t.Fatal(err)
	}
	relay.ShareURL = link
	oldHash := desiredConfigHash(node, model.State{Upstreams: []model.Upstream{upstream}, Relays: []model.Relay{relay}})
	seal := func(table, id string, value any) []byte {
		plain, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		data, err := crypt.Seal(plain, table+":"+id)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	exec := func(query string, args ...any) {
		if _, err := db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO accounts(id,data) VALUES(1,?)", seal("accounts", "1", map[string]string{"username": "Owner", "hash": hash}))
	exec("INSERT INTO sessions(hash,expires_at,created_at) VALUES(?,?,?)", auth.TokenHash(legacySession), time.Now().Add(time.Hour).Unix(), now.Unix())
	exec("INSERT INTO settings(id,data) VALUES(1,?)", seal("settings", "1", map[string]string{"core_version": model.DefaultCoreVersion, "panel_url": "https://legacy-panel.example.test", "subscription_token": legacyToken}))
	exec("INSERT INTO nodes(id,data) VALUES(?,?)", node.ID, seal("nodes", node.ID, node))
	exec("INSERT INTO upstreams(id,source_id,data) VALUES(?,?,?)", upstream.ID, "", seal("upstreams", upstream.ID, upstream))
	exec("INSERT INTO relays(id,node_id,upstream_id,data) VALUES(?,?,?,?)", relay.ID, node.ID, upstream.ID, seal("relays", relay.ID, relay))
	exec("INSERT INTO applied(node_id,data) VALUES(?,?)", node.ID, seal("applied", node.ID, store.Applied{Revision: node.AppliedRevision, ConfigHash: oldHash, RelayIDs: []string{relay.ID}, UpstreamIDs: []string{upstream.ID}, Previous: &store.Applied{Revision: "older-revision", ConfigHash: "older-hash", RelayIDs: []string{relay.ID}, UpstreamIDs: []string{upstream.ID}}}))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := New(Config{DataDir: directory, Runtime: &fakeRuntime{}})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	oldCookie := &http.Cookie{Name: cookieName, Value: legacySession}
	state := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, oldCookie), http.StatusOK)
	if state.CurrentUser == nil || state.CurrentUser.Role != model.RoleAdmin || state.CurrentUser.Username != "owner" || len(state.Nodes) != 1 || state.Nodes[0].ID != node.ID || state.Nodes[0].OwnerID != state.CurrentUser.ID || state.Settings.SubscriptionToken != legacyToken || state.Settings.RegistrationOpen {
		t.Fatal("legacy session did not retain administrator ownership and personal token")
	}
	login := request(t, s, "POST", "/api/auth/login", map[string]string{"username": "OWNER", "password": password}, nil)
	decodeResponse[map[string]any](t, login, http.StatusOK)
	if len(login.Result().Cookies()) != 1 {
		t.Fatal("legacy login did not issue a new session")
	}
	applied, err := s.store.Applied(context.Background(), node.ID)
	if err != nil || applied.ConfigHash != oldHash || applied.Previous == nil || applied.Previous.Revision != "older-revision" {
		t.Fatal("migration changed a historical applied snapshot")
	}
	job := decodeResponse[model.Job](t, request(t, s, "POST", "/api/nodes/"+node.ID+"/service", map[string]string{"action": "restart"}, oldCookie), http.StatusAccepted)
	waitJob(t, s, oldCookie, job.ID, "succeeded")
	state = decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, oldCookie), http.StatusOK)
	if state.Nodes[0].Status != "ready" {
		t.Fatal("adding ownership invalidated the old applied hash after restart")
	}
	_, newUserCookie := userFixture(t, s, "new-user")
	graphFixture(t, s, newUserCookie, "new-user")
	feed := request(t, s, "GET", "/sub/"+legacyToken, nil, nil)
	if feed.Code != http.StatusOK {
		t.Fatal("the legacy subscription URL stopped working")
	}
	content, err := base64.StdEncoding.DecodeString(feed.Body.String())
	if err != nil || strings.TrimSpace(string(content)) != link {
		t.Fatal("legacy administrator token exposed a newly registered user's relay")
	}
	newUserStateResponse := request(t, s, "GET", "/api/state", nil, newUserCookie)
	newUserState := decodeResponse[model.State](t, newUserStateResponse, http.StatusOK)
	if newUserState.Settings.SubscriptionToken == legacyToken || strings.Contains(newUserStateResponse.Body.String(), legacyToken) || len(newUserState.Nodes) != 1 {
		t.Fatal("legacy global token or configuration leaked to a normal user")
	}
	adminState := decodeResponse[model.State](t, request(t, s, "GET", "/api/state", nil, oldCookie), http.StatusOK)
	if len(adminState.Nodes) != 2 || len(adminState.Relays) != 2 {
		t.Fatal("migrated administrator lost all-user visibility")
	}

	// Sessions carry an account reference, never a cached role claim. Simulate a
	// persisted role change to prove the next request reads the real account.
	account, err := s.store.AccountByID(context.Background(), state.CurrentUser.ID)
	if err != nil {
		t.Fatal(err)
	}
	account.Role = model.RoleUser
	db, err = sql.Open("sqlite", filepath.Join(directory, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("UPDATE accounts SET data=? WHERE id=?", seal("accounts", account.ID, account), account.ID); err != nil {
		t.Fatal(err)
	}
	if response := request(t, s, "GET", "/api/users", nil, oldCookie); response.Code != http.StatusForbidden {
		t.Fatal("session trusted an old administrator role after the account changed")
	}
}
