package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/credentials"
	"xrayrelay/internal/model"
)

type legacyDatabase struct {
	directory         string
	state             model.State
	account           Account
	password          string
	session           Session
	applied           Applied
	accountCiphertext []byte
	appliedCiphertext []byte
}

// This fixture is created directly using the shipped v1 SQL structure and v1
// account/settings JSON, without opening (or downgrading) a v2 Store.
func createLegacyDatabase(t *testing.T, corruptNode bool) legacyDatabase {
	t.Helper()
	dir := t.TempDir()
	crypt, err := credentials.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, statement := range []string{
		`CREATE TABLE accounts (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`,
		`CREATE TABLE sessions (hash BLOB PRIMARY KEY, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE INDEX sessions_expiry ON sessions(expires_at)`,
		`CREATE TABLE nodes (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE subscriptions (id TEXT PRIMARY KEY, data BLOB NOT NULL)`,
		`CREATE TABLE upstreams (id TEXT PRIMARY KEY, source_id TEXT NOT NULL DEFAULT '', data BLOB NOT NULL)`,
		`CREATE INDEX upstreams_source ON upstreams(source_id)`,
		`CREATE TABLE relays (id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE RESTRICT, upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE RESTRICT, data BLOB NOT NULL)`,
		`CREATE INDEX relays_node ON relays(node_id)`,
		`CREATE INDEX relays_upstream ON relays(upstream_id)`,
		`CREATE TABLE jobs (id TEXT PRIMARY KEY, node_id TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, data BLOB NOT NULL)`,
		`CREATE INDEX jobs_recent ON jobs(created_at DESC)`,
		`CREATE TABLE probes (id TEXT PRIMARY KEY, node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, upstream_id TEXT NOT NULL REFERENCES upstreams(id) ON DELETE CASCADE, checked_at INTEGER NOT NULL, data BLOB NOT NULL)`,
		`CREATE INDEX probes_recent ON probes(checked_at DESC)`,
		`CREATE TABLE settings (id INTEGER PRIMARY KEY CHECK(id=1), data BLOB NOT NULL)`,
		`CREATE TABLE applied (node_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE, data BLOB NOT NULL)`,
		`PRAGMA user_version=1`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	password, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	sessionToken, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 1, 12, 13, 14, 123456789, time.UTC)
	finished := now.Add(time.Minute)
	fixture := legacyDatabase{directory: dir, account: Account{Username: "LegacyAdmin", Hash: hash}, password: password,
		session: Session{Hash: auth.TokenHash(sessionToken), ExpiresAt: time.Now().Add(time.Hour).Truncate(time.Second)},
		applied: Applied{Revision: "active-revision", ConfigHash: "v1-active-hash", RelayIDs: []string{"relay"}, UpstreamIDs: []string{"upstream"},
			Previous: &Applied{Revision: "previous-revision", ConfigHash: "v1-previous-hash", RelayIDs: []string{"relay"}, UpstreamIDs: []string{"upstream"}}},
		state: model.State{
			Nodes:         []model.Node{{ID: "node", Name: "Legacy SSH", Kind: "ssh", Host: "legacy.example.test", SSHPort: 2200, Username: "root", AuthMode: "privatekey", Password: password, PrivateKey: "legacy-private-key", KeyPassphrase: "legacy-key-passphrase", Fingerprint: "SHA256:legacy", PublicHost: "legacy-public.example.test", CoreVersion: model.DefaultCoreVersion, Status: "ready", LastError: "old warning", AppliedRevision: "active-revision", HasCredentials: true, CreatedAt: now, UpdatedAt: now}},
			Upstreams:     []model.Upstream{{ID: "upstream", Name: "Legacy upstream", Protocol: "socks", Server: "proxy.example.test", Port: 1080, SourceID: "subscription", Outbound: json.RawMessage(`{"protocol":"socks","settings":{"servers":[{"address":"proxy.example.test","port":1080,"users":[{"user":"old-user","pass":"old-pass"}]}]}}`), CreatedAt: now, UpdatedAt: now}},
			Relays:        []model.Relay{{ID: "relay", Name: "Legacy entry", NodeID: "node", UpstreamID: "upstream", Enabled: true, Protocol: "vless", Listen: "0.0.0.0", PublicHost: "legacy-public.example.test", Port: 24443, Network: "tcp", Security: "reality", UUID: "old-uuid", Password: password, RealityPrivateKey: "reality-secret", RealityPublicKey: "reality-public", ShortID: "a1b2", Certificate: "certificate", CertificateKey: "certificate-key", ShareURL: "legacy-share-url", CreatedAt: now, UpdatedAt: now}},
			Subscriptions: []model.Subscription{{ID: "subscription", Name: "Legacy subscription", URL: "https://source.example.test/sub?token=legacy-access", Count: 1, LastError: "preserved-error", UpdatedAt: now}},
			Jobs:          []model.Job{{ID: "job", NodeID: "node", Action: "apply", Status: "succeeded", Message: "old job", Revision: "active-revision", CreatedAt: now, FinishedAt: &finished}},
			Probes:        []model.ProbeResult{{ID: "probe", NodeID: "node", UpstreamID: "upstream", IPv4: "203.0.113.1", IPv6: "2001:db8::1", LatencyMS: 321, Status: "partial", IPv6Error: "old warning", CheckedAt: now}},
			Settings:      model.Settings{CoreVersion: model.DefaultCoreVersion, PanelURL: "https://panel.example.test", SubscriptionToken: token},
		},
	}
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
	fixture.accountCiphertext = seal("accounts", "1", map[string]string{"username": fixture.account.Username, "hash": hash})
	fixture.appliedCiphertext = seal("applied", "node", fixture.applied)
	exec("INSERT INTO accounts(id,data) VALUES(1,?)", fixture.accountCiphertext)
	exec("INSERT INTO sessions(hash,expires_at,created_at) VALUES(?,?,?)", fixture.session.Hash, fixture.session.ExpiresAt.Unix(), now.Unix())
	nodeData := seal("nodes", "node", fixture.state.Nodes[0])
	if corruptNode {
		nodeData = []byte("corrupt-v1-node")
	}
	exec("INSERT INTO nodes(id,data) VALUES(?,?)", "node", nodeData)
	exec("INSERT INTO subscriptions(id,data) VALUES(?,?)", "subscription", seal("subscriptions", "subscription", fixture.state.Subscriptions[0]))
	exec("INSERT INTO upstreams(id,source_id,data) VALUES(?,?,?)", "upstream", "subscription", seal("upstreams", "upstream", fixture.state.Upstreams[0]))
	exec("INSERT INTO relays(id,node_id,upstream_id,data) VALUES(?,?,?,?)", "relay", "node", "upstream", seal("relays", "relay", fixture.state.Relays[0]))
	exec("INSERT INTO jobs(id,node_id,status,created_at,data) VALUES(?,?,?,?,?)", "job", "node", "succeeded", now.UnixNano(), seal("jobs", "job", fixture.state.Jobs[0]))
	exec("INSERT INTO probes(id,node_id,upstream_id,checked_at,data) VALUES(?,?,?,?,?)", "probe", "node", "upstream", now.UnixNano(), seal("probes", "probe", fixture.state.Probes[0]))
	exec("INSERT INTO settings(id,data) VALUES(1,?)", seal("settings", "1", map[string]string{"core_version": fixture.state.Settings.CoreVersion, "panel_url": fixture.state.Settings.PanelURL, "subscription_token": token}))
	exec("INSERT INTO applied(node_id,data) VALUES(?,?)", "node", fixture.appliedCiphertext)
	return fixture
}

func TestV1MigrationPreservesIdentitySessionsSecretsReferencesAndSnapshots(t *testing.T) {
	fixture := createLegacyDatabase(t, false)
	s, err := Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	account, err := s.AccountByUsername(ctx, " LEGACYADMIN ")
	if err != nil {
		t.Fatal(err)
	}
	if account.ID == "" || account.ID == "1" || account.Role != model.RoleAdmin || account.Username != "legacyadmin" || account.Hash != fixture.account.Hash || !auth.VerifyPassword(account.Hash, fixture.password) || account.SubscriptionToken != fixture.state.Settings.SubscriptionToken {
		t.Fatal("migration did not preserve legacy login or token under a stable admin identity")
	}
	sessionAccount, err := s.SessionAccount(ctx, fixture.session.Hash, time.Now())
	if err != nil || sessionAccount.ID != account.ID {
		t.Fatal("legacy session was not bound to the migrated administrator")
	}
	for _, table := range []string{"nodes", "upstreams", "relays", "subscriptions", "jobs", "probes"} {
		var owner string
		if err := s.db.QueryRow("SELECT owner_id FROM " + table).Scan(&owner); err != nil || owner != account.ID {
			t.Fatalf("wrong migrated %s owner", table)
		}
	}
	fixture.state.Nodes[0].OwnerID = account.ID
	fixture.state.Upstreams[0].OwnerID = account.ID
	fixture.state.Relays[0].OwnerID = account.ID
	fixture.state.Subscriptions[0].OwnerID = account.ID
	fixture.state.Jobs[0].OwnerID = account.ID
	fixture.state.Probes[0].OwnerID = account.ID
	fixture.state.Settings.SubscriptionToken = ""
	state, err := s.State(ctx)
	if err != nil || !reflect.DeepEqual(state, fixture.state) {
		t.Fatalf("legacy configuration changed during migration: %v", err)
	}
	applied, err := s.Applied(ctx, "node")
	if err != nil || !reflect.DeepEqual(applied, fixture.applied) {
		t.Fatal("current/previous deployment snapshots changed")
	}
	var encrypted []byte
	if err := s.db.QueryRow("SELECT data FROM applied WHERE node_id='node'").Scan(&encrypted); err != nil || !bytes.Equal(encrypted, fixture.appliedCiphertext) {
		t.Fatal("unchanged snapshot AAD was unnecessarily moved")
	}
	if err := s.db.QueryRow("SELECT data FROM accounts WHERE id=?", account.ID).Scan(&encrypted); err != nil {
		t.Fatal(err)
	}
	if _, err := s.cipher.Open(encrypted, "accounts:1"); err == nil {
		t.Fatal("new account ciphertext still uses the singleton AAD")
	}
	var expiry int64
	if err := s.db.QueryRow("SELECT expires_at FROM sessions WHERE hash=?", fixture.session.Hash).Scan(&expiry); err != nil || expiry != fixture.session.ExpiresAt.Unix() {
		t.Fatal("legacy session expiry changed")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(fixture.directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	reopened, err := s.Account(ctx)
	if err != nil || reopened.ID != account.ID || reopened.SubscriptionToken != account.SubscriptionToken {
		t.Fatal("migration was not stable across restart")
	}
	file, err := os.ReadFile(filepath.Join(fixture.directory, "panel.db"))
	if err != nil || bytes.Contains(file, []byte(fixture.password)) {
		t.Fatal("migration exposed plaintext credentials")
	}
}

func TestV1MigrationRollsBackDDLAndAccountReencryptionOnCorruptRecord(t *testing.T) {
	fixture := createLegacyDatabase(t, true)
	if database, err := Open(fixture.directory); err == nil {
		database.Close()
		t.Fatal("corrupt v1 record was accepted")
	}
	db, err := sql.Open("sqlite", filepath.Join(fixture.directory, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var version int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 1 {
		t.Fatal("partial schema migration was committed")
	}
	var data []byte
	if err := db.QueryRow("SELECT data FROM accounts WHERE id=1").Scan(&data); err != nil || !bytes.Equal(data, fixture.accountCiphertext) {
		t.Fatal("failed migration replaced the old encrypted account")
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sessions WHERE hash=?", fixture.session.Hash).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed migration lost the old session")
	}
}
