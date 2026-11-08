package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/credentials"
	"xrayrelay/internal/model"
)

func TestEncryptedStateSurvivesRestartAndInterruptsJobs(t *testing.T) {
	t.Setenv(credentials.MasterKeyEnv, "")
	if err := os.Unsetenv(credentials.MasterKeyEnv); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	directory := t.TempDir()
	database, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	node := model.Node{ID: "node-one", Name: "SSH node", Kind: "ssh", Password: secret, Status: "ready", AppliedRevision: "previous-revision"}
	settings := model.Settings{SubscriptionToken: secret, CoreVersion: model.DefaultCoreVersion}
	upstream := model.Upstream{ID: "upstream-one", Outbound: []byte(`{"protocol":"freedom"}`)}
	relay := model.Relay{ID: "relay-one", NodeID: node.ID, UpstreamID: upstream.ID, Enabled: true, Password: secret}
	applied := Applied{Revision: node.AppliedRevision, RelayIDs: []string{relay.ID}, UpstreamIDs: []string{upstream.ID}, PendingDeleteRelayID: relay.ID,
		Previous: &Applied{Revision: "older-revision", RelayIDs: []string{relay.ID}, UpstreamIDs: []string{upstream.ID}}}
	if err := database.Commit(ctx, Changes{
		Nodes: []model.Node{node}, Settings: &settings, Upstreams: []model.Upstream{upstream}, Relays: []model.Relay{relay}, Applied: map[string]Applied{node.ID: applied},
		Jobs: []model.Job{
			{ID: "running-job", NodeID: node.ID, Action: "apply", Status: "running", CreatedAt: now},
			{ID: "queued-job", NodeID: node.ID, UpstreamID: upstream.ID, Action: "probe", Status: "queued", CreatedAt: now},
			{ID: "deleting-job", NodeID: node.ID, RelayID: relay.ID, Action: "delete-relay", Status: "running", CreatedAt: now},
		},
	}); err != nil {
		t.Fatal(err)
	}
	var ciphertext []byte
	if err := database.db.QueryRow("SELECT data FROM nodes WHERE id=?", node.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte(secret)) {
		t.Fatal("SQLite stored an unencrypted credential")
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.ReadFile(filepath.Join(directory, "panel.db"))
	if err != nil || bytes.Contains(file, []byte(secret)) {
		t.Fatal("credential appeared in the database file")
	}
	database, err = Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := database.InterruptUnfinished(ctx); err != nil {
		t.Fatal(err)
	}
	state, err := database.State(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Nodes) != 1 || state.Nodes[0].Password != secret || state.Nodes[0].AppliedRevision != "previous-revision" || state.Nodes[0].Status != "interrupted" {
		t.Fatal("restarted state lost credentials, revision, or interrupted status")
	}
	if len(state.Relays) != 1 || state.Relays[0].ID != relay.ID || state.Relays[0].Password != secret || !state.Relays[0].Enabled {
		t.Fatal("restart deleted or modified an unconfirmed deletion's original relay")
	}
	pending, err := database.Applied(ctx, node.ID)
	if err != nil || pending.PendingDeleteRelayID != relay.ID || pending.Revision != applied.Revision || pending.Previous == nil || pending.Previous.Revision != applied.Previous.Revision {
		t.Fatal("restart cleared the durable deletion intent or confirmed snapshots")
	}
	if len(state.Jobs) != 3 {
		t.Fatal("restart lost unfinished jobs")
	}
	for _, job := range state.Jobs {
		if job.Status != "interrupted" || job.FinishedAt == nil {
			t.Fatal("unfinished task was not marked interrupted")
		}
		if job.ID == "deleting-job" && (job.RelayID != relay.ID || job.Revision != "") {
			t.Fatal("interrupted deletion lost its persisted relay target or claimed success")
		}
	}
	if state.Upstreams == nil || state.Relays == nil || state.Probes == nil || state.Subscriptions == nil {
		t.Fatal("empty state collections must serialize as arrays")
	}
}

func TestSingletonSetupAndHashedSessions(t *testing.T) {
	database, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	token, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	account := Account{Username: "owner", Hash: token}
	session := Session{Hash: auth.TokenHash(token), ExpiresAt: time.Now().Add(time.Hour)}
	var wait sync.WaitGroup
	results := make(chan error, 4)
	for index := 0; index < 4; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			results <- database.Setup(context.Background(), account, session)
		}()
	}
	wait.Wait()
	close(results)
	success := 0
	for err := range results {
		if err == nil {
			success++
		} else if !errors.Is(err, ErrInitialized) {
			t.Fatal(err)
		}
	}
	if success != 1 {
		t.Fatalf("setup succeeded %d times", success)
	}
	loaded, err := database.Account(context.Background())
	if err != nil || loaded.Username != account.Username || loaded.Hash != account.Hash {
		t.Fatal("account did not round trip")
	}
	valid, err := database.HasSession(context.Background(), session.Hash, time.Now())
	if err != nil || !valid {
		t.Fatal("hashed session was not authenticated")
	}
	valid, err = database.HasSession(context.Background(), session.Hash, time.Now().Add(2*time.Hour))
	if err != nil || valid {
		t.Fatal("expired session was accepted")
	}
	var stored []byte
	if err := database.db.QueryRow("SELECT hash FROM sessions").Scan(&stored); err != nil || bytes.Equal(stored, []byte(token)) {
		t.Fatal("raw session token was persisted")
	}
	if err := database.DeleteSession(context.Background(), session.Hash); err != nil {
		t.Fatal(err)
	}
	valid, _ = database.HasSession(context.Background(), session.Hash, time.Now())
	if valid {
		t.Fatal("revoked session remained usable")
	}
}

func TestWrongKeyFailsAndForeignKeysProtectReferences(t *testing.T) {
	ctx := context.Background()
	directory := t.TempDir()
	database, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := database.Commit(ctx, Changes{
		Nodes: []model.Node{{ID: "node"}}, Upstreams: []model.Upstream{{ID: "upstream"}},
		Relays:   []model.Relay{{ID: "relay", NodeID: "node", UpstreamID: "upstream"}},
		Settings: &model.Settings{CoreVersion: model.DefaultCoreVersion},
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Commit(ctx, Changes{DeleteNodes: []string{"node"}}); err == nil {
		t.Fatal("SQLite allowed deleting a referenced node")
	}
	if err := database.Commit(ctx, Changes{DeleteUpstreams: []string{"upstream"}}); err == nil {
		t.Fatal("SQLite allowed deleting a referenced upstream")
	}
	database.Close()
	otherKey, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, _ := base64.RawURLEncoding.DecodeString(otherKey)
	t.Setenv(credentials.MasterKeyEnv, base64.StdEncoding.EncodeToString(keyBytes))
	database, err = Open(directory)
	if err != nil {
		return
	}
	defer database.Close()
	if _, err := database.Settings(ctx); err == nil {
		t.Fatal("wrong key decrypted existing settings")
	}
}
