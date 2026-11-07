package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"testing"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
)

func TestRegistrationTransactionRechecksSwitchAndUsernameUniqueness(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	pending := Account{ID: "candidate", Username: "Candidate", Hash: "prepared-password-hash", Role: model.RoleAdmin}
	if err := s.CreateAccount(ctx, pending, nil, true); !errors.Is(err, ErrNotInitialized) {
		t.Fatal("registration initialized the panel")
	}
	if err := s.Setup(ctx, Account{ID: "admin", Username: "admin", Hash: "admin-hash"}, Session{Hash: auth.TokenHash("admin-session"), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	settings := model.Settings{CoreVersion: model.DefaultCoreVersion}
	if err := s.Commit(ctx, Changes{Settings: &settings}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccount(ctx, pending, nil, true); !errors.Is(err, ErrRegistrationClosed) {
		t.Fatal("registration ignored the closed default")
	}
	settings.RegistrationOpen = true
	if err := s.Commit(ctx, Changes{Settings: &settings}); err != nil {
		t.Fatal(err)
	}

	// The request prepared its password while registration was open. Closing
	// registration commits before its queued insertion can acquire a transaction.
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	settings.RegistrationOpen = false
	data, err := s.encode("settings", "1", settings)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, "UPDATE settings SET data=? WHERE id=1", data); err != nil {
		t.Fatal(err)
	}
	session := Session{Hash: auth.TokenHash("candidate-session"), ExpiresAt: time.Now().Add(time.Hour)}
	started := make(chan struct{})
	result := make(chan error, 1)
	go func() { close(started); result <- s.CreateAccount(ctx, pending, &session, true) }()
	<-started
	select {
	case err := <-result:
		t.Fatalf("account insertion bypassed the active transaction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, ErrRegistrationClosed) {
		t.Fatalf("late registration committed after closure: %v", err)
	}
	if _, err := s.AccountByID(ctx, pending.ID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("denied registration left an account")
	}
	if valid, err := s.HasSession(ctx, session.Hash, time.Now()); err != nil || valid {
		t.Fatal("denied registration left a session")
	}

	settings.RegistrationOpen = true
	if err := s.Commit(ctx, Changes{Settings: &settings}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		go func(i int) {
			account := pending
			account.ID = fmt.Sprintf("candidate-%d", i)
			if i == 1 {
				account.Username = " CANDIDATE "
			}
			result <- s.CreateAccount(ctx, account, nil, true)
		}(i)
	}
	created, conflicts := 0, 0
	for i := 0; i < 2; i++ {
		err := <-result
		if err == nil {
			created++
		} else if errors.Is(err, ErrUsernameTaken) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if created != 1 || conflicts != 1 {
		t.Fatal("canonical username creation was not atomic")
	}
	account, err := s.AccountByUsername(ctx, "candidate")
	if err != nil || account.Role != model.RoleUser {
		t.Fatal("registration accepted an injected administrator role")
	}
	// Administrator creation remains available after registration closes.
	settings.RegistrationOpen = false
	if err := s.Commit(ctx, Changes{Settings: &settings}); err != nil {
		t.Fatal(err)
	}
	if err := s.CreateAccount(ctx, Account{ID: "managed", Username: "managed", Hash: "hash"}, nil, false); err != nil {
		t.Fatal(err)
	}
}

func TestSessionLimitAndTokensAreBoundPerAccount(t *testing.T) {
	ctx := context.Background()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Setup(ctx, Account{ID: "admin", Username: "admin", Hash: "hash"}, Session{Hash: auth.TokenHash("setup"), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"alice", "bob"} {
		if err := s.CreateAccount(ctx, Account{ID: name, Username: name, Hash: "hash"}, nil, false); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			if err := s.AddSession(ctx, Session{AccountID: name, Hash: auth.TokenHash(fmt.Sprintf("%s-%d", name, i)), ExpiresAt: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, name := range []string{"alice", "bob"} {
		var count int
		if err := s.db.QueryRow("SELECT COUNT(*) FROM sessions WHERE account_id=?", name).Scan(&count); err != nil || count != 16 {
			t.Fatalf("%s has %d sessions", name, count)
		}
		if ok, err := s.HasSession(ctx, auth.TokenHash(name+"-0"), time.Now()); err != nil || ok {
			t.Fatal("old per-account session was not evicted")
		}
		account, err := s.SessionAccount(ctx, auth.TokenHash(name+"-19"), time.Now())
		if err != nil || account.ID != name {
			t.Fatal("session resolved to the wrong principal")
		}
	}
	if ok, err := s.HasSession(ctx, auth.TokenHash("setup"), time.Now()); err != nil || !ok {
		t.Fatal("other accounts evicted the administrator session")
	}
	alice, err := s.AccountByID(ctx, "alice")
	if err != nil {
		t.Fatal(err)
	}
	bob, err := s.AccountByID(ctx, "bob")
	if err != nil || alice.SubscriptionToken == bob.SubscriptionToken {
		t.Fatal("accounts share subscription tokens")
	}
	rotated, err := auth.Token()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.RotateSubscriptionToken(ctx, alice.ID, rotated); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubscriptionAccount(ctx, alice.SubscriptionToken); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("rotation left the old subscription token usable")
	}
	if account, err := s.SubscriptionAccount(ctx, rotated); err != nil || account.ID != alice.ID {
		t.Fatal("rotated token is not account-bound")
	}
	if account, err := s.SubscriptionAccount(ctx, bob.SubscriptionToken); err != nil || account.ID != bob.ID {
		t.Fatal("rotating Alice's token changed Bob's token")
	}
	if err := s.AddSession(ctx, Session{Hash: auth.TokenHash("unbound"), ExpiresAt: time.Now().Add(time.Hour)}); err == nil {
		t.Fatal("an unbound session was accepted")
	}
}

func TestCommitRejectsOwnerTransferAtomically(t *testing.T) {
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	node := model.Node{ID: "node", OwnerID: "alice", Name: "Original"}
	if err := s.Commit(ctx, Changes{Nodes: []model.Node{node}}); err != nil {
		t.Fatal(err)
	}
	node.OwnerID, node.Name = "bob", "Transferred"
	if err := s.Commit(ctx, Changes{Nodes: []model.Node{{ID: "new", OwnerID: "bob"}, node}}); err == nil {
		t.Fatal("storage accepted a silent owner transfer")
	}
	state, err := s.State(ctx)
	if err != nil || len(state.Nodes) != 1 || state.Nodes[0].OwnerID != "alice" || state.Nodes[0].Name != "Original" {
		t.Fatal("rejected owner transfer partially committed")
	}
}
