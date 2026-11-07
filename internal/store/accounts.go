package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"xrayrelay/internal/auth"
	"xrayrelay/internal/model"
)

func prepareAccount(account *Account) error {
	var err error
	account.Username, err = auth.CanonicalUsername(account.Username)
	if err != nil {
		return err
	}
	if account.Role == "" {
		account.Role = model.RoleUser
	}
	if account.Role != model.RoleAdmin && account.Role != model.RoleUser {
		return errors.New("account role must be admin or user")
	}
	if account.ID == "" {
		account.ID, err = auth.Token()
		if err != nil {
			return err
		}
	}
	if account.SubscriptionToken == "" {
		account.SubscriptionToken, err = auth.Token()
	}
	return err
}

func (s *Store) insertAccount(ctx context.Context, tx *sql.Tx, account Account) error {
	var exists bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accounts WHERE username=?)", account.Username).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return ErrUsernameTaken
	}
	data, err := s.encode("accounts", account.ID, account)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO accounts(id,username,subscription_hash,data) VALUES(?,?,?,?)", account.ID, account.Username, auth.TokenHash(account.SubscriptionToken), data)
	return err
}

// Account returns the oldest account for compatibility with local callers.
// HTTP authentication always uses the explicit username or bound session.
func (s *Store) Account(ctx context.Context) (Account, error) {
	return s.readAccount(ctx, "SELECT id,data FROM accounts ORDER BY rowid LIMIT 1")
}

func (s *Store) AccountByID(ctx context.Context, id string) (Account, error) {
	return s.readAccount(ctx, "SELECT id,data FROM accounts WHERE id=?", id)
}

func (s *Store) AccountByUsername(ctx context.Context, username string) (Account, error) {
	name, err := auth.CanonicalUsername(username)
	if err != nil {
		return Account{}, sql.ErrNoRows
	}
	return s.readAccount(ctx, "SELECT id,data FROM accounts WHERE username=?", name)
}

func (s *Store) SessionAccount(ctx context.Context, hash []byte, now time.Time) (Account, error) {
	return s.readAccount(ctx, "SELECT a.id,a.data FROM accounts a JOIN sessions s ON s.account_id=a.id WHERE s.hash=? AND s.expires_at>?", hash, now.Unix())
}

func (s *Store) SubscriptionAccount(ctx context.Context, token string) (Account, error) {
	return s.readAccount(ctx, "SELECT id,data FROM accounts WHERE subscription_hash=?", auth.TokenHash(token))
}

func (s *Store) readAccount(ctx context.Context, query string, args ...any) (Account, error) {
	var id string
	var data []byte
	if err := s.db.QueryRowContext(ctx, query, args...).Scan(&id, &data); err != nil {
		return Account{}, err
	}
	var account Account
	if err := s.decode("accounts", id, data, &account); err != nil {
		return Account{}, err
	}
	if account.ID != id || account.Role != model.RoleAdmin && account.Role != model.RoleUser {
		return Account{}, errors.New("invalid persisted account identity")
	}
	return account, nil
}

func (s *Store) Users(ctx context.Context) ([]model.User, error) {
	accounts, err := readRecords[Account](ctx, s, "SELECT id,data FROM accounts ORDER BY username", "accounts")
	if err != nil {
		return nil, err
	}
	users := make([]model.User, 0, len(accounts))
	for _, account := range accounts {
		users = append(users, account.Public())
	}
	return users, nil
}

func (s *Store) Setup(ctx context.Context, account Account, session Session) error {
	account.Role = model.RoleAdmin
	if err := prepareAccount(&account); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var initialized bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accounts)").Scan(&initialized); err != nil {
		return err
	}
	if initialized {
		return ErrInitialized
	}
	// An uninitialized v1 panel may already have a generated legacy token.
	var data []byte
	err = tx.QueryRowContext(ctx, "SELECT data FROM settings WHERE id=1").Scan(&data)
	if err == nil {
		var settings model.Settings
		if err := s.decode("settings", "1", data, &settings); err != nil {
			return err
		}
		if settings.SubscriptionToken != "" {
			account.SubscriptionToken, settings.SubscriptionToken = settings.SubscriptionToken, ""
			data, err = s.encode("settings", "1", settings)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE settings SET data=? WHERE id=1", data); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err := s.insertAccount(ctx, tx, account); err != nil {
		return err
	}
	session.AccountID = account.ID
	if err := insertSession(ctx, tx, session); err != nil {
		return err
	}
	return tx.Commit()
}

// CreateAccount rechecks initialization and the registration switch inside the
// same transaction that inserts the account and session. Password hashing may
// run concurrently with an administrator closing registration.
func (s *Store) CreateAccount(ctx context.Context, account Account, session *Session, registration bool) error {
	if registration {
		account.Role = model.RoleUser
	}
	if err := prepareAccount(&account); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var initialized bool
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accounts)").Scan(&initialized); err != nil {
		return err
	}
	if !initialized {
		return ErrNotInitialized
	}
	if registration {
		var data []byte
		if err := tx.QueryRowContext(ctx, "SELECT data FROM settings WHERE id=1").Scan(&data); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrRegistrationClosed
			}
			return err
		}
		var settings model.Settings
		if err := s.decode("settings", "1", data, &settings); err != nil {
			return err
		}
		if !settings.RegistrationOpen {
			return ErrRegistrationClosed
		}
	}
	if err := s.insertAccount(ctx, tx, account); err != nil {
		return err
	}
	if session != nil {
		bound := *session
		bound.AccountID = account.ID
		if err := insertSession(ctx, tx, bound); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) RotateSubscriptionToken(ctx context.Context, accountID, token string) error {
	if !auth.ValidToken(token) {
		return errors.New("invalid subscription token")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var data []byte
	if err := tx.QueryRowContext(ctx, "SELECT data FROM accounts WHERE id=?", accountID).Scan(&data); err != nil {
		return err
	}
	var account Account
	if err := s.decode("accounts", accountID, data, &account); err != nil {
		return err
	}
	account.SubscriptionToken = token
	data, err = s.encode("accounts", accountID, account)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, "UPDATE accounts SET subscription_hash=?,data=? WHERE id=?", auth.TokenHash(token), data, accountID); err != nil {
		return err
	}
	return tx.Commit()
}
