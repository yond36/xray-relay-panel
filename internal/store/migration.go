package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"xrayrelay/internal/model"
)

// migrateV2 runs inside migrate's transaction. AAD includes the table and ID,
// so the old singleton account must be opened with accounts:1 and sealed again
// with its new stable ID. Applied snapshots retain their original IDs and bytes.
func (s *Store) migrateV2(ctx context.Context, tx *sql.Tx) error {
	var legacy Account
	var data []byte
	err := tx.QueryRowContext(ctx, "SELECT data FROM accounts WHERE id=1").Scan(&data)
	hasAccount := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if hasAccount {
		if err := s.decode("accounts", "1", data, &legacy); err != nil {
			return err
		}
		legacy.Role = model.RoleAdmin
	}
	var settings model.Settings
	err = tx.QueryRowContext(ctx, "SELECT data FROM settings WHERE id=1").Scan(&data)
	hasSettings := err == nil
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if hasSettings {
		if err := s.decode("settings", "1", data, &settings); err != nil {
			return err
		}
		settings.RegistrationOpen = false
		legacy.SubscriptionToken = settings.SubscriptionToken
	}
	if hasAccount {
		if err := prepareAccount(&legacy); err != nil {
			return err
		}
	}
	for _, statement := range []string{
		`ALTER TABLE accounts RENAME TO accounts_v1`,
		`CREATE TABLE accounts (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, subscription_hash BLOB NOT NULL UNIQUE, data BLOB NOT NULL)`,
		`ALTER TABLE sessions RENAME TO sessions_v1`,
		`CREATE TABLE sessions (hash BLOB PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	if hasAccount {
		if err := s.insertAccount(ctx, tx, legacy); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO sessions(hash,account_id,expires_at,created_at) SELECT hash,?,expires_at,created_at FROM sessions_v1`, legacy.ID); err != nil {
			return err
		}
		if hasSettings {
			settings.SubscriptionToken = ""
			data, err = s.encode("settings", "1", settings)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE settings SET data=? WHERE id=1", data); err != nil {
				return err
			}
		}
	}
	for _, statement := range []string{
		`DROP TABLE sessions_v1`,
		`DROP TABLE accounts_v1`,
		`CREATE INDEX sessions_expiry ON sessions(expires_at)`,
		`CREATE INDEX sessions_account ON sessions(account_id,created_at DESC)`,
	} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	for _, table := range []string{"nodes", "upstreams", "relays", "subscriptions", "jobs", "probes"} {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE "+table+" ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''"); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "CREATE INDEX "+table+"_owner ON "+table+"(owner_id)"); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, "SELECT id,data FROM "+table+" ORDER BY rowid")
		if err != nil {
			return err
		}
		type record struct {
			id   string
			data []byte
		}
		records := make([]record, 0)
		for rows.Next() {
			var item record
			if err := rows.Scan(&item.id, &item.data); err != nil {
				rows.Close()
				return err
			}
			records = append(records, item)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if len(records) > 0 && !hasAccount {
			return errors.New("legacy configuration has no owning administrator")
		}
		for _, item := range records {
			// Keep every old field, including secrets, timestamps and references.
			var value map[string]json.RawMessage
			if err := s.decode(table, item.id, item.data, &value); err != nil {
				return err
			}
			value["owner_id"], err = json.Marshal(legacy.ID)
			if err != nil {
				return err
			}
			encoded, err := s.encode(table, item.id, value)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, "UPDATE "+table+" SET owner_id=?,data=? WHERE id=?", legacy.ID, encoded, item.id); err != nil {
				return err
			}
		}
	}
	_, err = tx.ExecContext(ctx, "PRAGMA user_version=2")
	return err
}
