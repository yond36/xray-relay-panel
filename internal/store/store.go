package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"xrayrelay/internal/credentials"
	"xrayrelay/internal/model"
)

var (
	ErrInitialized        = errors.New("panel is already initialized")
	ErrNotInitialized     = errors.New("panel is not initialized")
	ErrRegistrationClosed = errors.New("registration is closed")
	ErrUsernameTaken      = errors.New("username is already in use")
)

// Account data is encrypted in addition to using a one-way password hash.
// Use Public when returning identities over HTTP.
type Account struct {
	ID                string `json:"id"`
	Username          string `json:"username"`
	Role              string `json:"role"`
	Hash              string `json:"hash"`
	SubscriptionToken string `json:"subscription_token"`
}

func (a Account) Public() model.User {
	return model.User{ID: a.ID, Username: a.Username, Role: a.Role}
}

type Session struct {
	AccountID string
	Hash      []byte
	ExpiresAt time.Time
}

// Applied records the last two confirmed deployments. PendingDeleteRelayID is
// persisted before a remote deletion so an interrupted or uncommitted result
// cannot use stale snapshots to roll back until an explicit apply or retry.
type Applied struct {
	ConfigHash           string   `json:"config_hash,omitempty"`
	Revision             string   `json:"revision"`
	RelayIDs             []string `json:"relay_ids"`
	UpstreamIDs          []string `json:"upstream_ids"`
	Previous             *Applied `json:"previous,omitempty"`
	PendingDeleteRelayID string   `json:"pending_delete_relay_id,omitempty"`
}

func (a Applied) ReferencesRelay(id string) bool {
	if a.PendingDeleteRelayID == id && id != "" {
		return true
	}
	for _, candidate := range a.RelayIDs {
		if candidate == id {
			return true
		}
	}
	return a.Previous != nil && a.Previous.ReferencesRelay(id)
}

func (a Applied) ReferencesUpstream(id string) bool {
	for _, candidate := range a.UpstreamIDs {
		if candidate == id {
			return true
		}
	}
	return a.Previous != nil && a.Previous.ReferencesUpstream(id)
}

type Changes struct {
	Nodes               []model.Node
	Upstreams           []model.Upstream
	Relays              []model.Relay
	Jobs                []model.Job
	Probes              []model.ProbeResult
	Subscriptions       []model.Subscription
	Settings            *model.Settings
	Applied             map[string]Applied
	DeleteNodes         []string
	DeleteUpstreams     []string
	DeleteRelays        []string
	DeleteSubscriptions []string
}

type Store struct {
	db     *sql.DB
	cipher *credentials.Cipher
}

func Open(dataDir string) (*Store, error) {
	if strings.TrimSpace(dataDir) == "" {
		return nil, errors.New("data directory is required")
	}
	absolute, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(absolute, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	if err := os.Chmod(absolute, 0700); err != nil {
		return nil, fmt.Errorf("protect data directory: %w", err)
	}
	crypt, err := credentials.Load(absolute)
	if err != nil {
		return nil, err
	}
	dbPath := filepath.Join(absolute, "panel.db")
	if info, err := os.Lstat(dbPath); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("database must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	uriPath := filepath.ToSlash(dbPath)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	dsn := (&url.URL{Scheme: "file", Path: uriPath}).String() + "?_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// One connection also ensures pragmas apply consistently and transactions
	// never contend with another connection owned by the same process.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	s := &Store{db: db, cipher: crypt}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		db.Close()
		return nil, fmt.Errorf("protect database: %w", err)
	}
	if err := s.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	// Fail closed with a wrong master key, including when the database only
	// contains an account and no managed nodes yet.
	if _, err := s.Account(ctx); err != nil && !errors.Is(err, sql.ErrNoRows) {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 2 {
		return errors.New("database schema is newer than this panel")
	}
	if version == 0 {
		statements := []string{
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
		}
		for _, statement := range statements {
			if _, err := tx.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("migrate SQLite database: %w", err)
			}
		}
	}
	if version < 2 {
		if err := s.migrateV2(ctx, tx); err != nil {
			return fmt.Errorf("migrate multi-user database: %w", err)
		}
	}
	return tx.Commit()
}

func (s *Store) encode(table, id string, value any) ([]byte, error) {
	plaintext, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	defer clear(plaintext)
	return s.cipher.Seal(plaintext, table+":"+id)
}

func (s *Store) decode(table, id string, data []byte, value any) error {
	plaintext, err := s.cipher.Open(data, table+":"+id)
	if err != nil {
		return fmt.Errorf("read %s record: %w", table, err)
	}
	defer clear(plaintext)
	if err := json.Unmarshal(plaintext, value); err != nil {
		return fmt.Errorf("decode %s record: %w", table, err)
	}
	return nil
}

func (s *Store) Initialized(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM accounts)").Scan(&exists)
	return exists, err
}

func insertSession(ctx context.Context, tx *sql.Tx, session Session) error {
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at<=?", now); err != nil {
		return err
	}
	if session.AccountID == "" {
		return errors.New("session account is required")
	}
	if _, err := tx.ExecContext(ctx, "INSERT INTO sessions(hash,account_id,expires_at,created_at) VALUES(?,?,?,?)", session.Hash, session.AccountID, session.ExpiresAt.Unix(), now); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, "DELETE FROM sessions WHERE account_id=? AND hash NOT IN (SELECT hash FROM sessions WHERE account_id=? ORDER BY created_at DESC,rowid DESC LIMIT 16)", session.AccountID, session.AccountID)
	return err
}

func (s *Store) AddSession(ctx context.Context, session Session) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := insertSession(ctx, tx, session); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) HasSession(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	_, err := s.SessionAccount(ctx, hash, now)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (s *Store) DeleteSession(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE hash=?", hash)
	return err
}

func readRecords[T any](ctx context.Context, s *Store, query, table string) ([]T, error) {
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	values := make([]T, 0)
	for rows.Next() {
		var id string
		var data []byte
		if err := rows.Scan(&id, &data); err != nil {
			return nil, err
		}
		var value T
		if err := s.decode(table, id, data, &value); err != nil {
			return nil, err
		}
		values = append(values, value)
	}
	return values, rows.Err()
}

func (s *Store) State(ctx context.Context) (model.State, error) {
	state := model.State{}
	var err error
	if state.Nodes, err = readRecords[model.Node](ctx, s, "SELECT id,data FROM nodes ORDER BY rowid", "nodes"); err != nil {
		return state, err
	}
	if state.Upstreams, err = readRecords[model.Upstream](ctx, s, "SELECT id,data FROM upstreams ORDER BY rowid", "upstreams"); err != nil {
		return state, err
	}
	if state.Relays, err = readRecords[model.Relay](ctx, s, "SELECT id,data FROM relays ORDER BY rowid", "relays"); err != nil {
		return state, err
	}
	if state.Jobs, err = readRecords[model.Job](ctx, s, "SELECT id,data FROM jobs ORDER BY created_at DESC,rowid DESC LIMIT 200", "jobs"); err != nil {
		return state, err
	}
	if state.Probes, err = readRecords[model.ProbeResult](ctx, s, "SELECT id,data FROM probes ORDER BY checked_at DESC,rowid DESC LIMIT 500", "probes"); err != nil {
		return state, err
	}
	if state.Subscriptions, err = readRecords[model.Subscription](ctx, s, "SELECT id,data FROM subscriptions ORDER BY rowid", "subscriptions"); err != nil {
		return state, err
	}
	state.Settings, err = s.Settings(ctx)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return state, err
}

func (s *Store) Settings(ctx context.Context) (model.Settings, error) {
	var value model.Settings
	var data []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM settings WHERE id=1").Scan(&data); err != nil {
		return value, err
	}
	if err := s.decode("settings", "1", data, &value); err != nil {
		return model.Settings{}, err
	}
	return value, nil
}

func (s *Store) Applied(ctx context.Context, nodeID string) (Applied, error) {
	var value Applied
	var data []byte
	if err := s.db.QueryRowContext(ctx, "SELECT data FROM applied WHERE node_id=?", nodeID).Scan(&data); err != nil {
		return value, err
	}
	if err := s.decode("applied", nodeID, data, &value); err != nil {
		return Applied{}, err
	}
	return value, nil
}

func (s *Store) Commit(ctx context.Context, change Changes) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	put := func(table, id, query string, value any, extra ...any) error {
		data, err := s.encode(table, id, value)
		if err != nil {
			return err
		}
		args := []any{id}
		args = append(args, extra...)
		args = append(args, data)
		result, err := tx.ExecContext(ctx, query, args...)
		if err != nil {
			return err
		}
		if count, err := result.RowsAffected(); err != nil {
			return err
		} else if count == 0 {
			return errors.New("resource ownership cannot change")
		}
		return nil
	}
	for _, value := range change.Nodes {
		if err := put("nodes", value.ID, "INSERT INTO nodes(id,owner_id,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE nodes.owner_id=excluded.owner_id", value, value.OwnerID); err != nil {
			return err
		}
	}
	for _, value := range change.Upstreams {
		if err := put("upstreams", value.ID, "INSERT INTO upstreams(id,owner_id,source_id,data) VALUES(?,?,?,?) ON CONFLICT(id) DO UPDATE SET source_id=excluded.source_id,data=excluded.data WHERE upstreams.owner_id=excluded.owner_id", value, value.OwnerID, value.SourceID); err != nil {
			return err
		}
	}
	for _, value := range change.Relays {
		if err := put("relays", value.ID, "INSERT INTO relays(id,owner_id,node_id,upstream_id,data) VALUES(?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET node_id=excluded.node_id,upstream_id=excluded.upstream_id,data=excluded.data WHERE relays.owner_id=excluded.owner_id", value, value.OwnerID, value.NodeID, value.UpstreamID); err != nil {
			return err
		}
	}
	for _, value := range change.Jobs {
		if err := put("jobs", value.ID, "INSERT INTO jobs(id,owner_id,node_id,status,created_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET status=excluded.status,data=excluded.data WHERE jobs.owner_id=excluded.owner_id", value, value.OwnerID, value.NodeID, value.Status, value.CreatedAt.UnixNano()); err != nil {
			return err
		}
	}
	for _, value := range change.Probes {
		if err := put("probes", value.ID, "INSERT INTO probes(id,owner_id,node_id,upstream_id,checked_at,data) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET checked_at=excluded.checked_at,data=excluded.data WHERE probes.owner_id=excluded.owner_id", value, value.OwnerID, value.NodeID, value.UpstreamID, value.CheckedAt.UnixNano()); err != nil {
			return err
		}
	}
	for _, value := range change.Subscriptions {
		if err := put("subscriptions", value.ID, "INSERT INTO subscriptions(id,owner_id,data) VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data WHERE subscriptions.owner_id=excluded.owner_id", value, value.OwnerID); err != nil {
			return err
		}
	}
	if change.Settings != nil {
		if err := put("settings", "1", "INSERT INTO settings(id,data) VALUES(?,?) ON CONFLICT(id) DO UPDATE SET data=excluded.data", change.Settings); err != nil {
			return err
		}
	}
	for nodeID, value := range change.Applied {
		if err := put("applied", nodeID, "INSERT INTO applied(node_id,data) VALUES(?,?) ON CONFLICT(node_id) DO UPDATE SET data=excluded.data", value); err != nil {
			return err
		}
	}
	// Delete references before their parents. SQLite independently enforces
	// referential integrity even if a caller misses a guard.
	for _, deletion := range []struct {
		table string
		ids   []string
	}{{"relays", change.DeleteRelays}, {"upstreams", change.DeleteUpstreams}, {"nodes", change.DeleteNodes}, {"subscriptions", change.DeleteSubscriptions}} {
		for _, id := range deletion.ids {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+deletion.table+" WHERE id=?", id); err != nil {
				return err
			}
		}
	}
	// Keep finite audit history, while never pruning unfinished work.
	if len(change.Jobs) != 0 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM jobs WHERE status NOT IN ('queued','running') AND id NOT IN (SELECT id FROM jobs ORDER BY created_at DESC,rowid DESC LIMIT 1000)"); err != nil {
			return err
		}
	}
	if len(change.Probes) != 0 {
		if _, err := tx.ExecContext(ctx, "DELETE FROM probes WHERE id NOT IN (SELECT id FROM probes ORDER BY checked_at DESC,rowid DESC LIMIT 2000)"); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// InterruptUnfinished never replays remote side effects after a restart. The
// deployment may already have reached the node, so the revision is preserved
// and the UI requires an explicit subsequent operation.
func (s *Store) InterruptUnfinished(ctx context.Context) error {
	jobs, err := readRecords[model.Job](ctx, s, "SELECT id,data FROM jobs WHERE status IN ('queued','running')", "jobs")
	if err != nil {
		return err
	}
	state, err := s.State(ctx)
	if err != nil {
		return err
	}
	changes := Changes{Jobs: jobs}
	interruptedNodes := make(map[string]bool)
	now := time.Now().UTC()
	for index := range changes.Jobs {
		changes.Jobs[index].Status = "interrupted"
		changes.Jobs[index].Message = "任务因服务关闭或重启中断，请核对节点状态后重新执行"
		changes.Jobs[index].Error = changes.Jobs[index].Message
		changes.Jobs[index].FinishedAt = &now
		interruptedNodes[changes.Jobs[index].NodeID] = true
	}
	for _, node := range state.Nodes {
		if interruptedNodes[node.ID] {
			node.Status = "interrupted"
			node.LastError = "上次任务中断，远端状态尚未确认"
			node.UpdatedAt = now
			changes.Nodes = append(changes.Nodes, node)
		}
	}
	if len(jobs) == 0 {
		return nil
	}
	return s.Commit(ctx, changes)
}
