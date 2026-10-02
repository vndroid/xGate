// Package store 是白名单的唯一事实来源（SQLite），内核 set 只是它的投影。
// 每次变更和对应的审计记录写在同一个事务里。
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

type Entry struct {
	Prefix    netip.Prefix
	Comment   string
	CreatedAt time.Time
	UpdatedAt time.Time
	ExpiresAt time.Time // 零值表示永久
	CreatedBy string
}

func (e Entry) Expired(now time.Time) bool {
	return !e.ExpiresAt.IsZero() && !e.ExpiresAt.After(now)
}

type AuditRecord struct {
	ID     int64     `json:"id"`
	Time   time.Time `json:"time"`
	Actor  string    `json:"actor"`
	Action string    `json:"action"` // add / update / delete / expire
	CIDR   string    `json:"cidr"`
	Detail string    `json:"detail,omitempty"`
}

type Store struct {
	db *sql.DB
}

const schema = `
CREATE TABLE IF NOT EXISTS allowlist (
	cidr       TEXT PRIMARY KEY,
	comment    TEXT NOT NULL DEFAULT '',
	created_at INTEGER NOT NULL,
	updated_at INTEGER NOT NULL,
	expires_at INTEGER,
	created_by TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS allowlist_expires ON allowlist(expires_at) WHERE expires_at IS NOT NULL;
CREATE TABLE IF NOT EXISTS audit (
	id     INTEGER PRIMARY KEY AUTOINCREMENT,
	ts     INTEGER NOT NULL,
	actor  TEXT NOT NULL,
	action TEXT NOT NULL,
	cidr   TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT ''
);
`

func Open(path string) (*Store, error) {
	if path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			return nil, err
		}
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// 单连接即可满足控制面的写入量，也避免 :memory: 下每个连接各自一个库。
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func ms(t time.Time) int64 { return t.UnixMilli() }

func nullableMS(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UnixMilli()
}

func fromMS(v int64) time.Time { return time.UnixMilli(v).UTC() }

// Upsert 新增或更新一条记录。返回 true 表示新增。
func (s *Store) Upsert(ctx context.Context, e Entry, actor string, now time.Time) (Entry, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, false, err
	}
	defer func() { _ = tx.Rollback() }()

	old, err := get(ctx, tx, e.Prefix)
	created := errors.Is(err, sql.ErrNoRows)
	if err != nil && !created {
		return Entry{}, false, err
	}
	e.UpdatedAt = now.UTC()
	if created {
		e.CreatedAt, e.CreatedBy = now.UTC(), actor
	} else {
		e.CreatedAt, e.CreatedBy = old.CreatedAt, old.CreatedBy
	}
	_, err = tx.ExecContext(ctx, `
		INSERT INTO allowlist (cidr, comment, created_at, updated_at, expires_at, created_by)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(cidr) DO UPDATE SET comment = excluded.comment, updated_at = excluded.updated_at, expires_at = excluded.expires_at`,
		e.Prefix.String(), e.Comment, ms(e.CreatedAt), ms(e.UpdatedAt), nullableMS(e.ExpiresAt), e.CreatedBy)
	if err != nil {
		return Entry{}, false, err
	}
	action := "update"
	if created {
		action = "add"
	}
	if err := audit(ctx, tx, now, actor, action, e.Prefix, describe(e)); err != nil {
		return Entry{}, false, err
	}
	return e, created, tx.Commit()
}

// Delete 删除一条记录。不存在时返回 ok=false。
func (s *Store) Delete(ctx context.Context, p netip.Prefix, actor, detail string, now time.Time) (Entry, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Entry{}, false, err
	}
	defer func() { _ = tx.Rollback() }()
	old, err := get(ctx, tx, p)
	if errors.Is(err, sql.ErrNoRows) {
		return Entry{}, false, nil
	} else if err != nil {
		return Entry{}, false, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM allowlist WHERE cidr = ?`, p.String()); err != nil {
		return Entry{}, false, err
	}
	if err := audit(ctx, tx, now, actor, "delete", p, detail); err != nil {
		return Entry{}, false, err
	}
	return old, true, tx.Commit()
}

// Active 返回所有在 now 时刻仍有效的记录。
func (s *Store) Active(ctx context.Context, now time.Time) ([]Entry, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT cidr, comment, created_at, updated_at, expires_at, created_by FROM allowlist
		WHERE expires_at IS NULL OR expires_at > ? ORDER BY cidr`, ms(now))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// PurgeExpired 删除已过期的记录并写审计，返回被删除的记录。
func (s *Store) PurgeExpired(ctx context.Context, now time.Time) ([]Entry, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT cidr, comment, created_at, updated_at, expires_at, created_by FROM allowlist
		WHERE expires_at IS NOT NULL AND expires_at <= ?`, ms(now))
	if err != nil {
		return nil, err
	}
	var expired []Entry
	for rows.Next() {
		e, err := scan(rows)
		if err != nil {
			_ = rows.Close()
			return nil, err
		}
		expired = append(expired, e)
	}
	_ = rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, e := range expired {
		if _, err := tx.ExecContext(ctx, `DELETE FROM allowlist WHERE cidr = ?`, e.Prefix.String()); err != nil {
			return nil, err
		}
		if err := audit(ctx, tx, now, "system", "expire", e.Prefix, describe(e)); err != nil {
			return nil, err
		}
	}
	return expired, tx.Commit()
}

// NextExpiry 返回最早的过期时间；没有带 TTL 的记录时 ok=false。
func (s *Store) NextExpiry(ctx context.Context) (time.Time, bool, error) {
	var v sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT MIN(expires_at) FROM allowlist WHERE expires_at IS NOT NULL`).Scan(&v)
	if err != nil || !v.Valid {
		return time.Time{}, false, err
	}
	return fromMS(v.Int64), true, nil
}

// Audit 按时间倒序返回最近的审计记录。
func (s *Store) Audit(ctx context.Context, limit int) ([]AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, ts, actor, action, cidr, detail FROM audit ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []AuditRecord
	for rows.Next() {
		var r AuditRecord
		var ts int64
		if err := rows.Scan(&r.ID, &ts, &r.Actor, &r.Action, &r.CIDR, &r.Detail); err != nil {
			return nil, err
		}
		r.Time = fromMS(ts)
		out = append(out, r)
	}
	return out, rows.Err()
}

type queryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

type scanner interface{ Scan(dest ...any) error }

func get(ctx context.Context, q queryer, p netip.Prefix) (Entry, error) {
	return scan(q.QueryRowContext(ctx, `
		SELECT cidr, comment, created_at, updated_at, expires_at, created_by FROM allowlist WHERE cidr = ?`, p.String()))
}

func scan(r scanner) (Entry, error) {
	var (
		e                Entry
		cidr             string
		created, updated int64
		expires          sql.NullInt64
	)
	if err := r.Scan(&cidr, &e.Comment, &created, &updated, &expires, &e.CreatedBy); err != nil {
		return Entry{}, err
	}
	p, err := netip.ParsePrefix(cidr)
	if err != nil {
		return Entry{}, fmt.Errorf("corrupt cidr %q in database: %w", cidr, err)
	}
	e.Prefix, e.CreatedAt, e.UpdatedAt = p, fromMS(created), fromMS(updated)
	if expires.Valid {
		e.ExpiresAt = fromMS(expires.Int64)
	}
	return e, nil
}

func audit(ctx context.Context, tx *sql.Tx, now time.Time, actor, action string, p netip.Prefix, detail string) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO audit (ts, actor, action, cidr, detail) VALUES (?, ?, ?, ?, ?)`,
		ms(now), actor, action, p.String(), detail)
	return err
}

func describe(e Entry) string {
	d := fmt.Sprintf("comment=%q", e.Comment)
	if !e.ExpiresAt.IsZero() {
		d += " expires_at=" + e.ExpiresAt.UTC().Format(time.RFC3339)
	}
	return d
}
