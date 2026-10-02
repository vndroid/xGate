package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "sub", "xgate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestUpsertDeleteAudit(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	p := netip.MustParsePrefix("198.51.100.0/24")

	e, created, err := s.Upsert(ctx, Entry{Prefix: p, Comment: "office"}, "alice", now)
	if err != nil || !created || e.CreatedBy != "alice" {
		t.Fatalf("first upsert: %+v %v %v", e, created, err)
	}
	later := now.Add(time.Minute)
	e, created, err = s.Upsert(ctx, Entry{Prefix: p, Comment: "office2", ExpiresAt: later.Add(time.Hour)}, "bob", later)
	if err != nil || created || e.CreatedBy != "alice" || !e.CreatedAt.Equal(now) {
		t.Fatalf("second upsert: %+v %v %v", e, created, err)
	}

	active, err := s.Active(ctx, later)
	if err != nil || len(active) != 1 || active[0].Comment != "office2" || !active[0].ExpiresAt.Equal(later.Add(time.Hour)) {
		t.Fatalf("active: %+v %v", active, err)
	}

	if _, ok, err := s.Delete(ctx, p, "carol", "", later); err != nil || !ok {
		t.Fatalf("delete: %v %v", ok, err)
	}
	if _, ok, err := s.Delete(ctx, p, "carol", "", later); err != nil || ok {
		t.Fatalf("second delete: %v %v", ok, err)
	}

	recs, err := s.Audit(ctx, 10)
	if err != nil || len(recs) != 3 {
		t.Fatalf("audit: %+v %v", recs, err)
	}
	if recs[0].Action != "delete" || recs[0].Actor != "carol" || recs[2].Action != "add" || recs[1].Action != "update" {
		t.Errorf("unexpected audit order/content: %+v", recs)
	}
}

func TestExpiry(t *testing.T) {
	ctx := context.Background()
	s := open(t)
	now := time.UnixMilli(1_700_000_000_000).UTC()
	mustUpsert(t, s, Entry{Prefix: netip.MustParsePrefix("10.0.0.0/24"), ExpiresAt: now.Add(time.Minute)}, "a", now)
	mustUpsert(t, s, Entry{Prefix: netip.MustParsePrefix("10.0.1.0/24"), ExpiresAt: now.Add(time.Hour)}, "a", now)
	mustUpsert(t, s, Entry{Prefix: netip.MustParsePrefix("2001:db8::/32")}, "a", now)

	next, ok, err := s.NextExpiry(ctx)
	if err != nil || !ok || !next.Equal(now.Add(time.Minute)) {
		t.Fatalf("next expiry = %v %v %v", next, ok, err)
	}

	at := now.Add(2 * time.Minute)
	if active, _ := s.Active(ctx, at); len(active) != 2 {
		t.Fatalf("active after expiry = %+v", active)
	}
	purged, err := s.PurgeExpired(ctx, at)
	if err != nil || len(purged) != 1 || purged[0].Prefix.String() != "10.0.0.0/24" {
		t.Fatalf("purged = %+v %v", purged, err)
	}
	if recs, _ := s.Audit(ctx, 1); recs[0].Action != "expire" || recs[0].Actor != "system" {
		t.Errorf("expire audit = %+v", recs)
	}
}

func mustUpsert(t *testing.T, s *Store, e Entry, actor string, now time.Time) {
	t.Helper()
	if _, _, err := s.Upsert(context.Background(), e, actor, now); err != nil {
		t.Fatal(err)
	}
}
