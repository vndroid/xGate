package reconcile

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vndroid/xGate/internal/config"
	"github.com/vndroid/xGate/internal/nft"
	"github.com/vndroid/xGate/internal/store"
)

type fakeNFT struct {
	mu      sync.Mutex
	scripts []string
	err     error
}

func (f *fakeNFT) Apply(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scripts = append(f.scripts, s)
	return f.err
}

func (f *fakeNFT) last() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.scripts) == 0 {
		return ""
	}
	return f.scripts[len(f.scripts)-1]
}

func setup(t *testing.T) (*Reconciler, *store.Store, *fakeNFT) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	fn := &fakeNFT{}
	rs := nft.Ruleset{Table: "xgate", Forwards: []config.Forward{{Name: "d", ListenPort: 35353, TargetPort: 8080, Protocols: []string{"tcp"}}}}
	r := New(st, fn, rs, time.Hour, slog.New(slog.NewTextHandler(io.Discard, nil)))
	return r, st, fn
}

func TestSyncFlattensOverlaps(t *testing.T) {
	ctx := context.Background()
	r, st, fn := setup(t)
	now := time.Now()
	mustUpsert(t, st, store.Entry{Prefix: netip.MustParsePrefix("10.0.0.0/8")}, "t", now)
	mustUpsert(t, st, store.Entry{Prefix: netip.MustParsePrefix("10.1.0.0/16")}, "t", now)

	s, err := r.Sync(ctx)
	if err != nil || !s.OK() || s.Entries != 2 || s.Elements != 1 {
		t.Fatalf("status = %+v, err = %v", s, err)
	}
	if script := fn.last(); !strings.Contains(script, "10.0.0.0/8\n") || strings.Contains(script, "10.1.0.0/16") {
		t.Errorf("unexpected script:\n%s", script)
	}
}

func TestSyncFailureRecorded(t *testing.T) {
	r, _, fn := setup(t)
	fn.err = errors.New("boom")
	s, err := r.Sync(context.Background())
	if err == nil || s.OK() || s.LastError != "boom" {
		t.Fatalf("status = %+v, err = %v", s, err)
	}
	fn.err = nil
	if s, _ := r.Sync(context.Background()); !s.OK() {
		t.Fatalf("status after recovery = %+v", s)
	}
}

func TestRunExpiresAtDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r, st, fn := setup(t)
	now := time.Now()
	mustUpsert(t, st, store.Entry{Prefix: netip.MustParsePrefix("203.0.113.0/24"), ExpiresAt: now.Add(150 * time.Millisecond)}, "t", now)

	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if recs, _ := st.Audit(ctx, 1); len(recs) == 1 && recs[0].Action == "expire" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if recs, _ := st.Audit(ctx, 1); len(recs) != 1 || recs[0].Action != "expire" {
		t.Fatalf("entry was not expired by the loop: %+v", recs)
	}
	// 过期之后的那次同步不应再包含该网段。
	time.Sleep(50 * time.Millisecond)
	if strings.Contains(fn.last(), "203.0.113.0/24") {
		t.Errorf("expired prefix still rendered:\n%s", fn.last())
	}
	cancel()
	<-done
}

func mustUpsert(t *testing.T, st *store.Store, e store.Entry, actor string, now time.Time) {
	t.Helper()
	if _, _, err := st.Upsert(context.Background(), e, actor, now); err != nil {
		t.Fatal(err)
	}
}
