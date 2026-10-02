// Package reconcile 把 SQLite 中的白名单同步到内核：启动时完整同步，
// 之后定期对账，并在最早一条 TTL 到期时清理过期记录。
package reconcile

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/vndroid/xGate/internal/cidr"
	"github.com/vndroid/xGate/internal/nft"
	"github.com/vndroid/xGate/internal/store"
)

type Status struct {
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	LastError   string    `json:"last_error,omitempty"`
	Entries     int       `json:"entries"`  // SQLite 中有效的记录数
	Elements    int       `json:"elements"` // 写入内核的区间数（展开重叠之后）
}

func (s Status) OK() bool { return s.LastError == "" && !s.LastSuccess.IsZero() }

type Reconciler struct {
	store    *store.Store
	nft      nft.Executor
	ruleset  nft.Ruleset
	interval time.Duration
	log      *slog.Logger

	// Now 可在测试中替换。
	Now func() time.Time

	mu     sync.Mutex // 串行化同步，保证内核状态按顺序收敛
	status Status
	kick   chan struct{}
}

func New(st *store.Store, ex nft.Executor, rs nft.Ruleset, interval time.Duration, log *slog.Logger) *Reconciler {
	return &Reconciler{
		store: st, nft: ex, ruleset: rs, interval: interval, log: log,
		Now:  time.Now,
		kick: make(chan struct{}, 1),
	}
}

// Script 渲染当前应写入内核的完整脚本。
func (r *Reconciler) Script(ctx context.Context) (string, int, int, error) {
	now := r.Now()
	entries, err := r.store.Active(ctx, now)
	if err != nil {
		return "", 0, 0, err
	}
	items := make([]cidr.Item, len(entries))
	for i, e := range entries {
		items[i] = cidr.Item{Prefix: e.Prefix, Expires: e.ExpiresAt}
	}
	flat := cidr.Flatten(items)
	return r.ruleset.Render(flat, now), len(entries), len(flat), nil
}

// Sync 用一个 nft 事务把内核状态整体替换为 SQLite 的投影。
func (r *Reconciler) Sync(ctx context.Context) (Status, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.status.LastAttempt = r.Now()
	script, entries, elems, err := r.Script(ctx)
	if err == nil {
		err = r.nft.Apply(ctx, script)
	}
	if err != nil {
		r.status.LastError = err.Error()
		return r.status, err
	}
	r.status.LastSuccess, r.status.LastError = r.status.LastAttempt, ""
	r.status.Entries, r.status.Elements = entries, elems
	return r.status, nil
}

func (r *Reconciler) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status
}

// Kick 请求后台循环尽快执行一次对账（非阻塞）。
func (r *Reconciler) Kick() {
	select {
	case r.kick <- struct{}{}:
	default:
	}
}

// Run 运行对账循环直到 ctx 结束。
func (r *Reconciler) Run(ctx context.Context) {
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-r.kick:
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		timer.Reset(r.tick(ctx))
	}
}

// tick 清理过期记录并同步，返回距下一次运行的等待时间。
func (r *Reconciler) tick(ctx context.Context) time.Duration {
	purged, err := r.store.PurgeExpired(ctx, r.Now())
	if err != nil {
		r.log.Error("purge expired entries", "err", err)
	}
	for _, e := range purged {
		r.log.Info("allowlist entry expired", "cidr", e.Prefix.String(), "comment", e.Comment)
	}
	if _, err := r.Sync(ctx); err != nil {
		r.log.Error("sync to kernel failed", "err", err)
	}
	wait := r.interval
	if next, ok, err := r.store.NextExpiry(ctx); err == nil && ok {
		if d := next.Sub(r.Now()); d < wait {
			wait = max(d, 10*time.Millisecond)
		}
	}
	return wait
}
