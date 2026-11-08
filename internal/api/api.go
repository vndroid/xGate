// Package api 提供 xgate 的 HTTP API：白名单增删查、手动对账、审计查询和健康检查。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/vndroid/xGate/internal/cidr"
	"github.com/vndroid/xGate/internal/config"
	"github.com/vndroid/xGate/internal/conntrack"
	"github.com/vndroid/xGate/internal/reconcile"
	"github.com/vndroid/xGate/internal/sockets"
	"github.com/vndroid/xGate/internal/store"
)

type Server struct {
	Store     *store.Store
	Rec       *reconcile.Reconciler
	Killer    conntrack.Killer
	Sockets   sockets.Destroyer
	Forwards  []config.Forward
	MinPrefix config.MinPrefixLen
	Token     string
	Log       *slog.Logger
	Now       func() time.Time
	// MaxEntries 是白名单有效条目的上限，0 表示不限制。
	MaxEntries int
	// MaxTTL 是 ttl 的上限，0 表示不限制。
	MaxTTL time.Duration

	writeSem    chan struct{} // 串行执行写操作
	writeQueued atomic.Int32  // 正在执行和排队中的写请求数
	maxQueued   int32         // 超过后返回 429，0 表示 defaultMaxQueuedWrites
}

const (
	// defaultMaxQueuedWrites 是同时在执行和排队的写请求上限。
	defaultMaxQueuedWrites = 16
	// maxKillRegions 限制 kill 时需要断开的地址区间数。每个区间都要为每条转发、
	// 每种协议各启动一次 ss / conntrack 子进程。
	maxKillRegions = 256
)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /v1/allowlist", s.auth(s.list))
	s.writeSem = make(chan struct{}, 1)
	mux.Handle("POST /v1/allowlist", s.auth(s.serialized(s.add)))
	mux.Handle("DELETE /v1/allowlist/{cidr...}", s.auth(s.serialized(s.remove)))
	mux.Handle("POST /v1/allowlist:sync", s.auth(s.serialized(s.sync)))
	mux.Handle("GET /v1/audit", s.auth(s.audit))
	mux.Handle("GET /v1/status", s.auth(s.status))

	// 拒绝浏览器发起的跨站写请求（CSRF）。例如通过 ssh -L 把 API 映射到本机后，
	// 任意网页都能用 text/plain 的 simple request 向 localhost 发 POST，而回环监听
	// 默认不要求 token。curl 等非浏览器客户端不带 Origin / Sec-Fetch-Site，不受影响。
	cop := http.NewCrossOriginProtection()
	cop.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErr(w, http.StatusForbidden, "cross-origin browser request rejected")
	}))
	return cop.Handler(mux)
}

// now 返回当前时间。API 输出的所有时间统一为 UTC。
func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

func (s *Server) auth(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.Token != "" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(s.Token)) != 1 {
				writeErr(w, http.StatusUnauthorized, "missing or invalid bearer token")
				return
			}
		}
		h(w, r)
	})
}

// serialized 让写操作逐个执行：每次变更都会触发一次整表同步，串行执行既避免了
// 无谓的并发同步，也让条目上限的检查不会被并发请求绕过。排队过多时返回 429。
func (s *Server) serialized(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := s.maxQueued
		if limit <= 0 {
			limit = defaultMaxQueuedWrites
		}
		if s.writeQueued.Add(1) > limit {
			s.writeQueued.Add(-1)
			writeErr(w, http.StatusTooManyRequests, "too many concurrent changes, retry later")
			return
		}
		defer s.writeQueued.Add(-1)
		select {
		case s.writeSem <- struct{}{}:
			defer func() { <-s.writeSem }()
		case <-r.Context().Done():
			writeErr(w, http.StatusServiceUnavailable, "request cancelled while waiting for other changes")
			return
		}
		h(w, r)
	}
}

// actor 标识审计日志中的操作者：可选的 X-Xgate-Actor 头 + 来源地址。
func actor(r *http.Request) string {
	name := strings.TrimSpace(r.Header.Get("X-Xgate-Actor"))
	if name == "" {
		name = "api"
	}
	if len(name) > 64 {
		name = name[:64]
	}
	name = strings.Map(func(c rune) rune {
		if c < 0x20 || c == 0x7f {
			return -1
		}
		return c
	}, name)
	if r.RemoteAddr != "" && r.RemoteAddr != "@" {
		return name + "@" + r.RemoteAddr
	}
	return name
}

type entryJSON struct {
	CIDR       string     `json:"cidr"`
	Comment    string     `json:"comment"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	CreatedBy  string     `json:"created_by"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	TTLSeconds *int64     `json:"ttl_seconds,omitempty"`
}

func toJSON(e store.Entry, now time.Time) entryJSON {
	j := entryJSON{CIDR: e.Prefix.String(), Comment: e.Comment, CreatedAt: e.CreatedAt, UpdatedAt: e.UpdatedAt, CreatedBy: e.CreatedBy}
	if !e.ExpiresAt.IsZero() {
		exp := e.ExpiresAt.UTC()
		secs := max(int64(exp.Sub(now).Seconds()), 0)
		j.ExpiresAt, j.TTLSeconds = &exp, &secs
	}
	return j
}

// healthz 不需要鉴权，所以只返回状态和计数；同步错误里可能带有 nft 的 stderr、
// 文件路径等内部细节，只在需要鉴权的 /v1/status 中返回。
func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	st := s.Rec.Status()
	code, status := http.StatusOK, "ok"
	if !st.OK() {
		code, status = http.StatusServiceUnavailable, "degraded"
	}
	writeJSON(w, code, map[string]any{
		"status":       status,
		"last_success": st.LastSuccess,
		"entries":      st.Entries,
		"elements":     st.Elements,
	})
}

// status 返回完整的同步状态，包括最近一次失败的原因。
func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"sync": s.Rec.Status()})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	now := s.now()
	entries, err := s.Store.Active(r.Context(), now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	out := make([]entryJSON, len(entries))
	for i, e := range entries {
		out[i] = toJSON(e, now)
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out})
}

type addRequest struct {
	CIDR    string `json:"cidr"`
	Comment string `json:"comment"`
	TTL     string `json:"ttl"`
	Force   bool   `json:"force"`
}

func (s *Server) add(w http.ResponseWriter, r *http.Request) {
	var req addRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return
	}
	p, err := cidr.Parse(req.CIDR)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if shortest := s.minBits(p); p.Bits() < shortest && !req.Force {
		writeErr(w, http.StatusBadRequest, fmt.Sprintf("%s is wider than /%d; set \"force\": true to allow it", p, shortest))
		return
	}
	if len(req.Comment) > 256 {
		writeErr(w, http.StatusBadRequest, "comment longer than 256 bytes")
		return
	}
	now := s.now()
	e := store.Entry{Prefix: p, Comment: req.Comment}
	if req.TTL != "" {
		ttl, err := parseTTL(req.TTL, s.MaxTTL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		e.ExpiresAt = now.Add(ttl)
	}
	if s.MaxEntries > 0 {
		exists, err := s.Store.IsActive(r.Context(), p, now)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		n, err := s.Store.CountActive(r.Context(), now)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if !exists && n >= s.MaxEntries {
			writeErr(w, http.StatusConflict, fmt.Sprintf("allowlist is full (%d entries, limits.max_entries); delete entries before adding new ones", n))
			return
		}
	}
	who := actor(r)
	e, created, err := s.Store.Upsert(r.Context(), e, who, now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	action := "update"
	if created {
		action = "add"
	}
	s.Log.Info("audit", "action", action, "actor", who, "cidr", p.String(), "comment", e.Comment, "expires_at", e.ExpiresAt)

	code := http.StatusOK
	if created {
		code = http.StatusCreated
	}
	resp := map[string]any{"entry": toJSON(e, now)}
	if !s.syncAfterChange(r.Context(), w, resp) {
		return
	}
	writeJSON(w, code, resp)
}

func (s *Server) remove(w http.ResponseWriter, r *http.Request) {
	p, err := cidr.Parse(r.PathValue("cidr"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	kill, _ := strconv.ParseBool(r.URL.Query().Get("kill"))
	who := actor(r)
	now := s.now()
	// 删除之前先算出需要断开的地址区间，超过上限就直接拒绝，不做任何改动。
	var regions []netip.Prefix
	if kill {
		if regions, err = s.killRegions(r.Context(), p, now); err != nil {
			writeErr(w, http.StatusInternalServerError, err.Error())
			return
		}
		if len(regions) > maxKillRegions {
			writeErr(w, http.StatusBadRequest, fmt.Sprintf(
				"kill would have to reset %d address ranges (limit %d) because other entries overlap %s; delete without kill, or remove the overlapping entries first",
				len(regions), maxKillRegions, p))
			return
		}
	}
	old, ok, err := s.Store.Delete(r.Context(), p, who, fmt.Sprintf("kill=%t", kill), now)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, p.String()+" is not in the allowlist")
		return
	}
	s.Log.Info("audit", "action", "delete", "actor", who, "cidr", p.String(), "kill", kill)

	resp := map[string]any{"deleted": toJSON(old, now)}
	if !s.syncAfterChange(r.Context(), w, resp) {
		return
	}
	if kill {
		res := s.killFlows(r.Context(), regions)
		resp["reset_sockets"] = res.resetSockets
		resp["killed_connections"] = res.conntrackEntries
		if len(res.warnings) > 0 {
			resp["warnings"] = res.warnings
			s.Log.Warn("connections were not reset, they only stop forwarding", "cidr", p.String(), "warnings", res.warnings)
		}
		if len(res.errs) > 0 {
			resp["error"] = "removed from allowlist, but clearing conntrack failed: " + strings.Join(res.errs, "; ")
			writeJSON(w, http.StatusInternalServerError, resp)
			return
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

type killResult struct {
	resetSockets     int      // 被销毁（两端都收到 RST）的 TCP 连接数
	conntrackEntries int      // 被删除的 conntrack 记录数
	warnings         []string // 未能主动断开，连接只是不再被转发
	errs             []string // conntrack 清理失败
}

// killRegions 返回 p 中不被其它有效条目覆盖的地址区间，也就是删除 p 后需要断开连接的范围。
func (s *Server) killRegions(ctx context.Context, p netip.Prefix, now time.Time) ([]netip.Prefix, error) {
	active, err := s.Store.Active(ctx, now)
	if err != nil {
		return nil, err
	}
	var holes []netip.Prefix
	for _, e := range active {
		if e.Prefix != p {
			holes = append(holes, e.Prefix)
		}
	}
	return cidr.Subtract(p, holes), nil
}

// killFlows 断开 regions 中已有的连接：
//  1. 销毁本机后端上的 TCP socket，两端立即收到 RST。此时 conntrack 里的 NAT
//     映射还在，发给客户端的 RST 会被转换回监听端口，客户端才能识别。
//  2. 再删除 conntrack 记录，覆盖 UDP 以及未能销毁的连接，使其后续报文不再被转发。
func (s *Server) killFlows(ctx context.Context, regions []netip.Prefix) killResult {
	var res killResult

	type target struct {
		peer netip.Prefix
		port uint16
	}
	done := map[target]bool{}
	for _, region := range regions {
		for _, f := range s.Forwards {
			t := target{region, f.TargetPort}
			if done[t] || !slices.Contains(f.Protocols, "tcp") {
				continue
			}
			done[t] = true
			n, err := s.Sockets.Destroy(ctx, region, f.TargetPort)
			res.resetSockets += n
			if err != nil {
				res.warnings = append(res.warnings, err.Error())
			}
		}
	}

	for _, region := range regions {
		for _, f := range s.Forwards {
			for _, proto := range f.Protocols {
				n, err := s.Killer.Kill(ctx, conntrack.Flow{Src: region, Proto: proto, DPort: f.ListenPort})
				res.conntrackEntries += n
				if err != nil {
					res.errs = append(res.errs, err.Error())
				}
			}
		}
	}
	return res
}

// syncAfterChange 在变更后立即同步内核。失败时写出 500 响应并返回 false；
// 记录已经持久化，后台对账会继续重试。
func (s *Server) syncAfterChange(ctx context.Context, w http.ResponseWriter, resp map[string]any) bool {
	st, err := s.Rec.Sync(ctx)
	resp["sync"] = st
	if err != nil {
		s.Log.Error("sync after change failed", "err", err)
		resp["error"] = "change stored, but kernel sync failed (will retry on next reconcile): " + err.Error()
		writeJSON(w, http.StatusInternalServerError, resp)
		return false
	}
	return true
}

func (s *Server) sync(w http.ResponseWriter, r *http.Request) {
	st, err := s.Rec.Sync(r.Context())
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"error": err.Error(), "sync": st})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sync": st})
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			writeErr(w, http.StatusBadRequest, "limit must be between 1 and 1000")
			return
		}
		limit = n
	}
	recs, err := s.Store.Audit(r.Context(), limit)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	if recs == nil {
		recs = []store.AuditRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"records": recs})
}

func (s *Server) minBits(p netip.Prefix) int {
	if p.Addr().Is4() {
		return s.MinPrefix.IPv4
	}
	return s.MinPrefix.IPv6
}

// parseTTL 在 time.ParseDuration 的基础上额外支持 "7d" 这种按天的写法，
// 并限制 ttl 不超过 maxTTL（0 表示不限制）。
func parseTTL(s string, maxTTL time.Duration) (time.Duration, error) {
	const day = 24 * time.Hour
	tooLong := func() error {
		return fmt.Errorf("ttl %q is longer than the limit %s (limits.max_ttl); omit ttl for a permanent entry", s, maxTTL)
	}
	var d time.Duration
	if days, ok := strings.CutSuffix(s, "d"); ok {
		n, err := strconv.ParseInt(days, 10, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid ttl %q", s)
		}
		// 先按天数比较再相乘，避免 n*24h 溢出 int64 后绕回成一个很小的正数。
		if n > int64(math.MaxInt64/day) {
			return 0, fmt.Errorf("ttl %q is too large; omit ttl for a permanent entry", s)
		}
		if maxTTL > 0 && n > int64(maxTTL/day) {
			return 0, tooLong()
		}
		d = time.Duration(n) * day
	} else {
		var err error
		if d, err = time.ParseDuration(s); err != nil { // 溢出时 ParseDuration 会返回错误
			return 0, fmt.Errorf("invalid ttl %q", s)
		}
	}
	if d < time.Second {
		return 0, errors.New("ttl must be at least 1s")
	}
	if maxTTL > 0 && d > maxTTL {
		return 0, tooLong()
	}
	return d, nil
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v) // 头已发出，写失败只能是客户端断开
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
