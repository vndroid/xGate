// Package api 提供 xgate 的 HTTP API：白名单增删查、手动对账、审计查询和健康检查。
package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
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
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.Handle("GET /v1/allowlist", s.auth(s.list))
	mux.Handle("POST /v1/allowlist", s.auth(s.add))
	mux.Handle("DELETE /v1/allowlist/{cidr...}", s.auth(s.remove))
	mux.Handle("POST /v1/allowlist:sync", s.auth(s.sync))
	mux.Handle("GET /v1/audit", s.auth(s.audit))
	return mux
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
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

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	st := s.Rec.Status()
	code, status := http.StatusOK, "ok"
	if !st.OK() {
		code, status = http.StatusServiceUnavailable, "degraded"
	}
	writeJSON(w, code, map[string]any{"status": status, "sync": st})
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
		ttl, err := parseTTL(req.TTL)
		if err != nil {
			writeErr(w, http.StatusBadRequest, err.Error())
			return
		}
		e.ExpiresAt = now.Add(ttl)
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
		res := s.killFlows(r.Context(), p, now)
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

// killFlows 断开 p 中、且不再被其它白名单覆盖的地址上的已有连接：
//  1. 销毁本机后端上的 TCP socket，两端立即收到 RST。此时 conntrack 里的 NAT
//     映射还在，发给客户端的 RST 会被转换回监听端口，客户端才能识别。
//  2. 再删除 conntrack 记录，覆盖 UDP 以及未能销毁的连接，使其后续报文不再被转发。
func (s *Server) killFlows(ctx context.Context, p netip.Prefix, now time.Time) killResult {
	var res killResult
	remaining, err := s.Store.Active(ctx, now)
	if err != nil {
		res.errs = append(res.errs, err.Error())
		return res
	}
	holes := make([]netip.Prefix, len(remaining))
	for i, e := range remaining {
		holes[i] = e.Prefix
	}
	regions := cidr.Subtract(p, holes)

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

// parseTTL 在 time.ParseDuration 的基础上额外支持 "7d" 这种按天的写法。
func parseTTL(s string) (time.Duration, error) {
	var d time.Duration
	var err error
	if days, ok := strings.CutSuffix(s, "d"); ok {
		var n int
		if n, err = strconv.Atoi(days); err == nil {
			d = time.Duration(n) * 24 * time.Hour
		}
	} else {
		d, err = time.ParseDuration(s)
	}
	if err != nil {
		return 0, fmt.Errorf("invalid ttl %q", s)
	}
	if d < time.Second {
		return 0, errors.New("ttl must be at least 1s")
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
