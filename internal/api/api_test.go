package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vndroid/xGate/internal/config"
	"github.com/vndroid/xGate/internal/conntrack"
	"github.com/vndroid/xGate/internal/nft"
	"github.com/vndroid/xGate/internal/reconcile"
	"github.com/vndroid/xGate/internal/store"
)

type fakeNFT struct {
	mu   sync.Mutex
	last string
	err  error
}

func (f *fakeNFT) Apply(_ context.Context, s string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.last = s
	return f.err
}

// fakeKiller 同时实现 conntrack.Killer 和 sockets.Destroyer，按调用顺序记录到 calls。
type fakeKiller struct {
	flows      []conntrack.Flow
	calls      []string
	destroyErr error
}

func (k *fakeKiller) Kill(_ context.Context, f conntrack.Flow) (int, error) {
	k.flows = append(k.flows, f)
	k.calls = append(k.calls, fmt.Sprintf("conntrack %s %s %d", f.Src, f.Proto, f.DPort))
	return 1, nil
}

func (k *fakeKiller) Destroy(_ context.Context, peer netip.Prefix, port uint16) (int, error) {
	k.calls = append(k.calls, fmt.Sprintf("destroy %s %d", peer, port))
	return 3, k.destroyErr
}

type env struct {
	srv        *httptest.Server
	srvHandler *Server
	nft        *fakeNFT
	killer     *fakeKiller
	now        time.Time
}

func setup(t *testing.T, token string) *env {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "x.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	e := &env{nft: &fakeNFT{}, killer: &fakeKiller{}, now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC)}
	clock := func() time.Time { return e.now }
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	fwd := []config.Forward{{Name: "d", ListenPort: 35353, TargetPort: 8080, Protocols: []string{"tcp", "udp"}}}
	rec := reconcile.New(st, e.nft, nft.Ruleset{Table: "xgate", Forwards: fwd}, time.Minute, log)
	rec.Now = clock
	s := &Server{
		Store: st, Rec: rec, Killer: e.killer, Sockets: e.killer, Forwards: fwd,
		MinPrefix: config.MinPrefixLen{IPv4: 8, IPv6: 32}, Token: token, Log: log, Now: clock,
	}
	e.srv, e.srvHandler = httptest.NewServer(s.Handler()), s
	t.Cleanup(e.srv.Close)
	return e
}

func (e *env) do(t *testing.T, method, path, body string, hdr ...string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("%s %s: decode response: %v", method, path, err)
	}
	return resp.StatusCode, out
}

func TestAddListDelete(t *testing.T) {
	e := setup(t, "")
	code, out := e.do(t, "POST", "/v1/allowlist", `{"cidr":"198.51.100.9/24","comment":"office","ttl":"24h"}`, "X-Xgate-Actor", "ops")
	if code != http.StatusCreated {
		t.Fatalf("add: %d %v", code, out)
	}
	entry := out["entry"].(map[string]any)
	if entry["cidr"] != "198.51.100.0/24" || entry["ttl_seconds"].(float64) != 86400 || !strings.HasPrefix(entry["created_by"].(string), "ops@") {
		t.Errorf("unexpected entry: %v", entry)
	}
	if !strings.Contains(e.nft.last, "198.51.100.0/24 timeout 86400s") {
		t.Errorf("kernel not synced:\n%s", e.nft.last)
	}

	if code, _ := e.do(t, "POST", "/v1/allowlist", `{"cidr":"198.51.100.0/24","comment":"office"}`); code != http.StatusOK {
		t.Errorf("re-add should update and return 200, got %d", code)
	}

	code, out = e.do(t, "GET", "/v1/allowlist", "")
	if code != 200 || len(out["entries"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, out)
	}

	// 未编码和 %2F 编码的路径都应可用。
	if code, out := e.do(t, "DELETE", "/v1/allowlist/198.51.100.0%2F24", ""); code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := e.do(t, "DELETE", "/v1/allowlist/198.51.100.0/24", ""); code != http.StatusNotFound {
		t.Errorf("second delete: %d", code)
	}
	if strings.Contains(e.nft.last, "198.51.100.0/24") {
		t.Errorf("deleted prefix still in kernel:\n%s", e.nft.last)
	}

	code, out = e.do(t, "GET", "/v1/audit?limit=10", "")
	if recs := out["records"].([]any); code != 200 || len(recs) != 3 || recs[0].(map[string]any)["action"] != "delete" {
		t.Errorf("audit: %d %v", code, out)
	}
}

func TestAddValidation(t *testing.T) {
	e := setup(t, "")
	cases := []string{
		`{"cidr":"0.0.0.0/0"}`,
		`{"cidr":"10.0.0.0/7"}`,
		`{"cidr":"2001:db8::/16"}`,
		`{"cidr":"bogus"}`,
		`{"cidr":"10.0.0.0/24","ttl":"soon"}`,
		`{"cidr":"10.0.0.0/24","ttl":"0s"}`,
		`{"cidr":"10.0.0.0/24","unknown":1}`,
	}
	for _, body := range cases {
		if code, out := e.do(t, "POST", "/v1/allowlist", body); code != http.StatusBadRequest {
			t.Errorf("%s: got %d %v, want 400", body, code, out)
		}
	}
	if code, _ := e.do(t, "POST", "/v1/allowlist", `{"cidr":"0.0.0.0/0","force":true}`); code != http.StatusCreated {
		t.Errorf("forced /0 rejected: %d", code)
	}
	if code, out := e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24","ttl":"7d"}`); code != http.StatusCreated ||
		out["entry"].(map[string]any)["ttl_seconds"].(float64) != 7*86400 {
		t.Errorf("7d ttl: %d %v", code, out)
	}
}

func TestDeleteKillsOnlyUncoveredFlows(t *testing.T) {
	e := setup(t, "")
	e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24"}`)
	e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.128/25"}`)

	code, out := e.do(t, "DELETE", "/v1/allowlist/10.0.0.0%2F24?kill=true", "")
	if code != 200 || out["killed_connections"].(float64) != 2 || out["reset_sockets"].(float64) != 3 || out["warnings"] != nil {
		t.Fatalf("delete: %d %v", code, out)
	}
	// 先销毁后端 socket（此时 NAT 映射还在，RST 才能回到客户端），再清 conntrack。
	wantCalls := []string{
		"destroy 10.0.0.0/25 8080",
		"conntrack 10.0.0.0/25 tcp 35353",
		"conntrack 10.0.0.0/25 udp 35353",
	}
	if !slices.Equal(e.killer.calls, wantCalls) {
		t.Errorf("calls = %q, want %q", e.killer.calls, wantCalls)
	}
	// 10.0.0.128/25 仍在白名单中，只能清理 10.0.0.0/25 上的连接（tcp、udp 各一次）。
	want := []conntrack.Flow{
		{Src: mustPrefix("10.0.0.0/25"), Proto: "tcp", DPort: 35353},
		{Src: mustPrefix("10.0.0.0/25"), Proto: "udp", DPort: 35353},
	}
	if len(e.killer.flows) != 2 || e.killer.flows[0] != want[0] || e.killer.flows[1] != want[1] {
		t.Errorf("killed flows = %+v", e.killer.flows)
	}

	e.killer.flows, e.killer.calls = nil, nil
	e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24"}`)
	e.do(t, "DELETE", "/v1/allowlist/10.0.0.128%2F25?kill=1", "")
	if len(e.killer.calls) != 0 {
		t.Errorf("fully covered prefix should not kill flows: %q", e.killer.calls)
	}
}

func TestDeleteKillWithoutSocketDestroy(t *testing.T) {
	e := setup(t, "")
	e.killer.destroyErr = errors.New("2 tcp sockets were not destroyed")
	e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24"}`)
	// 内核不支持销毁 socket 时仍清理 conntrack，返回 200 并带上警告。
	code, out := e.do(t, "DELETE", "/v1/allowlist/10.0.0.0%2F24?kill=true", "")
	if code != 200 || out["killed_connections"].(float64) != 2 {
		t.Fatalf("delete: %d %v", code, out)
	}
	if w, _ := out["warnings"].([]any); len(w) != 1 || !strings.Contains(w[0].(string), "not destroyed") {
		t.Errorf("warnings = %v", out["warnings"])
	}
}

func TestDeleteKillUDPOnlySkipsSocketDestroy(t *testing.T) {
	e := setup(t, "")
	e.srvHandler.Forwards = []config.Forward{{Name: "dns", ListenPort: 5353, TargetPort: 53, Protocols: []string{"udp"}}}
	e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24"}`)
	e.do(t, "DELETE", "/v1/allowlist/10.0.0.0%2F24?kill=true", "")
	if want := []string{"conntrack 10.0.0.0/24 udp 5353"}; !slices.Equal(e.killer.calls, want) {
		t.Errorf("calls = %q, want %q", e.killer.calls, want)
	}
}

func TestAuth(t *testing.T) {
	e := setup(t, "s3cret")
	if code, _ := e.do(t, "GET", "/v1/allowlist", ""); code != http.StatusUnauthorized {
		t.Errorf("no token: %d", code)
	}
	if code, _ := e.do(t, "GET", "/v1/allowlist", "", "Authorization", "Bearer wrong"); code != http.StatusUnauthorized {
		t.Errorf("wrong token: %d", code)
	}
	if code, _ := e.do(t, "GET", "/v1/allowlist", "", "Authorization", "Bearer s3cret"); code != http.StatusOK {
		t.Errorf("good token: %d", code)
	}
	// healthz 不需要鉴权；还没同步过时应报告 degraded。
	if code, out := e.do(t, "GET", "/healthz", ""); code != http.StatusServiceUnavailable || out["status"] != "degraded" {
		t.Errorf("healthz before sync: %d %v", code, out)
	}
	if code, _ := e.do(t, "POST", "/v1/allowlist:sync", "", "Authorization", "Bearer s3cret"); code != http.StatusOK {
		t.Errorf("manual sync: %d", code)
	}
	if code, _ := e.do(t, "GET", "/healthz", ""); code != http.StatusOK {
		t.Errorf("healthz after sync: %d", code)
	}
}

func TestSyncFailureReported(t *testing.T) {
	e := setup(t, "")
	e.nft.err = errors.New("nft unavailable")
	code, out := e.do(t, "POST", "/v1/allowlist", `{"cidr":"10.0.0.0/24"}`)
	if code != http.StatusInternalServerError || !strings.Contains(out["error"].(string), "change stored") {
		t.Fatalf("got %d %v", code, out)
	}
	e.nft.err = nil
	if _, out := e.do(t, "GET", "/v1/allowlist", ""); len(out["entries"].([]any)) != 1 {
		t.Errorf("entry should be persisted despite sync failure: %v", out)
	}
}

func mustPrefix(s string) netip.Prefix { return netip.MustParsePrefix(s) }
