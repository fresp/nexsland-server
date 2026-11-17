package server

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/fresp/nexsland-server/internal/config"
	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

const testPassword = "correct horse battery"

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *fakeClock) Add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t     *testing.T
	ts    *httptest.Server
	st    *store.Store
	clock *fakeClock
	srv   *Server
}

// newEnv starts a server whose public URL is the httptest URL. Its clock
// starts at 2026-11-17 01:30 in Asia/Jakarta (2026-11-16 18:30 UTC).
func newEnv(t *testing.T) *env {
	t.Helper()
	ctx := context.Background()
	st, err := store.Open(ctx, filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	clk := &fakeClock{t: time.Date(2026, 11, 16, 18, 30, 0, 0, time.UTC)}
	st.SetNow(clk.Now)
	hash, err := secret.HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.SetPasswordHash(ctx, store.OwnerID, hash); err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation("Asia/Jakarta")
	e := &env{t: t, st: st, clock: clk}
	// The handler needs the public URL, which exists only after the listener starts.
	var handler http.Handler
	e.ts = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(e.ts.Close)
	pub, err := config.ParsePublicURL(e.ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{PublicURL: pub, Location: loc, DBPath: "x", Listen: "x"}
	e.srv = New(cfg, st, slog.New(slog.NewTextHandler(io.Discard, nil)), clk.Now)
	handler = e.srv.Handler()
	return e
}

type resp struct {
	status int
	header http.Header
	body   []byte
}

func (r resp) json(t *testing.T, v any) {
	t.Helper()
	if err := json.Unmarshal(r.body, v); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

func (r resp) errCode(t *testing.T) string {
	var e apiErr
	r.json(t, &e)
	return e.Error.Code
}

func (e *env) do(c *http.Client, method, path, token string, body any) resp {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if c == nil {
		c = noRedirect(nil)
	}
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

func noRedirect(jar http.CookieJar) *http.Client {
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

var csrfRE = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

// browser is a logged-in owner session.
type browser struct {
	e    *env
	c    *http.Client
	csrf string
}

func (e *env) login() *browser {
	e.t.Helper()
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	page := e.do(c, "GET", "/login", "", nil)
	m := csrfRE.FindSubmatch(page.body)
	if m == nil {
		e.t.Fatalf("no csrf on login page: %s", page.body)
	}
	r := e.form(c, "/login", url.Values{"csrf": {string(m[1])}, "password": {testPassword}, "next": {"/"}})
	if r.status != http.StatusSeeOther {
		e.t.Fatalf("login: %d %s", r.status, r.body)
	}
	dash := e.do(c, "GET", "/", "", nil)
	m = csrfRE.FindSubmatch(dash.body)
	if dash.status != 200 || m == nil {
		e.t.Fatalf("dashboard: %d", dash.status)
	}
	return &browser{e: e, c: c, csrf: string(m[1])}
}

func (e *env) form(c *http.Client, path string, v url.Values) resp {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.ts.URL+path, strings.NewReader(v.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return resp{res.StatusCode, res.Header, b}
}

// pair runs the device flow end to end and returns the device token.
func (e *env) pair(b *browser, name string) string {
	e.t.Helper()
	var start struct {
		DeviceCode, UserCode, VerificationURI string
		Interval                              int
	}
	r := e.do(nil, "POST", "/v1/pair/start", "", map[string]string{"device_name": name})
	if r.status != 200 {
		e.t.Fatalf("pair start: %d %s", r.status, r.body)
	}
	var raw map[string]any
	r.json(e.t, &raw)
	start.DeviceCode, start.UserCode = raw["device_code"].(string), raw["user_code"].(string)
	if raw["verification_uri"] != e.ts.URL+"/pair" {
		e.t.Fatalf("verification_uri %v", raw["verification_uri"])
	}
	poll := func() resp {
		return e.do(nil, "POST", "/v1/pair/token", "", map[string]string{"device_code": start.DeviceCode})
	}
	if r := poll(); r.status != 400 || r.errCode(e.t) != "authorization_pending" {
		e.t.Fatalf("first poll: %d %s", r.status, r.body)
	}
	if r := poll(); r.errCode(e.t) != "slow_down" {
		e.t.Fatalf("fast poll: %s", r.body)
	}
	// Owner approves, typing the code in lowercase without the dash.
	page := e.do(b.c, "GET", "/pair?code="+strings.ToLower(strings.ReplaceAll(start.UserCode, "-", "")), "", nil)
	if !bytes.Contains(page.body, []byte(name)) {
		e.t.Fatalf("pair page does not show the device name: %s", page.body)
	}
	if r := e.form(b.c, "/pair", url.Values{"csrf": {b.csrf}, "code": {start.UserCode}, "decision": {"approve"}}); r.status != 200 {
		e.t.Fatalf("approve: %d", r.status)
	}
	e.clock.Add(6 * time.Second)
	r = poll()
	if r.status != 200 {
		e.t.Fatalf("token poll: %d %s", r.status, r.body)
	}
	var tok struct{ Token string }
	r.json(e.t, &tok)
	if !strings.HasPrefix(tok.Token, devicePrefix) {
		e.t.Fatalf("token %q", tok.Token)
	}
	e.clock.Add(6 * time.Second)
	if r := poll(); r.errCode(e.t) != "expired_token" {
		e.t.Fatalf("second delivery: %s", r.body)
	}
	return tok.Token
}

func TestPairingEndToEnd(t *testing.T) {
	e := newEnv(t)
	b := e.login()
	tok := e.pair(b, "laptop")
	var me map[string]any
	r := e.do(nil, "GET", "/v1/me", tok, nil)
	r.json(t, &me)
	if r.status != 200 || me["time_zone"] != "Asia/Jakarta" || me["today"] != "2026-11-17" {
		t.Fatalf("me: %d %s", r.status, r.body)
	}
	// The dashboard lists it; revoking it kills the token.
	dash := e.do(b.c, "GET", "/", "", nil)
	if !bytes.Contains(dash.body, []byte("laptop")) {
		t.Fatal("device not on dashboard")
	}
	devs, _ := e.st.Devices(context.Background(), store.OwnerID)
	if r := e.form(b.c, "/devices/"+devs[0].ID+"/revoke", url.Values{"csrf": {b.csrf}}); r.status != http.StatusSeeOther {
		t.Fatalf("revoke: %d", r.status)
	}
	if r := e.do(nil, "GET", "/v1/me", tok, nil); r.status != 401 {
		t.Fatalf("revoked token: %d", r.status)
	}
}

func TestPairingDeniedAndExpired(t *testing.T) {
	e := newEnv(t)
	b := e.login()
	start := func() (string, string) {
		var raw map[string]any
		e.do(nil, "POST", "/v1/pair/start", "", map[string]string{}).json(t, &raw)
		return raw["device_code"].(string), raw["user_code"].(string)
	}
	dc, uc := start()
	e.form(b.c, "/pair", url.Values{"csrf": {b.csrf}, "code": {uc}, "decision": {"deny"}})
	if r := e.do(nil, "POST", "/v1/pair/token", "", map[string]string{"device_code": dc}); r.errCode(t) != "access_denied" {
		t.Fatalf("denied: %s", r.body)
	}
	dc, uc = start()
	e.clock.Add(11 * time.Minute)
	if r := e.do(nil, "POST", "/v1/pair/token", "", map[string]string{"device_code": dc}); r.errCode(t) != "expired_token" {
		t.Fatalf("expired: %s", r.body)
	}
	if r := e.form(b.c, "/pair", url.Values{"csrf": {b.csrf}, "code": {uc}, "decision": {"approve"}}); !bytes.Contains(r.body, []byte("expired")) {
		t.Fatalf("approving an expired code: %s", r.body)
	}
	if r := e.do(nil, "POST", "/v1/pair/token", "", map[string]string{"device_code": "nope"}); r.errCode(t) != "invalid_grant" {
		t.Fatalf("unknown code: %s", r.body)
	}
}

func TestPairApprovalNeedsCSRFAndLogin(t *testing.T) {
	e := newEnv(t)
	var raw map[string]any
	e.do(nil, "POST", "/v1/pair/start", "", map[string]string{}).json(t, &raw)
	uc := raw["user_code"].(string)
	// Not logged in.
	jar, _ := cookiejar.New(nil)
	if r := e.form(noRedirect(jar), "/pair", url.Values{"code": {uc}, "decision": {"approve"}}); r.status != 401 {
		t.Fatalf("anonymous approve: %d", r.status)
	}
	// Logged in, wrong CSRF token.
	b := e.login()
	if r := e.form(b.c, "/pair", url.Values{"csrf": {"wrong"}, "code": {uc}, "decision": {"approve"}}); r.status != 403 {
		t.Fatalf("bad csrf: %d", r.status)
	}
	// Cross-site request (Fetch metadata) is blocked even with a valid token.
	req, _ := http.NewRequest("POST", e.ts.URL+"/pair", strings.NewReader(url.Values{"csrf": {b.csrf}, "code": {uc}, "decision": {"approve"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	res, _ := b.c.Do(req)
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cross-site: %d", res.StatusCode)
	}
	if p, err := e.st.PairByUserCode(context.Background(), uc); err != nil || p.Status != store.PairPending {
		t.Fatalf("pair changed: %+v %v", p, err)
	}
}

func TestAuthRejection(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "nxd_bogus", "nxa_bogus", "garbage"} {
		for _, path := range []string{"/v1/todos", "/v1/me"} {
			r := e.do(nil, "GET", path, tok, nil)
			if r.status != 401 || r.errCode(t) != "unauthorized" {
				t.Fatalf("%s with %q: %d %s", path, tok, r.status, r.body)
			}
		}
	}
	// Wrong password.
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	page := e.do(c, "GET", "/login", "", nil)
	m := csrfRE.FindSubmatch(page.body)
	if r := e.form(c, "/login", url.Values{"csrf": {string(m[1])}, "password": {"nope"}}); r.status != 401 {
		t.Fatalf("wrong password: %d", r.status)
	}
	// Dashboard without session redirects to login.
	if r := e.do(noRedirect(nil), "GET", "/", "", nil); r.status != http.StatusSeeOther || r.header.Get("Location") != "/login?next=%2F" {
		t.Fatalf("anonymous dashboard: %d %s", r.status, r.header.Get("Location"))
	}
}

func TestLoginRateLimit(t *testing.T) {
	e := newEnv(t)
	jar, _ := cookiejar.New(nil)
	c := noRedirect(jar)
	m := csrfRE.FindSubmatch(e.do(c, "GET", "/login", "", nil).body)
	var last int
	for range 7 {
		last = e.form(c, "/login", url.Values{"csrf": {string(m[1])}, "password": {"wrong"}}).status
	}
	if last != http.StatusTooManyRequests {
		t.Fatalf("after 7 failures: %d", last)
	}
}

// device is a simulated offline-first Nexsland client.
type device struct {
	e      *env
	token  string
	cursor int64
	local  map[string]todo.Todo
	outbox []map[string]any
}

func (d *device) edit(t todo.Todo) {
	d.local[t.ID] = t
	d.outbox = append(d.outbox, map[string]any{"op": "upsert", "todo": t})
}

func (d *device) sync() []store.Result {
	d.e.t.Helper()
	var results []store.Result
	if len(d.outbox) > 0 {
		r := d.e.do(nil, "POST", "/v1/ops", d.token, map[string]any{"ops": d.outbox})
		if r.status != 200 {
			d.e.t.Fatalf("ops: %d %s", r.status, r.body)
		}
		var out opsResponse
		r.json(d.e.t, &out)
		results = out.Results
		d.outbox = nil
	}
	for {
		var page changesResponse
		r := d.e.do(nil, "GET", "/v1/todos?limit=2&since="+itoa(d.cursor), d.token, nil)
		r.json(d.e.t, &page)
		for _, t := range page.Todos {
			if t.Deleted {
				delete(d.local, t.ID)
			} else {
				d.local[t.ID] = t
			}
		}
		d.cursor = page.Next
		if !page.More {
			return results
		}
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }

func TestSyncRoundTripTwoDevicesOffline(t *testing.T) {
	e := newEnv(t)
	b := e.login()
	a := &device{e: e, token: e.pair(b, "A"), local: map[string]todo.Todo{}}
	c := &device{e: e, token: e.pair(b, "B"), local: map[string]todo.Todo{}}
	base := e.clock.Now()

	shared := todo.Todo{ID: todo.NewID(), Title: "write report", Day: "2026-11-17", CreatedAt: base, UpdatedAt: base}
	other := todo.Todo{ID: todo.NewID(), Title: "call mum", Day: "2026-11-18", CreatedAt: base, UpdatedAt: base}
	a.edit(shared)
	a.edit(other)
	a.sync()
	c.sync()
	if len(c.local) != 2 {
		t.Fatalf("B sees %d todos", len(c.local))
	}

	// Both go offline and edit the same task. B edits later, so B wins.
	ea := a.local[shared.ID]
	ea.Title, ea.UpdatedAt = "write report (A)", base.Add(time.Minute)
	a.edit(ea)
	eb := c.local[shared.ID]
	nine := 540
	eb.Title, eb.Minutes, eb.UpdatedAt = "write report (B)", &nine, base.Add(2*time.Minute)
	c.edit(eb)
	// B also deletes the other task offline.
	c.outbox = append(c.outbox, map[string]any{"op": "delete", "id": other.ID, "updated_at": base.Add(2 * time.Minute)})

	// B syncs first, then A with its older edit.
	if res := c.sync(); res[0].Status != store.StatusApplied || res[1].Status != store.StatusApplied {
		t.Fatalf("B results: %+v", res)
	}
	res := a.sync()
	if res[0].Status != store.StatusStale || res[0].Todo.Title != "write report (B)" {
		t.Fatalf("A's older edit should be stale and report B's row: %+v", res)
	}
	c.sync()
	for name, d := range map[string]*device{"A": a, "B": c} {
		got := d.local[shared.ID]
		if len(d.local) != 1 || got.Title != "write report (B)" || got.Minutes == nil || *got.Minutes != 540 {
			t.Fatalf("%s converged to %+v", name, d.local)
		}
	}
	if a.cursor != c.cursor {
		t.Fatalf("cursors differ: %d vs %d", a.cursor, c.cursor)
	}
}

func TestOpsValidation(t *testing.T) {
	e := newEnv(t)
	tok := e.pair(e.login(), "d")
	now := e.clock.Now()
	good := map[string]any{"id": todo.NewID(), "title": "x", "day": "2026-11-17", "minutes": nil, "done": false,
		"created_at": now, "updated_at": now, "deleted": false}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for kk, vv := range good {
			m[kk] = vv
		}
		m[k] = v
		return m
	}
	cases := []struct {
		name string
		body any
		code string
		st   int
	}{
		{"empty", map[string]any{"ops": []any{}}, "invalid_op", 422},
		{"bad title", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("title", "  ")}}}, "invalid_op", 422},
		{"bad day", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("day", "2026-02-30")}}}, "invalid_op", 422},
		{"bad minutes", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("minutes", 1440)}}}, "invalid_op", 422},
		{"uuid v4", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("id", "0b8f9d64-3c1e-4c1a-9a55-6d4b3f1a2b3c")}}}, "invalid_op", 422},
		{"unknown field", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("colour", "red")}}}, "invalid_op", 422},
		{"bad op", map[string]any{"ops": []any{map[string]any{"op": "merge"}}}, "invalid_op", 422},
		{"duplicate id", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": good}, map[string]any{"op": "upsert", "todo": good}}}, "invalid_op", 422},
		{"clock skew", map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("updated_at", now.Add(6*time.Minute))}}}, "clock_skew", 422},
		{"not json", "nope", "bad_json", 400},
	}
	for _, tc := range cases {
		r := e.do(nil, "POST", "/v1/ops", tok, tc.body)
		if r.status != tc.st || r.errCode(t) != tc.code {
			t.Errorf("%s: %d %s", tc.name, r.status, r.body)
		}
	}
	// Within the skew window is fine.
	r := e.do(nil, "POST", "/v1/ops", tok, map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("updated_at", now.Add(4*time.Minute))}}})
	if r.status != 200 {
		t.Fatalf("4 min ahead: %d %s", r.status, r.body)
	}
	// Too many ops.
	ops := make([]any, maxOpsPerBatch+1)
	for i := range ops {
		ops[i] = map[string]any{"op": "delete", "id": todo.NewID(), "updated_at": now}
	}
	if r := e.do(nil, "POST", "/v1/ops", tok, map[string]any{"ops": ops}); r.status != 413 {
		t.Fatalf("too many ops: %d", r.status)
	}
	// Body too large.
	big := map[string]any{"ops": []any{map[string]any{"op": "upsert", "todo": with("title", strings.Repeat("a", maxOpsBody))}}}
	if r := e.do(nil, "POST", "/v1/ops", tok, big); r.status != 413 {
		t.Fatalf("large body: %d", r.status)
	}
	if r := e.do(nil, "GET", "/v1/todos?limit=5000", tok, nil); r.status != 400 {
		t.Fatalf("limit too big: %d", r.status)
	}
}

func TestSecurityHeadersAndNoCORS(t *testing.T) {
	e := newEnv(t)
	r := e.do(nil, "GET", "/healthz", "", nil)
	if r.status != 200 {
		t.Fatalf("healthz %d", r.status)
	}
	for _, h := range []string{"X-Content-Type-Options", "Content-Security-Policy", "X-Frame-Options", "Referrer-Policy"} {
		if r.header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
	req, _ := http.NewRequest("OPTIONS", e.ts.URL+"/v1/todos", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Method", "GET")
	res, _ := http.DefaultClient.Do(req)
	res.Body.Close()
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("API answered a CORS preflight")
	}
}
