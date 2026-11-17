package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

const claudeCallback = "https://claude.ai/api/mcp/auth_callback"

type tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
}

func (e *env) postForm(path string, v url.Values) resp {
	return e.form(noRedirect(nil), path, v)
}

func (e *env) registerClient(body map[string]any) map[string]any {
	e.t.Helper()
	r := e.do(nil, "POST", "/oauth/register", "", body)
	if r.status != 201 {
		e.t.Fatalf("register: %d %s", r.status, r.body)
	}
	var out map[string]any
	r.json(e.t, &out)
	return out
}

var hiddenRE = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)">`)

// authorize runs the browser part of the code flow and returns the redirect.
func (e *env) authorize(b *browser, q url.Values, decision string) *url.URL {
	e.t.Helper()
	page := e.do(b.c, "GET", "/oauth/authorize?"+q.Encode(), "", nil)
	if page.status != 200 {
		e.t.Fatalf("authorize page: %d %s", page.status, page.body)
	}
	if !strings.Contains(page.header.Get("Content-Security-Policy"), "https://claude.ai") {
		e.t.Fatalf("consent CSP lacks the redirect origin: %s", page.header.Get("Content-Security-Policy"))
	}
	form := url.Values{"decision": {decision}}
	for _, m := range hiddenRE.FindAllStringSubmatch(string(page.body), -1) {
		form.Set(m[1], htmlUnescape(m[2]))
	}
	r := e.form(b.c, "/oauth/authorize", form)
	if r.status != http.StatusFound {
		e.t.Fatalf("consent submit: %d %s", r.status, r.body)
	}
	u, _ := url.Parse(r.header.Get("Location"))
	return u
}

func htmlUnescape(s string) string {
	return strings.NewReplacer("&amp;", "&", "&#43;", "+", "&#34;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(s)
}

func pkce() (verifier, challenge string) {
	verifier = secret.Token("")
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// connectClaude performs discovery, DCR, consent and the code exchange the way
// Claude does, and returns the tokens.
func (e *env) connectClaude(b *browser) (clientID string, tok tokens) {
	e.t.Helper()
	// Unauthenticated MCP call points at the resource metadata.
	r := e.do(nil, "POST", "/mcp", "", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize"})
	want := `resource_metadata="` + e.ts.URL + `/.well-known/oauth-protected-resource/mcp"`
	if r.status != 401 || !strings.Contains(r.header.Get("WWW-Authenticate"), want) {
		e.t.Fatalf("401 challenge: %d %q", r.status, r.header.Get("WWW-Authenticate"))
	}
	var prm map[string]any
	e.do(nil, "GET", "/.well-known/oauth-protected-resource/mcp", "", nil).json(e.t, &prm)
	if prm["resource"] != e.ts.URL+"/mcp" || prm["authorization_servers"].([]any)[0] != e.ts.URL {
		e.t.Fatalf("resource metadata: %v", prm)
	}
	var asm map[string]any
	e.do(nil, "GET", "/.well-known/oauth-authorization-server", "", nil).json(e.t, &asm)
	if asm["issuer"] != e.ts.URL || asm["code_challenge_methods_supported"].([]any)[0] != "S256" || asm["registration_endpoint"] == nil {
		e.t.Fatalf("as metadata: %v", asm)
	}
	reg := e.registerClient(map[string]any{"client_name": "Claude", "redirect_uris": []string{claudeCallback},
		"grant_types": []string{"authorization_code", "refresh_token"}, "token_endpoint_auth_method": "none",
		"logo_uri": "https://example.com/x.png"})
	clientID = reg["client_id"].(string)
	verifier, challenge := pkce()
	q := url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {claudeCallback},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"st8"}, "scope": {"todos"},
		"resource": {e.ts.URL + "/mcp"}}
	loc := e.authorize(b, q, "approve")
	if loc.Scheme+"://"+loc.Host+loc.Path != claudeCallback || loc.Query().Get("state") != "st8" || loc.Query().Get("iss") != e.ts.URL {
		e.t.Fatalf("redirect: %s", loc)
	}
	r = e.postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {claudeCallback}, "client_id": {clientID}, "code_verifier": {verifier}, "resource": {e.ts.URL + "/mcp"}})
	if r.status != 200 {
		e.t.Fatalf("token: %d %s", r.status, r.body)
	}
	r.json(e.t, &tok)
	if tok.TokenType != "Bearer" || tok.Scope != "todos" || tok.ExpiresIn != 3600 {
		e.t.Fatalf("token response: %+v", tok)
	}
	return clientID, tok
}

type bearerRT struct{ tok string }

func (b bearerRT) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return http.DefaultTransport.RoundTrip(r)
}

func (e *env) mcpSession(access string) *mcp.ClientSession {
	e.t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "v0"}, nil)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   e.ts.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerRT{access}},
	}, nil)
	if err != nil {
		e.t.Fatal(err)
	}
	e.t.Cleanup(func() { cs.Close() })
	return cs
}

type toolOut struct {
	text    string
	isError bool
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) toolOut {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error %v", name, err)
	}
	return toolOut{text: res.Content[0].(*mcp.TextContent).Text, isError: res.IsError}
}

// payload decodes the JSON after the first line of a tool result.
func (o toolOut) payload(t *testing.T, v any) {
	t.Helper()
	_, js, _ := strings.Cut(o.text, "\n")
	if err := json.Unmarshal([]byte(js), v); err != nil {
		t.Fatalf("decode %q: %v", o.text, err)
	}
}

func TestMCPToolsEndToEnd(t *testing.T) {
	e := newEnv(t)
	b := e.login()
	_, tok := e.connectClaude(b)
	cs := e.mcpSession(tok.AccessToken)

	tools, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range tools.Tools {
		names = append(names, tl.Name)
	}
	if strings.Join(names, ",") != "add_todo,complete_todo,delete_todo,list_todos,reopen_todo,update_todo" {
		t.Fatalf("tools: %v", names)
	}

	// Today in Asia/Jakarta is 2026-11-17 even though UTC is still the 16th.
	out := call(t, cs, "add_todo", map[string]any{"title": "  dentist ", "date": "2026-11-18", "time": "09:00"})
	if out.isError || !strings.HasPrefix(out.text, "Today is 2026-11-17 (Tuesday, time zone Asia/Jakarta).") {
		t.Fatalf("add: %+v", out)
	}
	var added todoView
	out.payload(t, &added)
	if added.Title != "dentist" || added.Date != "2026-11-18" || *added.Time != "09:00" || todo.ValidID(added.ID) != nil {
		t.Fatalf("added: %+v", added)
	}
	var plain todoView
	call(t, cs, "add_todo", map[string]any{"title": "buy milk"}).payload(t, &plain)
	if plain.Date != "2026-11-17" || plain.Time != nil {
		t.Fatalf("defaults: %+v", plain)
	}

	// An overdue task synced from Nexsland.
	past := todo.Todo{ID: todo.NewID(), Title: "old", Day: "2026-11-10", UpdatedAt: e.clock.Now()}
	_, _ = e.st.ApplyOps(context.Background(), store.OwnerID, []store.Op{{Kind: store.OpUpsert, Todo: past}})

	var list []todoView
	call(t, cs, "list_todos", nil).payload(t, &list)
	if len(list) != 3 || list[0].ID != past.ID || !list[0].Overdue || list[1].ID != plain.ID || list[2].ID != added.ID {
		t.Fatalf("list: %+v", list)
	}

	if out := call(t, cs, "complete_todo", map[string]any{"id": plain.ID}); out.isError {
		t.Fatalf("complete: %s", out.text)
	}
	call(t, cs, "list_todos", nil).payload(t, &list)
	if len(list) != 2 {
		t.Fatalf("done todo still listed: %+v", list)
	}
	call(t, cs, "list_todos", map[string]any{"include_done": true}).payload(t, &list)
	if len(list) != 3 {
		t.Fatalf("include_done: %+v", list)
	}
	var reopened todoView
	call(t, cs, "reopen_todo", map[string]any{"id": plain.ID}).payload(t, &reopened)
	if reopened.Done {
		t.Fatal("reopen")
	}

	var upd todoView
	call(t, cs, "update_todo", map[string]any{"id": added.ID, "title": "dentist (moved)", "date": "2026-11-19"}).payload(t, &upd)
	if upd.Title != "dentist (moved)" || upd.Date != "2026-11-19" || *upd.Time != "09:00" {
		t.Fatalf("update: %+v", upd)
	}
	call(t, cs, "update_todo", map[string]any{"id": added.ID, "time": nil}).payload(t, &upd)
	if upd.Time != nil || upd.Title != "dentist (moved)" {
		t.Fatalf("clear time: %+v", upd)
	}
	call(t, cs, "update_todo", map[string]any{"id": added.ID, "time": "17:30"}).payload(t, &upd)
	if *upd.Time != "17:30" {
		t.Fatalf("set time: %+v", upd)
	}

	if out := call(t, cs, "delete_todo", map[string]any{"id": added.ID}); out.isError || !strings.Contains(out.text, "Deleted") {
		t.Fatalf("delete: %+v", out)
	}

	// MCP writes bump seq like any other write, so Nexsland sees them.
	changes, _, _ := e.st.Changes(context.Background(), store.OwnerID, 0, 100)
	last := changes[len(changes)-1]
	if last.ID != added.ID || !last.Deleted {
		t.Fatalf("last change: %+v", last)
	}
	if maxSeq, _ := e.st.MaxSeq(context.Background()); maxSeq != 9 {
		t.Fatalf("max seq %d, want 9 (1 sync + 8 MCP writes)", maxSeq)
	}
}

func TestMCPToolErrors(t *testing.T) {
	e := newEnv(t)
	_, tok := e.connectClaude(e.login())
	cs := e.mcpSession(tok.AccessToken)
	var a todoView
	call(t, cs, "add_todo", map[string]any{"title": "x"}).payload(t, &a)

	cases := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"add_todo", map[string]any{"title": "   "}, "title"},
		{"add_todo", map[string]any{"title": strings.Repeat("a", 201)}, "200"},
		{"add_todo", map[string]any{"title": "x", "date": "tomorrow"}, "YYYY-MM-DD"},
		{"add_todo", map[string]any{"title": "x", "date": "2026-11-16"}, "in the past"},
		{"add_todo", map[string]any{"title": "x", "date": "2027-11-18"}, "more than one year"},
		{"add_todo", map[string]any{"title": "x", "time": "9am"}, "HH:MM"},
		{"add_todo", map[string]any{"title": "x", "time": "24:00"}, "HH:MM"},
		{"list_todos", map[string]any{"from": "2026-11-20", "to": "2026-11-18"}, "before"},
		{"list_todos", map[string]any{"from": "nope"}, "YYYY-MM-DD"},
		{"complete_todo", map[string]any{"id": "nope"}, "No todo with that id"},
		{"complete_todo", map[string]any{"id": todo.NewID()}, "No todo with that id"},
		{"update_todo", map[string]any{"id": a.ID}, "Nothing to change"},
		{"update_todo", map[string]any{"id": a.ID, "time": 900}, ""},
		{"update_todo", map[string]any{"id": a.ID, "date": "2026-13-01"}, "YYYY-MM-DD"},
		{"delete_todo", map[string]any{"id": todo.NewID()}, "No todo with that id"},
	}
	for _, tc := range cases {
		out := call(t, cs, tc.tool, tc.args)
		if !out.isError || !strings.Contains(out.text, tc.want) || strings.Contains(out.text, "goroutine") {
			t.Errorf("%s %v: %+v", tc.tool, tc.args, out)
		}
	}
	// Deleting twice: the second time it is gone.
	call(t, cs, "delete_todo", map[string]any{"id": a.ID})
	if out := call(t, cs, "delete_todo", map[string]any{"id": a.ID}); !out.isError {
		t.Fatalf("double delete: %+v", out)
	}
}

func TestOAuthRefreshRevokeAndRejections(t *testing.T) {
	e := newEnv(t)
	b := e.login()
	clientID, tok := e.connectClaude(b)

	// Refresh rotates; the old refresh token is single-use and reuse revokes everything.
	r := e.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID}})
	var tok2 tokens
	r.json(t, &tok2)
	if r.status != 200 || tok2.RefreshToken == tok.RefreshToken || tok2.AccessToken == "" {
		t.Fatalf("refresh: %d %s", r.status, r.body)
	}
	e.mcpSession(tok2.AccessToken) // works
	r = e.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok.RefreshToken}, "client_id": {clientID}})
	if r.status != 400 || !strings.Contains(string(r.body), "invalid_grant") {
		t.Fatalf("refresh reuse: %d %s", r.status, r.body)
	}
	if r := e.do(nil, "POST", "/mcp", tok2.AccessToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.status != 401 {
		t.Fatalf("token after reuse detection: %d", r.status)
	}

	// Revoking from the dashboard cuts off a live connection.
	_, tok3 := e.connectClaude(b)
	grants, _ := e.st.Grants(context.Background(), store.OwnerID)
	if len(grants) != 1 || grants[0].ClientName != "Claude" {
		t.Fatalf("grants: %+v", grants)
	}
	e.form(b.c, "/clients/"+grants[0].ID+"/revoke", url.Values{"csrf": {b.csrf}})
	if r := e.do(nil, "POST", "/mcp", tok3.AccessToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.status != 401 {
		t.Fatalf("revoked grant: %d", r.status)
	}

	// Expired access token.
	_, tok4 := e.connectClaude(b)
	e.clock.Add(2 * time.Hour)
	if r := e.do(nil, "POST", "/mcp", tok4.AccessToken, map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"}); r.status != 401 {
		t.Fatalf("expired token: %d", r.status)
	}
	e.clock.Add(-2 * time.Hour)

	// Code-flow rejections.
	reg := e.registerClient(map[string]any{"client_name": "Claude", "redirect_uris": []string{claudeCallback}})
	cid := reg["client_id"].(string)
	verifier, challenge := pkce()
	base := url.Values{"response_type": {"code"}, "client_id": {cid}, "redirect_uri": {claudeCallback},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s"}}
	with := func(k, v string) url.Values {
		q := url.Values{}
		for kk, vv := range base {
			q[kk] = vv
		}
		if v == "" {
			q.Del(k)
		} else {
			q.Set(k, v)
		}
		return q
	}
	// Bad client or redirect URI: an error page, never a redirect.
	for _, q := range []url.Values{with("client_id", "nxclient_unknown"), with("redirect_uri", "https://evil.example/cb")} {
		if r := e.do(b.c, "GET", "/oauth/authorize?"+q.Encode(), "", nil); r.status != 400 || r.header.Get("Location") != "" {
			t.Fatalf("untrusted redirect: %d %s", r.status, r.header.Get("Location"))
		}
	}
	// Other errors go back to the client.
	for q, wantErr := range map[*url.Values]string{
		ptr(with("code_challenge_method", "")):             "invalid_request",
		ptr(with("code_challenge", "")):                    "invalid_request",
		ptr(with("response_type", "token")):                "unsupported_response_type",
		ptr(with("resource", "https://other.example/mcp")): "invalid_target",
	} {
		r := e.do(b.c, "GET", "/oauth/authorize?"+q.Encode(), "", nil)
		loc, _ := url.Parse(r.header.Get("Location"))
		if r.status != http.StatusFound || loc.Query().Get("error") != wantErr || loc.Query().Get("state") != "s" {
			t.Fatalf("%v: %d %s", wantErr, r.status, loc)
		}
	}
	// Denying consent.
	if loc := e.authorize(b, base, "deny"); loc.Query().Get("error") != "access_denied" {
		t.Fatalf("deny: %s", loc)
	}
	// Wrong PKCE verifier, then the same code is dead even with the right one.
	loc := e.authorize(b, base, "approve")
	code := loc.Query().Get("code")
	exchange := func(v, client string) resp {
		return e.postForm("/oauth/token", url.Values{"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {claudeCallback}, "client_id": {client}, "code_verifier": {v}})
	}
	other, _ := pkce()
	if r := exchange(other, cid); r.status != 400 {
		t.Fatalf("wrong verifier: %d %s", r.status, r.body)
	}
	if r := exchange(verifier, clientID); r.status != 400 {
		t.Fatalf("other client: %d %s", r.status, r.body)
	}
	if r := exchange(verifier, cid); r.status != 200 {
		t.Fatalf("right verifier: %d %s", r.status, r.body)
	}
	if r := exchange(verifier, cid); r.status != 400 {
		t.Fatalf("code replay: %d %s", r.status, r.body)
	}
	// Unknown client at the token endpoint.
	if r := exchange(verifier, "nxclient_x"); r.status != 401 {
		t.Fatalf("unknown client: %d", r.status)
	}
	// Unauthenticated user at authorize is sent to login.
	if r := e.do(nil, "GET", "/oauth/authorize?"+base.Encode(), "", nil); r.status != http.StatusSeeOther ||
		!strings.HasPrefix(r.header.Get("Location"), "/login?next=%2Foauth%2Fauthorize%3F") {
		t.Fatalf("anonymous authorize: %d %s", r.status, r.header.Get("Location"))
	}
}

func ptr(v url.Values) *url.Values { return &v }

func TestRegistrationValidation(t *testing.T) {
	e := newEnv(t)
	for _, body := range []map[string]any{
		{"redirect_uris": []string{}},
		{"redirect_uris": []string{"http://example.com/cb"}},
		{"redirect_uris": []string{"https://example.com/cb#frag"}},
		{"redirect_uris": []string{"https://x/cb"}, "token_endpoint_auth_method": "private_key_jwt"},
		{"redirect_uris": []string{"https://x/cb"}, "grant_types": []string{"client_credentials"}},
	} {
		if r := e.do(nil, "POST", "/oauth/register", "", body); r.status != 400 {
			t.Errorf("%v: %d %s", body, r.status, r.body)
		}
	}
	// Confidential client: gets a secret and must use it.
	reg := e.registerClient(map[string]any{"client_name": "Conf", "redirect_uris": []string{"http://127.0.0.1:9/cb"},
		"token_endpoint_auth_method": "client_secret_post"})
	if reg["client_secret"] == nil {
		t.Fatal("no secret issued")
	}
	r := e.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"},
		"client_id": {reg["client_id"].(string)}, "client_secret": {"wrong"}})
	if r.status != 401 {
		t.Fatalf("bad secret: %d", r.status)
	}
	r = e.postForm("/oauth/token", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"x"},
		"client_id": {reg["client_id"].(string)}, "client_secret": {reg["client_secret"].(string)}})
	if r.status != 400 || !strings.Contains(string(r.body), "invalid_grant") {
		t.Fatalf("good secret, bad refresh: %d %s", r.status, r.body)
	}
}

func TestMCPOriginValidation(t *testing.T) {
	e := newEnv(t)
	_, tok := e.connectClaude(e.login())
	post := func(origin string) int {
		req, _ := http.NewRequest("POST", e.ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		res.Body.Close()
		return res.StatusCode
	}
	if c := post("https://evil.example"); c != 403 {
		t.Fatalf("foreign origin: %d", c)
	}
	if c := post(e.ts.URL); c == 403 {
		t.Fatal("own origin rejected")
	}
	if c := post(""); c == 403 {
		t.Fatal("no origin rejected")
	}
}

func TestLoopbackRedirectIgnoresPort(t *testing.T) {
	reg := []string{"http://localhost/callback", "https://claude.ai/api/mcp/auth_callback"}
	for got, want := range map[string]bool{
		"http://localhost:3118/callback":              true,
		"http://localhost/callback":                   true,
		"http://127.0.0.1:3118/callback":              false, // different host than registered
		"http://localhost:3118/other":                 false,
		"https://claude.ai/api/mcp/auth_callback":     true,
		"https://claude.ai:444/api/mcp/auth_callback": false,
		"http://evil.example:3118/callback":           false,
	} {
		if redirectAllowed(reg, got) != want {
			t.Errorf("%s: want %v", got, want)
		}
	}
}
