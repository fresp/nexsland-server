package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

const listDefaultDays = 7

// verifyAccessToken is the MCP endpoint's token verifier: opaque tokens looked
// up by hash, accepted only if issued for this resource (no passthrough).
func (s *Server) verifyAccessToken(ctx context.Context, tok string, _ *http.Request) (*auth.TokenInfo, error) {
	if !strings.HasPrefix(tok, accessPref) {
		return nil, fmt.Errorf("%w: not an access token", auth.ErrInvalidToken)
	}
	g, exp, err := s.store.AccessToken(ctx, secret.Hash(tok))
	if errors.Is(err, store.ErrNotFound) {
		return nil, fmt.Errorf("%w: unknown or revoked token", auth.ErrInvalidToken)
	}
	if err != nil {
		return nil, err
	}
	if g.Resource != s.resourceURI() {
		return nil, fmt.Errorf("%w: token audience mismatch", auth.ErrInvalidToken)
	}
	remaining := exp.Sub(s.clock.NowUTC())
	if remaining <= 0 {
		return nil, fmt.Errorf("%w: token expired", auth.ErrInvalidToken)
	}
	return &auth.TokenInfo{
		Scopes: strings.Fields(g.Scope),
		// The middleware re-checks expiry against the wall clock; express it
		// relative to now so the server's (injectable) clock stays authoritative.
		Expiration: time.Now().Add(remaining),
		UserID:     strconv.FormatInt(g.UserID, 10),
		Extra:      map[string]any{"grant_id": g.ID},
	}, nil
}

func (s *Server) mcpHandler() http.Handler {
	srv := s.NewMCPServer()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, &mcp.StreamableHTTPOptions{
		Stateless:    true,
		JSONResponse: true,
		// Every request carries a bearer token bound to this resource, which
		// is what defeats DNS rebinding here. The built-in check would reject
		// a reverse proxy on the same host (loopback peer, public Host header).
		DisableLocalhostProtection: true,
		MaxRequestBodyBytes:        256 << 10,
	})
	return auth.RequireBearerToken(s.verifyAccessToken, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: s.resourceMetadataURL(),
		Scopes:              []string{scopeTodos},
	})(h)
}

// NewMCPServer builds the MCP server with the todo tools.
func (s *Server) NewMCPServer() *mcp.Server {
	srv := mcp.NewServer(&mcp.Implementation{Name: "nexsland-server", Title: "Nexsland todos", Version: Version},
		&mcp.ServerOptions{Instructions: "Todo list synced with the Nexsland desktop app. Every result starts with today's " +
			"date in the owner's time zone; resolve relative dates such as \"tomorrow\" from it and always pass explicit " +
			"YYYY-MM-DD dates and 24-hour HH:MM times."})
	yes := true
	mcp.AddTool(srv, &mcp.Tool{
		Name: "add_todo",
		Description: "Add a todo. Pass `date` as an explicit YYYY-MM-DD date between today and one year ahead " +
			"(resolve words like \"tomorrow\" using today's date from a previous result or list_todos); it defaults to today. " +
			"Pass `time` as 24-hour HH:MM only if the user gave a time; Nexsland announces timed todos as reminders.",
		Annotations: &mcp.ToolAnnotations{Title: "Add todo", OpenWorldHint: new(bool)},
	}, s.toolAdd)
	mcp.AddTool(srv, &mcp.Tool{
		Name: "list_todos",
		Description: "List todos. Without arguments: today and the next 7 days, plus unfinished todos from earlier days " +
			"flagged overdue. `from` and `to` are explicit YYYY-MM-DD dates (inclusive). Done todos are hidden unless include_done is true.",
		Annotations: &mcp.ToolAnnotations{Title: "List todos", ReadOnlyHint: true, OpenWorldHint: new(bool)},
	}, s.toolList)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "complete_todo",
		Description: "Mark a todo done by its id (from list_todos or add_todo).",
		Annotations: &mcp.ToolAnnotations{Title: "Complete todo", IdempotentHint: true, OpenWorldHint: new(bool)},
	}, s.toolSetDone(true))
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "reopen_todo",
		Description: "Mark a done todo as not done again, by its id.",
		Annotations: &mcp.ToolAnnotations{Title: "Reopen todo", IdempotentHint: true, OpenWorldHint: new(bool)},
	}, s.toolSetDone(false))
	mcp.AddTool(srv, &mcp.Tool{
		Name: "update_todo",
		Description: "Change a todo's title, date or time by its id. Pass only the fields to change. `date` is an explicit " +
			"YYYY-MM-DD date between today and one year ahead; `time` is 24-hour HH:MM, or null to remove the time.",
		Annotations: &mcp.ToolAnnotations{Title: "Update todo", IdempotentHint: true, OpenWorldHint: new(bool)},
		InputSchema: updateSchema(),
	}, s.toolUpdate)
	mcp.AddTool(srv, &mcp.Tool{
		Name:        "delete_todo",
		Description: "Delete a todo by its id. This removes it from every synced device.",
		Annotations: &mcp.ToolAnnotations{Title: "Delete todo", DestructiveHint: &yes, IdempotentHint: true, OpenWorldHint: new(bool)},
	}, s.toolDelete)
	return srv
}

func updateSchema() *jsonschema.Schema {
	str := func(desc string) *jsonschema.Schema { return &jsonschema.Schema{Type: "string", Description: desc} }
	return &jsonschema.Schema{
		Type:     "object",
		Required: []string{"id"},
		Properties: map[string]*jsonschema.Schema{
			"id":    str("todo id"),
			"title": str("new title, 1-200 characters"),
			"date":  str("new date, YYYY-MM-DD"),
			"time":  {Types: []string{"string", "null"}, Description: "new time as HH:MM, or null to remove the time"},
		},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}},
	}
}

// todoView is how a todo is shown to Claude.
type todoView struct {
	ID      string  `json:"id"`
	Title   string  `json:"title"`
	Date    string  `json:"date"`
	Time    *string `json:"time"`
	Done    bool    `json:"done"`
	Overdue bool    `json:"overdue,omitempty"`
}

func (s *Server) view(t todo.Todo, today string) todoView {
	v := todoView{ID: t.ID, Title: t.Title, Date: t.Day, Done: t.Done, Overdue: !t.Done && t.Day < today}
	if t.Minutes != nil {
		hm := todo.FormatTime(*t.Minutes)
		v.Time = &hm
	}
	return v
}

// result renders a tool result: today's date line first, then JSON.
func (s *Server) result(today, summary string, payload any) (*mcp.CallToolResult, any, error) {
	b, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	d, _ := time.Parse("2006-01-02", today)
	head := fmt.Sprintf("Today is %s (%s, time zone %s). %s", today, d.Weekday(), s.cfg.Location, summary)
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: head + "\n" + string(b)}}}, nil, nil
}

// toolErr is a readable error shown to Claude; anything else is logged and
// reported generically.
type toolErr struct{ msg string }

func (e toolErr) Error() string { return e.msg }

func (s *Server) toolFailure(ctx context.Context, today string, err error) (*mcp.CallToolResult, any, error) {
	var te toolErr
	var msg string
	switch {
	case errors.As(err, &te):
		msg = te.msg
	case todo.IsValidation(err):
		msg = "Invalid input: " + err.Error()
	case errors.Is(err, store.ErrNotFound):
		msg = "No todo with that id (it may have been deleted). Call list_todos to get current ids."
	default:
		s.log.ErrorContext(ctx, "mcp tool failed", "err", err)
		msg = "Internal server error; try again."
	}
	r := &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Today is %s. %s", today, msg)}}}
	return r, nil, nil
}

func userIDFrom(req *mcp.CallToolRequest) (int64, error) {
	if req.Extra == nil || req.Extra.TokenInfo == nil {
		return 0, toolErr{"Not authorized."}
	}
	id, err := strconv.ParseInt(req.Extra.TokenInfo.UserID, 10, 64)
	if err != nil {
		return 0, toolErr{"Not authorized."}
	}
	return id, nil
}

// checkDate validates a date Claude asks to schedule: today up to one year ahead.
func checkDate(date, today string) error {
	d, err := todo.ParseDay(date)
	if err != nil {
		return toolErr{fmt.Sprintf("date must be an explicit YYYY-MM-DD date, got %q.", date)}
	}
	t, _ := todo.ParseDay(today)
	if date < today {
		return toolErr{fmt.Sprintf("date %s is in the past; use today (%s) or later.", date, today)}
	}
	if d.After(t.AddDate(1, 0, 0)) {
		return toolErr{fmt.Sprintf("date %s is more than one year ahead (latest is %s).", date, t.AddDate(1, 0, 0).Format("2006-01-02"))}
	}
	return nil
}

func parseHM(s string) (*int, error) {
	m, err := todo.ParseTime(s)
	if err != nil {
		return nil, toolErr{fmt.Sprintf("time must be 24-hour HH:MM such as 09:00 or 17:30, got %q.", s)}
	}
	return &m, nil
}

type addIn struct {
	Title string `json:"title" jsonschema:"what to do, 1-200 characters"`
	Date  string `json:"date,omitempty" jsonschema:"YYYY-MM-DD; defaults to today"`
	Time  string `json:"time,omitempty" jsonschema:"24-hour HH:MM; omit for no time"`
}

func (s *Server) toolAdd(ctx context.Context, req *mcp.CallToolRequest, in addIn) (*mcp.CallToolResult, any, error) {
	today := s.clock.Today()
	uid, err := userIDFrom(req)
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	t := todo.Todo{ID: todo.NewID(), Title: in.Title, Day: in.Date, UpdatedAt: s.clock.NowUTC()}
	if t.Day == "" {
		t.Day = today
	}
	if err := checkDate(t.Day, today); err != nil {
		return s.toolFailure(ctx, today, err)
	}
	if in.Time != "" {
		if t.Minutes, err = parseHM(in.Time); err != nil {
			return s.toolFailure(ctx, today, err)
		}
	}
	if err := t.Normalize(); err != nil {
		return s.toolFailure(ctx, today, err)
	}
	res, err := s.store.ApplyOps(ctx, uid, []store.Op{{Kind: store.OpUpsert, Todo: t}})
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	return s.result(today, "Added:", s.view(res[0].Todo, today))
}

type listIn struct {
	From        string `json:"from,omitempty" jsonschema:"first date, YYYY-MM-DD; defaults to today"`
	To          string `json:"to,omitempty" jsonschema:"last date, YYYY-MM-DD; defaults to 7 days after from"`
	IncludeDone bool   `json:"include_done,omitempty" jsonschema:"also list done todos"`
}

func (s *Server) toolList(ctx context.Context, req *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, any, error) {
	today := s.clock.Today()
	uid, err := userIDFrom(req)
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	from, to := in.From, in.To
	if from == "" {
		from = today
	}
	if to == "" {
		to = todo.AddDays(from, listDefaultDays)
	}
	for _, d := range []string{from, to} {
		if _, err := todo.ParseDay(d); err != nil {
			return s.toolFailure(ctx, today, toolErr{fmt.Sprintf("from and to must be YYYY-MM-DD dates, got %q.", d)})
		}
	}
	if to < from {
		return s.toolFailure(ctx, today, toolErr{"to must not be before from."})
	}
	if to > todo.AddDays(from, 400) {
		return s.toolFailure(ctx, today, toolErr{"range too long; list at most about a year at a time."})
	}
	overdueBefore := ""
	if from <= today && today <= to {
		overdueBefore = from
	}
	todos, err := s.store.ListDays(ctx, uid, from, to, in.IncludeDone, overdueBefore)
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	views := make([]todoView, 0, len(todos))
	overdue := 0
	for _, t := range todos {
		v := s.view(t, today)
		if v.Overdue {
			overdue++
		}
		views = append(views, v)
	}
	summary := fmt.Sprintf("%d todos from %s to %s", len(views), from, to)
	if overdueBefore != "" {
		summary += fmt.Sprintf(", including %d overdue", overdue)
	}
	return s.result(today, summary+":", views)
}

type idIn struct {
	ID string `json:"id" jsonschema:"todo id"`
}

func (s *Server) toolSetDone(done bool) mcp.ToolHandlerFor[idIn, any] {
	return func(ctx context.Context, req *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, any, error) {
		today := s.clock.Today()
		uid, err := userIDFrom(req)
		if err != nil {
			return s.toolFailure(ctx, today, err)
		}
		if todo.ValidID(in.ID) != nil {
			return s.toolFailure(ctx, today, store.ErrNotFound)
		}
		t, err := s.store.Mutate(ctx, uid, in.ID, s.clock.NowUTC(), func(t *todo.Todo) error {
			t.Done = done
			return nil
		})
		if err != nil {
			return s.toolFailure(ctx, today, err)
		}
		verb := "Completed:"
		if !done {
			verb = "Reopened:"
		}
		return s.result(today, verb, s.view(t, today))
	}
}

type updateIn struct {
	ID    string          `json:"id"`
	Title *string         `json:"title"`
	Date  *string         `json:"date"`
	Time  json.RawMessage `json:"time"`
}

func (s *Server) toolUpdate(ctx context.Context, req *mcp.CallToolRequest, in updateIn) (*mcp.CallToolResult, any, error) {
	today := s.clock.Today()
	uid, err := userIDFrom(req)
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	if todo.ValidID(in.ID) != nil {
		return s.toolFailure(ctx, today, store.ErrNotFound)
	}
	if in.Title == nil && in.Date == nil && len(in.Time) == 0 {
		return s.toolFailure(ctx, today, toolErr{"Nothing to change: pass title, date or time."})
	}
	var title string
	if in.Title != nil {
		if title, err = todo.NormalizeTitle(*in.Title); err != nil {
			return s.toolFailure(ctx, today, err)
		}
	}
	if in.Date != nil {
		if err := checkDate(*in.Date, today); err != nil {
			return s.toolFailure(ctx, today, err)
		}
	}
	var minutes *int
	clearTime := string(in.Time) == "null"
	if len(in.Time) > 0 && !clearTime {
		var hm string
		if json.Unmarshal(in.Time, &hm) != nil {
			return s.toolFailure(ctx, today, toolErr{"time must be a HH:MM string or null."})
		}
		if minutes, err = parseHM(hm); err != nil {
			return s.toolFailure(ctx, today, err)
		}
	}
	t, err := s.store.Mutate(ctx, uid, in.ID, s.clock.NowUTC(), func(t *todo.Todo) error {
		if in.Title != nil {
			t.Title = title
		}
		if in.Date != nil {
			t.Day = *in.Date
		}
		if clearTime {
			t.Minutes = nil
		} else if minutes != nil {
			t.Minutes = minutes
		}
		return nil
	})
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	return s.result(today, "Updated:", s.view(t, today))
}

func (s *Server) toolDelete(ctx context.Context, req *mcp.CallToolRequest, in idIn) (*mcp.CallToolResult, any, error) {
	today := s.clock.Today()
	uid, err := userIDFrom(req)
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	if todo.ValidID(in.ID) != nil {
		return s.toolFailure(ctx, today, store.ErrNotFound)
	}
	t, err := s.store.Delete(ctx, uid, in.ID, s.clock.NowUTC())
	if err != nil {
		return s.toolFailure(ctx, today, err)
	}
	return s.result(today, "Deleted:", map[string]string{"id": t.ID, "title": t.Title})
}
