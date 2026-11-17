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
	"unicode/utf8"

	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

const (
	maxOpsBody     = 1 << 20
	maxOpsPerBatch = 500
	defaultPage    = 500
	maxPage        = 1000
	maxClockSkew   = 5 * time.Minute

	devicePrefix   = "nxd_"
	pairCodeTTL    = 10 * time.Minute
	pairInterval   = 5 * time.Second
	maxPendingPair = 20
)

type deviceKey struct{}

func deviceFrom(ctx context.Context) store.Device {
	d, _ := ctx.Value(deviceKey{}).(store.Device)
	return d
}

func bearer(r *http.Request) string {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(tok)
}

func (s *Server) requireDevice(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := bearer(r)
		if !strings.HasPrefix(tok, devicePrefix) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="nexsland"`)
			apiError(w, http.StatusUnauthorized, "unauthorized", "missing or malformed device token")
			return
		}
		d, err := s.store.DeviceByToken(r.Context(), secret.Hash(tok))
		if errors.Is(err, store.ErrNotFound) {
			w.Header().Set("WWW-Authenticate", `Bearer realm="nexsland", error="invalid_token"`)
			apiError(w, http.StatusUnauthorized, "unauthorized", "unknown or revoked device token")
			return
		}
		if err != nil {
			s.internal(w, r, err)
			return
		}
		h(w, r.WithContext(context.WithValue(r.Context(), deviceKey{}, d)))
	})
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, err error) {
	s.log.Error("internal error", "route", r.Pattern, "err", err)
	apiError(w, http.StatusInternalServerError, "internal", "internal error")
}

type changesResponse struct {
	Todos []todo.Todo `json:"todos"`
	Next  int64       `json:"next"`
	More  bool        `json:"more"`
}

func (s *Server) listChanges(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	since, err := intParam(q.Get("since"), 0)
	if err != nil || since < 0 {
		apiError(w, http.StatusBadRequest, "invalid_param", "since must be a non-negative integer")
		return
	}
	limit, err := intParam(q.Get("limit"), defaultPage)
	if err != nil || limit < 1 || limit > maxPage {
		apiError(w, http.StatusBadRequest, "invalid_param", fmt.Sprintf("limit must be between 1 and %d", maxPage))
		return
	}
	d := deviceFrom(r.Context())
	todos, more, err := s.store.Changes(r.Context(), d.UserID, since, int(limit))
	if err != nil {
		s.internal(w, r, err)
		return
	}
	next := since
	if len(todos) > 0 {
		next = todos[len(todos)-1].Seq
	}
	writeJSON(w, http.StatusOK, changesResponse{Todos: todos, Next: next, More: more})
}

func intParam(s string, def int64) (int64, error) {
	if s == "" {
		return def, nil
	}
	return strconv.ParseInt(s, 10, 64)
}

type opIn struct {
	Op        string          `json:"op"`
	Todo      json.RawMessage `json:"todo,omitempty"`
	ID        string          `json:"id,omitempty"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty"`
}

type todoIn struct {
	ID        string     `json:"id"`
	Title     string     `json:"title"`
	Day       string     `json:"day"`
	Minutes   *int       `json:"minutes"`
	Done      bool       `json:"done"`
	CreatedAt *time.Time `json:"created_at"`
	UpdatedAt *time.Time `json:"updated_at"`
	Deleted   bool       `json:"deleted"`
	Seq       int64      `json:"seq"` // accepted and ignored: the server owns seq
}

type opsResponse struct {
	Results []store.Result `json:"results"`
	MaxSeq  int64          `json:"max_seq"`
}

func (s *Server) postOps(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ops []opIn `json:"ops"`
	}
	if !decodeJSON(w, r, maxOpsBody, &body) {
		return
	}
	if len(body.Ops) == 0 {
		apiError(w, http.StatusUnprocessableEntity, "invalid_op", "ops must not be empty")
		return
	}
	if len(body.Ops) > maxOpsPerBatch {
		apiError(w, http.StatusRequestEntityTooLarge, "too_many_ops", fmt.Sprintf("at most %d ops per batch", maxOpsPerBatch))
		return
	}
	now := s.clock.NowUTC()
	ops := make([]store.Op, 0, len(body.Ops))
	seen := map[string]bool{}
	for i, in := range body.Ops {
		op, err := parseOp(in)
		if err == nil && seen[op.Todo.ID] {
			err = errors.New("id appears more than once in this batch")
		}
		if err != nil {
			apiError(w, http.StatusUnprocessableEntity, "invalid_op", fmt.Sprintf("ops[%d]: %v", i, err))
			return
		}
		if op.Todo.UpdatedAt.Sub(now) > maxClockSkew {
			apiError(w, http.StatusUnprocessableEntity, "clock_skew",
				fmt.Sprintf("ops[%d]: updated_at is more than 5 minutes ahead of server time %s", i, now.Format(time.RFC3339)))
			return
		}
		seen[op.Todo.ID] = true
		ops = append(ops, op)
	}
	d := deviceFrom(r.Context())
	results, err := s.store.ApplyOps(r.Context(), d.UserID, ops)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	maxSeq, err := s.store.MaxSeq(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, opsResponse{Results: results, MaxSeq: maxSeq})
}

func parseOp(in opIn) (store.Op, error) {
	switch in.Op {
	case store.OpUpsert:
		if len(in.Todo) == 0 || in.ID != "" || in.UpdatedAt != nil {
			return store.Op{}, errors.New("upsert takes only a todo object")
		}
		var t todoIn
		dec := json.NewDecoder(strings.NewReader(string(in.Todo)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&t); err != nil {
			return store.Op{}, fmt.Errorf("todo: %s", jsonErrMsg(err))
		}
		td := todo.Todo{ID: t.ID, Title: t.Title, Day: t.Day, Minutes: t.Minutes, Done: t.Done, Deleted: t.Deleted}
		if t.UpdatedAt != nil {
			td.UpdatedAt = *t.UpdatedAt
		}
		if t.CreatedAt != nil {
			td.CreatedAt = *t.CreatedAt
		}
		if err := td.Normalize(); err != nil {
			return store.Op{}, err
		}
		return store.Op{Kind: store.OpUpsert, Todo: td}, nil
	case store.OpDelete:
		if len(in.Todo) != 0 {
			return store.Op{}, errors.New("delete takes id and updated_at, not a todo")
		}
		if err := todo.ValidID(in.ID); err != nil {
			return store.Op{}, err
		}
		if in.UpdatedAt == nil {
			return store.Op{}, errors.New("updated_at: is required")
		}
		return store.Op{Kind: store.OpDelete, Todo: todo.Todo{ID: in.ID, UpdatedAt: todo.Millis(*in.UpdatedAt)}}, nil
	default:
		return store.Op{}, fmt.Errorf("op must be %q or %q", store.OpUpsert, store.OpDelete)
	}
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	maxSeq, err := s.store.MaxSeq(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	d := deviceFrom(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"time_zone":      s.cfg.Location.String(),
		"today":          s.clock.Today(),
		"server_version": Version,
		"max_seq":        maxSeq,
		"device":         map[string]string{"id": d.ID, "name": d.Name},
	})
}

// Pairing (RFC 8628 shaped).

func (s *Server) pairStart(w http.ResponseWriter, r *http.Request) {
	if !s.pairIP.allow(clientIP(r)) {
		apiError(w, http.StatusTooManyRequests, "rate_limited", "too many pairing attempts, try again later")
		return
	}
	var body struct {
		DeviceName string `json:"device_name"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	name := strings.TrimSpace(body.DeviceName)
	if name == "" {
		name = "Nexsland"
	}
	if utf8.RuneCountInString(name) > 64 {
		apiError(w, http.StatusUnprocessableEntity, "invalid_param", "device_name must be at most 64 characters")
		return
	}
	n, err := s.store.CountPendingPairs(r.Context())
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if n >= maxPendingPair {
		apiError(w, http.StatusTooManyRequests, "rate_limited", "too many pending pairing requests")
		return
	}
	deviceCode := secret.Token("nxp_")
	var userCode string
	for range 5 { // retry on the (unlikely) user code collision
		userCode = secret.UserCode()
		err = s.store.CreatePairRequest(r.Context(), store.PairRequest{
			DeviceCodeHash: secret.Hash(deviceCode), UserCode: userCode, DeviceName: name,
			ExpiresAt: s.clock.NowUTC().Add(pairCodeTTL),
		})
		if err == nil || !strings.Contains(err.Error(), "UNIQUE") {
			break
		}
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          s.cfg.Public() + "/pair",
		"verification_uri_complete": s.cfg.Public() + "/pair?code=" + userCode,
		"expires_in":                int(pairCodeTTL.Seconds()),
		"interval":                  int(pairInterval.Seconds()),
	})
}

func (s *Server) pairToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DeviceCode string `json:"device_code"`
	}
	if !decodeJSON(w, r, 4<<10, &body) {
		return
	}
	h := secret.Hash(body.DeviceCode)
	p, err := s.store.PollPair(r.Context(), h)
	if errors.Is(err, store.ErrNotFound) {
		apiError(w, http.StatusBadRequest, "invalid_grant", "unknown device_code")
		return
	}
	if err != nil {
		s.internal(w, r, err)
		return
	}
	now := s.clock.NowUTC()
	switch {
	case p.Status == store.PairDelivered:
		apiError(w, http.StatusBadRequest, "expired_token", "this device code was already used")
	case p.Status == store.PairDenied:
		apiError(w, http.StatusBadRequest, "access_denied", "the owner denied this device")
	case now.After(p.ExpiresAt):
		apiError(w, http.StatusBadRequest, "expired_token", "the pairing code expired; start again")
	case p.Status == store.PairPending && p.LastPollAt != nil && now.Sub(*p.LastPollAt) < pairInterval-500*time.Millisecond:
		apiError(w, http.StatusBadRequest, "slow_down", "polling too fast; add 5 seconds to the interval")
	case p.Status == store.PairPending:
		apiError(w, http.StatusBadRequest, "authorization_pending", "waiting for the owner to approve the code")
	default: // approved
		tok := secret.Token(devicePrefix)
		d := store.Device{ID: todo.NewID(), UserID: p.UserID, Name: p.DeviceName}
		if err := s.store.CompletePair(r.Context(), h, d, secret.Hash(tok)); err != nil {
			if errors.Is(err, store.ErrNotFound) { // a concurrent poll won
				apiError(w, http.StatusBadRequest, "expired_token", "this device code was already used")
				return
			}
			s.internal(w, r, err)
			return
		}
		s.log.Info("device paired", "device_id", d.ID)
		writeJSON(w, http.StatusOK, map[string]string{"token": tok, "token_type": "Bearer", "device_id": d.ID})
	}
}
