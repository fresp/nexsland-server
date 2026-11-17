// Package server wires the HTTP interfaces: REST sync and pairing for
// Nexsland, OAuth and MCP for Claude, and the owner's web pages.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/fresp/nexsland-server/internal/config"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

// Version is set at build time with -ldflags "-X .../server.Version=...".
var Version = "dev"

// Server holds shared state for all handlers.
type Server struct {
	cfg   *config.Config
	store *store.Store
	clock todo.Clock
	log   *slog.Logger

	loginIP     *limiter
	loginGlobal *rate.Limiter
	pairIP      *limiter
}

// New builds a Server. now may be nil (wall clock).
func New(cfg *config.Config, st *store.Store, log *slog.Logger, now func() time.Time) *Server {
	if now == nil {
		now = time.Now
	}
	return &Server{
		cfg:         cfg,
		store:       st,
		clock:       todo.Clock{Loc: cfg.Location, Now: now},
		log:         log,
		loginIP:     newLimiter(rate.Every(12*time.Second), 5),
		loginGlobal: rate.NewLimiter(rate.Every(2*time.Second), 20),
		pairIP:      newLimiter(rate.Every(6*time.Second), 10),
	}
}

// Handler returns the root handler with all routes and middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)

	// REST sync API (Nexsland). Bearer device tokens; no cookies, no CORS.
	mux.Handle("GET /v1/todos", s.requireDevice(s.listChanges))
	mux.Handle("POST /v1/ops", s.requireDevice(s.postOps))
	mux.Handle("GET /v1/me", s.requireDevice(s.me))
	mux.HandleFunc("POST /v1/pair/start", s.pairStart)
	mux.HandleFunc("POST /v1/pair/token", s.pairToken)
	mux.HandleFunc("/v1/", func(w http.ResponseWriter, r *http.Request) {
		apiError(w, http.StatusNotFound, "not_found", "no such endpoint")
	})

	// Owner web pages: cookie session, CSRF token, Fetch-metadata check.
	web := http.NewServeMux()
	web.HandleFunc("GET /login", s.loginPage)
	web.HandleFunc("POST /login", s.loginSubmit)
	web.Handle("POST /logout", s.requireOwner(s.logout))
	web.Handle("GET /{$}", s.requireOwner(s.dashboard))
	web.Handle("POST /devices/{id}/revoke", s.requireOwner(s.revokeDevice))
	web.Handle("POST /clients/{id}/revoke", s.requireOwner(s.revokeClient))
	web.Handle("GET /pair", s.requireOwner(s.pairPage))
	web.Handle("POST /pair", s.requireOwner(s.pairDecide))
	cop := http.NewCrossOriginProtection()
	webHandler := cop.Handler(web)
	for _, p := range []string{"/login", "/logout", "/{$}", "/devices/", "/clients/", "/pair"} {
		mux.Handle(p, webHandler)
	}

	return s.recoverer(s.logRequests(s.securityHeaders(mux)))
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.store.Ping(ctx); err != nil {
		s.log.Error("health check failed", "err", err)
		apiError(w, http.StatusServiceUnavailable, "unavailable", "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy", csp(""))
		h.Set("Cache-Control", "no-store")
		if s.cfg.Secure() {
			h.Set("Strict-Transport-Security", "max-age=63072000")
		}
		next.ServeHTTP(w, r)
	})
}

// csp builds the policy; extraFormAction allows a form POST to redirect to an
// OAuth client's origin (Chrome applies form-action to redirects).
func csp(extraFormAction string) string {
	fa := "'self'"
	if extraFormAction != "" {
		fa += " " + extraFormAction
	}
	return "default-src 'none'; style-src 'unsafe-inline'; img-src 'self' data:; form-action " + fa +
		"; frame-ancestors 'none'; base-uri 'none'"
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// logRequests logs method, matched route pattern, status and duration. It never
// logs the query string, headers or bodies: they can hold codes, tokens and titles.
func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w}
		next.ServeHTTP(sw, r)
		route := r.Pattern
		if route == "" {
			route = "unmatched"
		}
		level := slog.LevelInfo
		if r.URL.Path == "/healthz" {
			level = slog.LevelDebug
		}
		s.log.Log(r.Context(), level, "request", "method", r.Method, "route", route, "status", sw.status,
			"duration_ms", time.Since(start).Milliseconds())
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				if v == http.ErrAbortHandler {
					panic(v)
				}
				s.log.Error("panic", "route", r.Pattern, "panic", v)
				apiError(w, http.StatusInternalServerError, "internal", "internal error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// clientIP returns the caller's IP. Forwarding headers are trusted only when
// the TCP peer is a loopback or private address, i.e. the reverse proxy.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	if peer.IsLoopback() || peer.IsPrivate() {
		if v := strings.TrimSpace(r.Header.Get("X-Real-IP")); v != "" {
			if a, err := netip.ParseAddr(v); err == nil {
				return a.String()
			}
		}
		if v := r.Header.Get("X-Forwarded-For"); v != "" {
			parts := strings.Split(v, ",")
			if a, err := netip.ParseAddr(strings.TrimSpace(parts[len(parts)-1])); err == nil {
				return a.String()
			}
		}
	}
	return peer.String()
}

// limiter is a per-key token bucket with idle eviction.
type limiter struct {
	mu    sync.Mutex
	every rate.Limit
	burst int
	m     map[string]*limEntry
	last  time.Time
}

type limEntry struct {
	l    *rate.Limiter
	seen time.Time
}

func newLimiter(every rate.Limit, burst int) *limiter {
	return &limiter{every: every, burst: burst, m: map[string]*limEntry{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if now.Sub(l.last) > 10*time.Minute {
		for k, e := range l.m {
			if now.Sub(e.seen) > time.Hour {
				delete(l.m, k)
			}
		}
		l.last = now
	}
	e, ok := l.m[key]
	if !ok {
		e = &limEntry{l: rate.NewLimiter(l.every, l.burst)}
		l.m[key] = e
	}
	e.seen = now
	return e.l.Allow()
}

// API helpers.

type apiErr struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func apiError(w http.ResponseWriter, status int, code, msg string) {
	var e apiErr
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON reads a size-limited JSON body with unknown fields rejected.
func decodeJSON(w http.ResponseWriter, r *http.Request, max int64, v any) bool {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		apiError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type must be application/json")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, max))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			apiError(w, http.StatusRequestEntityTooLarge, "too_large", "request body too large")
			return false
		}
		apiError(w, http.StatusBadRequest, "bad_json", "invalid JSON body: "+jsonErrMsg(err))
		return false
	}
	return true
}

// jsonErrMsg keeps decoder errors useful without echoing values back.
func jsonErrMsg(err error) string {
	var te *json.UnmarshalTypeError
	if errors.As(err, &te) {
		return "field " + te.Field + " has the wrong type"
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field") || strings.HasPrefix(msg, "parsing time") {
		return msg
	}
	if strings.HasPrefix(msg, "unexpected EOF") || strings.Contains(msg, "invalid character") {
		return "malformed JSON"
	}
	return "malformed JSON"
}
