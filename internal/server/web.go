package server

import (
	"context"
	"embed"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

var pages = template.Must(template.New("").Funcs(template.FuncMap{
	"fmtTime": func(v any) string {
		switch t := v.(type) {
		case time.Time:
			return t.UTC().Format("2006-01-02 15:04 UTC")
		case *time.Time:
			if t != nil {
				return t.UTC().Format("2006-01-02 15:04 UTC")
			}
		}
		return ""
	},
}).ParseFS(templateFS, "templates/*.html"))

const (
	sessionTTL      = 7 * 24 * time.Hour
	loginCSRFCookie = "nexsland_login_csrf"
)

func (s *Server) sessionCookieName() string {
	if s.cfg.Secure() {
		return "__Host-nexsland_session"
	}
	return "nexsland_session"
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data map[string]any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := pages.ExecuteTemplate(w, name, data); err != nil {
		s.log.Error("template", "name", name, "err", err)
	}
}

func (s *Server) message(w http.ResponseWriter, status int, title, msg string) {
	s.render(w, status, "message", map[string]any{"Title": title, "Message": msg})
}

type sessionKey struct{}

type webSession struct {
	store.Session
	idHash string
}

func sessionFrom(ctx context.Context) webSession {
	v, _ := ctx.Value(sessionKey{}).(webSession)
	return v
}

func (s *Server) currentSession(r *http.Request) (webSession, bool) {
	c, err := r.Cookie(s.sessionCookieName())
	if err != nil || c.Value == "" {
		return webSession{}, false
	}
	h := secret.Hash(c.Value)
	sess, err := s.store.SessionByID(r.Context(), h)
	if err != nil {
		return webSession{}, false
	}
	return webSession{Session: sess, idHash: h}, true
}

// requireOwner redirects to the login page without a session, and checks the
// CSRF token on every unsafe request.
func (s *Server) requireOwner(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := s.currentSession(r)
		if !ok {
			if r.Method != http.MethodGet {
				s.message(w, http.StatusUnauthorized, "Signed out", "Your session ended. Sign in and try again.")
				return
			}
			http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if !secret.Equal(r.PostFormValue("csrf"), sess.CSRF) {
				s.message(w, http.StatusForbidden, "Request blocked", "The form expired or did not come from this site. Go back, reload and try again.")
				return
			}
		}
		h(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, sess)))
	})
}

func safeNext(next string) string {
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		return "/"
	}
	return next
}

func (s *Server) loginCSRF(w http.ResponseWriter, r *http.Request) string {
	if c, err := r.Cookie(loginCSRFCookie); err == nil && len(c.Value) > 20 {
		return c.Value
	}
	v := secret.Token("")
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: v, Path: "/login", HttpOnly: true,
		Secure: s.cfg.Secure(), SameSite: http.SameSiteStrictMode, MaxAge: 3600})
	return v
}

func (s *Server) loginPage(w http.ResponseWriter, r *http.Request) {
	next := safeNext(r.URL.Query().Get("next"))
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, next, http.StatusSeeOther)
		return
	}
	s.renderLogin(w, r, http.StatusOK, next, "")
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, status int, next, errMsg string) {
	hash, err := s.store.PasswordHash(r.Context(), store.OwnerID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, status, "login", map[string]any{
		"Title": "Sign in", "CSRF": s.loginCSRF(w, r), "Next": next, "Error": errMsg, "NoPassword": hash == "",
	})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	next := safeNext(r.PostFormValue("next"))
	c, err := r.Cookie(loginCSRFCookie)
	if err != nil || !secret.Equal(c.Value, r.PostFormValue("csrf")) {
		s.renderLogin(w, r, http.StatusForbidden, next, "The form expired. Try again.")
		return
	}
	ip := clientIP(r)
	if !s.loginIP.allow(ip) || !s.loginGlobal.Allow() {
		s.log.Warn("login rate limited")
		s.renderLogin(w, r, http.StatusTooManyRequests, next, "Too many attempts. Wait a minute and try again.")
		return
	}
	hash, err := s.store.PasswordHash(r.Context(), store.OwnerID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	if hash == "" || !secret.VerifyPassword(hash, r.PostFormValue("password")) {
		s.log.Warn("login failed")
		s.renderLogin(w, r, http.StatusUnauthorized, next, "Wrong password.")
		return
	}
	id := secret.Token("")
	sess := store.Session{UserID: store.OwnerID, CSRF: secret.Token("")}
	if err := s.store.CreateSession(r.Context(), secret.Hash(id), sess, s.clock.NowUTC().Add(sessionTTL)); err != nil {
		s.internal(w, r, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(), Value: id, Path: "/", HttpOnly: true,
		Secure: s.cfg.Secure(), SameSite: http.SameSiteLaxMode, MaxAge: int(sessionTTL.Seconds())})
	http.SetCookie(w, &http.Cookie{Name: loginCSRFCookie, Value: "", Path: "/login", MaxAge: -1})
	s.log.Info("owner signed in")
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	_ = s.store.DeleteSession(r.Context(), sessionFrom(r.Context()).idHash)
	http.SetCookie(w, &http.Cookie{Name: s.sessionCookieName(), Value: "", Path: "/", MaxAge: -1,
		Secure: s.cfg.Secure(), HttpOnly: true})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) dashboard(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	devices, err := s.store.Devices(r.Context(), sess.UserID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	grants, err := s.store.Grants(r.Context(), sess.UserID)
	if err != nil {
		s.internal(w, r, err)
		return
	}
	s.render(w, http.StatusOK, "dashboard", map[string]any{
		"Title": "Devices and clients", "CSRF": sess.CSRF, "Devices": devices, "Grants": grants,
		"Version": Version,
	})
}

func (s *Server) revokeDevice(w http.ResponseWriter, r *http.Request) {
	s.revokeThen(w, r, s.store.RevokeDevice(r.Context(), sessionFrom(r.Context()).UserID, r.PathValue("id")), "device revoked")
}

func (s *Server) revokeClient(w http.ResponseWriter, r *http.Request) {
	s.revokeThen(w, r, s.store.RevokeGrant(r.Context(), sessionFrom(r.Context()).UserID, r.PathValue("id")), "client revoked")
}

func (s *Server) revokeThen(w http.ResponseWriter, r *http.Request, err error, logMsg string) {
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, err)
		return
	}
	if err == nil {
		s.log.Info(logMsg, "id", r.PathValue("id"))
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) pairPage(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	data := map[string]any{"Title": "Pair a device", "CSRF": sess.CSRF}
	raw := r.URL.Query().Get("code")
	if raw != "" {
		code := secret.NormalizeUserCode(raw)
		p, err := s.store.PairByUserCode(r.Context(), code)
		switch {
		case code == "" || errors.Is(err, store.ErrNotFound):
			data["Error"] = "No pending request with that code. Codes expire after 10 minutes."
		case err != nil:
			s.internal(w, r, err)
			return
		default:
			data["Pair"] = p
		}
	}
	s.render(w, http.StatusOK, "pair", data)
}

func (s *Server) pairDecide(w http.ResponseWriter, r *http.Request) {
	sess := sessionFrom(r.Context())
	approve := r.PostFormValue("decision") == "approve"
	err := s.store.DecidePair(r.Context(), secret.NormalizeUserCode(r.PostFormValue("code")), sess.UserID, approve)
	data := map[string]any{"Title": "Pair a device", "CSRF": sess.CSRF}
	switch {
	case errors.Is(err, store.ErrNotFound):
		data["Error"] = "That request expired or was already handled."
	case err != nil:
		s.internal(w, r, err)
		return
	case approve:
		s.log.Info("pairing approved")
		data["Done"] = "Approved. Nexsland finishes pairing within a few seconds."
	default:
		s.log.Info("pairing denied")
		data["Done"] = "Denied. The device was not paired."
	}
	s.render(w, http.StatusOK, "pair", data)
}
