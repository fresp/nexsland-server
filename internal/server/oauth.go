package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/fresp/nexsland-server/internal/config"
	"github.com/fresp/nexsland-server/internal/secret"
	"github.com/fresp/nexsland-server/internal/store"
	"github.com/fresp/nexsland-server/internal/todo"
)

const (
	scopeTodos  = "todos"
	accessTTL   = time.Hour
	refreshTTL  = 90 * 24 * time.Hour
	codeTTL     = 5 * time.Minute
	accessPref  = "nxa_"
	refreshPref = "nxr_"
	codePref    = "nxc_"
	clientPref  = "nxclient_"
	secretPref  = "nxs_"

	authNone   = "none"
	authPost   = "client_secret_post"
	authBasic  = "client_secret_basic"
	grantCode  = "authorization_code"
	grantRefr  = "refresh_token"
	maxURIs    = 5
	maxURILen  = 512
	maxNameLen = 100
)

// resourceURI is the canonical identifier of the MCP endpoint (RFC 8707/9728).
func (s *Server) resourceURI() string { return s.cfg.Public() + "/mcp" }

func (s *Server) resourceMetadataURL() string {
	return s.cfg.Public() + "/.well-known/oauth-protected-resource/mcp"
}

func allowAnyOrigin(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Cache-Control", "public, max-age=3600")
}

// resourceMetadata serves RFC 9728 protected resource metadata.
func (s *Server) resourceMetadata(w http.ResponseWriter, r *http.Request) {
	allowAnyOrigin(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"resource":                 s.resourceURI(),
		"authorization_servers":    []string{s.cfg.Public()},
		"scopes_supported":         []string{scopeTodos},
		"bearer_methods_supported": []string{"header"},
		"resource_name":            "Nexsland todos",
	})
}

// authServerMetadata serves RFC 8414 authorization server metadata.
func (s *Server) authServerMetadata(w http.ResponseWriter, r *http.Request) {
	allowAnyOrigin(w)
	p := s.cfg.Public()
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                         p,
		"authorization_endpoint":                         p + "/oauth/authorize",
		"token_endpoint":                                 p + "/oauth/token",
		"registration_endpoint":                          p + "/oauth/register",
		"revocation_endpoint":                            p + "/oauth/revoke",
		"scopes_supported":                               []string{scopeTodos},
		"response_types_supported":                       []string{"code"},
		"response_modes_supported":                       []string{"query"},
		"grant_types_supported":                          []string{grantCode, grantRefr},
		"token_endpoint_auth_methods_supported":          []string{authNone, authPost, authBasic},
		"revocation_endpoint_auth_methods_supported":     []string{authNone, authPost, authBasic},
		"code_challenge_methods_supported":               []string{"S256"},
		"authorization_response_iss_parameter_supported": true,
		"client_id_metadata_document_supported":          false,
	})
}

// OAuth error responses (RFC 6749 §5.2).
func oauthError(w http.ResponseWriter, status int, code, desc string) {
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Basic realm="nexsland"`)
	}
	writeJSON(w, status, map[string]string{"error": code, "error_description": desc})
}

// validRedirectURI accepts https URLs and http loopback URLs without fragments.
func validRedirectURI(raw string) bool {
	if len(raw) > maxURILen {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.Fragment != "" || u.User != nil {
		return false
	}
	return u.Scheme == "https" || (u.Scheme == "http" && config.IsLoopbackHost(u.Hostname()))
}

// redirectAllowed matches redirect URIs exactly, except that for http
// loopback URIs the port is ignored (RFC 8252 §7.3): native clients such as
// Claude Code listen on an ephemeral port per session.
func redirectAllowed(registered []string, got string) bool {
	if slices.Contains(registered, got) {
		return true
	}
	g, err := url.Parse(got)
	if err != nil || g.Scheme != "http" || !config.IsLoopbackHost(g.Hostname()) {
		return false
	}
	for _, r := range registered {
		u, err := url.Parse(r)
		if err == nil && u.Scheme == "http" && u.Hostname() == g.Hostname() && u.Path == g.Path && u.RawQuery == g.RawQuery {
			return true
		}
	}
	return false
}

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
}

// register implements RFC 7591 dynamic client registration.
func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	if !s.registerIP.allow(clientIP(r)) {
		oauthError(w, http.StatusTooManyRequests, "rate_limited", "too many registrations")
		return
	}
	var req registerRequest
	// Unknown metadata fields are allowed by RFC 7591, so decode leniently.
	if err := decodeLenient(w, r, 16<<10, &req); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_client_metadata", err.Error())
		return
	}
	c, err := newClient(req, "dcr")
	if err != nil {
		code := "invalid_client_metadata"
		if strings.HasPrefix(err.Error(), "redirect_uris") {
			code = "invalid_redirect_uri"
		}
		oauthError(w, http.StatusBadRequest, code, err.Error())
		return
	}
	var clientSecret string
	if c.AuthMethod != authNone {
		clientSecret = secret.Token(secretPref)
		c.SecretHash = secret.Hash(clientSecret)
	}
	if err := s.store.CreateClient(r.Context(), c); err != nil {
		s.internal(w, r, err)
		return
	}
	s.log.Info("oauth client registered", "client_id", c.ID)
	resp := map[string]any{
		"client_id":                  c.ID,
		"client_id_issued_at":        time.Now().Unix(),
		"client_name":                c.Name,
		"redirect_uris":              c.RedirectURIs,
		"token_endpoint_auth_method": c.AuthMethod,
		"grant_types":                []string{grantCode, grantRefr},
		"response_types":             []string{"code"},
		"scope":                      scopeTodos,
	}
	if clientSecret != "" {
		resp["client_secret"] = clientSecret
		resp["client_secret_expires_at"] = 0
	}
	writeJSON(w, http.StatusCreated, resp)
}

// NewCLIClient creates a pre-registered public client (for "Use your own OAuth
// client" in Claude). It returns the client ID.
func NewCLIClient(ctx context.Context, st *store.Store, name string, redirects []string) (string, error) {
	c, err := newClient(registerRequest{ClientName: name, RedirectURIs: redirects}, "cli")
	if err != nil {
		return "", err
	}
	return c.ID, st.CreateClient(ctx, c)
}

func newClient(req registerRequest, source string) (store.OAuthClient, error) {
	if len(req.RedirectURIs) == 0 || len(req.RedirectURIs) > maxURIs {
		return store.OAuthClient{}, fmt.Errorf("redirect_uris must list 1 to %d URIs", maxURIs)
	}
	for _, u := range req.RedirectURIs {
		if !validRedirectURI(u) {
			return store.OAuthClient{}, errors.New("redirect_uris must be https (or http on loopback) without fragments")
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = authNone
	}
	if !slices.Contains([]string{authNone, authPost, authBasic}, method) {
		return store.OAuthClient{}, errors.New("unsupported token_endpoint_auth_method")
	}
	for _, g := range req.GrantTypes {
		if g != grantCode && g != grantRefr {
			return store.OAuthClient{}, errors.New("unsupported grant_types")
		}
	}
	for _, rt := range req.ResponseTypes {
		if rt != "code" {
			return store.OAuthClient{}, errors.New("unsupported response_types")
		}
	}
	name := strings.TrimSpace(req.ClientName)
	if name == "" {
		name = "Unnamed client"
	}
	if utf8.RuneCountInString(name) > maxNameLen {
		name = string([]rune(name)[:maxNameLen])
	}
	return store.OAuthClient{
		ID: clientPref + todo.NewID(), Name: name, RedirectURIs: req.RedirectURIs, AuthMethod: method, Source: source,
	}, nil
}

// authzRequest is a validated authorization request.
type authzRequest struct {
	client      store.OAuthClient
	redirectURI string
	state       string
	challenge   string
	scope       string
	resource    string
}

// errNoRedirect marks an authorization error that must not be sent to the
// redirect URI because the client or redirect URI could not be trusted.
type errNoRedirect struct{ msg string }

func (e errNoRedirect) Error() string { return e.msg }

type errRedirect struct{ code, desc string }

func (e errRedirect) Error() string { return e.code + ": " + e.desc }

func (s *Server) parseAuthz(r *http.Request, get func(string) string) (authzRequest, error) {
	var a authzRequest
	c, err := s.store.Client(r.Context(), get("client_id"))
	if errors.Is(err, store.ErrNotFound) {
		return a, errNoRedirect{"Unknown client. Remove the connector in Claude and add it again."}
	}
	if err != nil {
		return a, err
	}
	a.client = c
	a.redirectURI = get("redirect_uri")
	if a.redirectURI == "" && len(c.RedirectURIs) == 1 {
		a.redirectURI = c.RedirectURIs[0]
	}
	if !redirectAllowed(c.RedirectURIs, a.redirectURI) {
		return a, errNoRedirect{"The redirect URI is not registered for this client."}
	}
	a.state = get("state")
	if get("response_type") != "code" {
		return a, errRedirect{"unsupported_response_type", "only response_type=code is supported"}
	}
	a.challenge = get("code_challenge")
	if a.challenge == "" || get("code_challenge_method") != "S256" {
		return a, errRedirect{"invalid_request", "PKCE with code_challenge_method=S256 is required"}
	}
	if len(a.challenge) != 43 || strings.Trim(a.challenge, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		return a, errRedirect{"invalid_request", "code_challenge must be a base64url SHA-256 digest"}
	}
	a.resource, err = s.checkResource(get("resource"))
	if err != nil {
		return a, errRedirect{"invalid_target", err.Error()}
	}
	// Only one scope exists; unknown requested scopes are dropped (RFC 6749 §3.3).
	a.scope = scopeTodos
	return a, nil
}

// checkResource accepts the MCP endpoint (with or without trailing slash) or
// the bare origin, and returns the canonical resource.
func (s *Server) checkResource(res string) (string, error) {
	switch strings.TrimRight(res, "/") {
	case "", s.resourceURI(), s.cfg.Public():
		return s.resourceURI(), nil
	}
	return "", errors.New("resource must be " + s.resourceURI())
}

func (s *Server) redirectAuthz(w http.ResponseWriter, r *http.Request, a authzRequest, q url.Values) {
	u, _ := url.Parse(a.redirectURI)
	values := u.Query()
	for k, v := range q {
		values[k] = v
	}
	if a.state != "" {
		values.Set("state", a.state)
	}
	values.Set("iss", s.cfg.Public())
	u.RawQuery = values.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) authzFailure(w http.ResponseWriter, r *http.Request, a authzRequest, err error) {
	var nr errNoRedirect
	var er errRedirect
	switch {
	case errors.As(err, &nr):
		s.message(w, http.StatusBadRequest, "Cannot connect", nr.msg)
	case errors.As(err, &er):
		s.redirectAuthz(w, r, a, url.Values{"error": {er.code}, "error_description": {er.desc}})
	default:
		s.internal(w, r, err)
	}
}

var authzParams = []string{"client_id", "redirect_uri", "response_type", "state", "code_challenge",
	"code_challenge_method", "scope", "resource"}

func (s *Server) authorizePage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	a, err := s.parseAuthz(r, q.Get)
	if err != nil {
		s.authzFailure(w, r, a, err)
		return
	}
	params := map[string]string{}
	for _, k := range authzParams {
		if v := q.Get(k); v != "" {
			params[k] = v
		}
	}
	u, _ := url.Parse(a.redirectURI)
	w.Header().Set("Content-Security-Policy", csp(u.Scheme+"://"+u.Host))
	s.render(w, http.StatusOK, "consent", map[string]any{
		"Title": "Connect " + a.client.Name, "CSRF": sessionFrom(r.Context()).CSRF,
		"ClientName": a.client.Name, "RedirectHost": u.Host, "Params": params,
	})
}

func (s *Server) authorizeDecide(w http.ResponseWriter, r *http.Request) {
	a, err := s.parseAuthz(r, r.PostFormValue)
	if err != nil {
		s.authzFailure(w, r, a, err)
		return
	}
	if r.PostFormValue("decision") != "approve" {
		s.log.Info("oauth consent denied", "client_id", a.client.ID)
		s.redirectAuthz(w, r, a, url.Values{"error": {"access_denied"}, "error_description": {"the owner denied access"}})
		return
	}
	code := secret.Token(codePref)
	g := store.Grant{ID: todo.NewID(), UserID: sessionFrom(r.Context()).UserID, ClientID: a.client.ID,
		Scope: a.scope, Resource: a.resource}
	if err := s.store.CreateGrantWithCode(r.Context(), g, secret.Hash(code), a.redirectURI, a.challenge,
		s.clock.NowUTC().Add(codeTTL)); err != nil {
		s.internal(w, r, err)
		return
	}
	s.log.Info("oauth consent granted", "client_id", a.client.ID, "grant_id", g.ID)
	s.redirectAuthz(w, r, a, url.Values{"code": {code}})
}

// authenticateClient applies the client's registered token endpoint auth method.
func (s *Server) authenticateClient(r *http.Request) (store.OAuthClient, error) {
	id, sec, basic := r.BasicAuth()
	if basic {
		var err1, err2 error
		id, err1 = url.QueryUnescape(id)
		sec, err2 = url.QueryUnescape(sec)
		if err1 != nil || err2 != nil {
			return store.OAuthClient{}, errors.New("malformed basic credentials")
		}
	} else {
		id, sec = r.PostFormValue("client_id"), r.PostFormValue("client_secret")
	}
	c, err := s.store.Client(r.Context(), id)
	if err != nil {
		return c, errors.New("unknown client")
	}
	switch c.AuthMethod {
	case authNone:
		if sec != "" {
			return c, errors.New("public client must not send a secret")
		}
	default:
		if sec == "" || !secret.Equal(secret.Hash(sec), c.SecretHash) {
			return c, errors.New("bad client secret")
		}
	}
	return c, nil
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if !s.tokenIP.allow(clientIP(r)) {
		oauthError(w, http.StatusTooManyRequests, "rate_limited", "slow down")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	c, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	now := s.clock.NowUTC()
	access, refresh := secret.Token(accessPref), secret.Token(refreshPref)
	tokens := []store.IssuedToken{
		{Hash: secret.Hash(access), Kind: "access", ExpiresAt: now.Add(accessTTL)},
		{Hash: secret.Hash(refresh), Kind: "refresh", ExpiresAt: now.Add(refreshTTL)},
	}
	var g store.Grant
	switch r.PostFormValue("grant_type") {
	case grantCode:
		verifier := r.PostFormValue("code_verifier")
		redirect := r.PostFormValue("redirect_uri")
		resource := r.PostFormValue("resource")
		g, err = s.store.RedeemCode(r.Context(), secret.Hash(r.PostFormValue("code")), func(ac store.AuthCode) error {
			switch {
			case ac.Grant.ClientID != c.ID:
				return errGrant("code was issued to another client")
			case now.After(ac.ExpiresAt):
				return errGrant("code expired")
			case redirect != "" && redirect != ac.RedirectURI:
				return errGrant("redirect_uri does not match")
			case !pkceOK(verifier, ac.CodeChallenge):
				return errGrant("code_verifier does not match code_challenge")
			}
			if resource != "" {
				if res, err := s.checkResource(resource); err != nil || res != ac.Grant.Resource {
					return errGrant("resource does not match")
				}
			}
			return nil
		}, tokens)
	case grantRefr:
		g, err = s.store.RotateRefresh(r.Context(), secret.Hash(r.PostFormValue("refresh_token")), func(gr store.Grant) error {
			if gr.ClientID != c.ID {
				return errGrant("refresh token was issued to another client")
			}
			return nil
		}, tokens)
	default:
		oauthError(w, http.StatusBadRequest, "unsupported_grant_type", "use authorization_code or refresh_token")
		return
	}
	var ge errGrant
	switch {
	case errors.Is(err, store.ErrNotFound):
		oauthError(w, http.StatusBadRequest, "invalid_grant", "unknown, expired or revoked grant")
		return
	case errors.Is(err, store.ErrReplay):
		s.log.Warn("oauth credential reuse; grant revoked", "client_id", c.ID, "grant_id", g.ID)
		oauthError(w, http.StatusBadRequest, "invalid_grant", "credential already used; access revoked")
		return
	case errors.As(err, &ge):
		oauthError(w, http.StatusBadRequest, "invalid_grant", string(ge))
		return
	case err != nil:
		s.internal(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  access,
		"token_type":    "Bearer",
		"expires_in":    int(accessTTL.Seconds()),
		"refresh_token": refresh,
		"scope":         g.Scope,
	})
}

type errGrant string

func (e errGrant) Error() string { return string(e) }

func pkceOK(verifier, challenge string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return secret.Equal(base64.RawURLEncoding.EncodeToString(sum[:]), challenge)
}

// revoke implements RFC 7009. It revokes the whole grant the token belongs to.
func (s *Server) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, http.StatusBadRequest, "invalid_request", "malformed form body")
		return
	}
	c, err := s.authenticateClient(r)
	if err != nil {
		oauthError(w, http.StatusUnauthorized, "invalid_client", err.Error())
		return
	}
	if err := s.store.RevokeTokenByHash(r.Context(), secret.Hash(r.PostFormValue("token")), c.ID); err != nil {
		s.internal(w, r, err)
		return
	}
	w.WriteHeader(http.StatusOK)
}
