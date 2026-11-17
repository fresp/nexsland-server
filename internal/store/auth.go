package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// All *Hash arguments are SHA-256 hashes computed by the caller; plaintext
// secrets never reach this package.

// Device is a paired Nexsland installation.
type Device struct {
	ID         string
	UserID     int64
	Name       string
	CreatedAt  time.Time
	LastSeenAt *time.Time
}

// CreateDevice stores a new device token.
func (s *Store) CreateDevice(ctx context.Context, d Device, tokenHash string) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO devices (id, user_id, name, token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
		d.ID, d.UserID, d.Name, tokenHash, s.nowMs())
	return err
}

// DeviceByToken returns the live device for a token hash and records last use.
func (s *Store) DeviceByToken(ctx context.Context, tokenHash string) (Device, error) {
	var d Device
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, user_id, name, created_at FROM devices
		WHERE token_hash = ? AND revoked_at IS NULL`, tokenHash).Scan(&d.ID, &d.UserID, &d.Name, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	if err != nil {
		return d, err
	}
	d.CreatedAt = msToTime(created)
	// Coarse last-seen to avoid a write per request.
	_, err = s.db.ExecContext(ctx, `UPDATE devices SET last_seen_at = ?1 WHERE id = ?2
		AND (last_seen_at IS NULL OR last_seen_at < ?1 - 60000)`, s.nowMs(), d.ID)
	return d, err
}

// Devices lists live devices.
func (s *Store) Devices(ctx context.Context, userID int64) ([]Device, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, user_id, name, created_at, last_seen_at FROM devices
		WHERE user_id = ? AND revoked_at IS NULL ORDER BY created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Device
	for rows.Next() {
		var d Device
		var created int64
		var seen sql.NullInt64
		if err := rows.Scan(&d.ID, &d.UserID, &d.Name, &created, &seen); err != nil {
			return nil, err
		}
		d.CreatedAt = msToTime(created)
		if seen.Valid {
			t := msToTime(seen.Int64)
			d.LastSeenAt = &t
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// RevokeDevice revokes a device token.
func (s *Store) RevokeDevice(ctx context.Context, userID int64, id string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE devices SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
		s.nowMs(), id, userID)
	return affected(res, err)
}

func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Pair request statuses.
const (
	PairPending   = "pending"
	PairApproved  = "approved"
	PairDenied    = "denied"
	PairDelivered = "delivered"
)

// PairRequest is a pending device pairing.
type PairRequest struct {
	DeviceCodeHash string
	UserCode       string
	DeviceName     string
	ExpiresAt      time.Time
	LastPollAt     *time.Time
	Status         string
	UserID         int64
}

// CountPendingPairs counts unexpired pending pair requests.
func (s *Store) CountPendingPairs(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM pair_requests WHERE status = 'pending' AND expires_at > ?", s.nowMs()).Scan(&n)
	return n, err
}

// CreatePairRequest stores a pairing request; it also prunes expired ones.
func (s *Store) CreatePairRequest(ctx context.Context, p PairRequest) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM pair_requests WHERE expires_at < ?", s.nowMs()-3600_000); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO pair_requests (device_code_hash, user_code, device_name, created_at, expires_at)
			VALUES (?, ?, ?, ?, ?)`, p.DeviceCodeHash, p.UserCode, p.DeviceName, s.nowMs(), p.ExpiresAt.UnixMilli())
		return err
	})
}

func scanPair(r scanner) (PairRequest, error) {
	var p PairRequest
	var exp int64
	var poll, uid sql.NullInt64
	err := r.Scan(&p.DeviceCodeHash, &p.UserCode, &p.DeviceName, &exp, &poll, &p.Status, &uid)
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrNotFound
	}
	p.ExpiresAt = msToTime(exp)
	if poll.Valid {
		t := msToTime(poll.Int64)
		p.LastPollAt = &t
	}
	p.UserID = uid.Int64
	return p, err
}

const pairCols = "device_code_hash, user_code, device_name, expires_at, last_poll_at, status, user_id"

// PairByUserCode finds a pending, unexpired pairing by its user code.
func (s *Store) PairByUserCode(ctx context.Context, userCode string) (PairRequest, error) {
	return scanPair(s.db.QueryRowContext(ctx, "SELECT "+pairCols+` FROM pair_requests
		WHERE user_code = ? AND status = 'pending' AND expires_at > ?`, userCode, s.nowMs()))
}

// DecidePair approves or denies a pending pairing.
func (s *Store) DecidePair(ctx context.Context, userCode string, userID int64, approve bool) error {
	status := PairDenied
	if approve {
		status = PairApproved
	}
	res, err := s.db.ExecContext(ctx, `UPDATE pair_requests SET status = ?, user_id = ?
		WHERE user_code = ? AND status = 'pending' AND expires_at > ?`, status, userID, userCode, s.nowMs())
	return affected(res, err)
}

// PollPair records a poll and returns the request as it was before the poll.
func (s *Store) PollPair(ctx context.Context, deviceCodeHash string) (PairRequest, error) {
	var p PairRequest
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var err error
		p, err = scanPair(tx.QueryRowContext(ctx, "SELECT "+pairCols+" FROM pair_requests WHERE device_code_hash = ?", deviceCodeHash))
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "UPDATE pair_requests SET last_poll_at = ? WHERE device_code_hash = ?", s.nowMs(), deviceCodeHash)
		return err
	})
	return p, err
}

// CompletePair marks an approved pairing delivered and creates its device, atomically.
func (s *Store) CompletePair(ctx context.Context, deviceCodeHash string, d Device, tokenHash string) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		res, err := tx.ExecContext(ctx, "UPDATE pair_requests SET status = 'delivered' WHERE device_code_hash = ? AND status = 'approved'", deviceCodeHash)
		if err := affected(res, err); err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO devices (id, user_id, name, token_hash, created_at) VALUES (?, ?, ?, ?, ?)",
			d.ID, d.UserID, d.Name, tokenHash, s.nowMs())
		return err
	})
}

// OAuthClient is a registered OAuth client.
type OAuthClient struct {
	ID           string
	Name         string
	RedirectURIs []string
	SecretHash   string
	AuthMethod   string
	Source       string
	CreatedAt    time.Time
}

// CreateClient registers a client and prunes DCR clients that never got a grant within 24 h.
func (s *Store) CreateClient(ctx context.Context, c OAuthClient) error {
	uris, err := json.Marshal(c.RedirectURIs)
	if err != nil {
		return err
	}
	var secret any
	if c.SecretHash != "" {
		secret = c.SecretHash
	}
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, `DELETE FROM oauth_clients WHERE source = 'dcr' AND created_at < ?
			AND id NOT IN (SELECT client_id FROM oauth_grants)`, s.nowMs()-24*3600_000); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oauth_clients (id, name, redirect_uris, secret_hash, auth_method, source, created_at)
			VALUES (?, ?, ?, ?, ?, ?, ?)`, c.ID, c.Name, string(uris), secret, c.AuthMethod, c.Source, s.nowMs())
		return err
	})
}

// Client returns a registered client.
func (s *Store) Client(ctx context.Context, id string) (OAuthClient, error) {
	var c OAuthClient
	var uris string
	var secret sql.NullString
	var created int64
	err := s.db.QueryRowContext(ctx, `SELECT id, name, redirect_uris, secret_hash, auth_method, source, created_at
		FROM oauth_clients WHERE id = ?`, id).Scan(&c.ID, &c.Name, &uris, &secret, &c.AuthMethod, &c.Source, &created)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	if err != nil {
		return c, err
	}
	c.SecretHash = secret.String
	c.CreatedAt = msToTime(created)
	return c, json.Unmarshal([]byte(uris), &c.RedirectURIs)
}

// Grant is an owner's consent for one client: the "connected client".
type Grant struct {
	ID         string
	UserID     int64
	ClientID   string
	ClientName string
	Scope      string
	Resource   string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

// CreateGrantWithCode stores a consent grant and its authorization code.
func (s *Store) CreateGrantWithCode(ctx context.Context, g Grant, codeHash, redirectURI, challenge string, expires time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM oauth_codes WHERE expires_at < ?", s.nowMs()-3600_000); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO oauth_grants (id, user_id, client_id, scope, resource, created_at)
			VALUES (?, ?, ?, ?, ?, ?)`, g.ID, g.UserID, g.ClientID, g.Scope, g.Resource, s.nowMs()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO oauth_codes (code_hash, grant_id, redirect_uri, code_challenge, expires_at)
			VALUES (?, ?, ?, ?, ?)`, codeHash, g.ID, redirectURI, challenge, expires.UnixMilli())
		return err
	})
}

// AuthCode is a stored authorization code joined with its grant.
type AuthCode struct {
	Grant         Grant
	RedirectURI   string
	CodeChallenge string
	ExpiresAt     time.Time
}

// ErrReplay reports reuse of a single-use code or refresh token. The grant has
// been revoked when it is returned.
var ErrReplay = errors.New("credential reuse detected")

// IssuedToken is a token hash to store for a grant.
type IssuedToken struct {
	Hash      string
	Kind      string
	ExpiresAt time.Time
}

// RedeemCode marks a code used, checks it with check, and stores tokens, all
// in one transaction. On a reused code it revokes the grant and returns ErrReplay.
func (s *Store) RedeemCode(ctx context.Context, codeHash string, check func(AuthCode) error, tokens []IssuedToken) (Grant, error) {
	var g Grant
	var replay bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var c AuthCode
		var used, revoked bool
		var exp int64
		err := tx.QueryRowContext(ctx, `SELECT c.redirect_uri, c.code_challenge, c.expires_at, c.used,
			g.id, g.user_id, g.client_id, g.scope, g.resource, g.revoked_at IS NOT NULL
			FROM oauth_codes c JOIN oauth_grants g ON g.id = c.grant_id WHERE c.code_hash = ?`, codeHash).Scan(
			&c.RedirectURI, &c.CodeChallenge, &exp, &used, &c.Grant.ID, &c.Grant.UserID, &c.Grant.ClientID,
			&c.Grant.Scope, &c.Grant.Resource, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		c.ExpiresAt = msToTime(exp)
		if revoked {
			return ErrNotFound
		}
		if used {
			replay = true
			return nil
		}
		if err := check(c); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE oauth_codes SET used = 1 WHERE code_hash = ?", codeHash); err != nil {
			return err
		}
		g = c.Grant
		return insertTokens(ctx, tx, g.ID, tokens)
	})
	if err == nil && replay {
		// Revoke outside the read transaction so it commits.
		_ = s.revokeGrantByCode(ctx, codeHash)
		return g, ErrReplay
	}
	return g, err
}

func (s *Store) revokeGrantByCode(ctx context.Context, codeHash string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth_grants SET revoked_at = ? WHERE revoked_at IS NULL
		AND id = (SELECT grant_id FROM oauth_codes WHERE code_hash = ?)`, s.nowMs(), codeHash)
	return err
}

func insertTokens(ctx context.Context, tx *sql.Tx, grantID string, tokens []IssuedToken) error {
	for _, t := range tokens {
		if _, err := tx.ExecContext(ctx, "INSERT INTO oauth_tokens (token_hash, grant_id, kind, expires_at) VALUES (?, ?, ?, ?)",
			t.Hash, grantID, t.Kind, t.ExpiresAt.UnixMilli()); err != nil {
			return err
		}
	}
	return nil
}

// RotateRefresh exchanges a refresh token for new tokens. The old refresh
// token is marked used. Reusing a used refresh token revokes the grant and
// returns ErrReplay. check validates the grant (client binding).
func (s *Store) RotateRefresh(ctx context.Context, refreshHash string, check func(Grant) error, tokens []IssuedToken) (Grant, error) {
	var g Grant
	var replay bool
	err := s.tx(ctx, func(tx *sql.Tx) error {
		var used, revoked bool
		var exp int64
		err := tx.QueryRowContext(ctx, `SELECT t.used, t.expires_at, g.id, g.user_id, g.client_id, g.scope, g.resource,
			g.revoked_at IS NOT NULL FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
			WHERE t.token_hash = ? AND t.kind = 'refresh'`, refreshHash).Scan(
			&used, &exp, &g.ID, &g.UserID, &g.ClientID, &g.Scope, &g.Resource, &revoked)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if revoked || exp < s.nowMs() {
			return ErrNotFound
		}
		if err := check(g); err != nil {
			return err
		}
		if used {
			replay = true
			return nil
		}
		if _, err := tx.ExecContext(ctx, "UPDATE oauth_tokens SET used = 1 WHERE token_hash = ?", refreshHash); err != nil {
			return err
		}
		return insertTokens(ctx, tx, g.ID, tokens)
	})
	if err == nil && replay {
		_ = s.RevokeGrant(ctx, g.UserID, g.ID)
		return g, ErrReplay
	}
	return g, err
}

// AccessToken resolves a live access token to its grant and records last use.
func (s *Store) AccessToken(ctx context.Context, tokenHash string) (Grant, time.Time, error) {
	var g Grant
	var exp int64
	err := s.db.QueryRowContext(ctx, `SELECT t.expires_at, g.id, g.user_id, g.client_id, g.scope, g.resource
		FROM oauth_tokens t JOIN oauth_grants g ON g.id = t.grant_id
		WHERE t.token_hash = ? AND t.kind = 'access' AND g.revoked_at IS NULL`, tokenHash).Scan(
		&exp, &g.ID, &g.UserID, &g.ClientID, &g.Scope, &g.Resource)
	if errors.Is(err, sql.ErrNoRows) {
		return g, time.Time{}, ErrNotFound
	}
	if err != nil {
		return g, time.Time{}, err
	}
	_, err = s.db.ExecContext(ctx, `UPDATE oauth_grants SET last_used_at = ?1 WHERE id = ?2
		AND (last_used_at IS NULL OR last_used_at < ?1 - 60000)`, s.nowMs(), g.ID)
	return g, msToTime(exp), err
}

// RevokeTokenByHash revokes the grant a token belongs to (RFC 7009 allows
// revoking related tokens). Unknown tokens are not an error.
func (s *Store) RevokeTokenByHash(ctx context.Context, tokenHash, clientID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE oauth_grants SET revoked_at = ? WHERE revoked_at IS NULL
		AND client_id = ? AND id = (SELECT grant_id FROM oauth_tokens WHERE token_hash = ?)`, s.nowMs(), clientID, tokenHash)
	return err
}

// Grants lists live grants with their client names.
func (s *Store) Grants(ctx context.Context, userID int64) ([]Grant, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT g.id, g.user_id, g.client_id, c.name, g.scope, g.resource, g.created_at, g.last_used_at
		FROM oauth_grants g JOIN oauth_clients c ON c.id = g.client_id
		WHERE g.user_id = ? AND g.revoked_at IS NULL ORDER BY g.created_at`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Grant
	for rows.Next() {
		var g Grant
		var created int64
		var used sql.NullInt64
		if err := rows.Scan(&g.ID, &g.UserID, &g.ClientID, &g.ClientName, &g.Scope, &g.Resource, &created, &used); err != nil {
			return nil, err
		}
		g.CreatedAt = msToTime(created)
		if used.Valid {
			t := msToTime(used.Int64)
			g.LastUsedAt = &t
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// RevokeGrant revokes a grant and with it every token issued under it.
func (s *Store) RevokeGrant(ctx context.Context, userID int64, id string) error {
	res, err := s.db.ExecContext(ctx, "UPDATE oauth_grants SET revoked_at = ? WHERE id = ? AND user_id = ? AND revoked_at IS NULL",
		s.nowMs(), id, userID)
	return affected(res, err)
}

// Session is a logged-in owner browser session.
type Session struct {
	UserID int64
	CSRF   string
}

// CreateSession stores a web session and prunes expired ones.
func (s *Store) CreateSession(ctx context.Context, idHash string, sess Session, expires time.Time) error {
	return s.tx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM web_sessions WHERE expires_at < ?", s.nowMs()); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, "INSERT INTO web_sessions (id_hash, user_id, csrf, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
			idHash, sess.UserID, sess.CSRF, s.nowMs(), expires.UnixMilli())
		return err
	})
}

// SessionByID returns a live session.
func (s *Store) SessionByID(ctx context.Context, idHash string) (Session, error) {
	var sess Session
	err := s.db.QueryRowContext(ctx, "SELECT user_id, csrf FROM web_sessions WHERE id_hash = ? AND expires_at > ?",
		idHash, s.nowMs()).Scan(&sess.UserID, &sess.CSRF)
	if errors.Is(err, sql.ErrNoRows) {
		return sess, ErrNotFound
	}
	return sess, err
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, idHash string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM web_sessions WHERE id_hash = ?", idHash)
	return err
}

// DeleteUserSessions ends every session of a user (after a password change).
func (s *Store) DeleteUserSessions(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM web_sessions WHERE user_id = ?", userID)
	return err
}
