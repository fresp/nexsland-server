# Nexsland Server: design

Nexsland Server is a self-hosted todo service with two interfaces over one store:
an MCP endpoint for Claude (mobile, desktop, web) and a REST sync API for the
Nexsland GNOME Shell extension. One owner per deployment.

## Verified requirements and sources

Read on 2026-11-17 from the official pages (Markdown versions fetched directly).

**Claude custom connectors**
([claude.com/docs/connectors/building/authentication](https://claude.com/docs/connectors/building/authentication),
[claude.com/docs/connectors/custom/add-unlisted](https://claude.com/docs/connectors/custom/add-unlisted)):

- The same auth stack serves claude.ai, Desktop, mobile, Claude Code and Cowork.
- Auth types for a custom connector: OAuth (CIMD "Use Claude's published
  identity", DCR "Register automatically", or "Use your own OAuth client" with
  an optional secret), or none. Static request headers are a limited beta.
- Claude selects CIMD only when the authorization server metadata advertises
  `client_id_metadata_document_supported: true` and `none` in
  `token_endpoint_auth_methods_supported`; otherwise it falls back to DCR,
  which needs a `registration_endpoint`. DCR registers Claude as a public client.
- Sign-in starts only from a `401` with `WWW-Authenticate: Bearer
  resource_metadata="…"`; without the pointer Claude probes
  `/.well-known/oauth-protected-resource/<path>` then the root form.
- The metadata `resource` must equal the URL the user enters, path included.
  Only the first `authorization_servers` entry is used. The authorization
  server must serve RFC 8414 or OIDC discovery metadata.
- PKCE S256 on every request; the server must support it and advertise
  `code_challenge_methods_supported: ["S256"]`.
- Scopes: Claude requests the `scope` from the 401 header, else
  `scopes_supported` from the resource metadata, and appends `offline_access`
  only if the authorization server lists it.
- Callback for hosted apps (web, Desktop, mobile, Cowork):
  `https://claude.ai/api/mcp/auth_callback`. Claude Code uses a loopback
  redirect on an ephemeral port: match `localhost` and `127.0.0.1` ignoring
  the port. The consent screen must show the redirect host.
- Token endpoint: `application/x-www-form-urlencoded`; expired refresh tokens
  answer `invalid_grant`; public-client refresh tokens rotate, with the new one
  in the same response. Discovery, registration and token endpoints must answer
  within 10 s, refresh within 30 s. Claude refreshes on 401 and up to 5 minutes
  before expiry.
- Anthropic's egress range is `160.79.104.0/21`.

**MCP specification.** The current revision is
[2026-07-28](https://modelcontextprotocol.io/specification/versioning); the
SDK and Claude also speak 2025-11-25.
([authorization](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization),
[client registration](https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/client-registration),
[Streamable HTTP](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http),
and the [2025-11-25 authorization](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization) page):

- Authorization servers implement OAuth 2.1. MCP servers MUST serve Protected
  Resource Metadata (RFC 9728) with at least one authorization server, and
  SHOULD put `scope` in `WWW-Authenticate`.
- Authorization servers MUST provide RFC 8414 or OIDC discovery and MUST
  validate exact redirect URIs. Redirect URIs MUST be localhost or HTTPS.
- Clients MUST send `resource` (RFC 8707) in authorization and token
  requests; servers MUST only accept tokens issued for themselves.
- Public-client refresh tokens MUST rotate; access tokens SHOULD be short-lived.
- Authorization servers SHOULD send `iss` in authorization responses
  (RFC 9207), expected to become MUST.
- Client registration: CIMD SHOULD be supported; DCR is **deprecated** in
  2026-07-28 but still a valid fallback; pre-registration is allowed.
- Resource servers SHOULD NOT advertise `offline_access`.
- Streamable HTTP: servers MUST validate `Origin` and answer 403 when it is
  present and invalid. 2026-07-28 removes protocol sessions: ignore
  `Mcp-Session-Id`, and GET may answer 405.

**MCP Go SDK** (`github.com/modelcontextprotocol/go-sdk` v1.8.0, `docs/protocol.md`,
`auth/auth.go`, `mcp/streamable.go`):

- Stable: v1.x with semver since v1.0.0; requires Go 1.25.
- Server side provides `mcp.NewStreamableHTTPHandler` (with `Stateless`,
  required for 2026-07-28, `JSONResponse`, `MaxRequestBodyBytes`, a Host-based
  DNS-rebinding check), `auth.RequireBearerToken` (sets `WWW-Authenticate` with
  the resource metadata URL and `scope`, checks scopes and expiry) and
  `auth.ProtectedResourceMetadataHandler`.
- It does **not** ship an authorization server. The authorize, token,
  registration and revocation endpoints are implemented here.
- Decision: use the official SDK. No alternative needed.

## Auth decisions

- **Claude → server:** OAuth 2.1 authorization code + PKCE (S256 only), built
  into this server. Supported client modes: DCR ("Register automatically") and
  pre-registered clients created with `nexsland-server oauth-client add`.
  Client ID Metadata Documents are **not** supported: they require the server
  to fetch the client's URL, which breaks the "no outbound network calls"
  rule. The metadata says `client_id_metadata_document_supported: false`, so
  Claude falls back to DCR on its own; in the custom connector dialog the user
  picks "Register automatically". DCR is deprecated in MCP 2026-07-28, so this
  is the first thing to revisit if Claude ever drops it.
- Redirect URIs match exactly, except http loopback URIs, which match
  ignoring the port (RFC 8252 §7.3) so Claude Code's ephemeral ports work.
- Access tokens are opaque, 1 hour, bound to the resource `<public>/mcp`.
  Refresh tokens rotate on every use; reuse of a rotated refresh token or of
  an authorization code revokes the whole grant. A grant is what the owner
  sees and revokes as a "connected client".
- The consent page shows the client's self-declared name **and** the host of
  its redirect URI, because DCR names are not trustworthy.
- **Nexsland → server:** device pairing modelled on RFC 8628: `pair/start`
  returns a device code and a short user code, the owner approves the user
  code at `/pair`, the device polls `pair/token` and gets a long-lived device
  token once.
- **Owner:** password set from the CLI (argon2id hash). Login sets a
  `__Host-` session cookie (Secure, HttpOnly, SameSite=Lax). Failed logins are
  rate limited per client IP and globally.
- All tokens and codes are random 256-bit values stored as SHA-256 hashes.
- Forms carry a per-session CSRF token, and Go's `http.CrossOriginProtection`
  (Fetch metadata) rejects cross-origin unsafe requests. The REST API sends no
  CORS headers. Only the two OAuth metadata documents allow any origin, as
  RFC 9728 expects.

## Data contract (version 2)

| Field | Type | Rule |
|---|---|---|
| `id` | string | UUIDv7, generated by the creating client |
| `title` | string | trimmed, 1–200 characters |
| `day` | string | `YYYY-MM-DD`, a calendar date in the owner's time zone |
| `minutes` | int or null | 0–1439, null means no time |
| `done` | bool | |
| `created_at` | RFC 3339 | set by the creating writer, never changed afterwards |
| `updated_at` | RFC 3339 | set by the writer on every change; the LWW clock |
| `deleted` | bool | tombstone |
| `seq` | int | server-assigned, strictly increasing across all writes |

Timestamps are stored with millisecond precision in UTC. Device-local state
(reminder announced, snoozed until) is not synced.

**Rollover (confirmed by the owner):** the server never changes a task's
`day`. A task with `day` before today that is not done is "overdue"; clients
compute that for display. `list_todos` flags such tasks.

## REST sync API

All under `/v1`, JSON, `Authorization: Bearer <device token>`.

- `GET /v1/todos?since=<seq>&limit=<n>` returns
  `{ "todos": [...], "next": <seq>, "more": <bool> }` ordered by `seq`,
  tombstones included. `limit` defaults to 500, max 1000. Pass `next` as the
  following `since`.
- `POST /v1/ops` takes `{ "ops": [{ "op": "upsert", "todo": {...} },
  { "op": "delete", "id": "...", "updated_at": "..." }] }`, max 500 ops and
  1 MiB. Every op is validated first; one invalid op rejects the batch (422,
  message names the op index). The batch is applied in one transaction.
  Returns `{ "results": [{ "id", "status": "applied"|"stale", "todo" }],
  "max_seq" }`; for `stale` ops `todo` is the stored row that won.
- Last-write-wins: an op applies only if its `updated_at` is strictly newer
  than the stored row's. Ties keep the stored row. A delete of an unknown id
  stores a tombstone. An upsert newer than a tombstone revives the task (plain
  LWW; documented, not prevented).
- Clock-skew guard: an op with `updated_at` more than 5 minutes in the future
  rejects the batch with `clock_skew`.
- `GET /v1/me` returns `{ "time_zone", "today", "server_version", "max_seq",
  "device": { "id", "name" } }`.
- Pairing: `POST /v1/pair/start` `{ "device_name" }` →
  `{ "device_code", "user_code", "verification_uri", "expires_in", "interval" }`.
  `POST /v1/pair/token` `{ "device_code" }` → `{ "token", "device_id" }` or
  400 with `authorization_pending`, `slow_down`, `access_denied` or
  `expired_token`.
- Errors: `{ "error": { "code", "message" } }` with 400, 401, 404, 405, 413,
  422, 429 or 500.

## MCP endpoint

`POST <public>/mcp`, Streamable HTTP, stateless (no `Mcp-Session-Id`;
required for protocol 2026-07-28 and fine for older clients because the tools
need no server-to-client requests). A present `Origin` header other than the
server's own origin gets 403. Tools:

- `add_todo(title, date?, time?)`
- `list_todos(from?, to?, include_done?)`: default today..today+7 plus overdue
  unfinished tasks flagged `overdue: true`.
- `complete_todo(id)`, `reopen_todo(id)`
- `update_todo(id, title?, date?, time?)`: `time: null` clears the time.
- `delete_todo(id)`

Every result starts with today's date in the owner's zone. Descriptions tell
Claude to pass explicit `YYYY-MM-DD` dates and `HH:MM` times. New or moved
tasks must fall between today and one year ahead, mirroring Nexsland. MCP
writes go through the same store path as sync writes and bump `seq`.

## Storage

SQLite through `modernc.org/sqlite` (pure Go, no CGO), WAL, `busy_timeout`,
foreign keys on, a single pooled connection (one owner's load needs no more).
The server process is the only long-running writer; the admin CLI commands
make short writes that SQLite's locking serializes. Numbered SQL migrations are
embedded and applied on start inside a transaction; `schema_migrations`
records the version. Every user-data table has a `user_id`; this build creates
a single owner (id 1) and has no sign-up.

## Operations

Config is env only: `NEXSLAND_PUBLIC_URL`, `NEXSLAND_TZ`, `NEXSLAND_DB`,
`NEXSLAND_LISTEN` required; `NEXSLAND_LOG_LEVEL` optional. JSON logs via
`log/slog`; request logs carry method, route, status and duration, never
titles, tokens, codes or query strings. `GET /healthz` pings the database.
The client IP for rate limiting is taken from `X-Real-IP` / `X-Forwarded-For`
only when the TCP peer is a loopback or private address (the reverse proxy).

## Open risks

- If the user picks "Use Claude's published identity" in the connector dialog,
  sign-in fails because this server does not do CIMD; the README says to pick
  "Register automatically".
- DCR is deprecated in MCP 2026-07-28. Claude still supports it today.
- Refresh-token reuse revokes the grant. If Claude retries a refresh whose
  response was lost (timeout, proxy), the owner has to reconnect the
  connector. Chosen for safety; a short grace window would trade some of it away.
- DCR is open by design. Anyone can register a client, but it gets nothing
  without the owner's consent. Unused registrations are pruned after 24 h and
  registration is rate limited.
- LWW uses client clocks. A device with a clock up to 5 minutes fast can win
  over a later edit made elsewhere.
- Revival after delete is possible under LWW, as stated above.
- In-memory rate limits reset on restart; acceptable for one process.
- Stateless MCP mode is new in the spec and the SDK warns it is still being
  defined.
