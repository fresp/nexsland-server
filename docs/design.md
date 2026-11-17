# Nexsland Server: design

Nexsland Server is a self-hosted todo service with two interfaces over one store:
an MCP endpoint for Claude (mobile, desktop, web) and a REST sync API for the
Nexsland GNOME Shell extension. One owner per deployment.

## Verified requirements and sources

Checked on 2026-11-17. The session that wrote this could not open
`modelcontextprotocol.io` or `claude.com` directly (blocked by its network
policy), so the claims below come from the official MCP Go SDK source and docs
(fetched through the Go module proxy) and from web search results quoting the
official pages. Items marked *secondary* were not confirmed against an official
page and should be re-checked when those hosts are reachable.

**Claude custom connectors** (support.claude.com article 11503834
"Building custom connectors via remote MCP servers", article 11175166 "Get
started with custom connectors using remote MCP", claude.com/docs/connectors,
via search results):

- Remote MCP over Streamable HTTP (SSE is legacy). Available on web, desktop,
  iOS and Android once added on claude.ai.
- Auth is either none or OAuth. For OAuth the connector dialog offers three
  client modes: "Use Claude's published identity" (Client ID Metadata
  Document), "Register automatically" (Dynamic Client Registration, RFC 7591)
  and "Use your own OAuth client" (pre-registered client ID, optional secret).
- Callback URL is `https://claude.ai/api/mcp/auth_callback`; Anthropic says it
  may move to `https://claude.com/api/mcp/auth_callback`, so allow both.
  Client name is "Claude".
- *Secondary:* PKCE S256 is required (Claude refuses an authorization server
  that does not advertise it); sign-in starts from a 401 with
  `WWW-Authenticate`; only the first `authorization_servers` entry is used;
  discovery, registration and token endpoints must answer within 10 s.

**MCP specification** (current revision 2025-11-25, with 2026-07-28 also
present in the SDK; authorization and transports pages, via the SDK docs and
search results):

- Authorization is optional and HTTP-only. When present: OAuth 2.1, the MCP
  server is a resource server and MUST serve Protected Resource Metadata
  (RFC 9728) listing at least one authorization server, and return 401 with
  `WWW-Authenticate: Bearer resource_metadata="…"`.
- Clients discover the authorization server through RFC 8414 or OpenID
  Connect discovery. PKCE with S256 is mandatory and the server must advertise
  `code_challenge_methods_supported`.
- Client registration: Client ID Metadata Documents are the preferred path in
  2025-11-25, DCR is MAY, pre-registration is allowed.
- Resource indicators (RFC 8707 `resource`) are sent by clients; the server
  must only accept tokens issued for itself (no token passthrough).
- Streamable HTTP: one endpoint taking POST (and GET/DELETE for sessions),
  JSON or SSE responses, `Mcp-Session-Id`, `MCP-Protocol-Version`. The
  2026-07-28 revision adds a stateless mode without sessions.

**MCP Go SDK** (`github.com/modelcontextprotocol/go-sdk` v1.8.0, `docs/protocol.md`,
`auth/auth.go`, `mcp/streamable.go`):

- Stable: v1.x with semver since v1.0.0; requires Go 1.25.
- Server side provides `mcp.NewStreamableHTTPHandler` (with `Stateless`,
  `JSONResponse`, `MaxRequestBodyBytes`, localhost DNS-rebinding protection),
  `auth.RequireBearerToken` (sets `WWW-Authenticate` with the resource
  metadata URL, checks scopes and expiry, binds sessions to `TokenInfo.UserID`)
  and `auth.ProtectedResourceMetadataHandler`.
- It does **not** ship an authorization server. The authorize, token,
  registration and revocation endpoints are implemented here.
- Decision: use the official SDK. No alternative needed.

## Auth decisions

- **Claude → server:** OAuth 2.1 authorization code + PKCE (S256 only), built
  into this server. Supported client modes: DCR ("Register automatically") and
  pre-registered clients created with `nexsland-server oauth-client add`.
  Client ID Metadata Documents are **not** supported: they require the server
  to fetch the client's URL, which breaks the "no outbound network calls"
  rule. The authorization server metadata says so
  (`client_id_metadata_document_supported: false`). Users pick "Register
  automatically" in the Claude dialog.
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
need no server-to-client requests). Tools:

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
foreign keys on, one connection for writes. Numbered SQL migrations are
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

- Claude's default connector mode may be "Use Claude's published identity"
  (CIMD). This server rejects it; the user must choose "Register
  automatically" or a pre-registered client. Unverified how Claude reacts if
  the user leaves the default.
- Official Claude and MCP pages were not read directly (see first section).
- DCR is open by design. Anyone can register a client, but it gets nothing
  without the owner's consent. Unused registrations are pruned after 24 h and
  registration is rate limited.
- LWW uses client clocks. A device with a clock up to 5 minutes fast can win
  over a later edit made elsewhere.
- Revival after delete is possible under LWW, as stated above.
- In-memory rate limits reset on restart; acceptable for one process.
- Stateless MCP mode is new in the spec and the SDK warns it is still being
  defined.
