# Nexsland Server

A small self-hosted todo server for one person. Claude (web, desktop, iOS, Android)
reads and edits your todos through an MCP endpoint, and the
[Nexsland](https://github.com/fresp/nexsland) GNOME Shell extension syncs the same
list through a REST API.

- One static Go binary, SQLite storage, no CGO, no telemetry, no outbound network calls.
- OAuth 2.1 with PKCE and dynamic client registration for Claude; device pairing for Nexsland.
- One owner per deployment. No sign-up.

Design, data contract and the verified auth requirements: [docs/design.md](docs/design.md).

## Self-hosting

You need a host name pointing at a server with Docker and nginx (or any reverse
proxy that terminates TLS). The server itself only speaks plain HTTP on a local port.

1. **DNS.** Create an `A` (and `AAAA` if you have IPv6) record for your host, for
   example `todo.example.com`, pointing at the server.
2. **Run the container.** Copy `docker-compose.yml`, set `NEXSLAND_PUBLIC_URL` to
   `https://todo.example.com` and `NEXSLAND_TZ` to your time zone, then:

   ```sh
   docker compose up -d
   ```

   It listens on `127.0.0.1:8080` and keeps its database in the `nexsland-data` volume.
   To build the image yourself instead of pulling it, run `docker compose build` first.
3. **TLS and nginx.** Get a certificate (for example `certbot certonly --nginx -d
   todo.example.com`), copy `deploy/nginx.conf` to `/etc/nginx/sites-available/`, replace
   the host name and certificate paths, enable it and reload nginx. The `/mcp` location
   disables buffering so streamed responses reach Claude immediately.
4. **Owner password.**

   ```sh
   docker compose exec -it nexsland nexsland-server owner set-password
   ```

   Then sign in at `https://todo.example.com/`. The page lists paired devices and
   connected clients, each with a Revoke button.

Without Docker: `CGO_ENABLED=0 go build ./cmd/nexsland-server`, set the variables
below and run `nexsland-server serve` under systemd as an unprivileged user.

### Configuration

All configuration is environment variables.

| Variable | Required | Example | Meaning |
|---|---|---|---|
| `NEXSLAND_PUBLIC_URL` | yes | `https://todo.example.com` | External base URL. Must be HTTPS (http only for localhost). Used for OAuth metadata, cookies and pairing links. |
| `NEXSLAND_TZ` | yes | `Asia/Jakarta` | IANA zone that defines "today" for every client and for Claude. |
| `NEXSLAND_DB` | yes | `/data/nexsland.db` | SQLite database path. The directory must be writable (WAL files live next to it). |
| `NEXSLAND_LISTEN` | yes | `:8080` | Listen address. |
| `NEXSLAND_LOG_LEVEL` | no | `info` | `debug`, `info`, `warn` or `error`. Logs are JSON on stderr and never contain todo titles, tokens or codes. |

The Docker image sets `NEXSLAND_DB=/data/nexsland.db` and `NEXSLAND_LISTEN=:8080`.

Forwarding headers (`X-Real-IP`, `X-Forwarded-For`) are trusted only from loopback
and private addresses, so rate limiting sees real client IPs behind a local proxy.

### Commands

```
nexsland-server serve                         run the server (default)
nexsland-server owner set-password            set the owner password; signs out web sessions
nexsland-server oauth-client add NAME URI...  pre-register a public OAuth client
nexsland-server migrate                       apply migrations and print the schema version
nexsland-server healthcheck                   probe /healthz (used by the Docker HEALTHCHECK)
nexsland-server version
```

The admin commands open the same database as the running server. That is safe:
SQLite serializes the short writes they make.

## Connect Claude

Custom connectors are added on claude.ai and then work in the Claude apps too.

1. In Claude, open **Settings → Connectors → Add custom connector**.
2. Name: `Nexsland`. Remote MCP server URL: `https://todo.example.com/mcp`.
3. Under the OAuth client options choose **Register automatically**. This server
   does not support "Use Claude's published identity" (Client ID Metadata Documents),
   because that would require it to fetch a URL from the internet. If automatic
   registration is not offered, run
   `nexsland-server oauth-client add Claude https://claude.ai/api/mcp/auth_callback`
   and choose **Use your own OAuth client** with the printed client ID and an empty secret.
4. Click **Connect**. You are sent to your server: sign in, check that the consent
   page says it returns to `claude.ai`, and click **Allow**.
5. Try it: "add a todo for tomorrow 09:00: call the dentist", then "list my todos".

Tools: `add_todo`, `list_todos`, `complete_todo`, `reopen_todo`, `update_todo`,
`delete_todo`. Every result starts with today's date in `NEXSLAND_TZ`, so Claude
resolves "tomorrow" correctly. Unfinished todos from earlier days are listed as overdue;
the server never moves a todo to another day.

## Pair Nexsland

In Nexsland's preferences choose server storage, enter the server URL and press Pair.
Nexsland shows a code such as `BCDF-GHJK`; open `https://todo.example.com/pair`, enter
it and approve. The device receives a long-lived token, stored hashed on the server and
revocable from the dashboard.

The sync API is described in [docs/design.md](docs/design.md#rest-sync-api).

## Backup

The database is one SQLite file in WAL mode. Copy it with SQLite's online backup,
never with `cp` while the server runs:

```sh
docker run --rm -v nexsland-data:/data -v "$PWD":/backup alpine:3 \
  sh -c 'apk add -q sqlite && sqlite3 /data/nexsland.db ".backup /backup/nexsland-$(date +%F).db"'
```

For continuous off-site backup run [Litestream](https://litestream.io) as a sidecar
replicating `/data/nexsland.db`. To restore, stop the server and put the backup file
in place as `nexsland.db` (delete any stale `-wal` and `-shm` files).

## Upgrade

```sh
docker compose pull && docker compose up -d
```

Schema migrations are versioned, embedded in the binary and applied on start in a
transaction. Take a backup first. A binary refuses to start on a database whose schema
is newer than it knows, so roll back by restoring the pre-upgrade backup together with
the older image.

## Development

```sh
go vet ./... && go test -race ./...
```

Tests cover the store (migrations, last-write-wins, tombstones, cursor paging),
validation and time zones, the pairing and sync flows over HTTP, OAuth, and every MCP
tool through the SDK's client.

## License

GPL-3.0-or-later, the same as Nexsland. See [LICENSE](LICENSE).
