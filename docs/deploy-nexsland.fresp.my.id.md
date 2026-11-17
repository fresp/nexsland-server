# Deployment: nexsland.fresp.my.id

Step by step for the owner's instance. Run these on the VPS that will host it
(Docker, nginx and certbot installed). Replace `<VPS_IPV4>` / `<VPS_IPV6>`.

## 1. DNS

At the fresp.my.id DNS provider:

```
nexsland.fresp.my.id.  300  IN  A     <VPS_IPV4>
nexsland.fresp.my.id.  300  IN  AAAA  <VPS_IPV6>   ; only if the VPS has IPv6
```

Check: `dig +short nexsland.fresp.my.id` returns the VPS address. If the zone is
behind Cloudflare, use "DNS only" (grey cloud) at least until the certificate is
issued; proxied mode also works later but must not buffer `/mcp`.

## 2. Container

```sh
sudo mkdir -p /opt/nexsland && cd /opt/nexsland
git clone -b ccr-6bcafeb1-0r0p79 https://github.com/fresp/nexsland-server.git src
cp src/docker-compose.yml .
sed -i 's#https://nexsland.example.com#https://nexsland.fresp.my.id#; s#^    build: \.#    build: ./src#; s#image: ghcr.io/fresp/nexsland-server:latest#image: nexsland-server:local#' docker-compose.yml
docker compose build
docker compose up -d
docker compose ps            # STATUS should become "healthy"
curl -s http://127.0.0.1:8080/healthz    # {"status":"ok"}
```

(No image is published to a registry yet, so it builds from source.)

## 3. nginx and TLS

```sh
sudo certbot certonly --nginx -d nexsland.fresp.my.id
sudo cp src/deploy/nginx.conf /etc/nginx/sites-available/nexsland
sudo sed -i 's/nexsland.example.com/nexsland.fresp.my.id/g' /etc/nginx/sites-available/nexsland
sudo ln -s /etc/nginx/sites-available/nexsland /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
curl -s https://nexsland.fresp.my.id/.well-known/oauth-protected-resource/mcp
```

The last command must print JSON with `"resource":"https://nexsland.fresp.my.id/mcp"`.
On nginx older than 1.25.1, replace `http2 on;` with `listen 443 ssl http2;`.

## 4. Owner password

```sh
docker compose exec -it nexsland nexsland-server owner set-password
```

At least 12 characters. Then open https://nexsland.fresp.my.id/ and sign in.

## 5. Connector in claude.ai

1. claude.ai → Settings → Connectors → Add custom connector.
2. Name `Nexsland`, URL `https://nexsland.fresp.my.id/mcp`.
3. OAuth client: **Register automatically** (not "Use Claude's published identity").
4. Connect → sign in on your server → the consent page must say it returns to
   `claude.ai` → Allow.
5. The dashboard at https://nexsland.fresp.my.id/ now lists "Claude" under
   Connected clients.

If step 3 has no "Register automatically" option or connecting fails, run
`docker compose exec nexsland nexsland-server oauth-client add Claude https://claude.ai/api/mcp/auth_callback https://claude.com/api/mcp/auth_callback`
and use "Use your own OAuth client" with that client ID and no secret.

## 6. Test from Claude mobile

Make sure the connector is enabled in the chat's tools menu, then:

1. "add a todo for tomorrow 09:00: call the dentist" → Claude calls `add_todo`
   with `date` = tomorrow's date in Asia/Jakarta and `time` = `09:00`.
2. "list my todos" → the todo appears with that date and time.

## What to report back

- Output of `docker compose ps` and the `curl` in step 3.
- Whether the connector connected, and which OAuth client option you used.
- The two Claude replies from step 6 (or the error text).
- On failure: `docker compose logs --tail 100 nexsland` (logs contain no titles or tokens).
