# Web configuration and authoritative JSON

English | [简体中文](configuration.zh-CN.md)

One process has two layers: the web manager manages this side's logical
configuration, and the embedded sing-box/frp run only the most recently
**successfully applied** revision. The web page offers no shell, no arbitrary
file reads or writes and no raw JSON editor.

## Files and responsibilities

- `relay.json` / `home.json`: this side's only editable connection
  configuration, with `schemaVersion: 2` and a monotonically increasing
  `revision`; structure below.
- `secrets.json`: the actual UUID and frp token values; the normal
  configuration only holds `secret:...` references. Read, status and redacted
  export APIs never return the actual values.
- `tls/`: managed certificate and private key assets; the configuration stores
  references relative to this managed directory. The web import accepts PEM up
  to 128 KiB; the server chooses the file name and never accepts a path from the
  browser. The runtime reads the files here directly.
- `admin.json`: scrypt verifier of the separate admin password (same format as
  the earlier Python version, so passwords keep working after migration). The
  admin identity is unrelated to the app and frpc identities.
- `bootstrap-token` / `bootstrap.json`: the 15-minute credential for the first
  local setup and its verifier; deleted once an admin password is set.
- `*.backup.json`: the previous validated logical configuration, without actual
  secret values.
- `last-good.json`: the most recently applied revision; the service starts
  components from it. `previous-good.json`: the successful revision before
  that; its secret references are kept during cleanup.
- `status.json`: the revision actually in effect and failure state.
  `runtime.json`: component state published by the running service, read by
  the CLI `status`/`apply`.
- `revision.json`: counter of issued revisions, so even an explicit recovery
  from a damaged file never reuses an old revision.

The state directory defaults to `/var/lib/openplayx-relay/` or
`/var/lib/openplayx-home/`: directory 0700, configuration/secrets/assets 0600,
owned by the service account. After CLI commands that change configuration run
as root, the program restores the owner of the files to the directory's owner.

## Configuration structure (sing-box / frp fields)

Two layers: **sing-box for the network layer, frp for the registration layer**.
Field names match upstream, but only a controlled subset is available: types,
tags, loopback listeners, enforced TLS and other fixed values are validated by
the backend, and credential fields (`uuid`, `token`) only hold `secret:...`
references.

Relay `relay.json`:

```json
{
  "schemaVersion": 2, "revision": 6,
  "singBox": {
    "inbound": {
      "type": "vless", "tag": "proxy", "listen": "127.0.0.1", "listen_port": 443,
      "users": [ { "name": "home", "uuid": "secret:..." }, { "name": "app", "uuid": "secret:..." } ],
      "tls": { "enabled": true, "server_name": "relay.example.com", "certificate_path": "tls/proxy.crt", "key_path": "tls/proxy.key" }
    },
    "route": { "rules": [
      { "auth_user": ["home"], "port": [7000] },
      { "auth_user": ["app"], "port_range": ["18000:18999"] }
    ] }
  },
  "frps": {
    "bindPort": 7000, "auth": { "token": "secret:..." },
    "transport": { "tls": { "certFile": "tls/frps.crt", "keyFile": "tls/frps.key" } },
    "allowPorts": [ { "start": 18000, "end": 18999 } ]
  },
  "log": { "level": "warn" },
  "management": { "...": "..." }
}
```

- `inbound.users`: one user per Home and per app device; deleting a user
  revokes that identity. UUIDs must be unique.
- `route.rules`: only `auth_user`, `port` and `port_range` are allowed. When the
  runtime configuration is generated, every rule is limited to destination
  `127.0.0.1/32` and routed to direct, and a final reject is appended. Ports can
  only be `frps.bindPort` or ports inside `frps.allowPorts`. When you change
  `bindPort`, change the rule that allows it too.
- `frps`: always listens on loopback only and enforces TLS. `allowPorts` uses
  frp's native format (`{"single": n}` or `{"start": a, "end": b}`) and limits
  the `remotePort`s a Home may register. The Relay does not need to know the
  service list in advance.

Home `home.json`:

```json
{
  "schemaVersion": 2, "revision": 5,
  "singBox": {
    "inbound": { "type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": 1080 },
    "outbound": {
      "type": "vless", "tag": "relay", "server": "relay.example.com", "server_port": 443, "uuid": "secret:...",
      "tls": { "enabled": true, "server_name": "relay.example.com", "certificate": "(optional CA PEM)" }
    }
  },
  "frpc": {
    "user": "home", "serverAddr": "127.0.0.1", "serverPort": 7000, "auth": { "token": "secret:..." },
    "transport": { "tls": { "serverName": "openplayx-frps", "trustedCaFile": "tls/frps-ca.crt" } },
    "proxies": [
      { "name": "jellyfin", "type": "tcp", "localIP": "192.168.1.10", "localPort": 8096, "remotePort": 18096 }
    ]
  },
  "log": { "level": "warn" },
  "management": { "...": "..." }
}
```

- The `uuid` of `singBox.outbound` is the UUID of one user on the Relay;
  `inbound` is used only by frpc through `transport.proxyURL`.
- `frpc.serverAddr` is always `127.0.0.1`: frpc reaches frps on the Relay's
  loopback through SOCKS → VLESS. There is no direct mode.
- `frpc.proxies` is the service registration. Only `type: "tcp"` is supported;
  `remotePort` must be inside the Relay's `frps.allowPorts`, otherwise frps
  rejects it. With `user` set, the proxy name on frps is `user.name`.

The file for the app (`app.json`, generated by `pair`) has only two parts: one
sing-box `outbound` (with that app user's UUID) and the subset of frpc proxies
it may use, `proxies: [{ "name", "remotePort" }]`.

Secret update keys in the web form and API: on the Relay `uuid:<user name>` and
`token`, on the Home `uuid` and `token`. Leaving a field out keeps the value; an
empty string clears it.

## Initial setup

`schemaVersion: 1` (the old format with `homeId`, `services` and
`grants.json`) is no longer read and not imported automatically. Old
deployments need their configuration rewritten in the structure above, keeping
the existing `secret:` references.

New deployments use the Relay's `openplayx-relay pair` to generate separate
`relay/` and `home/` state directories and `app.json` in one step. The home side
receives only `home/`, which contains no app UUID and no Relay private key.
`app.json` contains real client secrets: hand it over through a trusted channel
and never publish it as a redacted configuration.

## Running and installing

Foreground (debugging, or environments without systemd):

```bash
./openplayx-relay serve --config-dir /path/to/private-state
```

`serve` provides the admin page and runs the components. On start, if
`last-good.json` exists, it starts sing-box/frps from that revision. If the
configuration is invalid or a component fails to start, the admin page stays
available and the status shows the component as `failed`. Without any applied
revision the components stay stopped.

Linux/systemd installation:

```bash
sudo ./openplayx-relay install
sudo systemctl status openplayx-relay
sudo openplayx-relay uninstall      # removes only the service; keeps state and releases
```

The service runs as the dedicated account `openplayx-relay` with restrictions
such as ProtectSystem=strict/ProtectHome; it can only write to the state
directory and keeps only `CAP_NET_BIND_SERVICE`. The API accepts no commands,
executable paths or arbitrary target file paths.

Default pages: Relay `http://127.0.0.1:9081`, Home `http://<home LAN IP>:9080`
(listening on 0.0.0.0). For the first login, read the bootstrap-token from the
private directory in a local terminal; it expires after 15 minutes. Run
`sudo openplayx-relay renew-bootstrap` to issue a new one. After setup, set an
admin password of at least 16 characters.

Open the Relay page locally or through an SSH port forward; the Home page is
opened directly by IP inside the home network by default. If you forward to a
different local port, the browser's Host must be among the origins the
management configuration allows; forwarding to the same port number is
simplest.

```bash
# Relay example
ssh -L 9081:127.0.0.1:9081 user@relay.example.com
```

### Sharing public port 443 with the proxy (built-in SNI routing)

The Relay can listen on public 443 itself and serve both the app/Home proxy
connections and the web admin page, without external programs such as HAProxy
or Caddy. It reads only the SNI in the TLS ClientHello and decrypts nothing:

- SNI equal to `singBox.inbound.tls.server_name` of the **currently applied
  revision**: the bytes are forwarded unchanged to sing-box on loopback
  (`singBox.inbound.listen:listen_port`), sing-box terminates TLS, and the
  app/Home outbounds keep their address, port, UUID and certificate. If sing-box
  is not running, the connection is closed.
- Any other TLS connection (for example a browser opening `https://<public IP>/`)
  is handed in-process to the HTTPS admin page, which sees the real client
  address, so login rate limits apply per client.
- Non-TLS connections, or connections without a complete ClientHello within 5
  seconds, are closed; the number of unfinished handshakes is capped.

Add the optional `frontend` to `management` in `relay.json` (the admin page's
"public TLS entry IP/port" fields):

```json
"singBox": { "inbound": { "listen": "127.0.0.1", "listen_port": 443, "tls": { "server_name": "relay.example.com", "...": "..." }, "...": "..." }, "...": "..." },
"management": {
  "listen": "127.0.0.1", "port": 9081, "https": true,
  "certificateFile": "tls/<admin certificate>.crt", "keyFile": "tls/<admin key>.key",
  "allowedHosts": ["localhost", "127.0.0.1", "203.0.113.10"],
  "frontend": { "listen": "203.0.113.10", "port": 443 }
}
```

Constraints (validated by the backend):

- `frontend.listen` is the machine's actual public IP (not loopback; `0.0.0.0`
  would conflict with sing-box on loopback and is rejected). `frontend.port`
  must equal `singBox.inbound.listen_port`, because that is the `server_port`
  of the Home and app outbounds.
- `singBox.inbound.listen` must be a loopback address; the admin page must use
  HTTPS with a managed certificate; an admin password must be set.
  `allowedHosts` must include the public IP or domain, the admin certificate's
  SAN must contain it, and a self-signed certificate must be trusted
  explicitly in the browser.
- It must not conflict with the inbound, the admin page, frps `bindPort` or
  `allowPorts` listeners. The admin page itself stays on its loopback port
  (for example 9081) and remains reachable through SSH forwarding.

`frontend` belongs to the management entry: after saving, run
`systemctl restart openplayx-relay` for it to take effect (components restart
with the applied revision, which briefly interrupts playback). After changing
`singBox.inbound.tls.server_name`, routing follows the newly applied revision
automatically. Once the public page, 401 for unauthenticated API calls, login
and the Home tunnel are verified, remove the host firewall rule for `9081/tcp`
if it is no longer needed.

Deployments that used HAProxy before (sing-box on `127.0.0.1:443`, admin page
on `127.0.0.2:443`) keep working. To switch to the built-in routing: save a
revision with `frontend`, run `systemctl disable --now haproxy`, then restart
`openplayx-relay` (the built-in entry needs the public 443 that HAProxy held).

The Home allows direct LAN IP access by default, still requiring the admin
password or the short-lived bootstrap credential, and accepts only requests
from loopback or private home networks. Literal IPs that actually reach a local
interface are allowed automatically; other host names must be listed in
allowedHosts. Home write requests must have an Origin that exactly matches the
current Host. Non-loopback Relay management still requires HTTPS and an admin
password. After changing the management listener, the page only saves it;
restart the service locally (`systemctl restart openplayx-relay`; components
restart with the applied revision, which briefly interrupts playback) before
applying component configuration, so the page does not report the old listener
as in effect.

## Workflow

1. Edit the typed form. Leaving a secret empty keeps it; if a secret is cleared
   explicitly while something still depends on it, the backend refuses to save.
2. Validate the draft: the server checks version, ports, duplicate services,
   permissions, credential references and TLS paths, independent of the
   frontend's checks.
3. Test the draft: generate the runtime configuration in memory, run the same
   built-in checks as `sing-box check` and `frps verify`/`frpc verify`, and load
   the TLS assets; the Home also tests TCP reachability of the configured Relay.
   This restarts no live components, writes no authoritative configuration and
   does not promise that media login or the tunnel already works.
4. Save the JSON with expectedRevision; concurrent changes return 409. Secrets
   are written first; the normal JSON is saved through a temporary file in the
   same directory, fsync and atomic replace. Saving is not applying.
5. Apply the saved revision: validate first, then stop the old components
   in-process and start the new ones in the order sing-box → frps/frpc. The
   Home starts frpc only after the SOCKS5 handshake is ready; frpc connects only
   through that SOCKS proxy and never falls back to a direct connection.
6. On failure, the saved desired revision is kept, the page shows "saved but
   not in effect", and the previous runtime configuration from
   `last-good.json` is restarted (or the components are stopped if there is
   none). Only on success is the actual revision updated and secrets no longer
   referenced by the current, backup, last-good and previous-good
   configurations cleaned up.

The CLI `apply` runs the same flow against the installed systemd service: it
writes `last-good.json`, restarts the service and waits until the service
reports, in `runtime.json`, that all components of that revision are active.
On failure it restores the previous one and reports applyFailed.

Configuration and apply changes may affect active playback; the page warns
before applying. Only this side is updated; never claim that the other machine
was updated too.

A normal "restore previous configuration" is also saved as a new revision and
still needs to be applied. Damaged files or unknown schemas are never
overwritten with defaults. If the management configuration cannot be read or is
unsafe at startup, only the fixed loopback recovery entry is used, still
requiring admin authentication, and the original file is not rewritten. After
authenticating you can explicitly restore the last known backup: concurrent
changes are checked by file hash first, the original bytes are saved as a
damaged file, and a new revision above the issued counter is created.

## API and security boundaries

- The management API uses an HttpOnly + SameSite=Strict session cookie that
  expires after 30 minutes; Secure is added over HTTPS.
- Changes require a login session, a separate CSRF token, a JSON request, an
  explicit Content-Length and an exact Origin/Host match. CORS is not offered.
  The static login page allows normal cross-page navigation and exposes no
  configuration.
- Login attempts are rate limited; request bodies, the number of TLS assets and
  concurrent connections (32) are capped. Logs record no request URLs, forms or
  secrets; component errors have known secret values removed before logging.
- Only three embedded static web resources are served. There is no private key
  download and no arbitrary file API.
- `GET /api/config`, `/api/status`, `/api/export`; `POST /api/validate`,
  `/api/test`, `/api/save`, `/api/apply`, `/api/restore`; explicit recovery
  from damaged files uses `/api/recovery` and `/api/recover`. All
  configuration and status endpoints require authentication.
- Changes to the management listener need a local service restart; the manager
  has no web API to stop or restart itself or any other system service.

The frp token is shared by all Homes and does not separate mappings between
homes; use separate instances for several homes. The generator currently
supports the pinned VLESS/TLS version; a new proxy protocol needs backend schema,
generator and real verification work, and must not be presented in the form as
already supported.

## Verification

```bash
cd src && go test ./...
```

The tests cover: secrets never appearing in normal JSON or APIs, revision
conflicts, backup restore, protection of unknown/damaged files, hash-checked
recovery, rejection of bad ports/paths/permissions, login/CSRF/cross-origin
limits, rollback after a failed apply, pairing output, and a media link with
real sing-box/frp running as both Relay and Home in one process
(`TestEndToEnd`, skipped with `go test -short`).

An existing Home loopback configuration can be switched with
`sudo ./openplayx-home install --enable-lan` (or, once installed,
`sudo openplayx-home enable-lan` followed by a service restart), which saves a
new revision explicitly. The option applies only to the Home; the Relay keeps
its loopback default. The host firewall should allow TCP 9080 only from the
home network; do not forward the port on the router.
