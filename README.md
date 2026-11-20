# OpenPlayX Relay

English | [简体中文](README.zh-CN.md)

[![License: GPL v3+](https://img.shields.io/badge/license-GPLv3%2B-blue.svg)](COPYING)

The VPS side of [OpenPlayX](https://github.com/openplayx/openplayx) remote
access: one Go program with a web configuration manager, **sing-box 1.12.12**
(VLESS + TLS ingress) and **frps 0.65.0**. The home side is
[openplayx-home](https://github.com/openplayx/openplayx-home). The app reaches
media services at home (Jellyfin, Emby, SMB, …) without installing an external
proxy client.

```text
App (embedded sing-box)
  -> VPS VLESS/TLS ingress (TCP 443)
  -> VPS 127.0.0.1:18096 (frps mapping)
  -> frp tunnel (home sing-box -> VPS -> 127.0.0.1:7000)
  -> home frpc -> NAS:8096
```

- **One binary**: sing-box and frp are compiled in as Go libraries, pinned in
  `src/go.mod` / `src/go.sum` (module checksums). No Python at runtime, no
  upstream binaries downloaded.
- **Minimal exposure**: only TCP 443 (or the configured proxy port) is public;
  the frps control port and media mappings listen on loopback. Each identity
  can reach only the ports assigned to it; everything else is rejected.
- **Web configuration**: typed forms, admin login, draft validation and
  testing, separate save and apply, redacted export, backups and recovery from
  damaged files.
- **Built-in SNI routing**: the proxy and the HTTPS admin page can share public
  port 443 without HAProxy or Caddy.
- **Safe upgrades**: `update` restores the previous binary if the new one fails
  to start; `rollback` switches back.

Supports Linux amd64/arm64 with systemd; the end-to-end tests also run on
macOS arm64. Availability over any particular network, including cross-border
links, is not guaranteed.

## Build

Requires Go 1.24+. The Go sources, module files and the embedded web page
(`src/web/`) are under `src/`; apart from `src/role.go`, `src/` is identical in
the Relay and Home repositories.

```bash
scripts/build.sh                       # dist/openplayx-relay-linux-{amd64,arm64} + SHA256SUMS
scripts/build.sh darwin/arm64          # other platforms
(cd src && go test ./...)             # unit tests + in-process end-to-end tests
```

## Quick start: pair and install

Prepare a domain for the VPS and a verifiable TLS certificate. Open only TCP
443 (or the proxy port you configure); 7000 and the media mapping ports stay on
loopback. An existing service on 443 needs another port. To open the admin page
directly at `https://<public IP>/`, enable the built-in SNI routing so the proxy
and the admin page share 443 (see [docs/configuration.md](docs/configuration.md)).

```bash
./openplayx-relay pair --host relay.example.com --tls-name relay.example.com \
  --certificate /etc/letsencrypt/live/relay.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/relay.example.com/privkey.pem
# Private CA: add --proxy-ca /path/to/ca.pem; certificate verification cannot be turned off.
# Refuses to run if the output directory (default secrets/) exists; keys are never rotated implicitly.

sudo mkdir -p /var/lib/openplayx-relay
sudo cp -a secrets/relay/. /var/lib/openplayx-relay/   # do not overwrite an existing directory
sudo ./openplayx-relay install       # install the binary and the systemd service (admin page + components)
sudo openplayx-relay apply           # apply the paired revision, start sing-box + frps
sudo openplayx-relay status
```

`install` creates the system account `openplayx-relay`, copies the binary to
`/opt/openplayx-relay/releases/<timestamp>/` and switches `current`, links
`/usr/local/bin/openplayx-relay`, and writes `openplayx-relay.service` (see
`deploy/openplayx-relay.service`); the config directory belongs to that
account. The service runs as that account with only `CAP_NET_BIND_SERVICE`, to
bind 443. `apply` applies the saved revision to the running service; the web
page's **Apply** button does the same after saving.

All pairing files contain credentials. Hand each one over through a trusted
channel:

- The whole `secrets/home/` directory goes to the home side. It holds only the
  Home configuration, Home-only secrets and the frps public certificate, no
  Relay private keys and no app UUIDs. Put it into the home side's private
  state directory, then edit `frpc.proxies` (home target address, port and
  `remotePort`) in the Home web form.
- `secrets/app.json` goes to the app: one sing-box `outbound` (the app user's
  UUID) plus the usable `proxies: [{name, remotePort}]`.
- `secrets/relay/` and the proxy private key stay on the VPS; the actual keys
  are in that directory's secrets.json and tls/ assets.

## Configuration model

Two layers, using sing-box / frp field names (details in
[docs/configuration.md](docs/configuration.md)):

- **Network layer (sing-box)**: the Relay's `singBox.inbound.users` gives every
  Home and every app device its own user; `singBox.route.rules` uses
  `auth_user` + `port`/`port_range` to decide which loopback ports on the Relay
  each user may reach (Home: `frps.bindPort`; apps: the mapping ports).
  Everything else is rejected.
- **Registration layer (frp)**: the Home's `frpc.proxies` declares the services
  to map and their `remotePort`; the Relay only limits which ports may be
  registered with `frps.allowPorts` (default 18000–18999) and does not need to
  know the service list.

To add a home service, change only the Home's `frpc.proxies` (port inside
`allowPorts`). To add an app device, add a user on the Relay with a matching
route rule and give that user's outbound to the device. One Relay
configuration serves one home: the frp token does not separate mappings
between homes, so use separate instances for several homes.

The current format is `schemaVersion: 2` (sing-box / frp fields). The old
format (`homeId`, `services`, `proxy`/`frp` sections) is no longer read and not
imported automatically; `install` only replaces the binary and does not
convert configuration.

## Web configuration

The page has two parts, **transport link** and **available services**. It shows
the saved configuration; expand a section to edit it. The Home manages the
actual service mappings; the Relay manages the registrable port range and
identity permissions. Certificates, logs and admin access are under the link
maintenance options. Save at the top of the page, then apply the saved
configuration.

The authoritative configuration is `relay.json`; the real UUIDs and tokens are
only in the private `secrets.json`. The admin page defaults to
`http://127.0.0.1:9081`; open it locally or through an SSH port forward.
Structure, startup, permissions and verification are described in
[docs/configuration.md](docs/configuration.md).

## Operations and rollback

```bash
sudo systemctl stop|start|restart openplayx-relay
sudo openplayx-relay status          # desired/actual revision and component state
sudo openplayx-relay check           # validate the saved configuration with the built-in sing-box/frps
sudo ./openplayx-relay update        # install a newly built binary; restores the old one if startup fails
sudo openplayx-relay rollback        # switch back to the previously installed binary
sudo openplayx-relay uninstall       # remove the systemd service, keep configuration and releases
```

`update` works like `install`: copy the new binary, switch `current`, restart
and confirm the service is active, otherwise restore the old version.
`previous` points to the last good version for `rollback`. Upgrading upstream
means changing `src/go.mod`, rebuilding and reviewing; the program never looks
for or downloads new versions itself. To roll back configuration, use
**restore previous configuration** on the web page and apply.

After renewing a certificate, import it on the web page and apply; at runtime
the program reads the managed assets in the config directory's `tls/`.

Generate and check configuration without installing:

```bash
./openplayx-relay check  --config-dir /path/to/state
./openplayx-relay render --config-dir /path/to/state --output generated   # output contains credentials
```

Topology, troubleshooting and the limits of what the tests prove:
[docs/operations.md](docs/operations.md).

## Contributing

Issues and pull requests are welcome, see [CONTRIBUTING.md](CONTRIBUTING.md).
Report security problems privately as described in [SECURITY.md](SECURITY.md).

## Disclaimer

This project is for reaching your own services at home. Follow your VPS
provider's terms and the laws on networking and encrypted communication where
you live. Availability on any network, including cross-border links, is not
guaranteed.

## Upstream and license

sing-box is licensed under GPL-3.0-or-later (with additional naming
restrictions). This program links sing-box statically, so the source in this
repository and the distributed binaries are provided as a whole under
**GPL-3.0-or-later**; the full text is in [COPYING](COPYING). frp is
Apache-2.0. When distributing binaries, provide the corresponding source (this
repository and the module versions locked in `src/go.sum`). Upstream sources:
[sing-box v1.12.12](https://github.com/SagerNet/sing-box/tree/v1.12.12),
[frp v0.65.0](https://github.com/fatedier/frp/tree/v0.65.0). Configuration
fields follow these pinned versions.

## Centrally managed nodes

The separate `managed --config <private-file>` mode consumes the central Relay profile, isolates Connector frps instances on loopback, applies per-identity port grants, acknowledges applied revisions, and stops forwarding when its lease expires. Legacy `serve`/`pair` mode is unchanged. See [managed mode](docs/managed.zh-CN.md) for deployment and current limits.
