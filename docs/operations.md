# Topology and runtime acceptance

English | [简体中文](operations.zh-CN.md)

On the VPS, sing-box and frps run inside the same `openplayx-relay` process; at
home, sing-box and frpc run inside the same `openplayx-home` process. Both use
the host network namespace: 127.0.0.1 in the configuration means the same host,
so the components cannot be split into containers with separate network
namespaces.

```text
App / embedded sing-box
  -> VPS VLESS/TLS ingress (TCP 443)
  -> VPS 127.0.0.1:18096 (frps mapping)
  -> frp tunnel (home sing-box -> VPS -> 127.0.0.1:7000)
  -> home frpc -> NAS:8096
```

The VPS opens only the chosen proxy TCP port. The frps control port and media
mappings listen on loopback, and the frps dashboard is off. App accounts may
reach only their assigned media ports; the home account only the control port.
Everything else is rejected, and domain targets cannot bypass the IP rules.

The home host listens only on a local SOCKS5 port. frpc's serverAddr=127.0.0.1
is the **VPS-side target** of the SOCKS request, not an frps on the home host;
frpc always uses `transport.proxyURL` and has no direct mode.

## Troubleshooting

- `systemctl status openplayx-relay` (home side: `openplayx-home`);
  `journalctl -u openplayx-relay --since -10min`. Component and manager logs
  share one unit; known secrets are removed from component errors before they
  are written, but still do not publish logs you have not checked.
- `sudo openplayx-relay status` shows the desired/actual revision and the
  sing-box and frps component states (`active`/`inactive`/`failed`).
- `ss -lntp` confirms the proxy port, the frps control port and the mapping
  addresses are as expected. Do not change mappings to 0.0.0.0 to work around
  connection problems.
- `sudo openplayx-relay check` validates the saved configuration with the
  built-in checks; `render --output DIR` writes the derived configuration
  (contains credentials; delete it after looking).
- For TLS errors, check the clock, serverName, CA, the full certificate chain,
  and the owner and permissions of the files in the config directory's `tls/`.
  Do not turn off verification.
- For frp login failures, check the token on both sides, additionalScopes, the
  control port and the dedicated home UUID; for mapping failures, check port
  conflicts and allowPorts.
- If the NAS is unreachable, test the single configured target from the home
  side; do not scan the home network. NAS admin pages are never added to the
  mappings automatically.
- App authentication failures need the media account fixed; 401/403 must not
  trigger repeated path switching. The source stays configured, and a
  connection failure must not delete media library resources.
- systemd `is-active` and component `active` only mean the process and
  components started. Acceptance also requires browsing, playing and seeking
  from the app and checking that the mappings are reachable.

## What the tests prove

`go test ./...` under `src/` runs the embedded sing-box and frp in both the
Relay and Home roles on single-machine loopback. It covers configuration
validation, TLS, VLESS, frpc over SOCKS, media authentication and Range
responses, and also checks app/home permission isolation, rejection of
unassigned ports and unknown UUIDs, and that stopping the home sing-box does not
fall back to a direct connection. This is not the same as acceptance over
Chinese carriers' cross-border links, long playback, mobile background
operation or Linux service management.

Known upstream issue: frpc in frp 0.65.0 has two unsynchronized reads/writes on
shutdown (visible with `go test -race`, inside frp's own code). They are
triggered only when the Home applies a new revision or the service stops.

Each relay instance currently serves one home, and several services share the
app identity. Isolating several people or homes needs separate identities and
an frp server authorization mechanism; do not treat the shared token as
multi-tenant control.
