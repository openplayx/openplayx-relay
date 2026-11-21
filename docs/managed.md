# Managed Relay mode

`openplayx-relay managed -config /etc/openplayx-relay/managed.json` subscribes to the central node profile using its dedicated machine credential. It is separate from legacy household `serve`/`pair` configuration.

## Base configuration and dynamic policy

| Part | Contents | Application |
|---|---|---|
| Base | Node identity, listen address, TLS identity/certificate paths, protocol settings, process logging | Deployment configuration; a controlled restart or reprovisioning is allowed |
| Policy | Accounts, Connector/device identities and credentials, service registration, per-device service grants | Immutable snapshot update; no shared listener or unrelated stream restart |

The API returns `baseRevision` for the node transport identity and `policyRevision` for `userPolicies`/`credentials`. The global `revision` remains the ordered ACK reference. Unsupported base transport changes are rejected for reprovisioning rather than silently ACKed.

The stable TLS/VLESS entry uses the same upstream VLESS implementation as sing-box. A new protocol authentication service is built off-path for each immutable snapshot. No live authentication map is mutated. Managed mode supports the TCP/TLS profile emitted by the API; UDP, VLESS multiplexing and Vision are not enabled. Legacy sing-box modes retain their existing capabilities.

Each Connector owns a separate loopback frps and token. Adding a Connector stages only its new frps. Service additions update the plugin's exact Connector/service/port checks and retain existing control and work connections. The private frps port range is broad, but the plugin requires both the owned port and the exact `<connectorId>.<serviceId>` proxy name. The public gateway allows only explicitly granted loopback destinations.

A transaction gate spans frp plugin approval through proxy binding. Policy commits freeze new registrations, publish the snapshot, close only revoked/rotated device or service streams, prune only removed native frps proxies, then release registrations. ACK follows completed cleanup. Removing a service releases its listener before its mapping port can be reused. Rotating a Connector's frp token replaces that Connector's frps and connections; other Connectors remain live.

New handshakes revalidate their authenticated identity and destination against the current snapshot. A handshake or pending dial that overlaps revocation cannot resurrect removed access. Invalid updates and revision rollback retain the last applied policy. Freshness timestamps never stop forwarding. Phones test and choose a fixed node; policy polling never switches that choice.

## Live statistics

The machine-authenticated status host serves `GET /live` next to `/health` (same `Authorization: Bearer <machine token>`). It reports each device and Connector with open streams (kind, owning user ID, stream count, real peer IPs, connected-since), up to 500 individual streams (service or Connector control, remote address, start time) and cumulative byte counters per principal and for the node since process start. `rxBytes` is what the client sent to the Relay, `txBytes` what the Relay sent to the client. Rates are derived by the caller from two samples. Credentials and payload are never included. The admin console reads it through the API's `GET /v1/adminzzz/relay/nodes/{nodeId}/live`.

## Verification

Run `cd src && go test ./...`, `go vet ./...`, and `go test -race ./...`. Real tests use native sing-box App/Connector clients and frp with a continuously transmitting TCP stream while registering services/devices/accounts, revoking grants, deleting a service and rotating a device UUID. They verify listener/control identity retention, targeted disconnects and immediate service-port release.

The pinned frp source and narrow update/concurrency patches are in `src/third_party/`; see its README and retained Apache-2.0 notices. The previously observed channel and control-pointer races have local fixes; the current full race suite passes. This does not imply that every upstream behavior has been audited.

Bandwidth and connection-count limits from `userPolicies` are not implemented as runtime quota enforcement. See [Chinese details](managed.zh-CN.md).
