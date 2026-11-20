# Managed Relay mode

`openplayx-relay managed -config /etc/openplayx-relay/managed.json` subscribes to the first-party node profile using a dedicated machine credential. This mode is provisioned by the API's `/adminzzz/relay` workflow and is separate from legacy single-household pairing.

Only enabled or preparing profiles are accepted. Revisions cannot move backwards, leases last at most 30 minutes, and expiry stops the runtime even if a profile request is blocked. The node ACKs only after applying the policy and closing the previous runtime. Its protected TLS health endpoint reports the node, release and applied revision.

Each Connector has its own loopback frps and authentication token. VLESS identities can reach only their logical control port or explicitly granted service ports. No frps or mapped service port is exposed publicly. Node TLS keys stay on the node; it never receives Vultr or DNS credentials.

Run `cd src && go test ./...` and `go vet ./...`. The tests include a real VLESS → frps → Connector → HTTP media path and lease expiry. The pinned frp v0.65.0 dependency reports internal close/send races during full managed race tests; isolated policy/plugin/sync race tests pass. Do not describe the full path as race-clean. See [Chinese operational details](managed.zh-CN.md).
