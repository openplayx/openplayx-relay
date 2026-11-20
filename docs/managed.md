# Managed Relay mode

`openplayx-relay managed -config /etc/openplayx-relay/managed.json` subscribes to the first-party node profile using a dedicated machine credential. This mode is provisioned by the API's `/adminzzz/relay` workflow and is separate from legacy single-household pairing.

Enabled/preparing profiles and empty disabled profiles are accepted. Revisions cannot move backwards. Freshness timestamps do not stop forwarding: temporary API failures and rejected updates retain the last applied policy. Revisions with identical authorization do not restart the runtime. Actual identity or port changes still reload the runtime and interrupt existing connections; this is not a zero-downtime reload. The node ACKs only after the effective policy is applied. Its protected TLS health endpoint reports the node, release and applied revision.

Each Connector has its own loopback frps and authentication token. VLESS identities can reach only their logical control port or explicitly granted service ports. No frps or mapped service port is exposed publicly. Node TLS keys stay on the node; it never receives Vultr or DNS credentials.

Run `cd src && go test ./...` and `go vet ./...`. The tests include a real VLESS → frps → Connector → HTTP media path and retention of the last applied policy. The pinned frp v0.65.0 dependency reports internal close/send races during full managed race tests; isolated policy/plugin/sync race tests pass. Do not describe the full path as race-clean. See [Chinese operational details](managed.zh-CN.md).

Phones choose a Relay node explicitly after TCP/TLS reachability tests. Background refresh never switches the selected node. Managed service ports remain reserved until the node ACKs revocation or Vultr confirms instance destruction; elapsed freshness time alone never permits reuse.
