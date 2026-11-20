# Pinned frp source

frp/ contains github.com/fatedier/frp v0.65.0 with its original Apache-2.0 notices
and LICENSE. Local changes are the managed update gate in
server/service.go and server/control.go, the hooks in server/managed.go, and
close/send synchronization in server/control.go and client/proxy/proxy_wrapper.go, plus guarded control pointer access in client/service.go and serialized/idempotent server Run/Close lifecycle.
No upstream version upgrade is involved.

The gate covers plugin approval through proxy binding. It allows immutable
policy publication and targeted proxy removal before ACK, without restarting
frps or unrelated controls and streams. Keep these files identical in Home and
Relay. The synchronized close/send paths address the previously observed upstream
work-connection and health-notification channel races.
