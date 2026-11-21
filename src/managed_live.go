package main

// Live statistics for the managed data plane: which devices (Apps) and
// Connectors hold streams right now, where they connect from, and byte
// counters that the admin console turns into rates. Counters are cumulative
// since process start and never contain credentials or payload data.
import (
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"encoding/json"
)

type managedTraffic struct{ rx, tx atomic.Uint64 }

// countingConn counts bytes on the client side of a stream: rx is what the
// client sent to the Relay, tx is what the Relay sent to the client.
type countingConn struct {
	net.Conn
	counters []*managedTraffic
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		for _, counter := range c.counters {
			counter.rx.Add(uint64(n))
		}
	}
	return n, err
}
func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		for _, counter := range c.counters {
			counter.tx.Add(uint64(n))
		}
	}
	return n, err
}

// CloseWrite keeps splice's half-close semantics of the wrapped connection.
func (c *countingConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return c.Conn.Close()
}

// The public frontend reaches the data plane over loopback. It records the
// loopback source address of each spliced connection so the data plane can
// report the real peer address of a stream.
var frontendPeers sync.Map

func frontendPeer(raw net.Conn) string {
	if peer, ok := frontendPeers.Load(raw.RemoteAddr().String()); ok {
		return peer.(string)
	}
	return raw.RemoteAddr().String()
}

const managedLiveStreamLimit = 500

func (d *managedDataPlane) principalTraffic(id string) *managedTraffic {
	counter := d.traffic[id]
	if counter == nil {
		counter = &managedTraffic{}
		d.traffic[id] = counter
	}
	return counter
}

// Live returns a consistent snapshot of streams and counters.
func (d *managedDataPlane) Live() obj {
	d.mu.Lock()
	defer d.mu.Unlock()
	type principalView struct {
		ID        string   `json:"id"`
		Kind      string   `json:"kind"`
		UserID    string   `json:"userId,omitempty"`
		Streams   int      `json:"streams"`
		Remotes   []string `json:"remotes"`
		Since     string   `json:"connectedSince,omitempty"`
		RxBytes   uint64   `json:"rxBytes"`
		TxBytes   uint64   `json:"txBytes"`
		since     time.Time
		remoteSet map[string]bool
	}
	principals := map[string]*principalView{}
	view := func(id string) *principalView {
		p := principals[id]
		if p == nil {
			p = &principalView{ID: id, Kind: "unknown", Remotes: []string{}, remoteSet: map[string]bool{}}
			if d.snapshot != nil {
				if principal, ok := d.snapshot.principals[id]; ok {
					p.Kind, p.UserID = principal.Kind, principal.UserID
				}
			}
			if counter := d.traffic[id]; counter != nil {
				p.RxBytes, p.TxBytes = counter.rx.Load(), counter.tx.Load()
			}
			principals[id] = p
		}
		return p
	}
	for id := range d.traffic {
		view(id)
	}
	streams := []obj{}
	ordered := make([]*managedStream, 0, len(d.streams))
	for stream := range d.streams {
		ordered = append(ordered, stream)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].startedAt.Before(ordered[j].startedAt) })
	for _, stream := range ordered {
		p := view(stream.auth.ID)
		p.Streams++
		if p.since.IsZero() || stream.startedAt.Before(p.since) {
			p.since = stream.startedAt
			p.Since = stream.startedAt.UTC().Format(time.RFC3339)
		}
		if host, _, err := net.SplitHostPort(stream.remote); err == nil && !p.remoteSet[host] {
			p.remoteSet[host] = true
			p.Remotes = append(p.Remotes, host)
		}
		if len(streams) < managedLiveStreamLimit {
			service := stream.route.Service
			kind := "service"
			if len(service) > 8 && service[:8] == "control:" {
				service, kind = "", "control"
			}
			streams = append(streams, obj{"principal": stream.auth.ID, "kind": kind, "serviceId": service, "connectorId": stream.route.Connector, "remote": stream.remote, "startedAt": stream.startedAt.UTC().Format(time.RFC3339), "rxBytes": stream.traffic.rx.Load(), "txBytes": stream.traffic.tx.Load()})
		}
	}
	list := make([]*principalView, 0, len(principals))
	for _, p := range principals {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	return obj{"observedAt": time.Now().UTC().Format(time.RFC3339Nano), "totals": obj{"rxBytes": d.totals.rx.Load(), "txBytes": d.totals.tx.Load(), "streams": len(d.streams)}, "principals": list, "streams": streams, "streamsTruncated": len(d.streams) > len(streams)}
}

func (m *managedAgent) live(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	live := m.runtime.Live()
	live["nodeId"], live["protocol"], live["processStartedAt"] = m.config.NodeID, "managed-v1", managedProcessStartedAt
	_ = json.NewEncoder(w).Encode(live)
}
