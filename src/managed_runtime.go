package main

// The managed data plane separates stable listeners/transports from immutable
// user policy. It uses the same upstream VLESS protocol implementation as
// sing-box, without mutating a live sing-box authentication map or router.
import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	vmess "github.com/sagernet/sing-vmess"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/util"
	frpserver "github.com/fatedier/frp/server"
	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"net/http"
)

type managedAuth struct{ ID, UUID string }
type managedRoute struct {
	Service, Connector string
	Port               int
	Token              string
}
type managedPrincipal struct {
	Auth   managedAuth
	Routes map[int]managedRoute
}
type managedSnapshot struct {
	principals map[string]managedPrincipal
	identities map[string]managedIdentity
	proxies    map[string]map[string]int
	protocol   *vless.Service[managedAuth]
}
type managedServer struct {
	service *frpserver.Service
	cancel  context.CancelFunc
	port    int
	token   string
}
type managedStream struct {
	auth     managedAuth
	route    managedRoute
	raw      net.Conn
	cancel   context.CancelFunc
	mu       sync.Mutex
	upstream net.Conn
	done     chan struct{}
}

func (s *managedStream) close() {
	s.cancel()
	s.raw.Close()
	s.mu.Lock()
	if s.upstream != nil {
		s.upstream.Close()
	}
	s.mu.Unlock()
}

type managedDataPlane struct {
	applyMu       sync.Mutex
	mu            sync.Mutex
	config        managedConfig
	listener      net.Listener
	address       string
	listenAddress string // defaults to loopback 10443; tests use ephemeral ports
	snapshot      *managedSnapshot
	servers       map[string]*managedServer
	streams       map[*managedStream]bool
	stopped       bool
}

func newManagedDataPlane(config managedConfig) *managedDataPlane {
	return &managedDataPlane{config: config, servers: map[string]*managedServer{}, streams: map[*managedStream]bool{}}
}
func (d *managedDataPlane) Components() map[string]string {
	d.mu.Lock()
	defer d.mu.Unlock()
	state := "inactive"
	if d.listener != nil && !d.stopped {
		state = "active"
	}
	return map[string]string{"vless": state, "frps": state}
}
func (d *managedDataPlane) proxyTarget() (string, string, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.address, d.config.Host, d.listener != nil && !d.stopped
}
func (d *managedDataPlane) Stop() error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	d.mu.Lock()
	d.stopped = true
	listener := d.listener
	d.listener = nil
	streams := make([]*managedStream, 0, len(d.streams))
	for s := range d.streams {
		streams = append(streams, s)
	}
	servers := d.servers
	d.servers = map[string]*managedServer{}
	d.snapshot = nil
	d.mu.Unlock()
	if listener != nil {
		listener.Close()
	}
	for _, s := range streams {
		s.close()
	}
	for _, s := range servers {
		s.service.Close()
		s.cancel()
	}
	return nil
}
func (d *managedDataPlane) compile(p managedProfile, identities map[string]managedIdentity, servers map[string]*managedServer) *managedSnapshot {
	s := &managedSnapshot{principals: map[string]managedPrincipal{}, identities: identities, proxies: map[string]map[string]int{}}
	users := []managedAuth{}
	uuids := []string{}
	flows := []string{}
	add := func(id, ref string, routes map[int]managedRoute) {
		a := managedAuth{id, p.Credentials[ref].Value}
		s.principals[id] = managedPrincipal{a, routes}
		users = append(users, a)
		uuids = append(uuids, a.UUID)
		flows = append(flows, "")
	}
	for _, policy := range p.Policies {
		services := map[string]managedService{}
		for _, svc := range policy.Services {
			services[svc.ServiceID] = svc
			if s.proxies[svc.ConnectorID] == nil {
				s.proxies[svc.ConnectorID] = map[string]int{}
			}
			s.proxies[svc.ConnectorID][svc.ConnectorID+"."+svc.ServiceID] = svc.RemotePort
		}
		for _, c := range policy.Connectors {
			server := servers[c.ConnectorID]
			add(c.ConnectorID, c.ProxyRef, map[int]managedRoute{7000: {Service: "control:" + c.ConnectorID, Connector: c.ConnectorID, Port: server.port, Token: server.token}})
		}
		for _, device := range policy.Devices {
			routes := map[int]managedRoute{}
			for _, id := range device.Allowed {
				svc := services[id]
				routes[svc.RemotePort] = managedRoute{Service: id, Connector: svc.ConnectorID, Port: svc.RemotePort, Token: servers[svc.ConnectorID].token}
			}
			add(device.DeviceID, device.ProxyRef, routes)
		}
	}
	s.protocol = vless.NewService[managedAuth](logger.NOP(), d)
	// This service becomes immutable before it is published; no concurrent
	// UpdateUsers on a service used by a handshake is possible.
	s.protocol.UpdateUsers(users, uuids, flows)
	return s
}
func (s *managedSnapshot) permits(a managedAuth, route managedRoute) bool {
	if s == nil {
		return false
	}
	p, ok := s.principals[a.ID]
	if !ok || p.Auth != a {
		return false
	}
	for _, r := range p.Routes {
		if r == route {
			return true
		}
	}
	return false
}
func (s *managedSnapshot) keepProxy(user, name string, port int) bool {
	return s != nil && s.proxies[user][name] == port && port != 0
}

// Apply stages new Connector frps instances, then commits a snapshot while
// proxy registration is frozen. Only revoked streams/proxies are closed.
func (d *managedDataPlane) Apply(p managedProfile, plan *managedPlan, identities map[string]managedIdentity) error {
	d.applyMu.Lock()
	defer d.applyMu.Unlock()
	initializeFRPLogging("error")
	d.mu.Lock()
	old := d.servers
	stopped := d.stopped
	d.mu.Unlock()
	if stopped {
		return net.ErrClosed
	}
	next := map[string]*managedServer{}
	added := []*managedServer{}
	rollback := func() {
		for _, s := range added {
			s.service.Close()
			s.cancel()
		}
	}
	for _, policy := range p.Policies {
		for _, c := range policy.Connectors {
			token := identities[c.ConnectorID].token
			existing := old[c.ConnectorID]
			raw := plan.servers[c.ConnectorID]
			if existing != nil && existing.token == token {
				next[c.ConnectorID] = existing
				continue
			}
			cfg, err := frpServerConfig(raw)
			if err != nil {
				rollback()
				return err
			}
			svc, err := frpserver.NewService(cfg)
			if err != nil {
				rollback()
				return err
			}
			ctx, cancel := context.WithCancel(context.Background())
			server := &managedServer{svc, cancel, cfg.BindPort, token}
			added = append(added, server)
			next[c.ConnectorID] = server
			go svc.Run(ctx)
		}
	}
	snapshot := d.compile(p, identities, next)
	// All ports used as frps controls must remain inaccessible as user services.
	for _, principal := range snapshot.principals {
		for _, route := range principal.Routes {
			if !strings.HasPrefix(route.Service, "control:") {
				for _, server := range next {
					if route.Port == server.port {
						rollback()
						return errors.New("service collides with private control port")
					}
				}
			}
		}
	}
	d.mu.Lock()
	listener := d.listener
	d.mu.Unlock()
	if listener == nil {
		cert, err := tls.LoadX509KeyPair(d.config.Certificate, d.config.Key)
		if err != nil {
			rollback()
			return err
		}
		address := d.listenAddress
		if address == "" {
			address = "127.0.0.1:10443"
		}
		tcp, err := net.Listen("tcp", address)
		if err != nil {
			rollback()
			return err
		}
		// Accept raw sockets so revocation can close them without blocking on a
		// TLS close_notify or a half-completed protocol handshake.
		d.mu.Lock()
		d.listener = tcp
		d.address = tcp.Addr().String()
		d.mu.Unlock()
		go d.accept(tcp, &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12})
	}
	all := []*managedServer{}
	seen := map[*managedServer]bool{}
	for _, pool := range []map[string]*managedServer{old, next} {
		for _, server := range pool {
			if !seen[server] {
				seen[server] = true
				all = append(all, server)
			}
		}
	}
	sort.Slice(all, func(i, j int) bool { return all[i].port < all[j].port })
	for _, s := range all {
		s.service.LockProxyUpdates()
	}
	unlock := func() {
		for i := len(all) - 1; i >= 0; i-- {
			all[i].service.UnlockProxyUpdates()
		}
	}
	d.mu.Lock()
	d.snapshot = snapshot
	d.servers = next
	revoked := []*managedStream{}
	for stream := range d.streams {
		if !snapshot.permits(stream.auth, stream.route) {
			revoked = append(revoked, stream)
		}
	}
	d.mu.Unlock()
	for _, stream := range revoked {
		stream.close()
	}
	var applyErr error
	for _, server := range all {
		if err := server.service.PruneManagedProxies(snapshot.keepProxy); err != nil {
			applyErr = err
		}
	}
	unlock()
	for id, server := range old {
		if next[id] != server {
			server.service.Close()
			server.cancel()
		}
	}
	for _, stream := range revoked {
		select {
		case <-stream.done:
		case <-time.After(5 * time.Second):
			applyErr = errors.New("revoked stream still draining")
		}
	}
	return applyErr
}

type managedRawKey struct{}

func (d *managedDataPlane) accept(listener net.Listener, config *tls.Config) {
	for {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			_ = raw.SetDeadline(time.Now().Add(10 * time.Second))
			conn := tls.Server(raw, config)
			if conn.Handshake() != nil {
				raw.Close()
				return
			}
			var header bytes.Buffer
			request, err := vless.ReadRequest(io.TeeReader(conn, &header))
			if err != nil || request.Command != vmess.CommandTCP || request.Flow != "" {
				raw.Close()
				return
			}
			d.mu.Lock()
			snapshot := d.snapshot
			d.mu.Unlock()
			if snapshot == nil {
				raw.Close()
				return
			}
			replay := &prefixConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(header.Bytes()), conn)}
			ctx := context.WithValue(context.Background(), managedRawKey{}, raw)
			if err := snapshot.protocol.NewConnection(ctx, replay, M.SocksaddrFromNet(raw.RemoteAddr()), nil); err != nil {
				raw.Close()
			}
		}()
	}
}
func (d *managedDataPlane) NewConnectionEx(ctx context.Context, conn net.Conn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	a, ok := auth.UserFromContext[managedAuth](ctx)
	raw, _ := ctx.Value(managedRawKey{}).(net.Conn)
	if raw == nil {
		conn.Close()
		return
	}
	if !ok || destination.IsFqdn() || destination.Addr.String() != "127.0.0.1" {
		raw.Close()
		return
	}
	ctx, cancel := context.WithCancel(ctx)
	d.mu.Lock()
	principal := managedPrincipal{}
	if d.snapshot != nil {
		principal = d.snapshot.principals[a.ID]
	}
	route, allowed := principal.Routes[int(destination.Port)]
	if !allowed || principal.Auth != a || d.stopped {
		d.mu.Unlock()
		cancel()
		raw.Close()
		return
	}
	stream := &managedStream{auth: a, route: route, raw: raw, cancel: cancel, done: make(chan struct{})}
	d.streams[stream] = true
	d.mu.Unlock()
	defer func() {
		stream.close()
		d.mu.Lock()
		delete(d.streams, stream)
		d.mu.Unlock()
		close(stream.done)
		if onClose != nil {
			onClose(nil)
		}
	}()
	upstream, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port)))
	if err != nil {
		return
	}
	stream.mu.Lock()
	stream.upstream = upstream
	stream.mu.Unlock()
	d.mu.Lock()
	stillAllowed := d.snapshot.permits(a, route) && !d.stopped
	d.mu.Unlock()
	if !stillAllowed {
		return
	}
	_ = raw.SetDeadline(time.Time{})
	splice(conn, upstream)
}
func (d *managedDataPlane) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	conn.Close()
	if onClose != nil {
		onClose(os.ErrPermission)
	}
}

func (d *managedDataPlane) plugin(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reject := func() {
		_ = json.NewEncoder(w).Encode(plugin.Response{Reject: true, RejectReason: "managed policy denied"})
	}
	if r.Method != "POST" {
		reject()
		return
	}
	var req struct {
		Op      string          `json:"op"`
		Content json.RawMessage `json:"content"`
	}
	if json.NewDecoder(http.MaxBytesReader(w, r.Body, 16384)).Decode(&req) != nil {
		reject()
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	snapshot := d.snapshot
	if snapshot == nil {
		reject()
		return
	}
	expected := strings.TrimPrefix(r.URL.Path, "/authorize/")
	verify := func(user, key string, stamp int64) bool {
		i, ok := snapshot.identities[user]
		return ok && user == expected && stamp > time.Now().Unix()-120 && stamp < time.Now().Unix()+30 && managedEqual(key, util.GetAuthKey(i.token, stamp))
	}
	var result any
	switch req.Op {
	case "Login":
		var c plugin.LoginContent
		if json.Unmarshal(req.Content, &c) != nil || !verify(c.User, c.PrivilegeKey, c.Timestamp) {
			reject()
			return
		}
		result = c
	case "Ping":
		var c plugin.PingContent
		if json.Unmarshal(req.Content, &c) != nil || !verify(c.User.User, c.PrivilegeKey, c.Timestamp) {
			reject()
			return
		}
		result = c
	case "NewWorkConn":
		var c plugin.NewWorkConnContent
		if json.Unmarshal(req.Content, &c) != nil || !verify(c.User.User, c.PrivilegeKey, c.Timestamp) {
			reject()
			return
		}
		result = c
	case "NewProxy":
		var c plugin.NewProxyContent
		if json.Unmarshal(req.Content, &c) != nil || c.User.User != expected || c.ProxyType != "tcp" || !snapshot.keepProxy(c.User.User, c.ProxyName, c.RemotePort) {
			reject()
			return
		}
		result = c
	default:
		reject()
		return
	}
	_ = json.NewEncoder(w).Encode(plugin.Response{Content: result})
}
