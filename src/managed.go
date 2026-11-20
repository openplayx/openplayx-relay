package main

// Managed mode is isolated from the legacy single-household configuration.
import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/util"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type managedConfig struct {
	APIOrigin     string `json:"apiOrigin"`
	NodeID        string `json:"nodeId"`
	MachineToken  string `json:"machineToken"`
	Host          string `json:"host"`
	Certificate   string `json:"certificate"`
	Key           string `json:"key"`
	ReleaseTag    string `json:"releaseTag"`
	BinaryVersion string `json:"binaryVersion"`
	ReleaseCommit string `json:"releaseCommit"`
}
type managedCredential struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}
type managedService struct {
	ServiceID   string `json:"serviceId"`
	ConnectorID string `json:"connectorId"`
	RemotePort  int    `json:"remotePort"`
}
type managedConnector struct {
	ConnectorID string `json:"connectorId"`
	ProxyRef    string `json:"proxyCredentialRef"`
	FRPRef      string `json:"frpCredentialRef"`
}
type managedDevice struct {
	DeviceID string   `json:"deviceId"`
	ProxyRef string   `json:"proxyCredentialRef"`
	Allowed  []string `json:"allowedServiceIds"`
}
type managedPolicy struct {
	UserID     string             `json:"userId"`
	Status     string             `json:"status"`
	Connectors []managedConnector `json:"connectors"`
	Devices    []managedDevice    `json:"devices"`
	Services   []managedService   `json:"services"`
}
type managedProfile struct {
	SchemaVersion int       `json:"schemaVersion"`
	Revision      string    `json:"revision"`
	ValidUntil    time.Time `json:"validUntil"`
	Node          struct {
		NodeID      string `json:"nodeId"`
		Host        string `json:"host"`
		Status      string `json:"status"`
		ControlPort int    `json:"frpsControlPort"`
	} `json:"node"`
	Policies    []managedPolicy              `json:"userPolicies"`
	Credentials map[string]managedCredential `json:"credentials"`
}
type managedIdentity struct {
	token string
	ports map[int]bool
}
type managedAgent struct {
	mu              sync.RWMutex
	config          managedConfig
	runtime         *Runtime
	revision        string
	policyHash      [32]byte
	identities      map[string]managedIdentity
	serverToken     string
	client          *http.Client
	pluginAddress   string
	nodeState       string
	ackedRevision   string
	highestRevision uint64
}

func (c managedConfig) validate() error {
	u, err := url.Parse(c.APIOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
		return errors.New("managed apiOrigin must be an HTTPS origin")
	}
	if !strings.HasPrefix(c.NodeID, "node_") || len(c.MachineToken) < 32 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$`).MatchString(c.Host) || len(c.Host) > 253 || c.Certificate == "" || c.Key == "" || c.ReleaseTag == "" || len(c.ReleaseCommit) != 40 {
		return errors.New("managed node configuration is incomplete")
	}
	return nil
}
func managedEqual(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (m *managedAgent) credential(p managedProfile, ref, kind string) (string, error) {
	c, ok := p.Credentials[ref]
	if !ok || c.Kind != kind || c.Value == "" {
		return "", errors.New("missing managed credential")
	}
	return c.Value, nil
}
func (m *managedAgent) plan(p managedProfile) (*Plan, map[string]managedIdentity, error) {
	if p.SchemaVersion != 1 || p.Node.NodeID != m.config.NodeID || p.Node.Host != m.config.Host || p.Node.ControlPort != 7000 {
		return nil, nil, errors.New("invalid managed profile envelope")
	}
	if _, err := strconv.ParseUint(p.Revision, 10, 64); err != nil {
		return nil, nil, errors.New("invalid managed revision")
	}
	if p.Node.Status != "enabled" && p.Node.Status != "disabled" && p.Node.Status != "preparing" {
		return nil, nil, errors.New("managed node is not active")
	}
	if p.Node.Status == "disabled" && len(p.Policies) > 0 {
		return nil, nil, errors.New("disabled node carries user policies")
	}
	servers := [][]byte{}
	users := []any{}
	rules := []any{}
	allow := []any{}
	identities := map[string]managedIdentity{}
	names := map[string]bool{}
	uuids := map[string]bool{}
	portsSeen := map[int]bool{}
	reservedControl := map[int]bool{7000: true, 10443: true}
	for _, policy := range p.Policies {
		for _, service := range policy.Services {
			reservedControl[service.RemotePort] = true
		}
	}
	secrets := obj{}
	addUser := func(name, ref string, ports []any) error {
		uuid, err := m.credential(p, ref, "vless_uuid")
		if err != nil || !parseUUID(uuid) || names[name] || uuids[uuid] || name == "" {
			return errors.New("invalid or duplicate managed identity")
		}
		names[name] = true
		uuids[uuid] = true
		secrets[ref] = uuid
		users = append(users, obj{"name": name, "uuid": uuid})
		if len(ports) > 0 {
			rules = append(rules, obj{"auth_user": []any{name}, "ip_cidr": []any{"127.0.0.1/32"}, "port": ports, "action": "route", "outbound": "direct"})
		}
		return nil
	}
	for _, policy := range p.Policies {
		if policy.Status != "active" || policy.UserID == "" {
			return nil, nil, errors.New("invalid managed account")
		}
		services := map[string]managedService{}
		connectors := map[string]managedConnector{}
		for _, c := range policy.Connectors {
			if c.ConnectorID == "" || connectors[c.ConnectorID].ConnectorID != "" {
				return nil, nil, errors.New("duplicate managed connector")
			}
			connectors[c.ConnectorID] = c
		}
		for _, s := range policy.Services {
			if s.RemotePort < 1024 || s.RemotePort > 65535 || s.RemotePort == 7000 || portsSeen[s.RemotePort] || connectors[s.ConnectorID].ConnectorID == "" || s.ServiceID == "" || services[s.ServiceID].ServiceID != "" {
				return nil, nil, errors.New("invalid managed service ownership or port")
			}
			portsSeen[s.RemotePort] = true
			services[s.ServiceID] = s
			allow = append(allow, obj{"single": s.RemotePort})
		}
		for _, c := range policy.Connectors {
			if err := addUser(c.ConnectorID, c.ProxyRef, []any{7000}); err != nil {
				return nil, nil, err
			}
			token, err := m.credential(p, c.FRPRef, "connector_frp_auth")
			if err != nil || len(token) < 32 {
				return nil, nil, errors.New("invalid connector frp credential")
			}
			secrets[c.FRPRef] = token
			owned := map[int]bool{}
			for _, s := range services {
				if s.ConnectorID == c.ConnectorID {
					owned[s.RemotePort] = true
				}
			}
			identities[c.ConnectorID] = managedIdentity{token: token, ports: owned}
			// Native frp encrypts its control stream with auth.token, so each
			// Connector needs its own loopback frps, not just a login plugin.
			controlPort := 0
			for attempt := 0; attempt < 20; attempt++ {
				listener, portErr := net.Listen("tcp", "127.0.0.1:0")
				if portErr != nil {
					return nil, nil, portErr
				}
				candidate := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				if !reservedControl[candidate] {
					controlPort = candidate
					reservedControl[candidate] = true
					break
				}
			}
			if controlPort == 0 {
				return nil, nil, errors.New("no free managed control port")
			}

			rules[len(rules)-1].(obj)["override_port"] = controlPort
			connectorAllow := []any{}
			for number := range owned {
				connectorAllow = append(connectorAllow, obj{"single": number})
			}
			server := obj{"bindAddr": "127.0.0.1", "bindPort": controlPort, "proxyBindAddr": "127.0.0.1", "auth": obj{"method": "token", "token": token, "additionalScopes": []any{"HeartBeats", "NewWorkConns"}}, "transport": obj{"tls": obj{"force": true, "certFile": m.config.Certificate, "keyFile": m.config.Key}}, "allowPorts": connectorAllow, "log": obj{"to": "console", "level": "error"}, "httpPlugins": []any{obj{"name": "managed-access", "addr": m.pluginAddress, "path": "/authorize/" + url.PathEscape(c.ConnectorID), "ops": []any{"Login", "NewProxy", "Ping", "NewWorkConn"}}}}
			raw, _ := json.Marshal(server)
			servers = append(servers, raw)
		}
		for _, d := range policy.Devices {
			ports := []any{}
			for _, serviceID := range d.Allowed {
				s, ok := services[serviceID]
				if !ok {
					return nil, nil, errors.New("cross-account managed grant")
				}
				ports = append(ports, s.RemotePort)
			}
			if err := addUser(d.DeviceID, d.ProxyRef, ports); err != nil {
				return nil, nil, err
			}
		}
	}
	rules = append(rules, obj{"action": "reject"})
	sing := obj{"log": obj{"level": "error"}, "inbounds": []any{obj{"type": "vless", "tag": "proxy", "listen": "127.0.0.1", "listen_port": 10443, "users": users, "tls": obj{"enabled": true, "server_name": m.config.Host, "certificate_path": m.config.Certificate, "key_path": m.config.Key}}}, "outbounds": []any{obj{"type": "direct", "tag": "direct"}}, "route": obj{"rules": rules}}
	frp := obj{"bindAddr": "127.0.0.1", "bindPort": 7000, "proxyBindAddr": "127.0.0.1", "auth": obj{"method": "token", "token": m.serverToken, "additionalScopes": []any{"HeartBeats", "NewWorkConns"}}, "transport": obj{"tls": obj{"force": true, "certFile": m.config.Certificate, "keyFile": m.config.Key}}, "allowPorts": allow, "log": obj{"to": "console", "level": "error"}, "httpPlugins": []any{obj{"name": "managed-access", "addr": m.pluginAddress, "path": "/authorize", "ops": []any{"Login", "NewProxy", "Ping", "NewWorkConn"}}}}
	plan := &Plan{Role: roleRelay, Revision: p.Revision, LogLevel: "error", ProxyAddress: "127.0.0.1:10443", ServerName: m.config.Host, secrets: secrets, FRPServers: servers}
	var err error
	plan.SingBox, err = json.Marshal(sing)
	if err != nil {
		return nil, nil, err
	}
	plan.FRP, err = json.Marshal(frp)
	return plan, identities, err
}
func (m *managedAgent) plugin(w http.ResponseWriter, r *http.Request) {
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
	if json.NewDecoder(io.LimitReader(r.Body, 16385)).Decode(&req) != nil {
		reject()
		return
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	expected := strings.TrimPrefix(r.URL.Path, "/authorize/")
	verify := func(user, key string, stamp int64) bool {
		i, ok := m.identities[user]
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
		if json.Unmarshal(req.Content, &c) != nil || c.User.User != expected || c.ProxyType != "tcp" || !m.identities[c.User.User].ports[c.RemotePort] {
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
func (m *managedAgent) health(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/health" || r.Host != "status."+m.config.Host || !managedEqual(r.Header.Get("Authorization"), "Bearer "+m.config.MachineToken) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	m.mu.RLock()
	revision, nodeState, acked := m.revision, m.nodeState, m.ackedRevision
	m.mu.RUnlock()
	components := m.runtime.Components()
	status := "inactive"
	if revision != "" && revision == acked && components["sing-box"] == "active" && components["frps"] == "active" {
		status = "active"
	} else {
		w.WriteHeader(503)
	}
	_ = json.NewEncoder(w).Encode(obj{"nodeId": m.config.NodeID, "protocol": "managed-v1", "nodeState": nodeState, "releaseTag": m.config.ReleaseTag, "releaseCommit": m.config.ReleaseCommit, "binaryVersion": version, "revision": revision, "runtime": status})
}
func (m *managedAgent) request(ctx context.Context, path string, body any) (*http.Response, error) {
	var reader io.Reader
	method := "GET"
	if body != nil {
		b, _ := json.Marshal(body)
		reader = strings.NewReader(string(b))
		method = "POST"
	}
	r, err := http.NewRequestWithContext(ctx, method, m.config.APIOrigin+path, reader)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "Bearer "+m.config.MachineToken)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("User-Agent", "OpenPlayX-Managed-Relay/1.0")
	return m.client.Do(r)
}
func (m *managedAgent) sync(ctx context.Context) error {
	response, err := m.request(ctx, "/v1/relay/node/config", nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return errors.New("central configuration unavailable")
	}
	var p managedProfile
	if json.NewDecoder(io.LimitReader(response.Body, 4*1024*1024)).Decode(&p) != nil {
		return errors.New("invalid central configuration")
	}
	plan, identities, err := m.plan(p)
	if err != nil {
		// A rejected update never tears down the last successfully applied policy.
		return err
	}
	incoming, _ := strconv.ParseUint(p.Revision, 10, 64)
	m.mu.Lock()
	if incoming < m.highestRevision {
		m.mu.Unlock()
		return errors.New("managed configuration revision moved backwards")
	}
	m.highestRevision = incoming
	m.mu.Unlock()
	// Global revisions and freshness timestamps can change without changing
	// this node's authorization. Do not restart working connections for that.
	policy, _ := json.Marshal(struct {
		Policies    []managedPolicy
		Credentials map[string]managedCredential
	}{p.Policies, p.Credentials})
	hash := sha256.Sum256(policy)
	m.mu.RLock()
	same := m.revision != "" && m.policyHash == hash
	m.mu.RUnlock()
	components := m.runtime.Components()
	same = same && components["sing-box"] == "active" && components["frps"] == "active"
	if !same {
		_ = m.runtime.Stop()
		m.mu.Lock()
		m.identities = identities
		m.revision = ""
		m.mu.Unlock()
		if err = m.runtime.Restart(nil, plan); err != nil {
			return errors.New("managed runtime could not apply configuration")
		}
	}
	m.mu.Lock()
	m.revision = p.Revision
	m.nodeState = p.Node.Status
	m.policyHash = hash
	m.mu.Unlock()
	ack, err := m.request(ctx, "/v1/relay/node/config-acks", obj{"revision": p.Revision, "status": "applied"})
	if err != nil {
		return err
	}
	defer ack.Body.Close()
	if ack.StatusCode != 200 {
		return errors.New("configuration ACK failed")
	}
	m.mu.Lock()
	m.ackedRevision = p.Revision
	m.mu.Unlock()
	return nil
}
func cmdManaged(args []string) error {
	flags := flag.NewFlagSet("managed", flag.ContinueOnError)
	file := flags.String("config", "/var/lib/openplayx-relay-managed/managed.json", "private managed node configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	content, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	var cfg managedConfig
	if json.Unmarshal(content, &cfg) != nil {
		return errors.New("invalid managed configuration")
	}
	if err = cfg.validate(); err != nil {
		return err
	}
	expectedVersion := cfg.BinaryVersion
	if expectedVersion == "" {
		expectedVersion = cfg.ReleaseTag
	}
	if version != expectedVersion {
		return errors.New("managed binary version does not match the pinned release")
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		return err
	}
	a := &managedAgent{config: cfg, runtime: NewRuntime(roleRelay), identities: map[string]managedIdentity{}, serverToken: hex.EncodeToString(key), client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	a.pluginAddress = listener.Addr().String()
	plugins := &http.Server{Handler: http.HandlerFunc(a.plugin), ReadHeaderTimeout: 5 * time.Second}
	go plugins.Serve(listener)
	defer plugins.Close()
	cert, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.Key)
	if err != nil {
		return errors.New("managed TLS certificate could not be loaded")
	}
	manager := newConnListener(&net.TCPAddr{Port: 443})
	front, err := NewFrontend(":443", manager, a.runtime.proxyTarget)
	if err != nil {
		return err
	}
	defer front.Close()
	defer manager.Close()
	go front.Serve()
	health := &http.Server{Handler: http.HandlerFunc(a.health), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
	go health.Serve(tls.NewListener(manager, health.TLSConfig))
	defer health.Close()
	defer a.runtime.Stop()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	for {
		if err = a.sync(ctx); err != nil {
			fmt.Fprintln(os.Stderr, "managed Relay: configuration not applied; waiting for retry")
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(20 * time.Second):
		}
	}
}
