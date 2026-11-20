package main

import (
	"bytes"
	"context"
	"encoding/json"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/util"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func managedFixture(t *testing.T) (*managedAgent, managedProfile, []byte) {
	t.Helper()
	certificate, key := testCertificate(t)
	root := t.TempDir()
	certPath, keyPath := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	writeFile(t, certPath, certificate)
	writeFile(t, keyPath, key)
	a := &managedAgent{config: managedConfig{APIOrigin: "https://api.example.com", NodeID: "node_test", MachineToken: strings.Repeat("node-token", 5), Host: "localhost", Certificate: certPath, Key: keyPath, ReleaseTag: "v-test", ReleaseCommit: strings.Repeat("a", 40)}, runtime: NewRuntime(roleRelay), identities: map[string]managedIdentity{}, serverToken: strings.Repeat("internal-token", 4), pluginAddress: "127.0.0.1:9999"}
	var p managedProfile
	p.SchemaVersion = 1
	p.Revision = "1"
	p.ValidUntil = time.Now().Add(30 * time.Minute)
	p.Node.NodeID = a.config.NodeID
	p.Node.Host = a.config.Host
	p.Node.ControlPort = 7000
	p.Node.Status = "preparing"
	p.Credentials = map[string]managedCredential{"connector_proxy": {"vless_uuid", newUUID()}, "connector_frp": {"connector_frp_auth", strings.Repeat("connector-secret", 4)}, "device_proxy": {"vless_uuid", newUUID()}}
	p.Policies = []managedPolicy{{UserID: "user_a", Status: "active", Connectors: []managedConnector{{ConnectorID: "connector_a", ProxyRef: "connector_proxy", FRPRef: "connector_frp"}}, Devices: []managedDevice{{DeviceID: "device_a", ProxyRef: "device_proxy", Allowed: []string{"service_a"}}}, Services: []managedService{{ServiceID: "service_a", ConnectorID: "connector_a", RemotePort: freePort(t)}}}}
	return a, p, certificate
}
func TestManagedPolicyIsolationAndFailClosedEnvelopes(t *testing.T) {
	a, p, _ := managedFixture(t)
	plan, identities, err := a.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	if err = checkPlan(plan); err != nil {
		t.Fatal(err)
	}
	if !identities["connector_a"].ports[p.Policies[0].Services[0].RemotePort] {
		t.Fatal("connector lost owned port")
	}
	var rendered obj
	_ = json.Unmarshal(plan.SingBox, &rendered)
	rules := rendered["route"].(map[string]any)["rules"].([]any)
	if rules[len(rules)-1].(map[string]any)["action"] != "reject" {
		t.Fatal("missing default deny")
	}
	original, _ := json.Marshal(p)
	cases := []func(*managedProfile){func(v *managedProfile) { v.ValidUntil = time.Now().Add(-time.Second) }, func(v *managedProfile) { v.Node.NodeID = "other" }, func(v *managedProfile) { v.Node.Status = "retired" }, func(v *managedProfile) { v.Node.Status = "disabled" }, func(v *managedProfile) { v.Policies[0].Devices[0].Allowed = []string{"other_user_service"} }, func(v *managedProfile) { v.Policies[0].Services[0].ConnectorID = "other_connector" }, func(v *managedProfile) { v.Policies[0].Services[0].RemotePort = 7000 }, func(v *managedProfile) { v.Credentials["device_proxy"] = v.Credentials["connector_proxy"] }}
	for index, change := range cases {
		var changed managedProfile
		_ = json.Unmarshal(original, &changed)
		change(&changed)
		if _, _, err = a.plan(changed); err == nil {
			t.Fatalf("unsafe profile %d accepted", index)
		}
	}
	p.Node.Status = "disabled"
	p.Policies = nil
	if _, _, err = a.plan(p); err != nil {
		t.Fatal("empty disabled policy must still be applicable", err)
	}
	cfg := a.config
	cfg.Host = "relay.example.com"
	if err = cfg.validate(); err != nil {
		t.Fatal(err)
	}
	cfg.APIOrigin = "http://api.example.com"
	if cfg.validate() == nil {
		t.Fatal("plaintext API accepted")
	}
}
func TestManagedFRPPluginVerifiesPerConnectorProofAndPortOwnership(t *testing.T) {
	a, p, _ := managedFixture(t)
	_, a.identities, _ = a.plan(p)
	a.validUntil = p.ValidUntil
	call := func(op string, content any) plugin.Response {
		data, _ := json.Marshal(obj{"op": op, "content": content})
		r := httptest.NewRequest("POST", "http://127.0.0.1/authorize/connector_a", bytes.NewReader(data))
		w := httptest.NewRecorder()
		a.plugin(w, r)
		var result plugin.Response
		_ = json.Unmarshal(w.Body.Bytes(), &result)
		return result
	}
	stamp := time.Now().Unix()
	proof := util.GetAuthKey(p.Credentials["connector_frp"].Value, stamp)
	login := obj{"user": "connector_a", "timestamp": stamp, "privilege_key": proof}
	result := call("Login", login)
	if result.Reject {
		t.Fatal("valid connector rejected")
	}
	if result.Content.(map[string]any)["privilege_key"] != proof {
		t.Fatal("per-Connector verifier key unexpectedly changed")
	}
	login["privilege_key"] = "wrong"
	if !call("Login", login).Reject {
		t.Fatal("forged connector proof accepted")
	}
	proxy := obj{"user": obj{"user": "connector_a"}, "proxy_type": "tcp", "remote_port": p.Policies[0].Services[0].RemotePort}
	if call("NewProxy", proxy).Reject {
		t.Fatal("owned TCP service rejected")
	}
	proxy["remote_port"] = p.Policies[0].Services[0].RemotePort + 1
	if !call("NewProxy", proxy).Reject {
		t.Fatal("unowned port accepted")
	}
	proxy["proxy_type"] = "udp"
	if !call("NewProxy", proxy).Reject {
		t.Fatal("UDP accepted")
	}
	for _, op := range []string{"Ping", "NewWorkConn"} {
		content := obj{"user": obj{"user": "connector_a"}, "timestamp": stamp, "privilege_key": proof}
		if call(op, content).Reject {
			t.Fatal(op, "valid proof rejected")
		}
		content["timestamp"] = stamp - 600
		if !call(op, content).Reject {
			t.Fatal(op, "stale proof accepted")
		}
	}
	a.validUntil = time.Now().Add(-time.Second)
	if !call("NewProxy", proxy).Reject {
		t.Fatal("expired lease still authorizes registration")
	}
}
func TestManagedVLESSFRPAndLeaseExpiry(t *testing.T) {
	if testing.Short() {
		t.Skip("managed bridge integration")
	}
	a, p, certificate := managedFixture(t)
	media := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Range", "bytes 3-7/10")
		w.WriteHeader(206)
		_, _ = io.WriteString(w, "34567")
	}))
	defer media.Close()
	plugins := httptest.NewServer(http.HandlerFunc(a.plugin))
	defer plugins.Close()
	a.pluginAddress = strings.TrimPrefix(plugins.URL, "http://")
	plan, identities, err := a.plan(p)
	if err != nil {
		t.Fatal(err)
	}
	a.identities = identities
	a.validUntil = p.ValidUntil
	a.revision = p.Revision
	// Portable test ports; the production envelope keeps frps on 7000.
	proxyPort, control, socks := freePort(t), freePort(t), freePort(t)
	var sing, frp obj
	_ = json.Unmarshal(plan.SingBox, &sing)
	_ = json.Unmarshal(plan.FRP, &frp)
	inbound := sing["inbounds"].([]any)[0].(map[string]any)
	inbound["listen_port"] = proxyPort
	sing["route"].(map[string]any)["rules"].([]any)[0].(map[string]any)["port"] = []any{control}
	frp["bindPort"] = control
	plan.SingBox, _ = json.Marshal(sing)
	plan.FRP, _ = json.Marshal(frp)
	if err = a.runtime.Restart(nil, plan); err != nil {
		t.Fatal(err)
	}
	defer a.runtime.Stop()
	root := t.TempDir()
	home, _ := NewStore(root, roleHome)
	writeFile(t, home.file("tls/ca.crt"), certificate)
	draft := home.blank()
	section(draft, "singBox", "inbound")["listen_port"] = socks
	out := section(draft, "singBox", "outbound")
	out["server"], out["server_port"] = "127.0.0.1", proxyPort
	section(out, "tls")["server_name"], section(out, "tls")["certificate"] = "localhost", string(certificate)
	frpc := section(draft, "frpc")
	frpc["user"] = "connector_a"
	frpc["serverPort"] = control
	section(frpc, "transport", "tls")["serverName"], section(frpc, "transport", "tls")["trustedCaFile"] = "localhost", "tls/ca.crt"
	frpc["proxies"] = []any{obj{"name": "service_a", "type": "tcp", "localIP": "127.0.0.1", "localPort": media.Listener.Addr().(*net.TCPAddr).Port, "remotePort": p.Policies[0].Services[0].RemotePort}}
	saved, err := home.save(draft, 0, obj{"uuid": p.Credentials["connector_proxy"].Value, "token": p.Credentials["connector_frp"].Value})
	if err != nil {
		t.Fatal(err)
	}
	homeRuntime := NewRuntime(roleHome)
	if _, err = home.apply(saved["revision"], homeRuntime); err != nil {
		t.Fatal(err)
	}
	defer homeRuntime.Stop()
	app := newAppClient(t, obj{"type": "vless", "tag": "relay", "server": "127.0.0.1", "server_port": proxyPort, "uuid": p.Credentials["device_proxy"].Value, "tls": obj{"enabled": true, "server_name": "localhost", "certificate": string(certificate)}})
	mapping := p.Policies[0].Services[0].RemotePort
	for attempt := 0; ; attempt++ {
		if err = app.fetch(mapping); err == nil {
			break
		}
		if attempt == 60 {
			t.Fatal("managed media bridge failed", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	app.denied(t, control)
	a.mu.Lock()
	a.validUntil = time.Now().Add(-time.Second)
	a.mu.Unlock()
	a.expire()
	if a.runtime.Components()["sing-box"] == "active" {
		t.Fatal("expired lease did not stop old connections")
	}
}
func TestManagedSyncRequiresScopedFreshConfigurationAndACK(t *testing.T) {
	a, p, _ := managedFixture(t)
	p.Policies = nil
	p.Node.Status = "disabled"
	plugins := httptest.NewServer(http.HandlerFunc(a.plugin))
	defer plugins.Close()
	a.pluginAddress = strings.TrimPrefix(plugins.URL, "http://")
	acked := false
	central := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+a.config.MachineToken {
			http.Error(w, "denied", 401)
			return
		}
		if r.URL.Path == "/v1/relay/node/config" {
			_ = json.NewEncoder(w).Encode(p)
		} else {
			acked = true
			_ = json.NewEncoder(w).Encode(obj{"status": "accepted"})
		}
	}))
	defer central.Close()
	a.config.APIOrigin = central.URL
	a.client = central.Client()
	a.client.Timeout = 5 * time.Second
	if err := a.sync(context.Background()); err != nil {
		t.Fatal(err)
	}
	defer a.runtime.Stop()
	if !acked || a.ackedRevision != p.Revision {
		t.Fatal("configuration not ACKed")
	}
	req := httptest.NewRequest("GET", "https://status.localhost/health", nil)
	req.Header.Set("Authorization", "Bearer "+a.config.MachineToken)
	w := httptest.NewRecorder()
	a.health(w, req)
	if w.Code != 200 {
		t.Fatal("ready health rejected", w.Body.String())
	}
	p.Revision = "0"
	if a.sync(context.Background()) == nil {
		t.Fatal("configuration rollback accepted")
	}
	p.Revision = "1"
	p.ValidUntil = time.Now().Add(-time.Second)
	if a.sync(context.Background()) == nil {
		t.Fatal("expired profile accepted")
	}
	if a.runtime.Components()["sing-box"] == "active" {
		t.Fatal("invalid profile left old runtime active")
	}
}
