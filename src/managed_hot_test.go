package main

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestManagedHotUpdatesPreserveLiveStreamsAndRevokeOnlyAffectedRoutes(t *testing.T) {
	if testing.Short() {
		t.Skip("real managed VLESS/frp streaming")
	}
	a, p, certificate := managedFixture(t)
	plugins := httptest.NewServer(http.HandlerFunc(a.plugin))
	defer plugins.Close()
	a.pluginAddress = strings.TrimPrefix(plugins.URL, "http://")
	apply := func() {
		t.Helper()
		plan, identities, err := a.plan(p)
		if err != nil {
			t.Fatal(err)
		}
		if err = a.runtime.Apply(p, plan, identities); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	defer a.runtime.Stop()
	initialListener := a.runtime.listener
	initialFRPS := a.runtime.servers["connector_a"]
	address, _, _ := a.runtime.proxyTarget()
	_, textPort, _ := net.SplitHostPort(address)
	proxyPort, _ := strconv.Atoi(textPort)
	echo, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go func() {
		for {
			c, e := echo.Accept()
			if e != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	root := t.TempDir()
	home, _ := NewStore(root, roleConnector)
	writeFile(t, home.file("tls/ca.crt"), certificate)
	draft := home.blank()
	section(draft, "singBox", "inbound")["listen_port"] = freePort(t)
	out := section(draft, "singBox", "outbound")
	out["server"], out["server_port"] = "127.0.0.1", proxyPort
	section(out, "tls")["server_name"], section(out, "tls")["certificate"] = "localhost", string(certificate)
	frpc := section(draft, "frpc")
	frpc["user"] = "connector_a"
	frpc["serverPort"] = 7000
	section(frpc, "transport", "tls")["serverName"], section(frpc, "transport", "tls")["trustedCaFile"] = "localhost", "tls/ca.crt"
	setProxies := func() {
		list := []any{}
		for _, service := range p.Policies[0].Services {
			list = append(list, obj{"name": service.ServiceID, "type": "tcp", "localIP": "127.0.0.1", "localPort": echo.Addr().(*net.TCPAddr).Port, "remotePort": service.RemotePort})
		}
		frpc["proxies"] = list
	}
	setProxies()
	values := obj{"uuid": p.Credentials["connector_proxy"].Value, "token": p.Credentials["connector_frp"].Value}
	saved, err := home.save(draft, 0, values)
	if err != nil {
		t.Fatal(err)
	}
	homeRuntime := NewRuntime(roleConnector)
	if _, err = home.apply(saved["revision"], homeRuntime); err != nil {
		t.Fatal(err)
	}
	defer homeRuntime.Stop()
	initialClient := homeRuntime.frpc
	newClient := func(uuid string) *appClient {
		return newAppClient(t, obj{"type": "vless", "tag": "relay", "server": "127.0.0.1", "server_port": proxyPort, "uuid": uuid, "tls": obj{"enabled": true, "server_name": "localhost", "certificate": string(certificate)}})
	}
	app := newClient(p.Credentials["device_proxy"].Value)
	check := func(c net.Conn, seq int) error {
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		payload := []byte(strings.Repeat(fmt.Sprintf("frame-%04d|", seq), 4096))
		sent := make(chan error, 1)
		go func() { _, e := c.Write(payload); sent <- e }()
		got := make([]byte, len(payload))
		_, e := io.ReadFull(c, got)
		if e != nil {
			return e
		}
		if e = <-sent; e != nil {
			return e
		}
		if string(got) != string(payload) {
			return fmt.Errorf("stream corrupted")
		}
		return nil
	}
	connect := func(client *appClient, port int) net.Conn {
		t.Helper()
		for i := 0; i < 80; i++ {
			conn, e := client.dial(port)
			if e == nil {
				e = check(conn, 0)
				if e == nil {
					return conn
				}
				conn.Close()
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("managed stream did not connect")
		return nil
	}
	portA := p.Policies[0].Services[0].RemotePort
	connA := connect(app, portA)
	defer connA.Close()
	// Register a service while A remains an established TCP/TLS/frp stream.
	portB := freePort(t)
	p.Policies[0].Services = append(p.Policies[0].Services, managedService{"service_b", "connector_a", portB})
	p.Policies[0].Devices[0].Allowed = append(p.Policies[0].Devices[0].Allowed, "service_b")
	p.Revision = "2"
	apply()
	if a.runtime.listener != initialListener || a.runtime.servers["connector_a"] != initialFRPS {
		t.Fatal("service registration restarted stable components")
	}
	// Native Connector/frpc reload adds only B, retaining A and its existing work conn.
	section(saved, "frpc")["proxies"] = []any{
		obj{"name": "service_a", "type": "tcp", "localIP": "127.0.0.1", "localPort": echo.Addr().(*net.TCPAddr).Port, "remotePort": portA},
		obj{"name": "service_b", "type": "tcp", "localIP": "127.0.0.1", "localPort": echo.Addr().(*net.TCPAddr).Port, "remotePort": portB},
	}
	storedValues, err := home.secrets()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := home.plan(saved, storedValues)
	if err != nil {
		t.Fatal(err)
	}
	_, proxies, err := frpClientConfig(plan.FRP)
	if err != nil {
		t.Fatal(err)
	}
	if err = homeRuntime.frpc.UpdateAllConfigurer(proxies, nil); err != nil {
		t.Fatal(err)
	}
	if err = check(connA, 1); err != nil {
		t.Fatal("service registration interrupted A", err)
	}
	connB := connect(app, portB)
	defer connB.Close()
	// Register another device; it can open A without disturbing either stream.
	p.Credentials["other_device"] = managedCredential{"vless_uuid", newUUID()}
	p.Policies[0].Devices = append(p.Policies[0].Devices, managedDevice{"device_other", "other_device", []string{"service_a", "service_b"}})
	p.Revision = "3"
	apply()
	other := newClient(p.Credentials["other_device"].Value)
	otherA := connect(other, portA)
	defer otherA.Close()
	otherB := connect(other, portB)
	defer otherB.Close()
	if err = check(connA, 2); err != nil {
		t.Fatal("device registration interrupted A", err)
	}
	// A different account and Connector stage a separate frps; A remains live.
	p.Credentials["second_proxy"] = managedCredential{"vless_uuid", newUUID()}
	p.Credentials["second_frp"] = managedCredential{"connector_frp_auth", strings.Repeat("second-connector-secret", 3)}
	p.Policies = append(p.Policies, managedPolicy{UserID: "second_account", Status: "active", Connectors: []managedConnector{{ConnectorID: "connector_second", ProxyRef: "second_proxy", FRPRef: "second_frp"}}})
	apply()
	if a.runtime.servers["connector_a"] != initialFRPS || a.runtime.servers["connector_second"] == nil {
		t.Fatal("new account replaced an existing Connector")
	}
	if err = check(connA, 21); err != nil {
		t.Fatal("new account interrupted A", err)
	}
	// Revoke only device_a's access to A. B and the other device's A stay open.
	p.Policies[0].Devices[0].Allowed = []string{"service_b"}
	p.Revision = "4"
	apply()
	if err = check(connA, 3); err == nil {
		t.Fatal("revoked A stream remained open")
	}
	if err = check(connB, 3); err != nil {
		t.Fatal("grant revocation interrupted B", err)
	}
	if err = check(otherA, 3); err != nil {
		t.Fatal("grant revocation interrupted other device", err)
	}
	app.denied(t, portA)
	// Removing A prunes precisely its frps listener and frees its mapping port.
	p.Policies[0].Services = p.Policies[0].Services[1:]
	p.Policies[0].Devices[1].Allowed = []string{"service_b"}
	p.Revision = "5"
	apply()
	if err = check(otherA, 4); err == nil {
		t.Fatal("deleted service stream remained open")
	}
	rebound, e := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(portA)))
	if e != nil {
		t.Fatal("deleted proxy did not release port", e)
	}
	rebound.Close()
	if err = check(connB, 4); err != nil {
		t.Fatal("service deletion interrupted B", err)
	}
	// Rotate a single device UUID. Other devices and Connector control survive.
	transmitting := make(chan struct{})
	stopFlow := make(chan struct{})
	flowDone := make(chan error, 1)
	go func() {
		if err := check(otherB, 500); err != nil {
			flowDone <- err
			close(transmitting)
			return
		}
		close(transmitting)
		for i := 501; ; i++ {
			select {
			case <-stopFlow:
				flowDone <- nil
				return
			default:
			}
			if err := check(otherB, i); err != nil {
				flowDone <- err
				return
			}
		}
	}()
	<-transmitting
	p.Credentials["device_proxy"] = managedCredential{"vless_uuid", newUUID()}
	p.Revision = "6"
	apply()
	if err = check(connB, 5); err == nil {
		t.Fatal("old credential stream remained open")
	}
	for i := 0; i < 8; i++ {
		ref := fmt.Sprintf("live_update_%d", i)
		p.Credentials[ref] = managedCredential{"vless_uuid", newUUID()}
		p.Policies[0].Devices = append(p.Policies[0].Devices, managedDevice{DeviceID: ref, ProxyRef: ref})
		apply()
	}
	close(stopFlow)
	if err := <-flowDone; err != nil {
		t.Fatal("continuous transfer broke during live updates", err)
	}
	if err = check(otherB, 5); err != nil {
		t.Fatal("credential rotation interrupted another device", err)
	}
	rotated := newClient(p.Credentials["device_proxy"].Value)
	rotatedB := connect(rotated, portB)
	defer rotatedB.Close()
	if homeRuntime.frpc != initialClient || a.runtime.listener != initialListener || a.runtime.servers["connector_a"] != initialFRPS {
		t.Fatal("dynamic updates restarted a shared transport")
	}
	// Malformed policies never replace the currently working immutable snapshot.
	p.Policies[0].Devices[0].Allowed = []string{"missing"}
	if _, _, err = a.plan(p); err == nil {
		t.Fatal("invalid policy accepted")
	}
	if err = check(rotatedB, 6); err != nil {
		t.Fatal("invalid policy disturbed last good stream", err)
	}
}
