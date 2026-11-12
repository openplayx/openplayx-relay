package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	M "github.com/sagernet/sing/common/metadata"
)

// appClient stands in for the App's embedded bridge: a sing-box instance
// with only the VLESS outbound from the App pairing file.
type appClient struct {
	box    *box.Box
	cancel context.CancelFunc
}

func newAppClient(t *testing.T, outbound obj) *appClient {
	t.Helper()
	data, _ := json.Marshal(obj{"log": obj{"disabled": true}, "outbounds": []any{outbound}})
	ctx, options, err := singBoxOptions(data)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	if err = instance.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	client := &appClient{box: instance, cancel: cancel}
	t.Cleanup(func() { instance.Close(); cancel() })
	return client
}

func (a *appClient) dial(port int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return a.box.Outbound().Default().DialContext(ctx, "tcp", M.ParseSocksaddrHostPort("127.0.0.1", uint16(port)))
}

func (a *appClient) fetch(port int) error {
	connection, err := a.dial(port)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	request := "GET /video HTTP/1.1\r\nHost: nas.example:8096\r\nRange: bytes=3-7\r\nAuthorization: Bearer media-secret\r\nConnection: close\r\n\r\n"
	if _, err = io.WriteString(connection, request); err != nil {
		return err
	}
	response, err := http.ReadResponse(bufio.NewReader(connection), nil)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != 206 || response.Header.Get("Content-Range") != "bytes 3-7/10" || string(body) != "34567" {
		return fmt.Errorf("unexpected media response %d %q", response.StatusCode, body)
	}
	return nil
}

// denied asserts an unauthorised destination yields no data at all.
func (a *appClient) denied(t *testing.T, port int) {
	t.Helper()
	connection, err := a.dial(port)
	if err != nil {
		return
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	_, _ = io.WriteString(connection, "GET /video HTTP/1.0\r\nHost: nas.example:8096\r\nRange: bytes=3-7\r\nAuthorization: Bearer media-secret\r\n\r\n")
	buffer := make([]byte, 1)
	if n, _ := connection.Read(buffer); n > 0 {
		t.Fatalf("unauthorised port %d returned data", port)
	}
}

func (a *appClient) controlTLS(port int, roots *x509.CertPool) error {
	connection, err := a.dial(port)
	if err != nil {
		return err
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
	// frp's TLS discriminator byte precedes the regular TLS handshake.
	if _, err = connection.Write([]byte{0x17}); err != nil {
		return err
	}
	return tls.Client(connection, &tls.Config{RootCAs: roots, ServerName: "localhost"}).Handshake()
}

// TestEndToEnd runs Relay and Home in-process with the embedded sing-box and
// frp: real TLS/VLESS, frpc through the Home SOCKS entry, authenticated Range
// media, account separation, and no direct fallback once Home's proxy stops.
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("end-to-end test")
	}
	var mediaErrors atomic.Value
	media := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Range") != "bytes=3-7" || r.Header.Get("Authorization") != "Bearer media-secret" || r.Host != "nas.example:8096" {
			mediaErrors.Store("unexpected request headers")
		}
		w.Header().Set("Content-Range", "bytes 3-7/10")
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(206)
		_, _ = io.WriteString(w, "34567")
	}))
	defer media.Close()
	mediaPort := media.Listener.Addr().(*net.TCPAddr).Port

	root := t.TempDir()
	certificate, key := testCertificate(t)
	certPath, keyPath := filepath.Join(root, "tls.crt"), filepath.Join(root, "tls.key")
	writeFile(t, certPath, certificate)
	writeFile(t, keyPath, key)
	proxyPort, control, mapping, socks := freePort(t), freePort(t), freePort(t), freePort(t)
	appUUID, homeUUID := newUUID(), newUUID()
	token := repeat("integration-test-token-", 3)
	relayStore, _ := NewStore(filepath.Join(root, "relay-state"), roleRelay)
	homeStore, _ := NewStore(filepath.Join(root, "home-state"), roleHome)
	for name, data := range map[string][]byte{"tls.crt": certificate, "tls.key": key} {
		writeFile(t, relayStore.file("tls/"+name), data)
	}
	writeFile(t, homeStore.file("tls/ca.crt"), certificate)

	relayDraft := relayStore.blank()
	inbound := section(relayDraft, "singBox", "inbound")
	inbound["listen"], inbound["listen_port"] = "127.0.0.1", proxyPort
	section(inbound, "tls")["server_name"] = "localhost"
	section(inbound, "tls")["certificate_path"], section(inbound, "tls")["key_path"] = "tls/tls.crt", "tls/tls.key"
	section(relayDraft, "singBox", "route")["rules"] = []any{
		obj{"auth_user": []any{"home"}, "port": []any{control}},
		obj{"auth_user": []any{"app"}, "port": []any{mapping}},
	}
	frps := section(relayDraft, "frps")
	frps["bindPort"], frps["allowPorts"] = control, []any{obj{"single": mapping}}
	section(frps, "transport", "tls")["certFile"], section(frps, "transport", "tls")["keyFile"] = "tls/tls.crt", "tls/tls.key"
	relayCfg, err := relayStore.save(relayDraft, 0, obj{"uuid:home": homeUUID, "uuid:app": appUUID, "token": token})
	if err != nil {
		t.Fatal(err)
	}

	homeDraft := homeStore.blank()
	section(homeDraft, "singBox", "inbound")["listen_port"] = socks
	outboundCfg := section(homeDraft, "singBox", "outbound")
	outboundCfg["server"], outboundCfg["server_port"] = "127.0.0.1", proxyPort
	section(outboundCfg, "tls")["server_name"], section(outboundCfg, "tls")["certificate"] = "localhost", string(certificate)
	frpc := section(homeDraft, "frpc")
	frpc["serverPort"] = control
	section(frpc, "transport", "tls")["serverName"], section(frpc, "transport", "tls")["trustedCaFile"] = "localhost", "tls/ca.crt"
	frpc["proxies"] = []any{obj{"name": "jellyfin", "type": "tcp", "localIP": "127.0.0.1", "localPort": mediaPort, "remotePort": mapping}}
	homeCfg, err := homeStore.save(homeDraft, 0, obj{"uuid": homeUUID, "token": token})
	if err != nil {
		t.Fatal(err)
	}
	for path, secret := range map[string]string{relayStore.path: appUUID, homeStore.path: homeUUID} {
		if data, _ := os.ReadFile(path); strings.Contains(string(data), secret) {
			t.Fatal("identity stored in authoritative JSON")
		}
	}
	relayRuntime, homeRuntime := NewRuntime(roleRelay), NewRuntime(roleHome)
	if _, err = relayStore.apply(relayCfg["revision"], relayRuntime); err != nil {
		t.Fatal(err)
	}
	defer relayRuntime.Stop()
	if _, err = homeStore.apply(homeCfg["revision"], homeRuntime); err != nil {
		t.Fatal(err)
	}
	defer homeRuntime.Stop()
	for _, runtime := range []*Runtime{relayRuntime, homeRuntime} {
		for name, state := range runtime.Components() {
			if state != "active" {
				t.Fatalf("%s %s is %s", runtime.role, name, state)
			}
		}
	}

	tlsOptions := obj{"enabled": true, "server_name": "localhost", "certificate": string(certificate)}
	outbound := func(uuid string) obj {
		return obj{"type": "vless", "tag": "relay", "server": "127.0.0.1", "server_port": proxyPort, "uuid": uuid, "tls": tlsOptions}
	}
	app := newAppClient(t, outbound(appUUID))
	for attempt := 0; ; attempt++ {
		if err = app.fetch(mapping); err == nil {
			break
		}
		if attempt == 60 {
			t.Fatalf("media through relay: %v", err)
		}
		time.Sleep(250 * time.Millisecond)
	}
	if message := mediaErrors.Load(); message != nil {
		t.Fatal(message)
	}
	t.Log("PASS embedded VLESS -> relay -> frp -> home -> authenticated Range media")

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	homeIdentity := newAppClient(t, outbound(homeUUID))
	if err = homeIdentity.controlTLS(control, roots); err != nil {
		t.Fatalf("home identity cannot reach frps control (probe broken): %v", err)
	}
	if err = app.controlTLS(control, roots); err == nil {
		t.Fatal("App identity reached the private frps TLS control entry")
	}
	app.denied(t, mediaPort)
	homeIdentity.denied(t, mapping)
	newAppClient(t, outbound(newUUID())).denied(t, mapping)
	t.Log("PASS App/home account separation, unallocated ports and unknown identity denied")

	homeRuntime.stopProxy()
	time.Sleep(time.Second)
	if err = app.fetch(mapping); err == nil {
		t.Fatal("media remained reachable after home proxy stopped")
	}
	t.Log("PASS home proxy stopped: no direct frpc fallback")
}

// TestFrontendRoutesBySNI checks the shared public TLS entry: the proxy SNI
// reaches sing-box unchanged, anything else reaches the HTTPS manager.
func TestFrontendRoutesBySNI(t *testing.T) {
	f := newFixture(t, roleRelay)
	certificate, _ := os.ReadFile(f.store.file("tls/proxy.crt"))
	cfg := cloneObj(f.saved)
	section(cfg, "singBox", "inbound", "tls")["server_name"] = "localhost"
	setBindPort(cfg, freePort(t))
	saved, err := f.store.save(cfg, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	runtime := NewRuntime(roleRelay)
	defer runtime.Stop()
	if _, err = f.store.apply(saved["revision"], runtime); err != nil {
		t.Fatal(err)
	}
	entryPort := freePort(t)
	management := obj{"listen": "127.0.0.1", "port": freePort(t), "https": true, "certificateFile": "tls/proxy.crt", "keyFile": "tls/proxy.key",
		"allowedHosts": []any{"127.0.0.1"}, "frontend": obj{"listen": "127.0.0.1", "port": entryPort}}
	server := startServer(t, f.store, cloneObj(management), "")
	feed, err := server.serveFrontend(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: entryPort})
	if err != nil {
		t.Fatal(err)
	}
	frontend, err := NewFrontend(net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), feed, runtime.proxyTarget)
	if err != nil {
		t.Fatal(err)
	}
	defer frontend.Close()
	go frontend.Serve()

	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(certificate)
	values, _ := f.store.secrets()
	homeUUID := values[section(saved, "singBox", "inbound")["users"].([]any)[0].(obj)["uuid"].(string)].(string)
	controlPort, _ := port(section(saved, "frps")["bindPort"])
	home := newAppClient(t, obj{"type": "vless", "tag": "relay", "server": "127.0.0.1", "server_port": entryPort, "uuid": homeUUID,
		"tls": obj{"enabled": true, "server_name": "localhost", "certificate": string(certificate)}})
	if err = home.controlTLS(controlPort, roots); err != nil {
		t.Fatalf("proxy SNI did not reach sing-box through the entry: %v", err)
	}
	for _, serverName := range []string{"127.0.0.1", "other.example"} {
		client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: serverName, InsecureSkipVerify: serverName != "127.0.0.1"}}}
		response, err := client.Get("https://127.0.0.1:" + strconv.Itoa(entryPort) + "/")
		if err != nil {
			t.Fatalf("manager through entry (SNI %s): %v", serverName, err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || !strings.Contains(string(body), "OpenPlayX") {
			t.Fatalf("manager through entry (SNI %s): %d", serverName, response.StatusCode)
		}
	}
	plain, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(entryPort)), time.Second)
	if err == nil {
		_, _ = io.WriteString(plain, "GET / HTTP/1.0\r\n\r\n")
		_ = plain.SetReadDeadline(time.Now().Add(6 * time.Second))
		if n, _ := plain.Read(make([]byte, 1)); n > 0 {
			t.Fatal("non-TLS request answered")
		}
		plain.Close()
	}
	_ = runtime.Stop()
	if err = home.controlTLS(controlPort, roots); err == nil {
		t.Fatal("proxy SNI still forwarded with the runtime stopped")
	}
}
