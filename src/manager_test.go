package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func forRoles(t *testing.T, test func(t *testing.T, f *fixture)) {
	for _, role := range roles {
		t.Run(role, func(t *testing.T) { test(t, newFixture(t, role)) })
	}
}

func TestRelayStaysLoopbackAndRejectsHomeLANMigration(t *testing.T) {
	f := newFixture(t, roleRelay)
	if f.store.blank()["management"].(obj)["listen"] != "127.0.0.1" {
		t.Fatal("relay default must be loopback")
	}
	before, _ := os.ReadFile(f.store.path)
	_, err := f.store.enableLAN()
	expectCode(t, err, "homeOnly")
	after, _ := os.ReadFile(f.store.path)
	if !bytes.Equal(before, after) {
		t.Fatal("relay config changed")
	}
	management := cloneObj(f.saved["management"].(obj))
	management["listen"] = "0.0.0.0"
	expectCode(t, f.store.validateManagement(management), "adminRequired")
	if err = NewAdmin(f.store.dir).setPassword("test-only-administrator-password"); err != nil {
		t.Fatal(err)
	}
	expectCode(t, f.store.validateManagement(management), "httpsRequired")
}

func TestSecretsRevisionAndBackup(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		data, _ := os.ReadFile(f.store.path)
		for _, value := range f.updates {
			if strings.Contains(string(data), value.(string)) {
				t.Fatal("secret value in authoritative JSON")
			}
		}
		info, _ := os.Stat(f.store.file("secrets.json"))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("secrets.json mode %v", info.Mode().Perm())
		}
		_, err := f.store.save(f.cfg, 0, f.updates)
		expectCode(t, err, "conflict")
		if err.(*ConfigError).Status != 409 {
			t.Fatal("conflict must be 409")
		}
		next := cloneObj(f.saved)
		next["log"].(obj)["level"] = "error"
		if _, err = f.store.save(next, 1, nil); err != nil {
			t.Fatal(err)
		}
		restored, err := f.store.restore(json.Number("2"))
		if err != nil {
			t.Fatal(err)
		}
		if canonical(restored["revision"]) != "3" || restored["log"].(obj)["level"] != "warn" {
			t.Fatalf("restore gave %v", restored)
		}
	})
}

func TestSharedTLSPortRequiresDistinctSameFamilyLoopbackAddresses(t *testing.T) {
	f := newFixture(t, roleRelay)
	values, _ := f.store.secrets()
	cfg := cloneObj(f.saved)
	section(cfg, "singBox", "inbound")["listen"], section(cfg, "singBox", "inbound")["listen_port"] = "127.0.0.1", 443
	management := cfg["management"].(obj)
	management["listen"], management["port"], management["https"] = "127.0.0.2", 443, true
	management["certificateFile"], management["keyFile"] = "tls/proxy.crt", "tls/proxy.key"
	cfg = cloneObj(cfg)
	if _, err := f.store.validate(cfg, values); err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"127.0.0.1", "127.0.0.1"}, {"0.0.0.0", "127.0.0.2"}, {"127.0.0.1", "::1"}} {
		invalid := cloneObj(cfg)
		section(invalid, "singBox", "inbound")["listen"], invalid["management"].(obj)["listen"] = pair[0], pair[1]
		if _, err := f.store.validate(invalid, values); err == nil {
			t.Fatalf("accepted %v", pair)
		}
	}
	setBindPort(cfg, 443)
	if _, err := f.store.validate(cfg, values); err == nil {
		t.Fatal("accepted frps on the shared port")
	}
}

func TestCorruptOrFutureFileNeverOverwritten(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		writeFile(t, f.store.path, []byte("{broken"))
		_, err := f.store.save(f.saved, 1, nil)
		expectCode(t, err, "invalidFile")
		if data, _ := os.ReadFile(f.store.path); string(data) != "{broken" {
			t.Fatal("corrupt file overwritten")
		}
		if err = atomicWrite(f.store.path, obj{"schemaVersion": 99, "revision": 50}); err != nil {
			t.Fatal(err)
		}
		_, err = f.store.load()
		expectCode(t, err, "unknownSchema")
		value, _ := readObj(f.store.path)
		if canonical(value["schemaVersion"]) != "99" {
			t.Fatal("future file overwritten")
		}
	})
}

func TestExplicitRecoveryPreservesCorruptFileAndUsesHashConflictCheck(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		if _, err := f.store.save(cloneObj(f.saved), 1, nil); err != nil {
			t.Fatal(err)
		}
		writeFile(t, f.store.path, []byte("{damaged"))
		info, err := f.store.recoveryInfo()
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.store.recover("wrong-hash")
		expectCode(t, err, "conflict")
		restored, err := f.store.recover(info["fileHash"])
		if err != nil {
			t.Fatal(err)
		}
		if canonical(restored["revision"]) != "3" {
			t.Fatalf("revision %v", restored["revision"])
		}
		copies, _ := filepath.Glob(f.store.file(f.store.role + ".damaged.*.json"))
		if len(copies) != 1 {
			t.Fatal("damaged copy missing")
		}
		if data, _ := os.ReadFile(copies[0]); string(data) != "{damaged" {
			t.Fatal("damaged copy altered")
		}
		loaded, err := f.store.load()
		if err != nil || canonical(loaded["revision"]) != "3" {
			t.Fatalf("load after recover: %v %v", loaded, err)
		}
	})
}

func TestTLSImportIsBoundedPrivateAndNotAPathWriteAPI(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		certificate, key := testCertificate(t)
		ref, err := f.store.importTLS("certificate", string(certificate))
		if err != nil {
			t.Fatal(err)
		}
		private, err := f.store.importTLS("privateKey", string(key))
		if err != nil {
			t.Fatal(err)
		}
		info, _ := os.Stat(f.store.file(private))
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("key mode %v", info.Mode().Perm())
		}
		if !strings.HasPrefix(ref, "tls/") || !strings.HasPrefix(private, "tls/") {
			t.Fatal("unexpected reference")
		}
		_, err = f.store.importTLS("../../outside", string(key))
		expectCode(t, err, "invalidTLS")
		_, err = f.store.importTLS("certificate", string(key))
		expectCode(t, err, "invalidTLS")
		encrypted := "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"
		_, err = f.store.importTLS("privateKey", encrypted)
		expectCode(t, err, "invalidTLS")
		if data, _ := os.ReadFile(f.store.path); strings.Contains(string(data), string(key)) {
			t.Fatal("key in config")
		}
	})
}

func TestBackendRejectsPathsPortsUnknownFieldsAndUnauthorizedMapping(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		for _, change := range []string{"port", "path", "field", "nested", "mapping", "identity"} {
			cfg := cloneObj(f.saved)
			relay := f.store.role == roleRelay
			switch change {
			case "port":
				if relay {
					section(cfg, "frps")["bindPort"] = section(cfg, "singBox", "inbound")["listen_port"]
				} else {
					cfg["frpc"].(obj)["proxies"].([]any)[0].(obj)["remotePort"] = section(cfg, "frpc")["serverPort"]
				}
			case "path":
				if relay {
					section(cfg, "frps", "transport", "tls")["keyFile"] = "../../arbitrary"
				} else {
					section(cfg, "frpc", "transport", "tls")["trustedCaFile"] = "../../arbitrary"
				}
			case "field":
				cfg["shellCommand"] = "whoami"
			case "nested":
				section(cfg, "singBox")["experimental"] = obj{"clash_api": obj{}}
			case "mapping":
				if relay {
					// A route rule may not open ports outside frps.bindPort/allowPorts.
					section(cfg, "singBox", "route")["rules"] = append(section(cfg, "singBox", "route")["rules"].([]any), obj{"auth_user": []any{"app"}, "port": []any{22}})
				} else {
					cfg["frpc"].(obj)["proxies"].([]any)[0].(obj)["type"] = "http"
				}
			default:
				if relay {
					users := section(cfg, "singBox", "inbound")["users"].([]any)
					users[1].(obj)["uuid"] = users[0].(obj)["uuid"]
				} else {
					section(cfg, "singBox", "outbound")["uuid"] = "11111111-1111-4111-8111-111111111111"
				}
			}
			if _, err := f.store.save(cloneObj(cfg), 1, nil); err == nil {
				t.Fatalf("%s accepted", change)
			}
		}
		loaded, _ := f.store.load()
		if canonical(loaded["revision"]) != "1" {
			t.Fatal("rejected change was saved")
		}
	})
}

func TestSaveIsNotApplyAndFailedApplyRestoresRuntime(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		controller := &fakeController{}
		f.store.controller = controller
		status, err := f.store.status()
		if err != nil || status["appliedRevision"] != nil {
			t.Fatalf("initial status %v %v", status, err)
		}
		if _, err = f.store.apply(json.Number("1"), controller); err != nil {
			t.Fatal(err)
		}
		cfg := cloneObj(f.saved)
		cfg["log"].(obj)["level"] = "error"
		if _, err = f.store.save(cfg, 1, nil); err != nil {
			t.Fatal(err)
		}
		controller.fail = func(cfg obj) error {
			if canonical(cfg["revision"]) == "2" {
				return errors.New("test-only component failure")
			}
			return nil
		}
		_, err = f.store.apply(2, controller)
		expectCode(t, err, "applyFailed")
		if got := canonical(controller.restarts); got != "[1,2,1]" {
			t.Fatalf("restart sequence %s", got)
		}
		status, _ = f.store.status()
		loaded, _ := f.store.load()
		if canonical(status["appliedRevision"]) != "1" || canonical(loaded["revision"]) != "2" || status["error"] != "applyFailed" || status["savedIsApplied"] != false {
			t.Fatalf("status %v", status)
		}
		lastGood, _ := readObj(f.store.file("last-good.json"))
		if canonical(lastGood["revision"]) != "1" {
			t.Fatal("last-good changed by failed apply")
		}
	})
}

func TestFirstFailedApplyStopsComponents(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		controller := &fakeController{fail: func(obj) error { return errors.New("boom") }}
		_, err := f.store.apply(1, controller)
		expectCode(t, err, "applyFailed")
		status, _ := f.store.status()
		if controller.stopped != 1 || status["appliedRevision"] != nil || status["error"] != "applyFailed" || canonical(status["failedRevision"]) != "1" {
			t.Fatalf("status %v stopped %d", status, controller.stopped)
		}
	})
}

func TestComponentCheckRejectsInvalidTLSMaterial(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		name := "tls/frps.key"
		if f.store.role == roleHome {
			name = "tls/ca.crt"
		}
		writeFile(t, f.store.file(name), []byte("test fixture only"))
		_, err := f.store.test(f.saved, nil)
		expectCode(t, err, "componentCheckFailed")
		_, err = f.store.apply(1, &fakeController{})
		expectCode(t, err, "applyFailed")
	})
}

func TestPreviousRuntimeSecretsSurviveMultiplePendingRotations(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		controller := &fakeController{}
		if _, err := f.store.apply(1, controller); err != nil {
			t.Fatal(err)
		}
		owner := "frps"
		if f.store.role == roleHome {
			owner = "frpc"
		}
		oldRef := section(f.saved, owner, "auth")["token"].(string)
		second, err := f.store.save(cloneObj(f.saved), 1, obj{"token": repeat("replacement-token-B-", 4)})
		if err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.save(second, 2, obj{"token": repeat("replacement-token-C-", 4)}); err != nil {
			t.Fatal(err)
		}
		if _, err = f.store.apply(3, controller); err != nil {
			t.Fatal(err)
		}
		values, _ := f.store.secrets()
		if _, ok := values[oldRef]; !ok {
			t.Fatal("previous runtime secret collected")
		}
		previous, _ := readObj(f.store.file("previous-good.json"))
		if canonical(previous["revision"]) != "1" {
			t.Fatal("previous-good missing")
		}
	})
}

func TestRenderedConfigBoundaries(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		values, _ := f.store.secrets()
		plan, err := f.store.plan(f.saved, values)
		if err != nil {
			t.Fatal(err)
		}
		output := filepath.Join(f.folder, "generated")
		if err = writeRendered(plan, output, f.store.frpName()); err != nil {
			t.Fatal(err)
		}
		sing, _ := readObj(filepath.Join(output, "sing-box.json"))
		frp, _ := readObj(filepath.Join(output, f.store.frpName()+".json"))
		if f.store.role == roleRelay {
			rules := sing["route"].(obj)["rules"].([]any)
			if frp["bindAddr"] != "127.0.0.1" || frp["proxyBindAddr"] != "127.0.0.1" || rules[2].(obj)["action"] != "reject" ||
				canonical(rules[0].(obj)["auth_user"]) != `["home"]` || canonical(rules[1].(obj)["auth_user"]) != `["app"]` {
				t.Fatalf("relay boundaries: %v %v", sing, frp)
			}
			if frp["transport"].(obj)["tls"].(obj)["force"] != true {
				t.Fatal("frps must force TLS")
			}
		} else {
			transport := frp["transport"].(obj)
			if transport["proxyURL"] != "socks5://127.0.0.1:1080" || transport["tls"].(obj)["trustedCaFile"] == "" {
				t.Fatalf("home transport %v", transport)
			}
			outbounds := sing["outbounds"].([]any)
			if len(outbounds) != 1 || outbounds[0].(obj)["type"] != "vless" {
				t.Fatal("home must only have the relay outbound")
			}
		}
		info, _ := os.Stat(filepath.Join(output, "sing-box.json"))
		if info.Mode().Perm() != 0o600 {
			t.Fatal("rendered config must be private")
		}
	})
}

func TestMappingCollisionAndWeakCredentialsRejected(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		duplicate := cloneObj(f.saved)
		if f.store.role == roleRelay {
			users := section(duplicate, "singBox", "inbound")["users"].([]any)
			users[1].(obj)["name"] = users[0].(obj)["name"]
		} else {
			proxies := section(duplicate, "frpc")["proxies"].([]any)
			second := cloneObj(proxies[0].(obj))
			second["name"] = "other"
			section(duplicate, "frpc")["proxies"] = append(proxies, second)
		}
		if _, _, err := f.store.prepare(duplicate, nil); err == nil {
			t.Fatal("duplicate user / remotePort accepted")
		}
		_, _, err := f.store.prepare(cloneObj(f.saved), obj{"token": "weak"})
		expectCode(t, err, "invalidSecret")
		_, _, err = f.store.prepare(cloneObj(f.saved), obj{"uuid:nobody": newUUID()})
		expectCode(t, err, "invalidSecret")
	})
}

func TestRouteRulesStayWithinFRPSPorts(t *testing.T) {
	f := newFixture(t, roleRelay)
	values, _ := f.store.secrets()
	appRule := func(c obj) obj { return section(c, "singBox", "route")["rules"].([]any)[1].(obj) }
	for name, change := range map[string]func(c obj){
		"unknown user":       func(c obj) { appRule(c)["auth_user"] = []any{"ghost"} },
		"range beyond allow": func(c obj) { appRule(c)["port_range"] = []any{"18000:19000"} },
		"bad range":          func(c obj) { appRule(c)["port_range"] = []any{"18999:18000"} },
		"no ports":           func(c obj) { delete(appRule(c), "port_range") },
		"unknown rule field": func(c obj) { appRule(c)["outbound"] = "direct" },
		"allow covers bind":  func(c obj) { section(c, "frps")["allowPorts"] = []any{obj{"start": 6000, "end": 8000}} },
		"allow both forms":   func(c obj) { section(c, "frps")["allowPorts"] = []any{obj{"single": 18000, "end": 18001}} },
	} {
		invalid := cloneObj(f.saved)
		change(invalid)
		if _, err := f.store.validate(cloneObj(invalid), values); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	valid := cloneObj(f.saved)
	section(valid, "frps")["allowPorts"] = []any{obj{"single": 18096}, obj{"start": 18400, "end": 18499}}
	section(valid, "singBox", "route")["rules"].([]any)[1] = obj{"auth_user": []any{"app"}, "port": []any{18096}, "port_range": []any{"18400:18450"}}
	if _, err := f.store.validate(valid, values); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapExpiry(t *testing.T) {
	f := newFixture(t, roleHome)
	now := 1000.0
	admin := NewAdmin(f.store.dir)
	admin.now = func() float64 { return now }
	if err := admin.bootstrap(false); err != nil {
		t.Fatal(err)
	}
	token, _ := os.ReadFile(f.store.file("bootstrap-token"))
	now = 2000
	_, _, err := admin.authenticate(strings.TrimSpace(string(token)), "local")
	expectCode(t, err, "loginFailed")
}

func TestAdminPasswordIsCompatibleWithPythonScrypt(t *testing.T) {
	// hashlib.scrypt(b"test-only-administrator-password", salt=bytes(16), n=16384, r=8, p=1).hex()
	digest, err := adminDigest("test-only-administrator-password", make([]byte, 16))
	if err != nil {
		t.Fatal(err)
	}
	// Existing admin.json files written by the previous Python manager must
	// keep working after the migration.
	if digest != "de6b0aa2c136c914b850c5de1c0207c6b8ccf6de51d28525fb9336f23de531d268e2e731087fb0e89c36c731b897917e26967e31d8d232d6f54b9bbb31f0795f" {
		t.Fatalf("scrypt digest differs from Python hashlib.scrypt: %s", digest)
	}
}

func TestPairingRoleCredentialsAndNoOverwrite(t *testing.T) {
	folder := t.TempDir()
	certificate, key := testCertificate(t)
	writeFile(t, filepath.Join(folder, "cert.pem"), certificate)
	writeFile(t, filepath.Join(folder, "key.pem"), key)
	options := pairOptions{Host: "relay.test", TLSName: "relay.test", Certificate: filepath.Join(folder, "cert.pem"), Key: filepath.Join(folder, "key.pem"), Output: filepath.Join(folder, "paired"), Port: 443}
	if _, err := pair(options); err != nil {
		t.Fatal(err)
	}
	paired := options.Output
	cfg, _ := readObj(filepath.Join(paired, "relay/relay.json"))
	home, _ := readObj(filepath.Join(paired, "home/home.json"))
	app, _ := readObj(filepath.Join(paired, "app.json"))
	relaySecrets, _ := readObj(filepath.Join(paired, "relay/secrets.json"))
	homeSecrets, _ := readObj(filepath.Join(paired, "home/secrets.json"))
	users := map[string]any{}
	for _, item := range section(cfg, "singBox", "inbound")["users"].([]any) {
		users[item.(obj)["name"].(string)] = relaySecrets[item.(obj)["uuid"].(string)]
	}
	appUUID := app["outbound"].(obj)["uuid"]
	if users["app"] != appUUID {
		t.Fatal("app uuid mismatch")
	}
	if users["home"] != homeSecrets[section(home, "singBox", "outbound")["uuid"].(string)] {
		t.Fatal("home uuid mismatch")
	}
	if relaySecrets[section(cfg, "frps", "auth")["token"].(string)] != homeSecrets[section(home, "frpc", "auth")["token"].(string)] {
		t.Fatal("frp token mismatch")
	}
	if home["management"].(obj)["listen"] != "0.0.0.0" || cfg["management"].(obj)["listen"] != "127.0.0.1" {
		t.Fatal("management defaults")
	}
	for _, value := range homeSecrets {
		if value == appUUID {
			t.Fatal("home received app uuid")
		}
	}
	if exists(filepath.Join(paired, "home/tls/frps.key")) || exists(filepath.Join(paired, "frps.key")) {
		t.Fatal("frps key left outside relay/")
	}
	if canonical(app["proxies"]) != `[{"name":"jellyfin","remotePort":18096}]` || len(app) != 2 {
		t.Fatalf("app file %v", app)
	}
	// Both generated directories pass the embedded upstream checks as-is.
	for _, side := range roles {
		store, _ := NewStore(filepath.Join(paired, side), side)
		saved, _ := store.load()
		values, _ := store.secrets()
		if _, err := store.plan(saved, values); err != nil {
			t.Fatalf("paired %s config fails checks: %v", side, err)
		}
	}
	if _, err := pair(options); err == nil {
		t.Fatal("existing output overwritten")
	}
}

type client struct {
	t      *testing.T
	base   string
	host   string
	origin string
	cookie string
	csrf   string
}

func (c *client) request(method, path string, body any, headers map[string]string) (int, obj, *http.Response) {
	c.t.Helper()
	var reader io.Reader
	if body != nil {
		data, _ := json.Marshal(body)
		reader = bytes.NewReader(data)
	}
	request, _ := http.NewRequest(method, c.base+path, reader)
	request.Host = c.host
	if c.origin != "" {
		request.Header.Set("Origin", c.origin)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if c.cookie != "" {
		request.Header.Set("Cookie", c.cookie)
	}
	if c.csrf != "" {
		request.Header.Set("X-CSRF-Token", c.csrf)
	}
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	response, err := http.DefaultTransport.RoundTrip(request)
	if err != nil {
		c.t.Fatal(err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	value, _ := decodeJSON(data)
	result, _ := value.(obj)
	return response.StatusCode, result, response
}

func startServer(t *testing.T, store *Store, management obj, address string) *ManagerServer {
	t.Helper()
	server, err := NewManagerServer(store, management, address)
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve()
	t.Cleanup(func() { server.Close() })
	return server
}

func TestHTTPAuthCSRFOriginsExpirationAndRedaction(t *testing.T) {
	forRoles(t, func(t *testing.T, f *fixture) {
		server := startServer(t, f.store, f.saved["management"].(obj), "127.0.0.1:0")
		hostport := "127.0.0.1:" + strconv.Itoa(server.port)
		c := &client{t: t, base: "http://" + hostport, host: hostport, origin: "http://" + hostport}
		if status, _, _ := c.request("GET", "/api/config", nil, nil); status != 401 {
			t.Fatalf("unauthenticated config: %d", status)
		}
		token, _ := os.ReadFile(f.store.file("bootstrap-token"))
		status, data, response := c.request("POST", "/api/login", obj{"password": strings.TrimSpace(string(token))}, nil)
		cookie := response.Header.Get("Set-Cookie")
		if status != 200 || !strings.Contains(cookie, "HttpOnly") || !strings.Contains(cookie, "SameSite=Strict") {
			t.Fatalf("login %d %q", status, cookie)
		}
		c.cookie = strings.Split(cookie, ";")[0]
		csrf := data["csrfToken"].(string)
		status, data, _ = c.request("GET", "/api/config", nil, nil)
		if status != 200 {
			t.Fatalf("config %d", status)
		}
		for _, value := range f.updates {
			if strings.Contains(canonical(data), value.(string)) {
				t.Fatal("secret returned by API")
			}
		}
		body := obj{"config": f.saved, "expectedRevision": 1}
		if status, _, _ = c.request("POST", "/api/save", body, nil); status != 403 {
			t.Fatalf("save without csrf %d", status)
		}
		c.csrf = csrf
		evil := &client{t: t, base: c.base, host: c.host, origin: "https://evil.example", cookie: c.cookie, csrf: csrf}
		if status, _, _ = evil.request("POST", "/api/save", body, nil); status != 403 {
			t.Fatalf("cross-origin save %d", status)
		}
		if status, _, _ = c.request("POST", "/api/save", body, map[string]string{"Sec-Fetch-Site": "cross-site"}); status != 403 {
			t.Fatalf("cross-site save %d", status)
		}
		if status, _, _ = c.request("POST", "/api/save", body, nil); status != 200 {
			t.Fatalf("save %d", status)
		}
		if status, _, _ = c.request("POST", "/api/save", body, nil); status != 409 {
			t.Fatalf("stale save %d", status)
		}
		if status, _, _ = c.request("GET", "/api/status", nil, nil); status != 200 {
			t.Fatalf("status %d", status)
		}
		if status, _, _ = c.request("POST", "/api/password", obj{"password": "new-test-password-with-32-characters"}, nil); status != 200 {
			t.Fatalf("password %d", status)
		}
		if status, _, _ = c.request("GET", "/api/config", nil, nil); status != 401 {
			t.Fatal("sessions survive password change")
		}
		anonymous := &client{t: t, base: c.base, host: c.host, origin: c.origin}
		if status, _, _ = anonymous.request("POST", "/api/login", obj{"password": strings.TrimSpace(string(token))}, nil); status != 401 {
			t.Fatal("bootstrap token survives password change")
		}
		status, _, response = anonymous.request("POST", "/api/login", obj{"password": "new-test-password-with-32-characters"}, nil)
		if status != 200 {
			t.Fatalf("password login %d", status)
		}
		server.admin.now = func() float64 { return wallClock() + 3600 }
		anonymous.cookie = strings.Split(response.Header.Get("Set-Cookie"), ";")[0]
		if status, _, _ = anonymous.request("GET", "/api/config", nil, nil); status != 401 {
			t.Fatal("expired session accepted")
		}
	})
}

func TestStaticAssetsAndHeaders(t *testing.T) {
	f := newFixture(t, roleRelay)
	server := startServer(t, f.store, f.saved["management"].(obj), "127.0.0.1:0")
	hostport := "127.0.0.1:" + strconv.Itoa(server.port)
	c := &client{t: t, base: "http://" + hostport, host: hostport}
	for _, path := range []string{"/", "/app.js", "/style.css"} {
		status, _, response := c.request("GET", path, nil, nil)
		if status != 200 || response.Header.Get("Content-Security-Policy") == "" || response.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: %d %v", path, status, response.Header)
		}
	}
	if status, _, _ := c.request("GET", "/../relay.json", nil, nil); status == 200 {
		t.Fatal("arbitrary file served")
	}
	other := &client{t: t, base: c.base, host: "rebinding.example:" + strconv.Itoa(server.port)}
	if status, _, _ := other.request("GET", "/", nil, nil); status != 403 {
		t.Fatalf("foreign Host accepted: %d", status)
	}
	if status, _, _ := c.request("OPTIONS", "/api/config", nil, nil); status != 403 {
		t.Fatal("CORS preflight accepted")
	}
}

func TestHomeLANDefaultAndOnlyRealDestinationIP(t *testing.T) {
	store, _ := NewStore(t.TempDir(), roleHome)
	management := store.blank()["management"].(obj)
	if management["listen"] != "0.0.0.0" || canonical(management["port"]) != "9080" {
		t.Fatal("home default must be LAN on 9080")
	}
	if err := store.validateManagement(management); err != nil {
		t.Fatal(err)
	}
	management["allowedHosts"] = []any{"configured-only.example"}
	server := startServer(t, store, management, "0.0.0.0:0")
	number := server.port
	origin := "http://192.168.50.10:" + strconv.Itoa(number)
	origins, err := server.requestOrigins("192.168.50.20", "192.168.50.10", origin)
	if err != nil || !origins[origin] {
		t.Fatal("real destination IP rejected")
	}
	for _, authority := range []string{"http://192.168.50.99:" + strconv.Itoa(number), "http://rebinding.example:" + strconv.Itoa(number),
		"http://192.168.50.10:" + strconv.Itoa(number+1), "http://user@192.168.50.10:" + strconv.Itoa(number)} {
		origins, _ := server.requestOrigins("192.168.50.20", "192.168.50.10", authority)
		if origins[authority] {
			t.Fatalf("accepted %s", authority)
		}
	}
	for _, pair := range [][2]string{{"8.8.8.8", "192.168.50.10"}, {"192.168.50.20", "8.8.8.8"}, {"198.51.100.20", "192.168.50.10"}} {
		if _, err := server.requestOrigins(pair[0], pair[1], origin); err == nil {
			t.Fatalf("accepted peer/local %v", pair)
		}
	}
	for _, address := range []string{"127.0.0.1", "192.168.1.2", "10.0.0.2", "172.16.0.2", "fd12::1", "::ffff:192.168.1.2"} {
		if !isLANAddress(address) {
			t.Fatal(address)
		}
	}
	for _, address := range []string{"8.8.8.8", "172.32.0.1", "198.51.100.2", "rebinding.example"} {
		if isLANAddress(address) {
			t.Fatal(address)
		}
	}
}

func TestHomeIPLoginKeepsAuthenticationCSRFAndExactOrigin(t *testing.T) {
	store, _ := NewStore(t.TempDir(), roleHome)
	management := store.blank()["management"].(obj)
	management["allowedHosts"] = []any{"configured-only.example"}
	server := startServer(t, store, management, "0.0.0.0:0")
	hostport := "127.0.0.1:" + strconv.Itoa(server.port)
	c := &client{t: t, base: "http://" + hostport, host: hostport, origin: "http://" + hostport}
	if status, _, _ := c.request("GET", "/", nil, nil); status != 200 {
		t.Fatalf("index %d", status)
	}
	if status, _, _ := c.request("GET", "/api/config", nil, nil); status != 401 {
		t.Fatal("unauthenticated config")
	}
	for _, foreign := range []string{"192.168.50.99:", "rebinding.example:"} {
		other := &client{t: t, base: c.base, host: foreign + strconv.Itoa(server.port)}
		if status, _, _ := other.request("GET", "/", nil, nil); status != 403 {
			t.Fatalf("foreign host %s accepted", foreign)
		}
	}
	token, _ := os.ReadFile(store.file("bootstrap-token"))
	status, data, response := c.request("POST", "/api/login", obj{"password": strings.TrimSpace(string(token))}, nil)
	if status != 200 {
		t.Fatalf("login %d", status)
	}
	c.cookie = strings.Split(response.Header.Get("Set-Cookie"), ";")[0]
	if status, _, _ = c.request("GET", "/api/config", nil, nil); status != 200 {
		t.Fatal("config after login")
	}
	if status, _, _ = c.request("POST", "/api/logout", obj{}, nil); status != 403 {
		t.Fatal("logout without csrf")
	}
	c.csrf = data["csrfToken"].(string)
	configured := &client{t: t, base: c.base, host: c.host, origin: "http://configured-only.example:" + strconv.Itoa(server.port), cookie: c.cookie, csrf: c.csrf}
	if status, _, _ = configured.request("POST", "/api/logout", obj{}, nil); status != 403 {
		t.Fatal("home write accepted with Origin different from Host")
	}
	if status, _, _ = c.request("POST", "/api/logout", obj{}, nil); status != 200 {
		t.Fatal("logout")
	}
	if status, _, _ = c.request("GET", "/api/config", nil, nil); status != 401 {
		t.Fatal("session survives logout")
	}
}

func TestExistingLoopbackConfigurationRequiresExplicitRevisionedMigration(t *testing.T) {
	f := newFixture(t, roleHome)
	cfg := cloneObj(f.saved)
	cfg["management"].(obj)["listen"] = "127.0.0.1"
	initial, err := f.store.save(cfg, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	migrated, err := f.store.enableLAN()
	if err != nil {
		t.Fatal(err)
	}
	if canonical(migrated["revision"]) != "3" || migrated["management"].(obj)["listen"] != "0.0.0.0" ||
		canonical(migrated["singBox"]) != canonical(initial["singBox"]) || canonical(migrated["frpc"]) != canonical(initial["frpc"]) {
		t.Fatalf("migration %v", migrated)
	}
	if exists(f.store.file("status.json")) {
		t.Fatal("migration must not apply")
	}
}

func frontendConfig(t *testing.T, f *fixture) obj {
	t.Helper()
	if err := NewAdmin(f.store.dir).setPassword("test-only-administrator-password"); err != nil {
		t.Fatal(err)
	}
	cfg := cloneObj(f.saved)
	section(cfg, "singBox", "inbound")["listen"], section(cfg, "singBox", "inbound")["listen_port"] = "127.0.0.1", 443
	management := cfg["management"].(obj)
	management["https"], management["certificateFile"], management["keyFile"] = true, "tls/proxy.crt", "tls/proxy.key"
	management["allowedHosts"] = []any{"203.0.113.10"}
	management["frontend"] = obj{"listen": "203.0.113.10", "port": 443}
	return cloneObj(cfg)
}

func TestPublicFrontendValidation(t *testing.T) {
	f := newFixture(t, roleRelay)
	values, _ := f.store.secrets()
	cfg := frontendConfig(t, f)
	if _, err := f.store.validate(cfg, values); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(c obj){
		"loopback entry":       func(c obj) { c["management"].(obj)["frontend"].(obj)["listen"] = "127.0.0.3" },
		"wildcard entry":       func(c obj) { c["management"].(obj)["frontend"].(obj)["listen"] = "0.0.0.0" },
		"not the proxy port":   func(c obj) { c["management"].(obj)["frontend"].(obj)["port"] = 8443 },
		"public proxy listen":  func(c obj) { section(c, "singBox", "inbound")["listen"] = "0.0.0.0" },
		"plain HTTP manager":   func(c obj) { c["management"].(obj)["https"] = false },
		"unknown entry field":  func(c obj) { c["management"].(obj)["frontend"].(obj)["sni"] = "x" },
		"manager on the entry": func(c obj) { c["management"].(obj)["listen"], c["management"].(obj)["port"] = "203.0.113.10", 443 },
	} {
		invalid := cloneObj(cfg)
		change(invalid)
		if _, err := f.store.validate(cloneObj(invalid), values); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
	_ = os.Remove(f.store.file("admin.json"))
	expectCode(t, f.store.validateManagement(cfg["management"]), "adminRequired")
	home := newFixture(t, roleHome)
	management := cloneObj(home.saved["management"].(obj))
	management["frontend"] = obj{"listen": "192.168.1.2", "port": 443}
	expectCode(t, home.store.validateManagement(management), "invalidFrontend")
}
