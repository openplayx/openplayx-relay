package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var roles = []string{roleRelay, roleHome}

// testCertificate returns a PEM certificate and unencrypted key for localhost.
func testCertificate(t *testing.T) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

func writeFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

type fakeController struct {
	fail       func(cfg obj) error
	restarts   []any
	stopped    int
	components map[string]string
}

func (f *fakeController) Restart(cfg obj, _ *Plan) error {
	f.restarts = append(f.restarts, cfg["revision"])
	if f.fail != nil {
		return f.fail(cfg)
	}
	return nil
}

func (f *fakeController) Stop() error { f.stopped++; return nil }

func (f *fakeController) Components() map[string]string {
	if f.components == nil {
		return map[string]string{"sing-box": "active"}
	}
	return f.components
}

type fixture struct {
	store   *Store
	cfg     obj
	saved   obj
	updates obj
	folder  string
}

// newFixture mirrors the Python ManagerTest setup with real TLS material so
// the embedded upstream checks can load it.
func newFixture(t *testing.T, role string) *fixture {
	t.Helper()
	folder := t.TempDir()
	store, err := NewStore(filepath.Join(folder, "state"), role)
	if err != nil {
		t.Fatal(err)
	}
	certificate, key := testCertificate(t)
	for name, data := range map[string][]byte{"proxy.crt": certificate, "proxy.key": key, "frps.crt": certificate, "frps.key": key, "ca.crt": certificate} {
		writeFile(t, store.file("tls/"+name), data)
	}
	cfg := store.blank()
	service := obj{"serviceId": "jellyfin", "relayPort": 18096}
	if role == roleRelay {
		proxy, frp := cfg["proxy"].(obj), cfg["frp"].(obj)
		proxy["certificateFile"], proxy["keyFile"] = "tls/proxy.crt", "tls/proxy.key"
		proxy["listen"] = "127.0.0.1"
		proxy["port"] = freePort(t)
		frp["certificateFile"], frp["keyFile"] = "tls/frps.crt", "tls/frps.key"
	} else {
		service["targetHost"], service["targetPort"] = "192.168.50.10", 8096
		cfg["frp"].(obj)["caFile"] = "tls/ca.crt"
		if err = atomicWrite(store.file("grants.json"), obj{"homeId": "home-main", "relayHost": "relay.example.com", "relayPort": 443, "services": []any{[]any{"jellyfin", 18096}}}); err != nil {
			t.Fatal(err)
		}
	}
	cfg["services"] = []any{service}
	cfg = cloneObj(cfg)
	updates := obj{"homeUUID": "11111111-1111-4111-8111-111111111111", "frpToken": repeat("test-token-", 6)}
	if role == roleRelay {
		updates["appUUID"] = "22222222-2222-4222-8222-222222222222"
	}
	saved, err := store.save(cfg, 0, updates)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{store: store, cfg: cfg, saved: saved, updates: updates, folder: folder}
}

func repeat(value string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += value
	}
	return result
}

func expectCode(t *testing.T, err error, code string) {
	t.Helper()
	configError, ok := err.(*ConfigError)
	if !ok || (code != "" && configError.Code != code) {
		t.Fatalf("expected ConfigError %q, got %v", code, err)
	}
}
