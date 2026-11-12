package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type pairOptions struct {
	Host, TLSName, Certificate, Key, ProxyCA, Output string
	Port                                             int
}

func cmdPair(args []string) error {
	flags := flag.NewFlagSet(binaryName()+" pair", flag.ExitOnError)
	options := pairOptions{}
	flags.StringVar(&options.Host, "host", "", "public Relay host (required)")
	flags.StringVar(&options.TLSName, "tls-name", "", "proxy TLS server name (required)")
	flags.StringVar(&options.Certificate, "certificate", "", "proxy TLS certificate chain PEM (required)")
	flags.StringVar(&options.Key, "key", "", "proxy TLS private key PEM (required)")
	flags.StringVar(&options.ProxyCA, "proxy-ca", "", "optional private CA for proxy TLS")
	flags.StringVar(&options.Output, "output", "secrets", "output directory; must not exist")
	flags.IntVar(&options.Port, "port", 443, "public proxy port")
	_ = flags.Parse(args)
	if options.Host == "" || options.TLSName == "" || options.Certificate == "" || options.Key == "" {
		flags.Usage()
		return errors.New("--host, --tls-name, --certificate and --key are required")
	}
	root, err := pair(options)
	if err != nil {
		return err
	}
	fmt.Println("Created relay/, home/ and app.json in", root)
	return nil
}

// selfSignedFRPS creates the dedicated frps server identity that Home pins as
// its trust anchor. Proxy TLS uses the supplied certificate, never this one.
func selfSignedFRPS() ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "openplayx-frps"}, DNSNames: []string{"openplayx-frps"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(1, 0, 0),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), nil
}

func newUUID() string {
	value := randomBytes(16)
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[0:4], value[4:6], value[6:8], value[8:10], value[10:16])
}

// pair creates one household's relay/ and home/ state directories and the
// App file (a sing-box outbound plus the frpc proxies it may use). It refuses
// an existing output directory so credentials are never rotated implicitly.
func pair(options pairOptions) (string, error) {
	if err := os.Mkdir(options.Output, 0o700); err != nil {
		return "", err
	}
	root, err := filepath.Abs(options.Output)
	if err != nil {
		return "", err
	}
	proxyCert, err := os.ReadFile(options.Certificate)
	if err != nil {
		return "", err
	}
	proxyKey, err := os.ReadFile(options.Key)
	if err != nil {
		return "", err
	}
	frpsCert, frpsKey, err := selfSignedFRPS()
	if err != nil {
		return "", err
	}
	caCertificate := ""
	if options.ProxyCA != "" {
		data, err := os.ReadFile(options.ProxyCA)
		if err != nil {
			return "", err
		}
		caCertificate = string(data)
	}
	appUUID, homeUUID, token := newUUID(), newUUID(), tokenURLSafe(48)
	const remotePort = 18096

	relay, err := NewStore(filepath.Join(root, roleRelay), roleRelay)
	if err != nil {
		return "", err
	}
	for name, data := range map[string][]byte{"proxy.crt": proxyCert, "proxy.key": proxyKey, "frps.crt": frpsCert, "frps.key": frpsKey} {
		if err = os.MkdirAll(relay.file("tls"), 0o700); err != nil {
			return "", err
		}
		if err = writeSynced(relay.file("tls/"+name), data); err != nil {
			return "", err
		}
	}
	relayCfg := relay.blank()
	inbound := section(relayCfg, "singBox", "inbound")
	inbound["listen_port"] = options.Port
	section(inbound, "tls")["server_name"] = options.TLSName
	section(inbound, "tls")["certificate_path"], section(inbound, "tls")["key_path"] = "tls/proxy.crt", "tls/proxy.key"
	frpsTLS := section(relayCfg, "frps", "transport", "tls")
	frpsTLS["certFile"], frpsTLS["keyFile"] = "tls/frps.crt", "tls/frps.key"
	if _, err = relay.save(relayCfg, 0, obj{"uuid:home": homeUUID, "uuid:app": appUUID, "token": token}); err != nil {
		return "", err
	}

	// Home never receives the App identity or Relay private keys.
	home, err := NewStore(filepath.Join(root, roleHome), roleHome)
	if err != nil {
		return "", err
	}
	if err = os.MkdirAll(home.file("tls"), 0o700); err != nil {
		return "", err
	}
	if err = writeSynced(home.file("tls/frps-ca.crt"), frpsCert); err != nil {
		return "", err
	}
	homeCfg := home.blank()
	outbound := section(homeCfg, "singBox", "outbound")
	outbound["server"], outbound["server_port"] = options.Host, options.Port
	section(outbound, "tls")["server_name"], section(outbound, "tls")["certificate"] = options.TLSName, caCertificate
	section(homeCfg, "frpc", "transport", "tls")["trustedCaFile"] = "tls/frps-ca.crt"
	section(homeCfg, "frpc")["proxies"] = []any{obj{"name": "jellyfin", "type": "tcp", "localIP": "192.168.50.10", "localPort": 8096, "remotePort": remotePort}}
	if _, err = home.save(homeCfg, 0, obj{"uuid": homeUUID, "token": token}); err != nil {
		return "", err
	}

	tls := obj{"enabled": true, "server_name": options.TLSName}
	if caCertificate != "" {
		tls["certificate"] = caCertificate
	}
	app := obj{
		"outbound": obj{"type": "vless", "tag": "relay", "server": options.Host, "server_port": options.Port, "uuid": appUUID, "tls": tls},
		"proxies":  []any{obj{"name": "jellyfin", "remotePort": remotePort}},
	}
	if err = atomicWrite(filepath.Join(root, "app.json"), app); err != nil {
		return "", err
	}
	return root, nil
}
