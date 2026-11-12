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
	fmt.Println("Created canonical relay/ and home/ configuration directories and App pairing in", root)
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
// App pairing file. It refuses an existing output directory so credentials
// are never rotated implicitly.
func pair(options pairOptions) (string, error) {
	if err := os.Mkdir(options.Output, 0o700); err != nil {
		return "", err
	}
	root, err := filepath.Abs(options.Output)
	if err != nil {
		return "", err
	}
	certificatePath, err := filepath.Abs(options.Certificate)
	if err != nil {
		return "", err
	}
	keyPath, err := filepath.Abs(options.Key)
	if err != nil {
		return "", err
	}
	frpsCert, frpsKey, err := selfSignedFRPS()
	if err != nil {
		return "", err
	}
	transient := map[string][]byte{"frps.crt": frpsCert, "frps.key": frpsKey}
	for name, data := range transient {
		if err = writeSynced(filepath.Join(root, name), data); err != nil {
			return "", err
		}
	}
	defer func() {
		for name := range transient {
			_ = os.Remove(filepath.Join(root, name))
		}
	}()
	caCertificate := ""
	if options.ProxyCA != "" {
		data, err := os.ReadFile(options.ProxyCA)
		if err != nil {
			return "", err
		}
		caCertificate = string(data)
	}
	appUUID, homeUUID := newUUID(), newUUID()
	token := tokenURLSafe(48)
	homeID, lineID := "home-"+newUUID(), "line-"+newUUID()
	proxy := obj{"host": options.Host, "port": options.Port, "serverName": options.TLSName, "appUUID": appUUID, "homeUUID": homeUUID,
		"certificatePath": certificatePath, "keyPath": keyPath}
	if caCertificate != "" {
		proxy["caCertificate"] = caCertificate
	}
	service := obj{"id": "jellyfin", "remotePort": 18096}
	relayLegacy := obj{"homeId": homeID, "proxy": proxy, "frpToken": token, "controlPort": 7000, "services": []any{service},
		"frpCertificatePath": filepath.Join(root, "frps.crt"), "frpKeyPath": filepath.Join(root, "frps.key")}
	homeProxy := obj{}
	for key, value := range proxy {
		if key != "appUUID" && key != "certificatePath" && key != "keyPath" {
			homeProxy[key] = value
		}
	}
	homeLegacy := obj{"homeId": homeID, "proxy": homeProxy, "frpToken": token, "controlPort": 7000, "socksPort": 1080,
		"frpServerName": "openplayx-frps", "frpCAPath": filepath.Join(root, "frps.crt"),
		"services": []any{obj{"id": "jellyfin", "remotePort": 18096, "localHost": "192.168.50.10", "localPort": 8096}}}
	tls := obj{"enabled": true, "server_name": options.TLSName}
	if caCertificate != "" {
		tls["certificate"] = caCertificate
	}
	app := obj{"version": 1, "lineId": lineID, "homeId": homeID, "serviceId": "jellyfin", "remotePort": 18096,
		"remoteAddress": "http://jellyfin.home.invalid:8096",
		"outbound":      obj{"type": "vless", "server": options.Host, "server_port": options.Port, "uuid": appUUID, "tls": tls}}
	if err = atomicWrite(filepath.Join(root, "app-jellyfin.json"), app); err != nil {
		return "", err
	}
	// Each side receives its own directory; Home never receives the App
	// identity or Relay private keys.
	for side, legacy := range map[string]obj{roleRelay: relayLegacy, roleHome: homeLegacy} {
		store, err := NewStore(filepath.Join(root, side), side)
		if err != nil {
			return "", err
		}
		if _, err = store.importLegacy(legacy, homeID); err != nil {
			return "", err
		}
	}
	return root, nil
}
