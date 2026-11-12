package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/config"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/config/v1/validation"
	"github.com/fatedier/frp/pkg/transport"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	singjson "github.com/sagernet/sing/common/json"
)

type serviceMapping struct {
	ID         string
	RemotePort int
	LocalHost  string
	LocalPort  int
}

// deployment is the validated, secret-resolved view the generators need.
type deployment struct {
	Role        string
	ProxyHost   string
	ProxyPort   int
	ServerName  string
	HomeUUID    string
	AppUUID     string
	ProxyCA     string
	Listen      string
	ProxyCert   string
	ProxyKey    string
	FRPToken    string
	ControlPort int
	LogLevel    string
	Services    []serviceMapping
	FRPCert     string
	FRPKey      string
	SocksPort   int
	FRPServer   string
	FRPCA       string
	Retry       int
}

func (s *Store) materialize(cfg obj, values obj) (*deployment, error) {
	if _, err := s.validate(cfg, values); err != nil {
		return nil, err
	}
	p, f := cfg["proxy"].(obj), cfg["frp"].(obj)
	proxyPort, _ := port(p["port"])
	controlPort, _ := port(f["controlPort"])
	d := &deployment{
		Role: s.role, ProxyHost: p["host"].(string), ProxyPort: proxyPort, ServerName: p["serverName"].(string),
		HomeUUID: values[p["homeCredentialRef"].(string)].(string), FRPToken: values[f["credentialRef"].(string)].(string),
		ControlPort: controlPort, LogLevel: cfg["log"].(obj)["level"].(string),
	}
	for _, value := range cfg["services"].([]any) {
		item := value.(obj)
		remote, _ := port(item["relayPort"])
		mapping := serviceMapping{ID: item["serviceId"].(string), RemotePort: remote}
		if s.role == roleHome {
			mapping.LocalHost = item["targetHost"].(string)
			mapping.LocalPort, _ = port(item["targetPort"])
		}
		d.Services = append(d.Services, mapping)
	}
	var err error
	if s.role == roleRelay {
		d.AppUUID = values[p["appCredentialRef"].(string)].(string)
		d.Listen = p["listen"].(string)
		for _, item := range []struct {
			target *string
			ref    any
		}{{&d.ProxyCert, p["certificateFile"]}, {&d.ProxyKey, p["keyFile"]}, {&d.FRPCert, f["certificateFile"]}, {&d.FRPKey, f["keyFile"]}} {
			if *item.target, err = s.tlsPath(item.ref); err != nil {
				return nil, err
			}
		}
	} else {
		d.ProxyCA = p["caCertificate"].(string)
		d.SocksPort, _ = port(cfg["singBox"].(obj)["socksPort"])
		d.FRPServer = f["serverName"].(string)
		if d.FRPCA, err = s.tlsPath(f["caFile"]); err != nil {
			return nil, err
		}
		retry, _ := intValue(cfg["reconnect"].(obj)["intervalSeconds"])
		d.Retry = int(retry)
	}
	return d, nil
}

// Plan holds derived sing-box and frp configuration that passed the same
// checks as `sing-box check` and `frps/frpc verify`.
type Plan struct {
	Role      string
	Revision  any
	SingBox   []byte
	FRP       []byte
	SocksPort int
	Retry     time.Duration
	LogLevel  string
	// Relay only: where the shared public TLS entry forwards proxy traffic.
	ProxyAddress string
	ServerName   string
	secrets      obj
}

func (s *Store) plan(cfg obj, values obj) (*Plan, error) {
	d, err := s.materialize(cfg, values)
	if err != nil {
		return nil, err
	}
	sing, frp, err := render(d)
	if err != nil {
		return nil, err
	}
	plan := &Plan{Role: s.role, Revision: cfg["revision"], SocksPort: d.SocksPort, Retry: time.Duration(max(d.Retry, 1)) * time.Second, LogLevel: d.LogLevel, secrets: values}
	if s.role == roleRelay {
		plan.ProxyAddress, plan.ServerName = net.JoinHostPort(d.Listen, strconv.Itoa(d.ProxyPort)), d.ServerName
	}
	if plan.SingBox, err = json.Marshal(sing); err != nil {
		return nil, err
	}
	if plan.FRP, err = json.Marshal(frp); err != nil {
		return nil, err
	}
	if err = checkPlan(plan); err != nil {
		return nil, err
	}
	return plan, nil
}

func checkMappings(d *deployment) error {
	if len(d.Services) < 1 || len(d.Services) > 32 {
		return errors.New("configure 1..32 explicitly authorized services")
	}
	names, ports := map[string]bool{}, map[int]bool{}
	for _, item := range d.Services {
		valid := item.ID != ""
		for _, character := range item.ID {
			valid = valid && (isAlnum(character) || character == '-' || character == '_')
		}
		if !valid || names[item.ID] || ports[item.RemotePort] || item.RemotePort < 1 || item.RemotePort > 65535 {
			return errors.New("service ids and mapping ports must be unique")
		}
		names[item.ID], ports[item.RemotePort] = true, true
	}
	if ports[d.ControlPort] {
		return errors.New("control port collides with a media mapping")
	}
	if len(d.FRPToken) < 32 {
		return errors.New("frpToken must have at least 32 characters")
	}
	return nil
}

// render produces the derived sing-box options and frp configuration (frp's
// JSON form of the same fields as the TOML file used previously).
func render(d *deployment) (obj, obj, error) {
	if err := checkMappings(d); err != nil {
		return nil, nil, err
	}
	logLevel := d.LogLevel
	mappingPorts := []any{}
	for _, item := range d.Services {
		mappingPorts = append(mappingPorts, item.RemotePort)
	}
	auth := obj{"method": "token", "token": d.FRPToken, "additionalScopes": []any{"HeartBeats", "NewWorkConns"}}
	frpLog := obj{"to": "console", "level": logLevel}
	if d.Role == roleRelay {
		if !parseUUID(d.AppUUID) || !parseUUID(d.HomeUUID) {
			return nil, nil, errors.New("invalid identity")
		}
		if d.AppUUID == d.HomeUUID {
			return nil, nil, errors.New("home and app identities must be distinct")
		}
		if d.ProxyPort == d.ControlPort || containsAny(mappingPorts, d.ProxyPort) {
			return nil, nil, errors.New("proxy port collides with frp ports")
		}
		// Each deployment is one household. Independent households use separate
		// instances; a shared frp token is not a multi-tenant authorization system.
		rules := []any{
			obj{"auth_user": []any{"home"}, "ip_cidr": []any{"127.0.0.1/32"}, "port": []any{d.ControlPort}, "action": "route", "outbound": "direct"},
			obj{"auth_user": []any{"app"}, "ip_cidr": []any{"127.0.0.1/32"}, "port": mappingPorts, "action": "route", "outbound": "direct"},
			obj{"action": "reject"},
		}
		sing := obj{
			"log": obj{"level": logLevel, "timestamp": true},
			"inbounds": []any{obj{"type": "vless", "tag": "proxy", "listen": d.Listen, "listen_port": d.ProxyPort,
				"users": []any{obj{"name": "app", "uuid": d.AppUUID}, obj{"name": "home", "uuid": d.HomeUUID}},
				"tls":   obj{"enabled": true, "certificate_path": d.ProxyCert, "key_path": d.ProxyKey}}},
			"outbounds": []any{obj{"type": "direct", "tag": "direct"}},
			"route":     obj{"rules": rules},
		}
		allow := []any{}
		for _, number := range mappingPorts {
			allow = append(allow, obj{"single": number})
		}
		frp := obj{"bindAddr": "127.0.0.1", "bindPort": d.ControlPort, "proxyBindAddr": "127.0.0.1", "auth": auth,
			"transport":  obj{"tls": obj{"force": true, "certFile": d.FRPCert, "keyFile": d.FRPKey}},
			"allowPorts": allow, "log": frpLog}
		return sing, frp, nil
	}
	if !parseUUID(d.HomeUUID) {
		return nil, nil, errors.New("invalid identity")
	}
	if d.ServerName == "" || d.ProxyHost == "" {
		return nil, nil, errors.New("proxy host and TLS serverName are required")
	}
	tls := obj{"enabled": true, "server_name": d.ServerName}
	if d.ProxyCA != "" {
		tls["certificate"] = d.ProxyCA
	}
	sing := obj{
		"log":       obj{"level": logLevel, "timestamp": true},
		"inbounds":  []any{obj{"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": d.SocksPort}},
		"outbounds": []any{obj{"type": "vless", "tag": "relay", "server": d.ProxyHost, "server_port": d.ProxyPort, "uuid": d.HomeUUID, "tls": tls}},
		"route":     obj{"final": "relay"},
	}
	proxies := []any{}
	for _, item := range d.Services {
		if item.LocalHost == "" || strings.ContainsAny(item.LocalHost, "/\\\n") {
			return nil, nil, errors.New("invalid localHost")
		}
		proxies = append(proxies, obj{"name": item.ID, "type": "tcp", "localIP": item.LocalHost, "localPort": item.LocalPort,
			"remotePort": item.RemotePort, "healthCheck": obj{"type": "tcp", "intervalSeconds": 10}})
	}
	frp := obj{"serverAddr": "127.0.0.1", "serverPort": d.ControlPort, "loginFailExit": false, "auth": auth,
		"transport": obj{"protocol": "tcp", "proxyURL": fmt.Sprintf("socks5://127.0.0.1:%d", d.SocksPort),
			"tls": obj{"enable": true, "serverName": d.FRPServer, "trustedCaFile": d.FRPCA}},
		"log": frpLog, "proxies": proxies}
	return sing, frp, nil
}

func containsAny(values []any, value int) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func singBoxOptions(data []byte) (context.Context, option.Options, error) {
	ctx := include.Context(context.Background())
	options, err := singjson.UnmarshalExtendedContext[option.Options](ctx, data)
	return ctx, options, err
}

func frpServerConfig(data []byte) (*v1.ServerConfig, error) {
	cfg := &v1.ServerConfig{}
	if err := config.LoadConfigure(data, cfg, true); err != nil {
		return nil, err
	}
	if err := cfg.Complete(); err != nil {
		return nil, err
	}
	if _, err := validation.ValidateServerConfig(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

func frpClientConfig(data []byte) (*v1.ClientCommonConfig, []v1.ProxyConfigurer, error) {
	all := &v1.ClientConfig{}
	if err := config.LoadConfigure(data, all, true); err != nil {
		return nil, nil, err
	}
	common := &all.ClientCommonConfig
	if err := common.Complete(); err != nil {
		return nil, nil, err
	}
	proxies := []v1.ProxyConfigurer{}
	for _, item := range all.Proxies {
		item.ProxyConfigurer.Complete(common.User)
		proxies = append(proxies, item.ProxyConfigurer)
	}
	if _, err := validation.ValidateAllClientConfig(common, proxies, nil); err != nil {
		return nil, nil, err
	}
	return common, proxies, nil
}

// checkPlan runs the embedded equivalents of `sing-box check` and
// `frps verify`/`frpc verify`, plus loading the referenced TLS material.
func checkPlan(plan *Plan) error {
	ctx, options, err := singBoxOptions(plan.SingBox)
	if err != nil {
		return fmt.Errorf("sing-box options: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	options.Log = &option.LogOptions{Disabled: true}
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		return fmt.Errorf("sing-box check: %w", err)
	}
	instance.Close()
	if plan.Role == roleRelay {
		cfg, err := frpServerConfig(plan.FRP)
		if err != nil {
			return fmt.Errorf("frps verify: %w", err)
		}
		if _, err = transport.NewServerTLSConfig(cfg.Transport.TLS.CertFile, cfg.Transport.TLS.KeyFile, cfg.Transport.TLS.TrustedCaFile); err != nil {
			return fmt.Errorf("frps tls: %w", err)
		}
		return nil
	}
	common, _, err := frpClientConfig(plan.FRP)
	if err != nil {
		return fmt.Errorf("frpc verify: %w", err)
	}
	data, err := os.ReadFile(common.Transport.TLS.TrustedCaFile)
	if err != nil || !x509.NewCertPool().AppendCertsFromPEM(data) {
		return errors.New("frpc tls: trusted CA is not a PEM certificate")
	}
	return nil
}

// writeRendered writes the derived files for inspection. They contain
// credentials and are created private.
func writeRendered(plan *Plan, directory string, frpName string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	for name, data := range map[string][]byte{"sing-box.json": plan.SingBox, frpName + ".json": plan.FRP} {
		value, err := decodeJSON(data)
		if err != nil {
			return err
		}
		if err = atomicWrite(filepath.Join(directory, name), value); err != nil {
			return err
		}
	}
	return nil
}

// logRedacted logs upstream errors with every known secret value removed.
func logRedacted(format string, secrets obj, args ...any) {
	message := fmt.Sprintf(format, args...)
	for _, value := range secrets {
		if text, ok := value.(string); ok && len(text) >= 8 {
			message = strings.ReplaceAll(message, text, "[redacted]")
		}
	}
	log.Print(message)
}
