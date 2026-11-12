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

// homeRetry is the delay between Home sing-box start attempts.
const homeRetry = 5 * time.Second

func (s *Store) plan(cfg obj, values obj) (*Plan, error) {
	if _, err := s.validate(cfg, values); err != nil {
		return nil, err
	}
	var sing, frp obj
	var err error
	plan := &Plan{Role: s.role, Revision: cfg["revision"], Retry: homeRetry, LogLevel: stringValue(section(cfg, "log")["level"]), secrets: values}
	if s.role == roleRelay {
		sing, frp, err = s.renderRelay(cfg, values)
		inbound := section(cfg, "singBox", "inbound")
		listenPort, _ := port(inbound["listen_port"])
		plan.ProxyAddress = net.JoinHostPort(stringValue(inbound["listen"]), strconv.Itoa(listenPort))
		plan.ServerName = stringValue(section(inbound, "tls")["server_name"])
	} else {
		sing, frp, err = s.renderHome(cfg, values)
		plan.SocksPort, _ = port(section(cfg, "singBox", "inbound")["listen_port"])
	}
	if err != nil {
		return nil, err
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

func ints(value any) []any {
	result := []any{}
	items, _ := value.([]any)
	for _, item := range items {
		number, _ := intValue(item)
		result = append(result, number)
	}
	return result
}

func frpAuth(values obj, ref any) obj {
	return obj{"method": "token", "token": values[stringValue(ref)], "additionalScopes": []any{"HeartBeats", "NewWorkConns"}}
}

// renderRelay produces the sing-box and frps runtime configuration. Users
// keep their names; route rules only reach loopback, everything else is
// rejected. frps binds loopback only.
func (s *Store) renderRelay(cfg, values obj) (obj, obj, error) {
	inbound := section(cfg, "singBox", "inbound")
	tls := section(inbound, "tls")
	certificate, err := s.tlsPath(tls["certificate_path"])
	if err != nil {
		return nil, nil, err
	}
	key, err := s.tlsPath(tls["key_path"])
	if err != nil {
		return nil, nil, err
	}
	users := []any{}
	for _, item := range inbound["users"].([]any) {
		user := item.(obj)
		users = append(users, obj{"name": user["name"], "uuid": values[stringValue(user["uuid"])]})
	}
	listenPort, _ := port(inbound["listen_port"])
	rules := []any{}
	for _, item := range section(cfg, "singBox", "route")["rules"].([]any) {
		rule := item.(obj)
		rendered := obj{"auth_user": rule["auth_user"], "ip_cidr": []any{"127.0.0.1/32"}, "action": "route", "outbound": "direct"}
		if value, ok := rule["port"]; ok {
			rendered["port"] = ints(value)
		}
		if value, ok := rule["port_range"]; ok {
			rendered["port_range"] = value
		}
		rules = append(rules, rendered)
	}
	rules = append(rules, obj{"action": "reject"})
	logLevel := stringValue(section(cfg, "log")["level"])
	sing := obj{
		"log": obj{"level": logLevel, "timestamp": true},
		"inbounds": []any{obj{"type": "vless", "tag": "proxy", "listen": inbound["listen"], "listen_port": listenPort, "users": users,
			"tls": obj{"enabled": true, "server_name": tls["server_name"], "certificate_path": certificate, "key_path": key}}},
		"outbounds": []any{obj{"type": "direct", "tag": "direct"}},
		"route":     obj{"rules": rules},
	}
	frps := cfg["frps"].(obj)
	certFile, err := s.tlsPath(section(frps, "transport", "tls")["certFile"])
	if err != nil {
		return nil, nil, err
	}
	keyFile, err := s.tlsPath(section(frps, "transport", "tls")["keyFile"])
	if err != nil {
		return nil, nil, err
	}
	allow := []any{}
	ranges, _ := allowPorts(frps["allowPorts"])
	for _, item := range ranges {
		if item.start == item.end {
			allow = append(allow, obj{"single": item.start})
		} else {
			allow = append(allow, obj{"start": item.start, "end": item.end})
		}
	}
	bindPort, _ := port(frps["bindPort"])
	frp := obj{"bindAddr": "127.0.0.1", "bindPort": bindPort, "proxyBindAddr": "127.0.0.1", "auth": frpAuth(values, section(frps, "auth")["token"]),
		"transport":  obj{"tls": obj{"force": true, "certFile": certFile, "keyFile": keyFile}},
		"allowPorts": allow, "log": obj{"to": "console", "level": logLevel}}
	return sing, frp, nil
}

// renderHome produces the sing-box (SOCKS -> VLESS) and frpc configuration.
// frpc only reaches frps through the SOCKS inbound; there is no direct mode.
func (s *Store) renderHome(cfg, values obj) (obj, obj, error) {
	inbound := section(cfg, "singBox", "inbound")
	outbound := section(cfg, "singBox", "outbound")
	socksPort, _ := port(inbound["listen_port"])
	serverPort, _ := port(outbound["server_port"])
	tls := obj{"enabled": true, "server_name": section(outbound, "tls")["server_name"]}
	if ca := stringValue(section(outbound, "tls")["certificate"]); ca != "" {
		tls["certificate"] = ca
	}
	logLevel := stringValue(section(cfg, "log")["level"])
	sing := obj{
		"log":      obj{"level": logLevel, "timestamp": true},
		"inbounds": []any{obj{"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{obj{"type": "vless", "tag": "relay", "server": outbound["server"], "server_port": serverPort,
			"uuid": values[stringValue(outbound["uuid"])], "tls": tls}},
		"route": obj{"final": "relay"},
	}
	frpc := cfg["frpc"].(obj)
	frpTLS := section(frpc, "transport", "tls")
	trusted, err := s.tlsPath(frpTLS["trustedCaFile"])
	if err != nil {
		return nil, nil, err
	}
	proxies := []any{}
	for _, item := range frpc["proxies"].([]any) {
		proxy := item.(obj)
		localIP := stringValue(proxy["localIP"])
		if localIP == "" || strings.ContainsAny(localIP, "/\\\n") {
			return nil, nil, errors.New("invalid localIP")
		}
		localPort, _ := port(proxy["localPort"])
		remotePort, _ := port(proxy["remotePort"])
		proxies = append(proxies, obj{"name": proxy["name"], "type": "tcp", "localIP": localIP, "localPort": localPort,
			"remotePort": remotePort, "healthCheck": obj{"type": "tcp", "intervalSeconds": 10}})
	}
	serverPortFRP, _ := port(frpc["serverPort"])
	frp := obj{"serverAddr": "127.0.0.1", "serverPort": serverPortFRP, "loginFailExit": false, "auth": frpAuth(values, section(frpc, "auth")["token"]),
		"transport": obj{"protocol": "tcp", "proxyURL": fmt.Sprintf("socks5://127.0.0.1:%d", socksPort),
			"tls": obj{"enable": true, "serverName": frpTLS["serverName"], "trustedCaFile": trusted}},
		"log": obj{"to": "console", "level": logLevel}, "proxies": proxies}
	if user := stringValue(frpc["user"]); user != "" {
		frp["user"] = user
	}
	return sing, frp, nil
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
