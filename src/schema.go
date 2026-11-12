package main

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The authoritative relay.json / home.json reuse sing-box and frp field
// names. They are a curated subset: fixed values (protocol types, loopback
// binds, TLS enforcement) are validated, not freely editable, and every
// credential is a "secret:..." reference into secrets.json.
//
// Relay (schemaVersion 2):
//
//	singBox.inbound      sing-box VLESS inbound: listen, listen_port, users[{name, uuid}], tls
//	singBox.route.rules  sing-box route rules: auth_user + port / port_range (loopback only, rest rejected)
//	frps                 frp server: bindPort, auth.token, transport.tls, allowPorts
//
// Home (schemaVersion 2):
//
//	singBox.inbound      sing-box SOCKS inbound used only by frpc (loopback)
//	singBox.outbound     sing-box VLESS outbound to the Relay
//	frpc                 frp client: user, serverAddr, serverPort, auth.token, transport.tls, proxies
const schemaVersion = 2

var managementFields = []string{"listen", "port", "https", "allowedHosts", "certificateFile", "keyFile", "frontend"}
var managementRequired = []string{"listen", "port", "https", "allowedHosts"}

func (s *Store) blank() obj {
	management := obj{"listen": "0.0.0.0", "port": 9080, "https": false, "allowedHosts": []any{"localhost", "127.0.0.1"}}
	cfg := obj{"schemaVersion": schemaVersion, "revision": 0, "log": obj{"level": "warn"}}
	if s.role == roleRelay {
		management["listen"], management["port"] = "127.0.0.1", 9081
		cfg["singBox"] = obj{
			"inbound": obj{"type": "vless", "tag": "proxy", "listen": "0.0.0.0", "listen_port": 443,
				"users": []any{obj{"name": "home", "uuid": ""}, obj{"name": "app", "uuid": ""}},
				"tls":   obj{"enabled": true, "server_name": "relay.example.com", "certificate_path": "", "key_path": ""}},
			"route": obj{"rules": []any{
				obj{"auth_user": []any{"home"}, "port": []any{7000}},
				obj{"auth_user": []any{"app"}, "port_range": []any{"18000:18999"}},
			}},
		}
		cfg["frps"] = obj{"bindPort": 7000, "auth": obj{"token": ""},
			"transport":  obj{"tls": obj{"certFile": "", "keyFile": ""}},
			"allowPorts": []any{obj{"start": 18000, "end": 18999}}}
	} else {
		cfg["singBox"] = obj{
			"inbound": obj{"type": "socks", "tag": "socks", "listen": "127.0.0.1", "listen_port": 1080},
			"outbound": obj{"type": "vless", "tag": "relay", "server": "relay.example.com", "server_port": 443, "uuid": "",
				"tls": obj{"enabled": true, "server_name": "relay.example.com", "certificate": ""}},
		}
		cfg["frpc"] = obj{"user": "home", "serverAddr": "127.0.0.1", "serverPort": 7000, "auth": obj{"token": ""},
			"transport": obj{"tls": obj{"serverName": "openplayx-frps", "trustedCaFile": ""}},
			"proxies":   []any{}}
	}
	cfg["management"] = management
	return cloneObj(cfg)
}

// checkShape requires exactly the object keys of the template, recursively
// for nested objects. Lists and the management section are checked by their
// own validators.
func checkShape(value any, template obj) error {
	keys := keysOf(template)
	if err := checkKeys(value, keys, keys); err != nil {
		return err
	}
	fields := value.(obj)
	for key, sub := range template {
		if nested, ok := sub.(obj); ok && key != "management" {
			if err := checkShape(fields[key], nested); err != nil {
				return err
			}
		}
	}
	return nil
}

// secretRefs returns every "secret:..." reference in a configuration.
func secretRefs(value any, into map[string]bool) {
	switch typed := value.(type) {
	case obj:
		for _, item := range typed {
			secretRefs(item, into)
		}
	case []any:
		for _, item := range typed {
			secretRefs(item, into)
		}
	case string:
		if strings.HasPrefix(typed, "secret:") {
			into[typed] = true
		}
	}
}

// plainSecret reports a credential field ("uuid", "token") holding anything
// other than an empty value or a secret reference.
func plainSecret(value any) bool {
	switch typed := value.(type) {
	case obj:
		for key, item := range typed {
			if key == "uuid" || key == "token" {
				text, ok := item.(string)
				if !ok || (text != "" && !strings.HasPrefix(text, "secret:")) {
					return true
				}
			} else if plainSecret(item) {
				return true
			}
		}
	case []any:
		for _, item := range typed {
			if plainSecret(item) {
				return true
			}
		}
	}
	return false
}

func (s *Store) load() (obj, error) {
	if !exists(s.path) {
		return s.blank(), nil
	}
	value, err := readJSON(s.path)
	if err != nil {
		return nil, err
	}
	cfg, ok := value.(obj)
	if version, isInt := intValue(cfg["schemaVersion"]); !ok || !isInt || version != schemaVersion {
		return nil, cfgErr("unknownSchema", "配置版本不支持，禁止覆盖原文件。", 409)
	}
	if err = checkShape(cfg, s.blank()); err != nil {
		return nil, err
	}
	if err = checkKeys(cfg["management"], managementFields, managementRequired); err != nil {
		return nil, err
	}
	if plainSecret(cfg) {
		return nil, cfgErr("plainSecretDenied", "普通配置只能保存机密引用，原文件已保留。", 409)
	}
	if s.role == roleHome {
		if ca, _ := cfg["singBox"].(obj)["outbound"].(obj)["tls"].(obj)["certificate"].(string); strings.Contains(ca, "PRIVATE KEY") {
			return nil, cfgErr("plainSecretDenied", "CA 字段不能包含私钥，原文件已保留。", 409)
		}
	}
	return cfg, nil
}

// section returns a nested object by path in a shape-checked configuration.
func section(cfg obj, path ...string) obj {
	current := cfg
	for _, key := range path {
		current, _ = current[key].(obj)
	}
	return current
}

func list(value any, minimum, maximum int, message string) ([]any, error) {
	items, ok := value.([]any)
	if !ok || len(items) < minimum || len(items) > maximum {
		return nil, cfgErr("invalidFields", message)
	}
	return items, nil
}

func secretUUID(values obj, ref any) (string, error) {
	text, _ := ref.(string)
	value, present := values[text]
	if !strings.HasPrefix(text, "secret:") || !present {
		return "", cfgErr("missingSecret", "请设置必需的连接凭据。")
	}
	if !parseUUID(value) {
		return "", cfgErr("invalidSecret", "UUID 格式无效。")
	}
	return value.(string), nil
}

func secretToken(values obj, ref any) (string, error) {
	text, _ := ref.(string)
	value, present := values[text]
	if !strings.HasPrefix(text, "secret:") || !present {
		return "", cfgErr("missingSecret", "请设置必需的连接凭据。")
	}
	token, ok := value.(string)
	if length := utf8.RuneCountInString(token); !ok || length < 32 || length > 4096 {
		return "", cfgErr("invalidSecret", "frp auth.token 须为 32–4096 字符。")
	}
	return token, nil
}

// portSet is a set of frp allowPorts / sing-box port ranges.
type portRange struct{ start, end int }

func (r portRange) contains(number int) bool { return number >= r.start && number <= r.end }

func (r portRange) within(ranges []portRange) bool {
	for _, outer := range ranges {
		if r.start >= outer.start && r.end <= outer.end {
			return true
		}
	}
	return false
}

func anyContains(ranges []portRange, number int) bool {
	for _, item := range ranges {
		if item.contains(number) {
			return true
		}
	}
	return false
}

// allowPorts parses frp's [{"single": n}] / [{"start": a, "end": b}] form.
func allowPorts(value any) ([]portRange, error) {
	items, err := list(value, 1, 32, "frps.allowPorts 须为 1–32 项。")
	if err != nil {
		return nil, err
	}
	result := []portRange{}
	for _, item := range items {
		entry, ok := item.(obj)
		if !ok {
			return nil, cfgErr("invalidFields", "frps.allowPorts 项无效。")
		}
		if _, single := entry["single"]; single {
			if err = checkKeys(entry, []string{"single"}, []string{"single"}); err != nil {
				return nil, err
			}
			number, err := port(entry["single"])
			if err != nil {
				return nil, err
			}
			result = append(result, portRange{number, number})
			continue
		}
		if err = checkKeys(entry, []string{"start", "end"}, []string{"start", "end"}); err != nil {
			return nil, err
		}
		start, err := port(entry["start"])
		if err != nil {
			return nil, err
		}
		end, err := port(entry["end"])
		if err != nil {
			return nil, err
		}
		if start > end {
			return nil, cfgErr("invalidPort", "frps.allowPorts 的 start 不能大于 end。")
		}
		result = append(result, portRange{start, end})
	}
	return result, nil
}

// ruleRanges parses a sing-box rule's port / port_range ("a:b") lists.
func ruleRanges(rule obj) ([]portRange, error) {
	result := []portRange{}
	if value, ok := rule["port"]; ok {
		items, err := list(value, 1, 64, "route rule 的 port 无效。")
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			number, err := port(item)
			if err != nil {
				return nil, err
			}
			result = append(result, portRange{number, number})
		}
	}
	if value, ok := rule["port_range"]; ok {
		items, err := list(value, 1, 64, "route rule 的 port_range 无效。")
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			text, _ := item.(string)
			parts := strings.Split(text, ":")
			if len(parts) != 2 {
				return nil, cfgErr("invalidPort", "port_range 格式为 \"起始:结束\"。")
			}
			start, errStart := strconv.Atoi(parts[0])
			end, errEnd := strconv.Atoi(parts[1])
			if errStart != nil || errEnd != nil || start < 1 || end > 65535 || start > end {
				return nil, cfgErr("invalidPort", "port_range 格式为 \"起始:结束\"。")
			}
			result = append(result, portRange{start, end})
		}
	}
	if len(result) == 0 {
		return nil, cfgErr("invalidFields", "route rule 须包含 port 或 port_range。")
	}
	return result, nil
}

func (s *Store) validate(value any, values obj) (obj, error) {
	template := s.blank()
	if err := checkShape(value, template); err != nil {
		return nil, err
	}
	cfg := value.(obj)
	version, okVersion := intValue(cfg["schemaVersion"])
	revision, okRevision := intValue(cfg["revision"])
	if !okVersion || version != schemaVersion || !okRevision || revision < 0 {
		return nil, cfgErr("unknownSchema", "不支持的 schemaVersion 或 revision。")
	}
	if err := checkKeys(cfg["log"], []string{"level"}, []string{"level"}); err != nil {
		return nil, err
	}
	switch cfg["log"].(obj)["level"] {
	case "warn", "error", "info":
	default:
		return nil, cfgErr("invalidLog", "日志级别无效。")
	}
	if err := s.validateManagement(cfg["management"]); err != nil {
		return nil, err
	}
	if s.role == roleRelay {
		return cfg, s.validateRelay(cfg, values)
	}
	return cfg, s.validateHome(cfg, values)
}

func (s *Store) validateRelay(cfg obj, values obj) error {
	inbound := section(cfg, "singBox", "inbound")
	if inbound["type"] != "vless" || inbound["tag"] != "proxy" {
		return cfgErr("invalidProtocol", "Relay 入站固定为 sing-box VLESS（tag proxy）。")
	}
	listen, err := netip.ParseAddr(stringValue(inbound["listen"]))
	if err != nil {
		return cfgErr("invalidListen", "inbound.listen 须为明确的 IP。")
	}
	proxyPort, err := port(inbound["listen_port"])
	if err != nil {
		return err
	}
	tls := inbound["tls"].(obj)
	if tls["enabled"] != true {
		return cfgErr("invalidTLS", "inbound.tls.enabled 必须为 true。")
	}
	if _, err = host(tls["server_name"]); err != nil {
		return err
	}
	for _, key := range []string{"certificate_path", "key_path"} {
		if _, err = s.tlsPath(tls[key]); err != nil {
			return err
		}
	}
	users, err := list(inbound["users"], 1, 32, "inbound.users 须为 1–32 个。")
	if err != nil {
		return err
	}
	names, identities := map[string]bool{}, map[string]bool{}
	for _, item := range users {
		if err = checkKeys(item, []string{"name", "uuid"}, []string{"name", "uuid"}); err != nil {
			return err
		}
		name, err := identifier(item.(obj)["name"])
		if err != nil {
			return err
		}
		uuid, err := secretUUID(values, item.(obj)["uuid"])
		if err != nil {
			return err
		}
		if names[name] {
			return cfgErr("duplicateUser", "inbound.users 的 name 重复。")
		}
		if identities[strings.ToLower(uuid)] {
			return cfgErr("sharedIdentity", "每个 user 必须使用不同的 UUID。")
		}
		names[name], identities[strings.ToLower(uuid)] = true, true
	}

	frps := cfg["frps"].(obj)
	bindPort, err := port(frps["bindPort"])
	if err != nil {
		return err
	}
	if _, err = secretToken(values, section(frps, "auth")["token"]); err != nil {
		return err
	}
	for _, key := range []string{"certFile", "keyFile"} {
		if _, err = s.tlsPath(section(frps, "transport", "tls")[key]); err != nil {
			return err
		}
	}
	allowed, err := allowPorts(frps["allowPorts"])
	if err != nil {
		return err
	}

	m := cfg["management"].(obj)
	managementPort, _ := port(m["port"])
	if proxyPort == bindPort || managementPort == bindPort {
		return cfgErr("portConflict", "inbound、frps.bindPort 与管理监听端口冲突。")
	}
	// A TLS SNI frontend may route one public port to two distinct loopback
	// addresses. Wildcard, identical and mixed-family listeners are rejected.
	if proxyPort == managementPort {
		managerIP, errManager := netip.ParseAddr(stringValue(m["listen"]))
		shared := errManager == nil && listen.IsLoopback() && managerIP.IsLoopback() && listen.Is4() == managerIP.Is4() && listen != managerIP
		if !shared {
			return cfgErr("portConflict", "inbound 与管理监听端口冲突。")
		}
	}
	for _, number := range []int{proxyPort, bindPort, managementPort} {
		if anyContains(allowed, number) {
			return cfgErr("portConflict", "frps.allowPorts 不能包含 inbound、bindPort 或管理端口。")
		}
	}
	frontendIP, frontendPort, hasFrontend := frontendEndpoint(m)
	if hasFrontend {
		// listen_port is the port in Home outbounds and App outbounds, so the
		// shared public entry must use it.
		if frontendPort != proxyPort {
			return cfgErr("invalidFrontend", "公网入口端口须与 inbound.listen_port 一致。")
		}
		if !listen.Unmap().IsLoopback() {
			return cfgErr("invalidFrontend", "启用公网入口时，inbound.listen 须为回环地址。")
		}
		if endpointConflict(frontendIP, frontendPort, listen.String(), proxyPort) ||
			endpointConflict(frontendIP, frontendPort, stringValue(m["listen"]), managementPort) ||
			endpointConflict(frontendIP, frontendPort, "127.0.0.1", bindPort) ||
			(frontendIP.Unmap().IsLoopback() && anyContains(allowed, frontendPort)) {
			return cfgErr("portConflict", "公网入口与 inbound、管理、frps 监听冲突。")
		}
	}

	rules, err := list(section(cfg, "singBox", "route")["rules"], 1, 64, "route.rules 须为 1–64 条。")
	if err != nil {
		return err
	}
	permitted := append([]portRange{{bindPort, bindPort}}, allowed...)
	for _, item := range rules {
		if err = checkKeys(item, []string{"auth_user", "port", "port_range"}, []string{"auth_user"}); err != nil {
			return err
		}
		rule := item.(obj)
		who, err := list(rule["auth_user"], 1, 32, "route rule 的 auth_user 无效。")
		if err != nil {
			return err
		}
		for _, name := range who {
			if text, ok := name.(string); !ok || !names[text] {
				return cfgErr("unknownUser", "route rule 引用了不存在的 user。")
			}
		}
		ranges, err := ruleRanges(rule)
		if err != nil {
			return err
		}
		for _, item := range ranges {
			if !item.within(permitted) {
				return cfgErr("unauthorizedPort", "route rule 只能放行 frps.bindPort 或 frps.allowPorts 内的端口。")
			}
		}
	}
	return nil
}

func (s *Store) validateHome(cfg obj, values obj) error {
	inbound := section(cfg, "singBox", "inbound")
	if inbound["type"] != "socks" || inbound["tag"] != "socks" || inbound["listen"] != "127.0.0.1" {
		return cfgErr("mandatoryProxy", "Home 入站固定为仅监听 127.0.0.1 的 sing-box SOCKS（tag socks）。")
	}
	socksPort, err := port(inbound["listen_port"])
	if err != nil {
		return err
	}
	outbound := section(cfg, "singBox", "outbound")
	if outbound["type"] != "vless" || outbound["tag"] != "relay" {
		return cfgErr("invalidProtocol", "Home 出站固定为 sing-box VLESS（tag relay）。")
	}
	if _, err = host(outbound["server"]); err != nil {
		return err
	}
	if _, err = port(outbound["server_port"]); err != nil {
		return err
	}
	if _, err = secretUUID(values, outbound["uuid"]); err != nil {
		return err
	}
	tls := outbound["tls"].(obj)
	if tls["enabled"] != true {
		return cfgErr("invalidTLS", "outbound.tls.enabled 必须为 true。")
	}
	if _, err = host(tls["server_name"]); err != nil {
		return err
	}
	if ca, ok := tls["certificate"].(string); !ok || utf8.RuneCountInString(ca) > 32768 || strings.Contains(ca, "PRIVATE KEY") ||
		(ca != "" && !validCertificates([]byte(ca))) {
		return cfgErr("invalidCA", "outbound.tls.certificate 须为空或 PEM 证书。")
	}

	frpc := cfg["frpc"].(obj)
	if user, _ := frpc["user"].(string); user != "" {
		if _, err = identifier(user); err != nil {
			return err
		}
	} else if _, ok := frpc["user"].(string); !ok {
		return cfgErr("invalidFields", "frpc.user 须为字符串。")
	}
	// frpc reaches frps through the SOCKS inbound; Relay route rules only
	// allow loopback destinations there.
	if frpc["serverAddr"] != "127.0.0.1" {
		return cfgErr("mandatoryProxy", "frpc.serverAddr 固定为 127.0.0.1（经 sing-box 到达 Relay 回环上的 frps）。")
	}
	serverPort, err := port(frpc["serverPort"])
	if err != nil {
		return err
	}
	if _, err = secretToken(values, section(frpc, "auth")["token"]); err != nil {
		return err
	}
	frpTLS := section(frpc, "transport", "tls")
	if _, err = host(frpTLS["serverName"]); err != nil {
		return err
	}
	if _, err = s.tlsPath(frpTLS["trustedCaFile"]); err != nil {
		return err
	}
	managementPort, _ := port(cfg["management"].(obj)["port"])
	if socksPort == managementPort {
		return cfgErr("portConflict", "SOCKS 与管理监听端口冲突。")
	}
	proxies, err := list(frpc["proxies"], 1, 32, "请配置 1–32 个 frpc proxies。")
	if err != nil {
		return err
	}
	fields := []string{"name", "type", "localIP", "localPort", "remotePort"}
	names, remotes := map[string]bool{}, map[int]bool{}
	for _, item := range proxies {
		if err = checkKeys(item, fields, fields); err != nil {
			return err
		}
		proxy := item.(obj)
		name, err := identifier(proxy["name"])
		if err != nil {
			return err
		}
		if proxy["type"] != "tcp" {
			return cfgErr("invalidProxyType", "当前只支持 tcp 类型的 proxy。")
		}
		remote, err := port(proxy["remotePort"])
		if err != nil {
			return err
		}
		target, err := host(proxy["localIP"])
		if err != nil {
			return err
		}
		local, err := port(proxy["localPort"])
		if err != nil {
			return err
		}
		if names[name] || remotes[remote] || remote == serverPort {
			return cfgErr("portConflict", "proxy name 或 remotePort 重复，或与 frpc.serverPort 冲突。")
		}
		names[name], remotes[remote] = true, true
		if (target == "127.0.0.1" || target == "localhost" || target == "::1") && (local == socksPort || local == managementPort) {
			return cfgErr("targetConflict", "proxy 不能指向本机管理或 SOCKS 端口。")
		}
	}
	return nil
}

// secretTargets maps the secret update keys a role accepts to the config
// field holding the reference. Relay users are addressed as "uuid:<name>".
func secretTargets(role string, cfg obj) map[string]obj {
	targets := map[string]obj{}
	if role == roleRelay {
		if frps, ok := cfg["frps"].(obj); ok {
			targets["token"] = section(frps, "auth")
		}
		users, _ := section(cfg, "singBox", "inbound")["users"].([]any)
		for _, item := range users {
			if user, ok := item.(obj); ok {
				targets["uuid:"+stringValue(user["name"])] = user
			}
		}
		return targets
	}
	if frpc, ok := cfg["frpc"].(obj); ok {
		targets["token"] = section(frpc, "auth")
	}
	if outbound := section(cfg, "singBox", "outbound"); outbound != nil {
		targets["uuid"] = outbound
	}
	return targets
}

func (s *Store) prepare(value, updatesValue any) (obj, obj, error) {
	cfg, ok := clone(value).(obj)
	if !ok || checkShape(cfg, s.blank()) != nil {
		return nil, nil, cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
	}
	values, err := s.secrets()
	if err != nil {
		return nil, nil, err
	}
	if updatesValue == nil {
		updatesValue = obj{}
	}
	updates, ok := updatesValue.(obj)
	if !ok {
		return nil, nil, cfgErr("invalidSecret", "机密更新格式无效。")
	}
	targets := secretTargets(s.role, cfg)
	keys := make([]string, 0, len(updates))
	for key := range updates {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, field := range keys {
		update := updates[field]
		owner, ok := targets[field]
		if !ok {
			return nil, nil, cfgErr("invalidSecret", fmt.Sprintf("此端不支持机密字段 %s。", field))
		}
		key := "token"
		if strings.HasPrefix(field, "uuid") {
			key = "uuid"
		}
		if update == nil {
			continue // untouched
		}
		if text, isString := update.(string); isString && text == "" {
			owner[key] = "" // explicit clear; required references fail validation
			continue
		}
		ref := "secret:" + tokenHex(16)
		values[ref] = update
		owner[key] = ref
	}
	if _, err = s.validate(cfg, values); err != nil {
		return nil, nil, err
	}
	return cfg, values, nil
}

// collectSecrets drops secret values no longer referenced by the current,
// backup, last applied or previously applied configuration. Any unreadable
// file aborts collection rather than risking a referenced key.
func (s *Store) collectSecrets() {
	references := map[string]bool{}
	for _, name := range []string{s.role + ".json", s.role + ".backup.json", "last-good.json", "previous-good.json"} {
		if !exists(s.file(name)) {
			continue
		}
		cfg, err := readObj(s.file(name))
		if err != nil {
			return
		}
		secretRefs(cfg, references)
	}
	values, err := s.secrets()
	if err != nil {
		return
	}
	kept := obj{}
	for key, value := range values {
		if references[key] {
			kept[key] = value
		}
	}
	_ = atomicWrite(s.file("secrets.json"), kept)
}
