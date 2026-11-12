package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	roleRelay = "relay"
	roleHome  = "home"
)

// Controller switches the running sing-box/frp components. The in-process
// runtime implements it for the service; the CLI drives the systemd unit.
type Controller interface {
	Restart(cfg obj, plan *Plan) error
	Stop() error
	Components() map[string]string
}

// Store owns the authoritative logical JSON configuration of one role. It
// never accepts browser-supplied file paths.
type Store struct {
	dir        string
	role       string
	path       string
	controller Controller
	// applyMu serialises apply and the boot start inside one process; the
	// file lock (which a CLI apply holds while the service boots) does not.
	applyMu sync.Mutex
}

func NewStore(directory, role string) (*Store, error) {
	if role != roleRelay && role != roleHome {
		return nil, fmt.Errorf("unknown role %q", role)
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	if err = os.MkdirAll(absolute, 0o700); err != nil {
		return nil, err
	}
	if resolved, err := filepath.EvalSymlinks(absolute); err == nil {
		absolute = resolved
	}
	return &Store{dir: absolute, role: role, path: filepath.Join(absolute, role+".json")}, nil
}

func (s *Store) file(name string) string { return filepath.Join(s.dir, name) }

func (s *Store) frpName() string {
	if s.role == roleRelay {
		return "frps"
	}
	return "frpc"
}

// lock serialises writers across the service and CLI processes.
func (s *Store) lock() (func(), error) {
	file, err := os.OpenFile(s.file(".lock"), os.O_CREATE|os.O_RDWR|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	_ = file.Chmod(0o600)
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		file.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}, nil
}

func (s *Store) blank() obj {
	management := obj{"listen": "0.0.0.0", "port": 9080, "https": false, "allowedHosts": []any{"localhost", "127.0.0.1"}}
	if s.role == roleRelay {
		management["listen"], management["port"] = "127.0.0.1", 9081
	}
	cfg := obj{
		"schemaVersion": 1, "revision": 0, "homeId": "home-main",
		"proxy":      obj{"host": "relay.example.com", "port": 443, "serverName": "relay.example.com", "protocol": "vless-tls", "homeCredentialRef": ""},
		"frp":        obj{"controlPort": 7000, "credentialRef": "", "serverName": "openplayx-frps"},
		"services":   []any{},
		"log":        obj{"level": "warn"},
		"management": management,
	}
	proxy, frp := cfg["proxy"].(obj), cfg["frp"].(obj)
	if s.role == roleRelay {
		proxy["appCredentialRef"], proxy["listen"], proxy["certificateFile"], proxy["keyFile"] = "", "0.0.0.0", "", ""
		frp["certificateFile"], frp["keyFile"] = "", ""
	} else {
		proxy["caCertificate"] = ""
		cfg["singBox"] = obj{"socksListen": "127.0.0.1", "socksPort": 1080}
		frp["caFile"] = ""
		cfg["reconnect"] = obj{"intervalSeconds": 5}
	}
	return cloneObj(cfg)
}

func (s *Store) serviceFields() []string {
	if s.role == roleHome {
		return []string{"serviceId", "relayPort", "targetHost", "targetPort"}
	}
	return []string{"serviceId", "relayPort"}
}

var managementFields = []string{"listen", "port", "https", "allowedHosts", "certificateFile", "keyFile", "frontend"}
var managementRequired = []string{"listen", "port", "https", "allowedHosts"}

func (s *Store) load() (obj, error) {
	if !exists(s.path) {
		return s.blank(), nil
	}
	value, err := readJSON(s.path)
	if err != nil {
		return nil, err
	}
	cfg, ok := value.(obj)
	if version, isInt := intValue(cfg["schemaVersion"]); !ok || !isInt || version != 1 {
		return nil, cfgErr("unknownSchema", "配置版本不支持，禁止覆盖原文件。", 409)
	}
	template := s.blank()
	if err = checkKeys(cfg, keysOf(template), keysOf(template)); err != nil {
		return nil, err
	}
	sections := []string{"proxy", "frp", "log"}
	if s.role == roleHome {
		sections = append(sections, "singBox", "reconnect")
	}
	for _, section := range sections {
		fields := keysOf(template[section].(obj))
		if err = checkKeys(cfg[section], fields, fields); err != nil {
			return nil, err
		}
	}
	if err = checkKeys(cfg["management"], managementFields, managementRequired); err != nil {
		return nil, err
	}
	services, ok := cfg["services"].([]any)
	if !ok {
		return nil, cfgErr("invalidFields", "服务配置无效，原文件已保留。", 409)
	}
	for _, service := range services {
		if err = checkKeys(service, s.serviceFields(), s.serviceFields()); err != nil {
			return nil, err
		}
	}
	for _, owner := range []obj{cfg["proxy"].(obj), cfg["frp"].(obj)} {
		for key, ref := range owner {
			if strings.HasSuffix(key, "CredentialRef") || key == "credentialRef" {
				value, isString := ref.(string)
				if !isString || (value != "" && !strings.HasPrefix(value, "secret:")) {
					return nil, cfgErr("plainSecretDenied", "普通配置只能保存机密引用，原文件已保留。", 409)
				}
			}
		}
	}
	if ca, _ := cfg["proxy"].(obj)["caCertificate"].(string); strings.Contains(ca, "PRIVATE KEY") {
		return nil, cfgErr("plainSecretDenied", "CA 字段不能包含私钥，原文件已保留。", 409)
	}
	return cfg, nil
}

func (s *Store) secrets() (obj, error) {
	if !exists(s.file("secrets.json")) {
		return obj{}, nil
	}
	return readObj(s.file("secrets.json"))
}

// tlsPath resolves a reference to an already imported TLS asset. There is no
// relative traversal, arbitrary host path, symlink or download endpoint.
func (s *Store) tlsPath(value any) (string, error) {
	name, ok := value.(string)
	parts := []string{}
	for _, part := range strings.Split(name, "/") {
		if part != "" && part != "." {
			parts = append(parts, part)
		}
	}
	if !ok || !strings.HasPrefix(name, "tls/") || len(parts) != 2 || parts[0] != "tls" {
		return "", cfgErr("invalidCertificate", "请选择已经导入的 TLS 文件。")
	}
	directory := s.file("tls")
	path := filepath.Join(directory, parts[1])
	invalid := cfgErr("invalidCertificate", "TLS 文件不存在或超出受控目录。")
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", invalid
	}
	if info, err := os.Lstat(directory); err != nil || info.Mode()&os.ModeSymlink != 0 {
		return "", invalid
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Dir(resolved) != directory {
		return "", invalid
	}
	return path, nil
}

func (s *Store) readGrants() (obj, error) { return readObj(s.file("grants.json")) }

type credentialRef struct {
	owner obj
	key   string
	kind  string
}

func (s *Store) validate(value any, values obj) (obj, error) {
	template := s.blank()
	if err := checkKeys(value, keysOf(template), keysOf(template)); err != nil {
		return nil, err
	}
	cfg := value.(obj)
	version, okVersion := intValue(cfg["schemaVersion"])
	revision, okRevision := intValue(cfg["revision"])
	if !okVersion || version != 1 || !okRevision || revision < 0 {
		return nil, cfgErr("unknownSchema", "不支持的 schemaVersion 或 revision。")
	}
	if _, err := identifier(cfg["homeId"]); err != nil {
		return nil, err
	}
	proxyFields := keysOf(template["proxy"].(obj))
	if err := checkKeys(cfg["proxy"], proxyFields, proxyFields); err != nil {
		return nil, err
	}
	p := cfg["proxy"].(obj)
	if _, err := host(p["host"]); err != nil {
		return nil, err
	}
	proxyPort, err := port(p["port"])
	if err != nil {
		return nil, err
	}
	if _, err = host(p["serverName"]); err != nil {
		return nil, err
	}
	if p["protocol"] != "vless-tls" {
		return nil, cfgErr("invalidProtocol", "当前管理器使用 VLESS + TLS 配置模板。")
	}
	frpFields := keysOf(template["frp"].(obj))
	if err = checkKeys(cfg["frp"], frpFields, frpFields); err != nil {
		return nil, err
	}
	f := cfg["frp"].(obj)
	controlPort, err := port(f["controlPort"])
	if err != nil {
		return nil, err
	}
	if _, err = host(f["serverName"]); err != nil {
		return nil, err
	}
	if proxyPort == controlPort {
		return nil, cfgErr("portConflict", "代理和 frps 控制端口冲突。")
	}
	refs := []credentialRef{{p, "homeCredentialRef", "uuid"}, {f, "credentialRef", "token"}}
	if s.role == roleRelay {
		if _, err = host(p["listen"]); err != nil {
			return nil, err
		}
		refs = append(refs, credentialRef{p, "appCredentialRef", "uuid"})
		for _, item := range []struct {
			owner obj
			key   string
		}{{p, "certificateFile"}, {p, "keyFile"}, {f, "certificateFile"}, {f, "keyFile"}} {
			if _, err = s.tlsPath(item.owner[item.key]); err != nil {
				return nil, err
			}
		}
	} else {
		if err = checkKeys(cfg["singBox"], []string{"socksListen", "socksPort"}, []string{"socksListen", "socksPort"}); err != nil {
			return nil, err
		}
		singBox := cfg["singBox"].(obj)
		if singBox["socksListen"] != "127.0.0.1" {
			return nil, cfgErr("mandatoryProxy", "家庭 SOCKS 必须只监听回环。")
		}
		if _, err = port(singBox["socksPort"]); err != nil {
			return nil, err
		}
		if _, err = s.tlsPath(f["caFile"]); err != nil {
			return nil, err
		}
		if err = checkKeys(cfg["reconnect"], []string{"intervalSeconds"}, []string{"intervalSeconds"}); err != nil {
			return nil, err
		}
		if interval, ok := intValue(cfg["reconnect"].(obj)["intervalSeconds"]); !ok || interval < 1 || interval > 60 {
			return nil, cfgErr("invalidReconnect", "重试间隔须为 1–60 秒。")
		}
		ca, ok := p["caCertificate"].(string)
		if !ok || utf8.RuneCountInString(ca) > 32768 || strings.Contains(ca, "PRIVATE KEY") {
			return nil, cfgErr("invalidCA", "CA 内容过大。")
		}
	}
	for _, item := range refs {
		ref, ok := item.owner[item.key].(string)
		if _, present := values[ref]; !ok || !strings.HasPrefix(ref, "secret:") || !present {
			return nil, cfgErr("missingSecret", "请设置必需的连接凭据。")
		}
		secret := values[ref]
		if item.kind == "uuid" {
			ok = parseUUID(secret)
		} else {
			token, isString := secret.(string)
			length := utf8.RuneCountInString(token)
			ok = isString && length >= 32 && length <= 4096
		}
		if !ok {
			return nil, cfgErr("invalidSecret", "UUID 或 frp token 格式无效。")
		}
	}
	if s.role == roleRelay && values[p["homeCredentialRef"].(string)] == values[p["appCredentialRef"].(string)] {
		return nil, cfgErr("sharedIdentity", "App 与家庭端必须使用不同身份。")
	}
	if err = checkKeys(cfg["log"], []string{"level"}, []string{"level"}); err != nil {
		return nil, err
	}
	switch cfg["log"].(obj)["level"] {
	case "warn", "error", "info":
	default:
		return nil, cfgErr("invalidLog", "日志级别无效。")
	}
	if err = s.validateManagement(cfg["management"]); err != nil {
		return nil, err
	}
	m := cfg["management"].(obj)
	managementPort, _ := port(m["port"])
	used := []int{proxyPort, controlPort, managementPort}
	if s.role == roleHome {
		socksPort, _ := port(cfg["singBox"].(obj)["socksPort"])
		used = append(used, socksPort)
	}
	// A TLS SNI frontend may route one public port to two distinct loopback
	// addresses. Wildcard, identical and mixed-family listeners must still be
	// rejected, as must any collision with frps.
	sharedLoopback := false
	if s.role == roleRelay && proxyPort == managementPort && controlPort != managementPort {
		proxyIP, errProxy := netip.ParseAddr(fmt.Sprint(p["listen"]))
		managerIP, errManager := netip.ParseAddr(fmt.Sprint(m["listen"]))
		sharedLoopback = errProxy == nil && errManager == nil && proxyIP.IsLoopback() && managerIP.IsLoopback() &&
			proxyIP.Is4() == managerIP.Is4() && proxyIP != managerIP
	}
	if hasDuplicate(used) && !sharedLoopback {
		return nil, cfgErr("portConflict", "组件与管理监听端口冲突。")
	}
	frontendIP, frontendPort, hasFrontend := frontendEndpoint(m)
	if hasFrontend {
		// proxy.port is the public port in App pairing files and Home grants,
		// so the shared public entry must use it.
		if frontendPort != proxyPort {
			return nil, cfgErr("invalidFrontend", "公网入口端口须与代理端口（App/Home 连接的端口）一致。")
		}
		if proxyIP, err := netip.ParseAddr(fmt.Sprint(p["listen"])); err != nil || !proxyIP.Unmap().IsLoopback() {
			return nil, cfgErr("invalidFrontend", "启用公网入口时，代理监听须为回环地址。")
		}
		managementPort, _ := port(m["port"])
		if endpointConflict(frontendIP, frontendPort, fmt.Sprint(p["listen"]), proxyPort) ||
			endpointConflict(frontendIP, frontendPort, fmt.Sprint(m["listen"]), managementPort) ||
			endpointConflict(frontendIP, frontendPort, "127.0.0.1", controlPort) {
			return nil, cfgErr("portConflict", "公网入口与代理、管理或 frps 监听冲突。")
		}
	}
	services, ok := cfg["services"].([]any)
	if !ok || len(services) < 1 || len(services) > 32 {
		return nil, cfgErr("invalidServices", "请明确配置 1–32 个服务。")
	}
	var grants obj
	if s.role == roleHome {
		if grants, err = s.readGrants(); err != nil {
			return nil, err
		}
		if len(grants) > 0 {
			relayPort, _ := intValue(grants["relayPort"])
			if grants["homeId"] != cfg["homeId"] || grants["relayHost"] != p["host"] || relayPort != int64(proxyPort) {
				return nil, cfgErr("grantMismatch", "家庭或 relay 与已导入授权不匹配，请在本机重新导入可信授权。")
			}
		}
	}
	names, numbers := map[string]bool{}, map[int]bool{}
	for _, value := range services {
		if err = checkKeys(value, s.serviceFields(), s.serviceFields()); err != nil {
			return nil, err
		}
		item := value.(obj)
		name, err := identifier(item["serviceId"])
		if err != nil {
			return nil, err
		}
		number, err := port(item["relayPort"])
		if err != nil {
			return nil, err
		}
		if names[name] || numbers[number] || containsInt(used, number) || (hasFrontend && endpointConflict(frontendIP, frontendPort, "127.0.0.1", number)) {
			return nil, cfgErr("portConflict", "服务引用或映射端口重复，或与组件监听冲突。")
		}
		names[name], numbers[number] = true, true
		if s.role == roleHome {
			target, err := host(item["targetHost"])
			if err != nil {
				return nil, err
			}
			targetPort, err := port(item["targetPort"])
			if err != nil {
				return nil, err
			}
			if len(grants) == 0 || !granted(grants, name, number) {
				return nil, cfgErr("unauthorizedMapping", "映射未获 Relay 授权；Home 页面不能扩大映射范围。")
			}
			if (target == "127.0.0.1" || target == "localhost" || target == "::1") && containsInt(used, targetPort) {
				return nil, cfgErr("targetConflict", "家庭服务不能指向本机管理或代理端口。")
			}
		}
	}
	return cfg, nil
}

// frontendEndpoint returns the optional public TLS entry of a validated
// management section.
func frontendEndpoint(management obj) (netip.Addr, int, bool) {
	frontend, ok := management["frontend"].(obj)
	if !ok {
		return netip.Addr{}, 0, false
	}
	address, err := netip.ParseAddr(stringValue(frontend["listen"]))
	number, errPort := port(frontend["port"])
	return address, number, err == nil && errPort == nil
}

// endpointConflict reports whether two TCP listeners cannot coexist: same
// port and the same address, or either side bound to a wildcard address.
func endpointConflict(address netip.Addr, number int, other string, otherPort int) bool {
	if number != otherPort {
		return false
	}
	otherAddress, err := netip.ParseAddr(other)
	if err != nil {
		return true
	}
	return address.IsUnspecified() || otherAddress.IsUnspecified() || address.Unmap() == otherAddress.Unmap()
}

func granted(grants obj, name string, number int) bool {
	list, _ := grants["services"].([]any)
	for _, entry := range list {
		pair, ok := entry.([]any)
		if !ok || len(pair) != 2 {
			continue
		}
		value, isInt := intValue(pair[1])
		if pair[0] == name && isInt && value == int64(number) {
			return true
		}
	}
	return false
}

func hasDuplicate(values []int) bool {
	seen := map[int]bool{}
	for _, value := range values {
		if seen[value] {
			return true
		}
		seen[value] = true
	}
	return false
}

func containsInt(values []int, value int) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func (s *Store) validateManagement(value any) error {
	if err := checkKeys(value, managementFields, managementRequired); err != nil {
		return err
	}
	m := value.(obj)
	listenText, _ := m["listen"].(string)
	listen, err := netip.ParseAddr(listenText)
	if err != nil {
		return cfgErr("invalidListen", "管理监听地址须为明确的 IP。")
	}
	if _, err = port(m["port"]); err != nil {
		return err
	}
	_, isBool := m["https"].(bool)
	hosts, isList := m["allowedHosts"].([]any)
	if !isBool || !isList || len(hosts) < 1 || len(hosts) > 10 {
		return cfgErr("invalidManagement", "管理页面配置无效。")
	}
	for _, name := range hosts {
		if _, err = host(name); err != nil {
			return err
		}
	}
	if m["https"] == true {
		if _, err = s.tlsPath(m["certificateFile"]); err != nil {
			return err
		}
		if _, err = s.tlsPath(m["keyFile"]); err != nil {
			return err
		}
	}
	if frontend, present := m["frontend"]; present {
		if s.role != roleRelay {
			return cfgErr("invalidFrontend", "公网 TLS 入口仅用于 Relay。")
		}
		if err = checkKeys(frontend, []string{"listen", "port"}, []string{"listen", "port"}); err != nil {
			return err
		}
		address, err := netip.ParseAddr(stringValue(frontend.(obj)["listen"]))
		if err != nil || address.Unmap().IsLoopback() {
			return cfgErr("invalidFrontend", "公网入口须为本机明确的非回环 IP。")
		}
		if _, err = port(frontend.(obj)["port"]); err != nil {
			return err
		}
		// The management page becomes publicly reachable through the entry.
		if !exists(s.file("admin.json")) {
			return cfgErr("adminRequired", "启用公网入口前必须先设置管理员密码。")
		}
		if m["https"] != true {
			return cfgErr("httpsRequired", "启用公网入口时管理页必须开启 HTTPS。")
		}
	}
	if s.role == roleHome {
		if !(listen.IsUnspecified() || isLANAddress(listenText)) {
			return cfgErr("lanOnly", "Home 管理页仅允许回环或家庭局域网监听。")
		}
	} else if !listen.Unmap().IsLoopback() {
		if !exists(s.file("admin.json")) {
			return cfgErr("adminRequired", "非回环管理必须先设置管理员密码。")
		}
		if m["https"] != true {
			return cfgErr("httpsRequired", "Relay 或公网管理必须开启 HTTPS。")
		}
	}
	return nil
}

func (s *Store) importTLS(kindValue, contentValue any) (string, error) {
	kind, _ := kindValue.(string)
	content, isString := contentValue.(string)
	length := utf8.RuneCountInString(content)
	if (kind != "certificate" && kind != "privateKey") || !isString || length < 1 || length > 131072 {
		return "", cfgErr("invalidTLS", "请选择 PEM 证书或未加密私钥，最多 128 KiB。")
	}
	directory := s.file("tls")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return "", err
	}
	if len(entries) >= 128 {
		return "", cfgErr("tlsQuota", "TLS 文件数量已达上限，请在本机整理旧资产。", 409)
	}
	var valid bool
	if kind == "certificate" {
		valid = validCertificates([]byte(content))
	} else {
		valid = validPrivateKey([]byte(content))
	}
	if !valid {
		return "", cfgErr("invalidTLS", "TLS 文件格式无效，私钥须为未加密 PEM。")
	}
	digest := sha256.Sum256([]byte(content))
	name := hex.EncodeToString(digest[:]) + map[string]string{"certificate": ".crt", "privateKey": ".key"}[kind]
	if err = atomicBytes(filepath.Join(directory, name), []byte(content)); err != nil {
		return "", err
	}
	return "tls/" + name, nil
}

// validCertificates accepts one or more PEM certificates (a full chain) and
// nothing else.
func validCertificates(data []byte) bool {
	count := 0
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		count++
	}
	return count > 0 && strings.TrimSpace(string(data)) == ""
}

// validPrivateKey requires an unencrypted PEM private key.
func validPrivateKey(data []byte) bool {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return false
		}
		if !strings.HasSuffix(block.Type, "PRIVATE KEY") {
			continue
		}
		//nolint:staticcheck // legacy encrypted PEM must be rejected, not decrypted
		if block.Type == "ENCRYPTED PRIVATE KEY" || x509.IsEncryptedPEMBlock(block) {
			return false
		}
		if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return true
		}
		if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return true
		}
		_, err := x509.ParseECPrivateKey(block.Bytes)
		return err == nil
	}
}

func (s *Store) prepare(value, updatesValue any) (obj, obj, error) {
	cfg, ok := clone(value).(obj)
	if !ok {
		return nil, nil, cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
	}
	proxy, okProxy := cfg["proxy"].(obj)
	frp, okFRP := cfg["frp"].(obj)
	if !okProxy || !okFRP {
		return nil, nil, cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
	}
	values, err := s.secrets()
	if err != nil {
		return nil, nil, err
	}
	if updatesValue == nil {
		updatesValue = obj{}
	}
	if err = checkKeys(updatesValue, []string{"homeUUID", "appUUID", "frpToken"}, nil); err != nil {
		return nil, nil, err
	}
	type target struct {
		owner obj
		key   string
	}
	fields := map[string]target{"homeUUID": {proxy, "homeCredentialRef"}, "frpToken": {frp, "credentialRef"}}
	if s.role == roleRelay {
		fields["appUUID"] = target{proxy, "appCredentialRef"}
	}
	for field, update := range updatesValue.(obj) {
		destination, ok := fields[field]
		if !ok {
			return nil, nil, cfgErr("invalidSecret", "此端不支持该机密字段。")
		}
		if update == nil {
			continue // untouched
		}
		if text, isString := update.(string); isString && text == "" {
			destination.owner[destination.key] = "" // explicit clear; required references fail validation
			continue
		}
		ref := "secret:" + tokenHex(16)
		values[ref] = update
		destination.owner[destination.key] = ref
	}
	if _, err = s.validate(cfg, values); err != nil {
		return nil, nil, err
	}
	return cfg, values, nil
}

func (s *Store) revisionClock(fallback int64) (int64, error) {
	path := s.file("revision.json")
	if !exists(path) {
		return fallback, nil
	}
	value, err := readObj(path)
	if err != nil {
		return 0, err
	}
	clock, ok := intValue(value["lastIssuedRevision"])
	if !ok || clock < 0 {
		return 0, cfgErr("invalidRevision", "修订元数据损坏，已保留原文件。", 409)
	}
	return clock, nil
}

func (s *Store) save(value, expectedValue, updates any) (obj, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	return s.saveLocked(value, expectedValue, updates)
}

func (s *Store) saveLocked(value, expectedValue, updates any) (obj, error) {
	old, err := s.load()
	if err != nil {
		return nil, err
	}
	expected, ok := intValue(expectedValue)
	current, _ := intValue(old["revision"])
	if !ok || expected != current {
		return nil, cfgErr("conflict", "配置已修改，请重新加载后编辑。", 409)
	}
	draft, isObj := value.(obj)
	if !isObj {
		return nil, cfgErr("invalidFields", "配置字段缺失或包含未知字段。")
	}
	if revision, ok := intValue(draft["revision"]); !ok || revision != expected {
		return nil, cfgErr("conflict", "草稿修订不匹配。", 409)
	}
	cfg, values, err := s.prepare(draft, updates)
	if err != nil {
		return nil, err
	}
	clock, err := s.revisionClock(expected)
	if err != nil {
		return nil, err
	}
	cfg["revision"] = json.Number(strconv.FormatInt(max(expected, clock)+1, 10))
	if err = atomicWrite(s.file("revision.json"), obj{"lastIssuedRevision": cfg["revision"]}); err != nil {
		return nil, err
	}
	prior, err := s.secrets()
	if err != nil {
		return nil, err
	}
	if err = atomicWrite(s.file("secrets.json"), values); err != nil { // new secrets first
		return nil, err
	}
	writeErr := func() error {
		if exists(s.path) {
			if err := atomicWrite(s.file(s.role+".backup.json"), old); err != nil {
				return err
			}
		}
		return atomicWrite(s.path, cfg)
	}()
	if writeErr != nil {
		// A successful config write followed by a directory fsync error must
		// not discard keys now referenced by the authoritative file.
		committed := false
		if saved, err := readJSON(s.path); err == nil {
			committed = canonical(saved) == canonical(cfg)
		}
		if !committed {
			_ = atomicWrite(s.file("secrets.json"), prior)
		}
		return nil, writeErr
	}
	return cfg, nil
}

func (s *Store) test(value, updates any) (obj, error) {
	cfg, values, err := s.prepare(value, updates)
	if err != nil {
		return nil, err
	}
	if _, err = s.plan(cfg, values); err != nil {
		return nil, cfgErr("componentCheckFailed", "组件配置校验失败；请检查证书、凭据与内置组件配置。")
	}
	// Connect to only this explicitly configured proxy endpoint; no credentials
	// or media requests are sent and no production component is restarted.
	var reachable any
	if s.role == roleHome {
		proxy := cfg["proxy"].(obj)
		proxyPort, _ := port(proxy["port"])
		connection, err := net.DialTimeout("tcp", net.JoinHostPort(proxy["host"].(string), strconv.Itoa(proxyPort)), 2*time.Second)
		reachable = err == nil
		if connection != nil {
			connection.Close()
		}
	}
	return obj{"draftRevision": cfg["revision"], "configValid": true, "relayTcpReachable": reachable,
		"message": "组件配置已通过；TCP 可达不等于代理认证、家庭隧道或媒体播放成功。"}, nil
}

var stateErrors = map[any]bool{nil: true, "applyFailed": true, "stateRecovered": true, "legacyRuntimeRolledBack": true}

func validState(value any) bool {
	state, ok := value.(obj)
	if !ok {
		return false
	}
	for key := range state {
		switch key {
		case "appliedRevision", "error", "appliedAt", "failedRevision":
		default:
			return false
		}
	}
	applied, present := state["appliedRevision"]
	if !present {
		return false
	}
	if _, isInt := intValue(applied); applied != nil && !isInt {
		return false
	}
	errorValue := state["error"]
	if _, isString := errorValue.(string); errorValue != nil && !isString {
		return false
	}
	return stateErrors[errorValue]
}

func (s *Store) state() (obj, error) {
	path := s.file("status.json")
	if !exists(path) {
		return obj{"appliedRevision": nil, "error": nil}, nil
	}
	value, err := readJSON(path)
	if err != nil || !validState(value) {
		return nil, cfgErr("invalidState", "运行状态文件损坏，原文件已保留。", 409)
	}
	return value.(obj), nil
}

func (s *Store) status() (obj, error) {
	state, err := s.state()
	if err != nil {
		return nil, err
	}
	cfg, err := s.load()
	if err != nil {
		return nil, err
	}
	var components map[string]string
	if s.controller != nil {
		components = s.controller.Components()
	} else {
		components = s.recordedComponents()
	}
	result := obj{}
	for key, value := range state {
		result[key] = value
	}
	applied, isInt := intValue(state["appliedRevision"])
	desired, _ := intValue(cfg["revision"])
	result["desiredRevision"] = cfg["revision"]
	result["components"] = components
	result["savedIsApplied"] = isInt && applied == desired
	return result, nil
}

// recordedComponents reads the state the running service last published,
// for CLI processes that do not host the runtime themselves.
func (s *Store) recordedComponents() map[string]string {
	components := map[string]string{"sing-box": "unavailable", s.frpName(): "unavailable"}
	value, err := readObj(s.file("runtime.json"))
	if err != nil {
		return components
	}
	if recorded, ok := value["components"].(obj); ok {
		for name := range components {
			if state, ok := recorded[name].(string); ok {
				components[name] = state
			}
		}
	}
	return components
}

func (s *Store) readOptional(name string) obj {
	if !exists(s.file(name)) {
		return nil
	}
	value, err := readObj(s.file(name))
	if err != nil {
		return nil
	}
	return value
}

// apply switches the components to the saved revision. A failure keeps the
// saved revision as desired, restores the previous runtime and reports
// "saved but not effective".
func (s *Store) apply(expectedValue any, controller Controller) (obj, error) {
	s.applyMu.Lock()
	defer s.applyMu.Unlock()
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	cfg, err := s.load()
	if err != nil {
		return nil, err
	}
	expected, ok := intValue(expectedValue)
	revision, _ := intValue(cfg["revision"])
	if !ok || expected != revision {
		return nil, cfgErr("conflict", "配置已修改，未应用其他修订。", 409)
	}
	values, err := s.secrets()
	if err != nil {
		return nil, err
	}
	if _, err = s.validate(cfg, values); err != nil {
		return nil, err
	}
	state, err := s.state()
	if err != nil {
		state = obj{"appliedRevision": nil, "error": nil}
	}
	failed := func(cause error) (obj, error) {
		logRedacted("apply revision %d failed: %v", values, revision, cause)
		next := obj{}
		for key, value := range state {
			next[key] = value
		}
		next["error"], next["failedRevision"] = "applyFailed", cfg["revision"]
		_ = atomicWrite(s.file("status.json"), next)
		return nil, cfgErr("applyFailed", "配置已保存但未生效；已尝试恢复上一份运行配置。", 409)
	}
	plan, err := s.plan(cfg, values)
	if err != nil {
		return failed(err)
	}
	previous := s.readOptional("last-good.json")
	if err = controller.Restart(cfg, plan); err != nil {
		restored := false
		if previous != nil {
			if oldPlan, planErr := s.plan(previous, values); planErr == nil {
				restored = controller.Restart(previous, oldPlan) == nil
			}
		}
		if !restored {
			_ = controller.Stop()
		}
		return failed(err)
	}
	if previous != nil && canonical(previous) != canonical(cfg) {
		_ = atomicWrite(s.file("previous-good.json"), previous)
	}
	if err = atomicWrite(s.file("last-good.json"), cfg); err != nil {
		return nil, err
	}
	if err = atomicWrite(s.file("status.json"), obj{"appliedRevision": cfg["revision"], "error": nil, "appliedAt": time.Now().Unix()}); err != nil {
		return nil, err
	}
	s.collectSecrets()
	return obj{"appliedRevision": cfg["revision"], "error": nil}, nil
}

func (s *Store) enableLAN() (obj, error) {
	if s.role != roleHome {
		return nil, cfgErr("homeOnly", "局域网直连选项仅用于 Home。")
	}
	cfg, err := s.load()
	if err != nil {
		return nil, err
	}
	if !exists(s.path) {
		return cfg, nil // Fresh installs already use the LAN default.
	}
	cfg["management"].(obj)["listen"] = "0.0.0.0"
	if err = s.validateManagement(cfg["management"]); err != nil {
		return nil, err
	}
	return s.save(cfg, cfg["revision"], nil)
}

func (s *Store) recoveryInfo() (obj, error) {
	if !exists(s.path) {
		return nil, cfgErr("noConfig", "没有待恢复文件。", 409)
	}
	backup := s.file(s.role + ".backup.json")
	if !exists(backup) {
		return nil, cfgErr("noBackup", "没有可用的配置备份。", 409)
	}
	cfg, err := readJSON(backup)
	if err != nil {
		return nil, err
	}
	values, err := s.secrets()
	if err != nil {
		return nil, err
	}
	if _, err = s.validate(cfg, values); err != nil {
		return nil, err
	}
	original, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(original)
	return obj{"fileHash": hex.EncodeToString(digest[:]), "backupRevision": cfg.(obj)["revision"]}, nil
}

func (s *Store) recover(expectedHash any) (obj, error) {
	unlock, err := s.lock()
	if err != nil {
		return nil, err
	}
	defer unlock()
	info, err := s.recoveryInfo()
	if err != nil {
		return nil, err
	}
	if hash, ok := expectedHash.(string); !ok || hash != info["fileHash"] {
		return nil, cfgErr("conflict", "待恢复文件已变化，请重新检查。", 409)
	}
	cfg, err := readObj(s.file(s.role + ".backup.json"))
	if err != nil {
		return nil, err
	}
	revision, _ := intValue(cfg["revision"])
	original, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	if current, err := decodeJSON(original); err == nil {
		if fields, ok := current.(obj); ok {
			if number, ok := intValue(fields["revision"]); ok {
				revision = max(revision, number)
			}
		}
	}
	preserved := s.file(fmt.Sprintf("%s.damaged.%d.json", s.role, time.Now().UnixNano()))
	if err = writeSynced(preserved, original); err != nil {
		return nil, err
	}
	clock, err := s.revisionClock(revision)
	if err != nil {
		return nil, cfgErr("invalidRevision", "修订元数据损坏。", 409)
	}
	cfg["revision"] = json.Number(strconv.FormatInt(max(revision, clock)+1, 10))
	if err = atomicWrite(s.file("revision.json"), obj{"lastIssuedRevision": cfg["revision"]}); err != nil {
		return nil, err
	}
	if err = atomicWrite(s.path, cfg); err != nil {
		return nil, err
	}
	statefile := s.file("status.json")
	if exists(statefile) {
		if value, err := readJSON(statefile); err != nil || !validState(value) {
			raw, _ := os.ReadFile(statefile)
			_ = writeSynced(s.file(fmt.Sprintf("status.damaged.%d.json", time.Now().UnixNano())), raw)
			if err := atomicWrite(statefile, obj{"appliedRevision": nil, "error": "stateRecovered"}); err != nil {
				return nil, err
			}
		}
	}
	return cfg, nil
}

func writeSynced(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (s *Store) restore(expected any) (obj, error) {
	backup := s.file(s.role + ".backup.json")
	if !exists(backup) {
		return nil, cfgErr("noBackup", "没有可恢复的配置。", 409)
	}
	cfg, err := readObj(backup)
	if err != nil {
		return nil, err
	}
	cfg["revision"] = expected
	return s.save(cfg, expected, nil)
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
		for _, section := range []string{"proxy", "frp"} {
			owner, _ := cfg[section].(obj)
			for key, value := range owner {
				if ref, ok := value.(string); ok && (strings.HasSuffix(key, "CredentialRef") || key == "credentialRef") {
					references[ref] = true
				}
			}
		}
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

func (s *Store) tlsFiles() []string {
	result := []string{}
	entries, err := os.ReadDir(s.file("tls"))
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() {
			result = append(result, "tls/"+entry.Name())
		}
	}
	sort.Strings(result)
	return result
}

// importLegacy initialises an empty state directory from the previous flat
// deployment format. It never overwrites an existing authoritative file.
func (s *Store) importLegacy(raw obj, homeID string) (obj, error) {
	if exists(s.path) {
		return nil, cfgErr("alreadyInitialized", "已有配置，禁止覆盖初始化。", 409)
	}
	raw = cloneObj(raw)
	if homeID == "" {
		homeID, _ = raw["homeId"].(string)
		if homeID == "" {
			homeID = "home-main"
		}
	}
	cfg := s.blank()
	if _, err := identifier(homeID); err != nil {
		return nil, err
	}
	cfg["homeId"] = homeID
	p, ok := raw["proxy"].(obj)
	if !ok {
		return nil, errors.New("legacy configuration has no proxy section")
	}
	proxy, frp := cfg["proxy"].(obj), cfg["frp"].(obj)
	proxy["host"], proxy["port"], proxy["serverName"] = p["host"], p["port"], p["serverName"]
	frp["controlPort"] = valueOr(raw, "controlPort", json.Number("7000"))
	directory := s.file("tls")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	copyTLS := func(source any, label string) (string, error) {
		path, _ := source.(string)
		data, err := os.ReadFile(path)
		if err != nil {
			return "", err
		}
		if len(data) > 131072 {
			return "", cfgErr("invalidCertificate", "TLS 文件过大。")
		}
		if err = writeSynced(filepath.Join(directory, label), data); err != nil {
			return "", err
		}
		return "tls/" + label, nil
	}
	var err error
	if s.role == roleRelay {
		proxy["listen"] = valueOr(raw, "listen", "0.0.0.0")
		for _, item := range []struct {
			owner       obj
			key, source string
			from        obj
			label       string
		}{
			{proxy, "certificateFile", "certificatePath", p, "proxy.crt"}, {proxy, "keyFile", "keyPath", p, "proxy.key"},
			{frp, "certificateFile", "frpCertificatePath", raw, "frps.crt"}, {frp, "keyFile", "frpKeyPath", raw, "frps.key"},
		} {
			if item.owner[item.key], err = copyTLS(item.from[item.source], item.label); err != nil {
				return nil, err
			}
		}
	} else {
		proxy["caCertificate"] = valueOr(p, "caCertificate", "")
		cfg["singBox"].(obj)["socksPort"] = valueOr(raw, "socksPort", json.Number("1080"))
		frp["serverName"] = raw["frpServerName"]
		if frp["caFile"], err = copyTLS(raw["frpCAPath"], "frps-ca.crt"); err != nil {
			return nil, err
		}
	}
	services := []any{}
	grantList := []any{}
	legacyServices, _ := raw["services"].([]any)
	for _, value := range legacyServices {
		legacy, _ := value.(obj)
		service := obj{"serviceId": legacy["id"], "relayPort": legacy["remotePort"]}
		if s.role == roleHome {
			service["targetHost"], service["targetPort"] = legacy["localHost"], legacy["localPort"]
		}
		services = append(services, service)
		grantList = append(grantList, []any{legacy["id"], legacy["remotePort"]})
	}
	cfg["services"] = services
	if s.role == roleHome {
		if err = atomicWrite(s.file("grants.json"), obj{"homeId": homeID, "relayHost": p["host"], "relayPort": p["port"], "services": grantList}); err != nil {
			return nil, err
		}
	}
	updates := obj{"homeUUID": p["homeUUID"], "frpToken": raw["frpToken"]}
	if s.role == roleRelay {
		updates["appUUID"] = p["appUUID"]
	}
	return s.save(cfg, 0, updates)
}

func valueOr(source obj, key string, fallback any) any {
	if value, ok := source[key]; ok {
		return value
	}
	return fallback
}

// writeRuntimeState publishes component state for CLI status/apply.
func (s *Store) writeRuntimeState(revision any, components map[string]string) {
	_ = atomicWrite(s.file("runtime.json"), obj{"revision": revision, "components": components, "updatedAt": time.Now().UnixNano(), "pid": os.Getpid()})
}
