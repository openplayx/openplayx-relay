package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"embed"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

//go:embed web/index.html web/app.js web/style.css
var webAssets embed.FS

var staticFiles = map[string][2]string{
	"/":          {"web/index.html", "text/html; charset=utf-8"},
	"/app.js":    {"web/app.js", "text/javascript; charset=utf-8"},
	"/style.css": {"web/style.css", "text/css; charset=utf-8"},
}

const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"

// ManagerServer is the role-scoped configuration API. Home permits
// authenticated LAN access; Relay stays loopback unless HTTPS is configured.
type ManagerServer struct {
	store      *Store
	management obj
	admin      *Admin
	scheme     string
	port       int
	listener   net.Listener
	server     *http.Server
	tlsConfig  *tls.Config
}

func NewManagerServer(store *Store, management obj, address string) (*ManagerServer, error) {
	admin := NewAdmin(store.dir)
	if err := admin.bootstrap(false); err != nil {
		return nil, err
	}
	listenPort, _ := port(management["port"])
	if address == "" {
		address = net.JoinHostPort(stringValue(management["listen"]), strconv.Itoa(listenPort))
	}
	hostPart, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	network := "tcp4"
	if ip, err := netip.ParseAddr(hostPart); err == nil && ip.Is6() && !ip.Is4In6() {
		network = "tcp6"
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}
	m := &ManagerServer{store: store, management: management, admin: admin, scheme: "http", port: listener.Addr().(*net.TCPAddr).Port}
	listener = &limitListener{Listener: listener, limit: 32}
	if management["https"] == true {
		certificate, errCert := store.tlsPath(management["certificateFile"])
		key, errKey := store.tlsPath(management["keyFile"])
		if errCert != nil || errKey != nil {
			listener.Close()
			return nil, cfgErr("invalidCertificate", "管理 HTTPS 证书不可用。")
		}
		pair, err := tls.LoadX509KeyPair(certificate, key)
		if err != nil {
			listener.Close()
			return nil, err
		}
		m.tlsConfig = &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}
		listener = tls.NewListener(listener, m.tlsConfig)
		m.scheme = "https"
	}
	m.listener = listener
	m.server = &http.Server{
		Handler: m, ReadTimeout: 10 * time.Second, ReadHeaderTimeout: 10 * time.Second,
		// Apply waits for components (Home: SOCKS readiness and retries), so
		// responses may take longer than a single read or write.
		WriteTimeout: 3 * time.Minute, IdleTimeout: 10 * time.Second,
		ErrorLog: discardLogger(), MaxHeaderBytes: 65536,
	}
	return m, nil
}

func (m *ManagerServer) Serve() error {
	err := m.server.Serve(m.listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (m *ManagerServer) Close() error { return m.server.Close() }

// serveFrontend serves HTTPS on connections handed over by the public TLS
// entry. They keep their real remote address.
func (m *ManagerServer) serveFrontend(address net.Addr) (*connListener, error) {
	if m.tlsConfig == nil {
		return nil, cfgErr("httpsRequired", "启用公网入口时管理页必须开启 HTTPS。")
	}
	feed := newConnListener(address)
	go func() { _ = m.server.Serve(tls.NewListener(&limitListener{Listener: feed, limit: 32}, m.tlsConfig)) }()
	return feed, nil
}

func (m *ManagerServer) Shutdown(ctx context.Context) error { return m.server.Shutdown(ctx) }

func (m *ManagerServer) origins() map[string]bool {
	result := map[string]bool{}
	defaultPort := map[string]int{"http": 80, "https": 443}[m.scheme]
	ports := []int{m.port}
	if _, frontendPort, ok := frontendEndpoint(m.management); ok {
		ports = append(ports, frontendPort)
	}
	hosts, _ := m.management["allowedHosts"].([]any)
	for _, value := range hosts {
		name := stringValue(value)
		if strings.Contains(name, ":") {
			name = "[" + name + "]"
		}
		for _, number := range ports {
			suffix := ""
			if number != defaultPort {
				suffix = ":" + strconv.Itoa(number)
			}
			result[m.scheme+"://"+name+suffix] = true
		}
	}
	return result
}

func (m *ManagerServer) requestOrigins(peer, local, authority string) (map[string]bool, error) {
	origins := m.origins()
	if m.store.role != roleHome {
		return origins, nil
	}
	if !isLANAddress(peer) || !isLANAddress(local) {
		return nil, cfgErr("lanOnly", "Home 管理页只允许家庭局域网访问。", 403)
	}
	// Accept a literal IP only when it is the actual destination interface of
	// this connection. Never allow arbitrary Host values or LAN wildcards.
	parsed, err := url.Parse(authority)
	if err != nil || parsed.User != nil || parsed.Path != "" || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery {
		return origins, nil
	}
	number := map[string]int{"http": 80, "https": 443}[m.scheme]
	if parsed.Port() != "" {
		if number, err = strconv.Atoi(parsed.Port()); err != nil {
			return origins, nil
		}
	}
	hostIP, errHost := netip.ParseAddr(parsed.Hostname())
	localIP, errLocal := netip.ParseAddr(local)
	if errHost == nil && errLocal == nil && number == m.port && hostIP == localIP {
		origins[authority] = true
	}
	return origins, nil
}

func (m *ManagerServer) reply(w http.ResponseWriter, status int, value any, extra map[string]string) {
	data, _ := json.Marshal(value)
	m.send(w, status, data, "application/json; charset=utf-8", extra)
}

func (m *ManagerServer) send(w http.ResponseWriter, status int, data []byte, contentType string, extra map[string]string) {
	header := w.Header()
	header.Set("Content-Type", contentType)
	header.Set("Content-Length", strconv.Itoa(len(data)))
	header.Set("Cache-Control", "no-store")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("Content-Security-Policy", contentSecurityPolicy)
	for key, value := range extra {
		header.Set(key, value)
	}
	w.WriteHeader(status)
	_, _ = w.Write(data)
}

func remoteHost(address string) string {
	hostPart, _, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	return hostPart
}

func (m *ManagerServer) checkOrigin(r *http.Request, write bool) error {
	authority := m.scheme + "://" + r.Host
	local := ""
	if address, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok {
		local = remoteHost(address.String())
	}
	origins, err := m.requestOrigins(remoteHost(r.RemoteAddr), local, authority)
	if err != nil {
		return err
	}
	if r.Host == "" || !origins[authority] {
		return cfgErr("originDenied", "请求来源不允许。", 403)
	}
	if _, static := staticFiles[r.RequestURI]; !write && static {
		return nil
	}
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return cfgErr("originDenied", "请求来源不允许。", 403)
	}
	values := r.Header.Values("Origin")
	if write && len(values) == 0 {
		return cfgErr("originDenied", "请求来源不允许。", 403)
	}
	if len(values) > 0 {
		origin := values[0]
		if !origins[origin] || (m.store.role == roleHome && origin != authority) {
			return cfgErr("originDenied", "请求来源不允许。", 403)
		}
	}
	return nil
}

func readBody(r *http.Request) (obj, error) {
	contentType := strings.SplitN(r.Header.Get("Content-Type"), ";", 2)[0]
	if len(r.TransferEncoding) > 0 || contentType != "application/json" {
		return nil, cfgErr("invalidRequest", "请求必须是有长度的 JSON。", 415)
	}
	if r.ContentLength < 1 || r.ContentLength > 262144 {
		return nil, cfgErr("invalidRequest", "请求过大或为空。", 413)
	}
	raw := make([]byte, r.ContentLength)
	if _, err := io.ReadFull(r.Body, raw); err != nil {
		return nil, cfgErr("invalidRequest", "JSON 无效。")
	}
	value, err := decodeJSON(raw)
	data, ok := value.(obj)
	if err != nil || !ok {
		return nil, cfgErr("invalidRequest", "JSON 无效。")
	}
	return data, nil
}

func (m *ManagerServer) authenticate(r *http.Request, write bool) (string, session, error) {
	token := ""
	if cookie, err := r.Cookie("opx_admin"); err == nil {
		token = cookie.Value
	}
	current, err := m.admin.session(token)
	if err != nil {
		return "", session{}, err
	}
	if write && subtle.ConstantTimeCompare([]byte(current.csrf), []byte(r.Header.Get("X-CSRF-Token"))) != 1 {
		return "", session{}, cfgErr("csrfDenied", "会话校验失败，请重新登录。", 403)
	}
	return token, current, nil
}

func (m *ManagerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// URLs, login fields and secrets never enter logs.
	defer func() {
		if recover() != nil {
			m.reply(w, 500, obj{"error": "operationFailed", "message": "操作失败；请检查本机组件状态。机密未写入日志。"}, nil)
		}
	}()
	var write bool
	switch r.Method {
	case http.MethodGet:
	case http.MethodPost:
		write = true
	case http.MethodOptions:
		m.reply(w, 403, obj{"error": "originDenied", "message": "不允许跨域访问。"}, nil)
		return
	default:
		m.reply(w, 405, obj{"error": "methodNotAllowed", "message": "不支持的请求方法。"}, nil)
		return
	}
	if err := m.handle(w, r, write); err != nil {
		var configError *ConfigError
		if errors.As(err, &configError) {
			m.reply(w, configError.Status, obj{"error": configError.Code, "message": configError.Message}, nil)
			return
		}
		m.reply(w, 400, obj{"error": "invalidRequest", "message": "操作失败，请检查配置和服务权限；原文件未被默认值覆盖。"}, nil)
	}
}

func (m *ManagerServer) needsPassword() bool { return !exists(m.store.file("admin.json")) }

func (m *ManagerServer) handle(w http.ResponseWriter, r *http.Request, write bool) error {
	if err := m.checkOrigin(r, write); err != nil {
		return err
	}
	path := r.RequestURI
	if asset, static := staticFiles[path]; !write && static {
		content, err := webAssets.ReadFile(asset[0])
		if err != nil {
			return err
		}
		m.send(w, 200, content, asset[1], nil)
		return nil
	}
	data := obj{}
	if write {
		var err error
		if data, err = readBody(r); err != nil {
			return err
		}
	}
	role := m.store.role
	if write && path == "/api/login" {
		token, csrf, err := m.admin.authenticate(data["password"], remoteHost(r.RemoteAddr))
		if err != nil {
			return err
		}
		cookie := "opx_admin=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=1800"
		if m.scheme == "https" {
			cookie += "; Secure"
		}
		m.reply(w, 200, obj{"csrfToken": csrf, "role": role, "needsPassword": m.needsPassword()}, map[string]string{"Set-Cookie": cookie})
		return nil
	}
	token, current, err := m.authenticate(r, write)
	if err != nil {
		return err
	}
	store := m.store
	switch {
	case !write && path == "/api/session":
		m.reply(w, 200, obj{"csrfToken": current.csrf, "role": role, "needsPassword": m.needsPassword()}, nil)
	case write && path == "/api/password":
		if err = m.admin.setPassword(data["password"]); err != nil {
			return err
		}
		m.reply(w, 200, obj{"message": "管理员密码已设置，所有会话已退出。请重新登录。"}, nil)
	case write && path == "/api/logout":
		m.admin.logout(token)
		m.reply(w, 200, obj{}, map[string]string{"Set-Cookie": "opx_admin=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
	case !write && (path == "/api/config" || path == "/api/export"):
		cfg, err := store.load()
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"config": cfg, "role": role, "tlsFiles": store.tlsFiles()}, nil)
	case !write && path == "/api/recovery":
		info, err := store.recoveryInfo()
		if err != nil {
			return err
		}
		m.reply(w, 200, info, nil)
	case write && path == "/api/recover":
		cfg, err := store.recover(data["fileHash"])
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"config": cfg, "message": "原文件已另存保留，备份已恢复为新修订，尚未应用。"}, nil)
	case !write && path == "/api/status":
		status, err := store.status()
		if err != nil {
			return err
		}
		cfg, err := store.load()
		if err != nil {
			return err
		}
		status["managementRestartRequired"] = canonical(cfg["management"]) != canonical(m.management)
		m.reply(w, 200, status, nil)
	case write && path == "/api/tls":
		file, err := store.importTLS(data["kind"], data["content"])
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"file": file}, nil)
	case write && path == "/api/validate":
		cfg, _, err := store.prepare(data["config"], secretsField(data))
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"draftRevision": cfg["revision"], "valid": true}, nil)
	case write && path == "/api/test":
		result, err := store.test(data["config"], secretsField(data))
		if err != nil {
			return err
		}
		m.reply(w, 200, result, nil)
	case write && path == "/api/save":
		cfg, err := store.save(data["config"], data["expectedRevision"], secretsField(data))
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"config": cfg, "message": "配置已保存，尚未应用。"}, nil)
	case write && path == "/api/apply":
		cfg, err := store.load()
		if err != nil {
			return err
		}
		if canonical(cfg["management"]) != canonical(m.management) {
			return cfgErr("managementRestartRequired", "管理入口变化需要先保存，再在本机重启管理服务后应用。当前运行修订保持不变。", 409)
		}
		if store.controller == nil {
			return cfgErr("applyFailed", "运行组件不可用。", 409)
		}
		result, err := store.apply(data["expectedRevision"], store.controller)
		if err != nil {
			return err
		}
		m.reply(w, 200, result, nil)
	case write && path == "/api/restore":
		cfg, err := store.restore(data["expectedRevision"])
		if err != nil {
			return err
		}
		m.reply(w, 200, obj{"config": cfg, "message": "旧配置已保存为新修订，尚未应用。"}, nil)
	default:
		return cfgErr("notFound", "接口不存在。", 404)
	}
	return nil
}

func secretsField(data obj) any {
	if value, ok := data["secrets"]; ok {
		return value
	}
	return obj{}
}

// limitListener drops connections beyond a fixed number of active requests.
type limitListener struct {
	net.Listener
	limit  int64
	active atomic.Int64
}

func (l *limitListener) Accept() (net.Conn, error) {
	for {
		connection, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.active.Add(1) > l.limit {
			l.active.Add(-1)
			connection.Close()
			continue
		}
		return &trackedConn{Conn: connection, release: func() { l.active.Add(-1) }}, nil
	}
}

type trackedConn struct {
	net.Conn
	release func()
	closed  atomic.Bool
}

func (c *trackedConn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.release()
	}
	return c.Conn.Close()
}
