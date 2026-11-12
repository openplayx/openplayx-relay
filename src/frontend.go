package main

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

// Frontend lets the proxy and the management page share one public TLS port
// (Relay only). It reads the TLS ClientHello without terminating TLS: a
// connection whose SNI equals the applied proxy.serverName is passed
// byte-for-byte to sing-box on loopback; any other TLS connection is handed
// in-process to the HTTPS management server, which keeps the real peer
// address for its login rate limit.
type Frontend struct {
	listener net.Listener
	manager  *connListener
	target   func() (address, serverName string, ok bool)
	slots    chan struct{}
}

var errHelloCaptured = errors.New("client hello captured")

func NewFrontend(address string, manager *connListener, target func() (string, string, bool)) (*Frontend, error) {
	listener, err := net.Listen(networkFor(address), address)
	if err != nil {
		return nil, err
	}
	return &Frontend{listener: listener, manager: manager, target: target, slots: make(chan struct{}, 256)}, nil
}

func (f *Frontend) Addr() net.Addr { return f.listener.Addr() }

func (f *Frontend) Close() error { return f.listener.Close() }

func (f *Frontend) Serve() {
	for {
		connection, err := f.listener.Accept()
		if err != nil {
			var temporary interface{ Temporary() bool }
			if errors.As(err, &temporary) && temporary.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		select {
		case f.slots <- struct{}{}:
			go f.handle(connection)
		default:
			connection.Close() // too many unfinished handshakes
		}
	}
}

func (f *Frontend) handle(connection net.Conn) {
	released := false
	release := func() {
		if !released {
			released = true
			<-f.slots
		}
	}
	defer release()
	_ = connection.SetReadDeadline(time.Now().Add(5 * time.Second))
	serverName, prefix, ok := readClientHello(connection)
	_ = connection.SetReadDeadline(time.Time{})
	if !ok {
		connection.Close()
		return
	}
	replay := &prefixConn{Conn: connection, reader: io.MultiReader(bytes.NewReader(prefix), connection)}
	address, proxyName, running := f.target()
	if proxyName != "" && strings.EqualFold(serverName, proxyName) {
		release()
		if !running {
			connection.Close()
			return
		}
		upstream, err := net.DialTimeout("tcp", address, 5*time.Second)
		if err != nil {
			connection.Close()
			return
		}
		splice(replay, upstream)
		return
	}
	release()
	if !f.manager.deliver(replay) {
		connection.Close()
	}
}

// readClientHello parses the first TLS handshake message with crypto/tls and
// returns its SNI plus every byte read, so the connection can be replayed.
func readClientHello(connection net.Conn) (string, []byte, bool) {
	var recorded bytes.Buffer
	var serverName string
	captured := false
	probe := tls.Server(readOnlyConn{reader: io.TeeReader(connection, &recorded)}, &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			serverName, captured = hello.ServerName, true
			return nil, errHelloCaptured
		},
	})
	_ = probe.Handshake()
	return serverName, recorded.Bytes(), captured
}

type readOnlyConn struct{ reader io.Reader }

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.reader.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (readOnlyConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }

type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (c *prefixConn) CloseWrite() error {
	if closer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return closer.CloseWrite()
	}
	return nil
}

func splice(client, upstream net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	pipe := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(destination, source)
		if closer, ok := destination.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		} else {
			_ = destination.Close()
		}
	}
	go pipe(upstream, client)
	go pipe(client, upstream)
	wait.Wait()
	client.Close()
	upstream.Close()
}

// connListener is a net.Listener fed with connections from the frontend.
type connListener struct {
	address net.Addr
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func newConnListener(address net.Addr) *connListener {
	return &connListener{address: address, conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *connListener) deliver(connection net.Conn) bool {
	select {
	case l.conns <- connection:
		return true
	case <-l.done:
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

func (l *connListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.conns:
		return connection, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *connListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *connListener) Addr() net.Addr { return l.address }

func networkFor(address string) string {
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return "tcp6"
		}
	}
	return "tcp4"
}
