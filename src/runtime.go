package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	frpclient "github.com/fatedier/frp/client"
	frplog "github.com/fatedier/frp/pkg/util/log"
	frpserver "github.com/fatedier/frp/server"
	box "github.com/sagernet/sing-box"
)

// Runtime hosts sing-box and frps (Relay) or sing-box and frpc (Home) inside
// this process. Home starts frpc only after its loopback SOCKS5 entry answers
// a handshake, and frpc always dials through it: there is no direct mode.
type Runtime struct {
	mu         sync.Mutex
	role       string
	box        *box.Box
	boxCancel  context.CancelFunc
	frps       *frpserver.Service
	frpsCancel context.CancelFunc
	frpc       *frpclient.Service
	frpcCancel context.CancelFunc
	frpcDone   chan struct{}
	state      map[string]string
	revision   any
	onChange   func(revision any, components map[string]string)
	// proxyAddress/serverName describe the running sing-box inbound (Relay)
	// for the shared public TLS entry.
	proxyAddress string
	serverName   string
}

// proxyTarget tells the public TLS entry where the running proxy listens and
// which SNI belongs to it.
func (r *Runtime) proxyTarget() (string, string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.proxyAddress, r.serverName, r.box != nil
}

func NewRuntime(role string) *Runtime {
	r := &Runtime{role: role}
	r.state = map[string]string{"sing-box": "inactive", r.frpName(): "inactive"}
	return r
}

func (r *Runtime) frpName() string {
	if r.role == roleRelay {
		return "frps"
	}
	return "frpc"
}

func (r *Runtime) Components() map[string]string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.componentsLocked()
}

func (r *Runtime) componentsLocked() map[string]string {
	result := map[string]string{}
	for key, value := range r.state {
		result[key] = value
	}
	return result
}

func (r *Runtime) notifyLocked() {
	if r.onChange != nil {
		r.onChange(r.revision, r.componentsLocked())
	}
}

// Restart replaces the running components with the plan. On failure every
// component of the new plan is stopped again and the error is returned.
func (r *Runtime) Restart(_ obj, plan *Plan) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	err := r.startLocked(plan)
	if err != nil {
		r.stopLocked()
		r.state["sing-box"], r.state[r.frpName()] = "failed", "failed"
		r.revision = nil
		logRedacted("%s runtime failed to start: %v", plan.secrets, r.role, err)
	} else {
		r.revision = plan.Revision
		r.proxyAddress, r.serverName = plan.ProxyAddress, plan.ServerName
	}
	r.notifyLocked()
	return err
}

func (r *Runtime) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopLocked()
	r.revision = nil
	r.notifyLocked()
	return nil
}

func (r *Runtime) startLocked(plan *Plan) error {
	frplog.InitLogger("console", plan.LogLevel, 0, true)
	attempts := 1
	if r.role == roleHome {
		attempts = 3
	}
	var err error
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			time.Sleep(plan.Retry)
		}
		if err = r.startBoxLocked(plan); err == nil {
			break
		}
	}
	if err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	r.state["sing-box"] = "active"
	if r.role == roleRelay {
		cfg, err := frpServerConfig(plan.FRP)
		if err != nil {
			return fmt.Errorf("frps config: %w", err)
		}
		service, err := frpserver.NewService(cfg)
		if err != nil {
			return fmt.Errorf("frps: %w", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		r.frps, r.frpsCancel = service, cancel
		go service.Run(ctx)
		r.state["frps"] = "active"
		return nil
	}
	if err = waitSOCKS(plan.SocksPort, 30); err != nil {
		return err
	}
	common, proxies, err := frpClientConfig(plan.FRP)
	if err != nil {
		return fmt.Errorf("frpc config: %w", err)
	}
	service, err := frpclient.NewService(frpclient.ServiceOptions{Common: common, ProxyCfgs: proxies})
	if err != nil {
		return fmt.Errorf("frpc: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	r.frpc, r.frpcCancel, r.frpcDone = service, cancel, done
	go func() {
		defer close(done)
		_ = service.Run(ctx) // loginFailExit=false: keeps retrying through SOCKS
	}()
	r.state["frpc"] = "active"
	return nil
}

func (r *Runtime) startBoxLocked(plan *Plan) error {
	ctx, options, err := singBoxOptions(plan.SingBox)
	if err != nil {
		return err
	}
	if options.Log != nil {
		options.Log.DisableColor = true // plain text for journald
	}
	ctx, cancel := context.WithCancel(ctx)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	if err != nil {
		cancel()
		return err
	}
	if err = instance.Start(); err != nil {
		instance.Close()
		cancel()
		return err
	}
	r.box, r.boxCancel = instance, cancel
	return nil
}

func (r *Runtime) stopLocked() {
	if r.frpc != nil {
		// Cancelling Run's context makes Run stop the service itself; calling
		// Close concurrently with that would race inside frp.
		r.frpcCancel()
		select {
		case <-r.frpcDone:
		case <-time.After(5 * time.Second):
		}
		r.frpc, r.frpcCancel, r.frpcDone = nil, nil, nil
	}
	if r.frps != nil {
		r.frps.Close()
		r.frpsCancel()
		r.frps, r.frpsCancel = nil, nil
		// Proxy listeners close asynchronously with their control connection.
		time.Sleep(200 * time.Millisecond)
	}
	r.stopBoxLocked()
	for key := range r.state {
		r.state[key] = "inactive"
	}
}

func (r *Runtime) stopBoxLocked() {
	if r.box != nil {
		r.box.Close()
		r.boxCancel()
		r.box, r.boxCancel = nil, nil
	}
}

// stopProxy stops only sing-box; used to prove frpc never falls back to a
// direct connection.
func (r *Runtime) stopProxy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.stopBoxLocked()
	r.state["sing-box"] = "inactive"
	r.notifyLocked()
}

// waitSOCKS confirms the loopback SOCKS5 entry answers a no-auth handshake.
func waitSOCKS(number, attempts int) error {
	for attempt := 0; attempt < attempts; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(number)), time.Second)
		if err != nil {
			continue
		}
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		reply := make([]byte, 2)
		_, err = connection.Write([]byte{5, 1, 0})
		if err == nil {
			_, err = readFull(connection, reply)
		}
		connection.Close()
		if err == nil && reply[0] == 5 && reply[1] == 0 {
			return nil
		}
	}
	return errors.New("sing-box SOCKS entry is unavailable; refusing direct frpc fallback")
}

func readFull(connection net.Conn, buffer []byte) (int, error) {
	total := 0
	for total < len(buffer) {
		n, err := connection.Read(buffer[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
