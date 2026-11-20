// Copyright 2026 OpenPlayX contributors. Licensed under Apache-2.0.
package server

import (
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// LockProxyUpdates freezes registrations across plugin approval and binding.
func (svr *Service) LockProxyUpdates()   { svr.managedProxyGate.Lock() }
func (svr *Service) UnlockProxyUpdates() { svr.managedProxyGate.Unlock() }

// PruneManagedProxies closes only disallowed TCP proxies. Call while holding
// the exclusive update gate. Allowed proxies and control connections stay live.
func (svr *Service) PruneManagedProxies(keep func(user, name string, port int) bool) error {
	svr.ctlManager.mu.RLock()
	controls := make([]*Control, 0, len(svr.ctlManager.ctlsByRunID))
	for _, ctl := range svr.ctlManager.ctlsByRunID {
		controls = append(controls, ctl)
	}
	svr.ctlManager.mu.RUnlock()
	for _, ctl := range controls {
		ctl.mu.RLock()
		names := []string{}
		for name, proxy := range ctl.proxies {
			cfg, ok := proxy.GetConfigurer().(*v1.TCPProxyConfig)
			if !ok || !keep(ctl.loginMsg.User, name, cfg.RemotePort) {
				names = append(names, name)
			}
		}
		ctl.mu.RUnlock()
		for _, name := range names {
			if err := ctl.CloseProxy(&msg.CloseProxy{ProxyName: name}); err != nil {
				return err
			}
		}
	}
	return nil
}
