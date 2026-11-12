package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func serviceUnit() string { return binaryName() + ".service" }

func unitPath() string { return filepath.Join("/etc/systemd/system", serviceUnit()) }

func serviceInstalled() bool { return runtime.GOOS == "linux" && exists(unitPath()) }

// Units of the previous Python deployment, migrated away by install.
func legacyUnits() []string {
	frp := map[string]string{roleRelay: "frps", roleHome: "frpc"}[role]
	return []string{"openplayx-" + role + "-manager.service", "openplayx-" + role + "-sing-box.service", "openplayx-" + role + "-" + frp + ".service"}
}

func systemctl(args ...string) error {
	command := exec.Command("systemctl", args...)
	command.Stdout, command.Stderr = io.Discard, io.Discard
	return command.Run()
}

func requireRootLinux() error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("requires Linux, systemd and root")
	}
	return nil
}

func installFlags(name string) (*string, *string, *bool, []string) {
	flags, directory := newFlags(name)
	prefix := flags.String("prefix", "/opt/openplayx-"+role, "installation prefix for binary releases")
	enableLAN := flags.Bool("enable-lan", false, "Home only: migrate an existing loopback configuration to LAN access")
	_ = flags.Parse(os.Args[2:])
	return directory, prefix, enableLAN, flags.Args()
}

func unitText(prefix, directory string) string {
	return fmt.Sprintf(`[Unit]
Description=OpenPlayX %[1]s (manager + embedded sing-box + %[4]s)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=%[2]s
Group=%[2]s
ExecStart=%[3]s/current/%[2]s serve --config-dir %[5]s
Restart=on-failure
RestartSec=5
UMask=0077
LimitNOFILE=65535
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=%[5]s
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
`, role, binaryName(), prefix, map[string]string{roleRelay: "frps", roleHome: "frpc"}[role], directory)
}

// ensureAccount creates the dedicated system account the service runs as.
func ensureAccount() (int, int, error) {
	name := binaryName()
	if _, err := user.Lookup(name); err != nil {
		// The previous Python installer created a system group of this name
		// for its components; reuse it instead of failing on --user-group.
		group := []string{"--user-group"}
		if _, err := user.LookupGroup(name); err == nil {
			group = []string{"--gid", name}
		}
		args := append([]string{"--system"}, group...)
		args = append(args, "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", name)
		command := exec.Command("useradd", args...)
		if output, err := command.CombinedOutput(); err != nil {
			return 0, 0, fmt.Errorf("useradd: %v: %s", err, strings.TrimSpace(string(output)))
		}
	}
	account, err := user.Lookup(name)
	if err != nil {
		return 0, 0, err
	}
	uid, _ := strconv.Atoi(account.Uid)
	gid, _ := strconv.Atoi(account.Gid)
	return uid, gid, nil
}

func chownTree(directory string, uid, gid int) error {
	return filepath.Walk(directory, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(path, uid, gid)
	})
}

// restoreOwnership keeps a service-owned directory readable by the service
// after a root CLI command wrote files into it.
func restoreOwnership(directory string) {
	if os.Geteuid() != 0 {
		return
	}
	info, err := os.Stat(directory)
	if err != nil {
		return
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid == 0 {
		return
	}
	_ = chownTree(directory, int(stat.Uid), int(stat.Gid))
}

func copyExecutable(destination string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	if source, err = filepath.EvalSymlinks(source); err != nil {
		return err
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o755)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	if closeErr := output.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(destination, 0o755)
	}
	return err
}

func switchLink(link, target string) error {
	temporary := link + ".next"
	_ = os.Remove(temporary)
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	return os.Rename(temporary, link)
}

// isGoRelease reports whether a release directory holds this Go binary
// rather than a release of the previous Python deployment.
func isGoRelease(directory string) bool { return exists(filepath.Join(directory, binaryName())) }

func waitActive() error {
	time.Sleep(2 * time.Second)
	return systemctl("is-active", "--quiet", serviceUnit())
}

func cmdInstall(_ []string) error {
	directoryFlag, prefixFlag, enableLAN, _ := installFlags(os.Args[1])
	if *enableLAN && role != roleHome {
		return errors.New("--enable-lan is only supported by Home")
	}
	if err := requireRootLinux(); err != nil {
		return err
	}
	directory, err := filepath.Abs(*directoryFlag)
	if err != nil {
		return err
	}
	prefix, err := filepath.Abs(*prefixFlag)
	if err != nil {
		return err
	}
	if strings.ContainsAny(directory+prefix, " \t\n") {
		return errors.New("paths cannot contain whitespace")
	}
	uid, gid, err := ensureAccount()
	if err != nil {
		return err
	}
	if err = os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err = os.Chmod(directory, 0o700); err != nil {
		return err
	}
	store, err := NewStore(directory, role)
	if err != nil {
		return err
	}
	if *enableLAN {
		if _, err = store.enableLAN(); err != nil {
			return err
		}
	}
	if err = NewAdmin(store.dir).bootstrap(false); err != nil {
		return err
	}
	if err = chownTree(store.dir, uid, gid); err != nil {
		return err
	}
	releases := filepath.Join(prefix, "releases")
	if err = os.MkdirAll(releases, 0o755); err != nil {
		return err
	}
	release := filepath.Join(releases, strconv.FormatInt(time.Now().UnixNano(), 10))
	if err = os.Mkdir(release, 0o755); err != nil {
		return err
	}
	// The process umask is 077; the service account must be able to traverse
	// to and execute the binary, which holds no secrets.
	for _, directory := range []string{prefix, releases, release} {
		if err = os.Chmod(directory, 0o755); err != nil {
			return err
		}
	}
	if err = copyExecutable(filepath.Join(release, binaryName())); err != nil {
		return err
	}
	current := filepath.Join(prefix, "current")
	// oldTarget may be a release of the previous Python deployment, whose
	// units start components through current/bin; previous is only ever a
	// Go release, usable by rollback.
	oldTarget, _ := filepath.EvalSymlinks(current)
	previous := ""
	if oldTarget != "" && isGoRelease(oldTarget) {
		previous = oldTarget
	}
	// Stop the previous Python units (same ports) but keep their unit files
	// until the new service is confirmed active, so a failure can restore them.
	legacy := []string{}
	for _, unit := range legacyUnits() {
		path := filepath.Join("/etc/systemd/system", unit)
		if exists(path) {
			legacy = append(legacy, unit)
		}
	}
	for _, unit := range legacy {
		_ = systemctl("disable", "--now", unit)
	}
	if err = os.WriteFile(unitPath(), []byte(unitText(prefix, store.dir)), 0o644); err != nil {
		return err
	}
	if err = switchLink(current, release); err != nil {
		return err
	}
	started := systemctl("daemon-reload")
	if started == nil {
		started = systemctl("enable", serviceUnit())
	}
	if started == nil {
		started = systemctl("restart", serviceUnit())
	}
	if started == nil {
		started = waitActive()
	}
	if started != nil {
		if oldTarget != "" {
			_ = switchLink(current, oldTarget)
		} else {
			_ = os.Remove(current)
		}
		if previous != "" {
			_ = systemctl("restart", serviceUnit())
		} else {
			_ = systemctl("disable", "--now", serviceUnit())
			_ = os.Remove(unitPath())
			_ = systemctl("daemon-reload")
			for _, unit := range legacy {
				_ = systemctl("enable", "--now", unit)
			}
		}
		return fmt.Errorf("service failed to start; previous installation restored (see journalctl -u %s)", serviceUnit())
	}
	if previous != "" {
		_ = switchLink(filepath.Join(prefix, "previous"), previous)
	}
	// Convenience command path for status/apply/check; only replaced when it
	// is absent or already ours.
	command := filepath.Join("/usr/local/bin", binaryName())
	if target, err := os.Readlink(command); err != nil && !exists(command) || err == nil && strings.HasPrefix(target, prefix+"/") {
		_ = switchLink(command, filepath.Join(current, binaryName()))
	}
	for _, unit := range legacy {
		_ = os.Remove(filepath.Join("/etc/systemd/system", unit))
	}
	if len(legacy) > 0 {
		_ = systemctl("daemon-reload")
		fmt.Println("Removed previous Python units:", strings.Join(legacy, ", "))
	}
	fmt.Printf("Installed %s %s as %s (config %s).\n", binaryName(), version, serviceUnit(), store.dir)
	if exists(store.file("bootstrap-token")) {
		fmt.Println("No administrator password yet: read bootstrap-token in", store.dir, "to sign in (15 minute expiry).")
	}
	return nil
}

func cmdRollback(_ []string) error {
	_, prefixFlag, _, _ := installFlags("rollback")
	if err := requireRootLinux(); err != nil {
		return err
	}
	prefix, err := filepath.Abs(*prefixFlag)
	if err != nil {
		return err
	}
	previous, err := filepath.EvalSymlinks(filepath.Join(prefix, "previous"))
	if err != nil || !isGoRelease(previous) {
		return errors.New("no previous release")
	}
	current, _ := filepath.EvalSymlinks(filepath.Join(prefix, "current"))
	if err = switchLink(filepath.Join(prefix, "current"), previous); err != nil {
		return err
	}
	if err = systemctl("restart", serviceUnit()); err == nil {
		err = waitActive()
	}
	if err != nil {
		if current != "" {
			_ = switchLink(filepath.Join(prefix, "current"), current)
			_ = systemctl("restart", serviceUnit())
		}
		return errors.New("previous release failed to start; current release restored")
	}
	if current != "" {
		_ = switchLink(filepath.Join(prefix, "previous"), current)
	}
	fmt.Println("Rolled back to", previous)
	return nil
}

func cmdUninstall(_ []string) error {
	_, prefixFlag, _, _ := installFlags("uninstall")
	if err := requireRootLinux(); err != nil {
		return err
	}
	_ = systemctl("disable", "--now", serviceUnit())
	_ = os.Remove(unitPath())
	command := filepath.Join("/usr/local/bin", binaryName())
	if target, err := os.Readlink(command); err == nil && strings.HasPrefix(target, *prefixFlag+"/") {
		_ = os.Remove(command)
	}
	_ = systemctl("daemon-reload")
	fmt.Println("Service removed. Configuration, credentials and releases preserved at", *prefixFlag, "and the config directory.")
	return nil
}

// systemdController applies a revision to the installed service from the
// CLI: the service starts last-good.json at boot and publishes runtime.json.
type systemdController struct{ store *Store }

func (c *systemdController) Restart(cfg obj, plan *Plan) error {
	if err := atomicWrite(c.store.file("last-good.json"), cfg); err != nil {
		return err
	}
	restoreOwnership(c.store.dir)
	since := time.Now().UnixNano()
	if err := systemctl("restart", serviceUnit()); err != nil {
		return err
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		state, err := readObj(c.store.file("runtime.json"))
		if err != nil {
			continue
		}
		updated, _ := intValue(state["updatedAt"])
		if updated < since {
			continue
		}
		components, _ := state["components"].(obj)
		failed, active := false, len(components) > 0
		for _, value := range components {
			failed = failed || value == "failed"
			active = active && value == "active"
		}
		if failed {
			return errors.New("components failed to start")
		}
		if active && canonical(state["revision"]) == canonical(plan.Revision) {
			return nil
		}
	}
	return errors.New("timed out waiting for components")
}

func (c *systemdController) Stop() error {
	_ = os.Remove(c.store.file("last-good.json"))
	return systemctl("restart", serviceUnit())
}

func (c *systemdController) Components() map[string]string { return c.store.recordedComponents() }
