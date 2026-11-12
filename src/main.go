// Command openplayx-relay / openplayx-home is a single Go service: the Web
// configuration manager plus embedded sing-box and frp (frps on Relay, frpc
// on Home). No Python runtime or separately downloaded proxy binaries.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const (
	singBoxVersion = "1.12.12"
	frpVersion     = "0.65.0"
)

func binaryName() string { return "openplayx-" + role }

func defaultConfigDir() string { return "/var/lib/openplayx-" + role }

func discardLogger() *log.Logger { return log.New(io.Discard, "", 0) }

func usage() {
	fmt.Fprintf(os.Stderr, `%[1]s %[2]s (sing-box %[3]s, frp %[4]s)

Usage: %[1]s <command> [flags]

Commands:
  serve            run the Web manager and the embedded sing-box/%[5]s (default)
  apply            apply the saved revision to the installed systemd service
  status           print saved/applied revision and component state
  check            validate the saved configuration with the embedded upstream checks
  render           write derived sing-box/%[5]s configuration for inspection
  import-legacy    initialise from an old flat deployment.json
  renew-bootstrap  issue a new 15 minute local bootstrap credential
`, binaryName(), version, singBoxVersion, frpVersion, map[string]string{roleRelay: "frps", roleHome: "frpc"}[role])
	if role == roleRelay {
		fmt.Fprintln(os.Stderr, "  pair             create relay/, home/ and App pairing bundles")
	} else {
		fmt.Fprintln(os.Stderr, "  enable-lan       save LAN management access for an existing configuration")
	}
	fmt.Fprintf(os.Stderr, `  install          install or update this binary as a systemd service (Linux, root)
  update           same as install
  rollback         switch the service back to the previous installed binary
  uninstall        remove the systemd service, keeping configuration and releases
  version          print versions

Run "%s <command> -h" for flags.
`, binaryName())
}

func main() {
	log.SetFlags(log.LstdFlags)
	syscall.Umask(0o077)
	args := os.Args[1:]
	command := "serve"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		command, args = args[0], args[1:]
	}
	var err error
	switch command {
	case "serve":
		err = cmdServe(args)
	case "apply":
		err = cmdApply(args)
	case "status":
		err = cmdStatus(args)
	case "check", "render":
		err = cmdCheck(command, args)
	case "import-legacy":
		err = cmdImportLegacy(args)
	case "renew-bootstrap":
		err = cmdRenewBootstrap(args)
	case "enable-lan":
		err = cmdEnableLAN(args)
	case "pair":
		if role != roleRelay {
			err = errors.New("pair is only available on Relay")
		} else {
			err = cmdPair(args)
		}
	case "install", "update":
		err = cmdInstall(args)
	case "rollback":
		err = cmdRollback(args)
	case "uninstall":
		err = cmdUninstall(args)
	case "version", "--version", "-version":
		fmt.Printf("%s %s\nsing-box %s\nfrp %s\n", binaryName(), version, singBoxVersion, frpVersion)
	case "help", "-h", "--help":
		usage()
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		var configError *ConfigError
		if errors.As(err, &configError) {
			fmt.Fprintln(os.Stderr, configError.Code+": "+configError.Message)
		} else {
			fmt.Fprintln(os.Stderr, "Operation failed:", err)
		}
		os.Exit(1)
	}
}

func newFlags(name string) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(binaryName()+" "+name, flag.ExitOnError)
	directory := flags.String("config-dir", defaultConfigDir(), "private configuration directory")
	return flags, directory
}

// openStore opens the state directory. When a root CLI command modifies a
// directory owned by the service account, ownership is restored afterwards.
func openStore(directory string) (*Store, func(), error) {
	store, err := NewStore(directory, role)
	if err != nil {
		return nil, nil, err
	}
	return store, func() { restoreOwnership(store.dir) }, nil
}

func cmdServe(args []string) error {
	flags, directory := newFlags("serve")
	_ = flags.Parse(args)
	store, err := NewStore(*directory, role)
	if err != nil {
		return err
	}
	management, err := func() (obj, error) {
		cfg, err := store.load()
		if err != nil {
			return nil, err
		}
		management := cfg["management"].(obj)
		if role == roleHome {
			return management, store.validateManagement(management)
		}
		_, _, public := frontendEndpoint(management)
		if listen, err := netip.ParseAddr(stringValue(management["listen"])); err != nil || !listen.Unmap().IsLoopback() || public {
			values, err := store.secrets()
			if err != nil {
				return nil, err
			}
			if _, err = store.validate(cfg, values); err != nil {
				return nil, err
			}
		}
		return management, nil
	}()
	if err != nil {
		// Recovery uses a fixed safe loopback listener, never guessed public
		// settings, and never writes defaults over the unrecognised file.
		management = store.blank()["management"].(obj)
		management["listen"] = "127.0.0.1"
		fmt.Println("Configuration unavailable; using authenticated loopback recovery. Original files preserved.")
	}
	runtime := NewRuntime(role)
	runtime.onChange = store.writeRuntimeState
	store.controller = runtime
	server, err := NewManagerServer(store, management, "")
	if err != nil {
		return err
	}
	store.writeRuntimeState(nil, runtime.Components())
	listenPort, _ := port(management["port"])
	fmt.Printf("OpenPlayX %s manager: %s://%s:%d\n", role, server.scheme, management["listen"], listenPort)
	if role == roleHome && (management["listen"] == "0.0.0.0" || management["listen"] == "::") {
		fmt.Printf("LAN access: %s://<Home LAN IP>:%d\n", server.scheme, listenPort)
	}
	if exists(store.file("bootstrap-token")) {
		fmt.Println("Read local bootstrap-token in the private config directory to sign in (15 minute expiry).")
	}
	if frontendIP, frontendPort, ok := frontendEndpoint(management); ok && role == roleRelay {
		address := net.JoinHostPort(frontendIP.String(), strconv.Itoa(frontendPort))
		feed, err := server.serveFrontend(&net.TCPAddr{IP: net.IP(frontendIP.AsSlice()), Port: frontendPort})
		if err != nil {
			return err
		}
		// A failed bind (wrong IP, port still held by another program) must
		// not take down the manager or the components.
		if frontend, err := NewFrontend(address, feed, runtime.proxyTarget); err != nil {
			log.Printf("public TLS entry %s unavailable: %v; manager and components keep running", address, err)
		} else {
			defer frontend.Close()
			go frontend.Serve()
			fmt.Printf("Public TLS entry: %s (SNI of the applied proxy.serverName -> sing-box, other TLS -> manager)\n", address)
		}
	}
	go startApplied(store, runtime)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-signals
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	}()
	err = server.Serve()
	_ = runtime.Stop()
	return err
}

// startApplied runs the last successfully applied revision at boot. A
// failure leaves the manager running so the administrator can fix it.
func startApplied(store *Store, runtime *Runtime) {
	store.applyMu.Lock()
	defer store.applyMu.Unlock()
	applied := store.readOptional("last-good.json")
	if applied == nil {
		fmt.Println("No applied revision yet; components stay stopped until a saved revision is applied.")
		return
	}
	values, err := store.secrets()
	if err != nil {
		log.Printf("cannot read secrets: %v", err)
		return
	}
	plan, err := store.plan(applied, values)
	if err != nil {
		logRedacted("applied revision is no longer valid: %v", values, err)
		runtime.mu.Lock()
		runtime.state["sing-box"], runtime.state[runtime.frpName()] = "failed", "failed"
		runtime.notifyLocked()
		runtime.mu.Unlock()
		return
	}
	if err = runtime.Restart(applied, plan); err == nil {
		fmt.Printf("Started components for applied revision %v.\n", applied["revision"])
	}
}

func cmdApply(args []string) error {
	flags, directory := newFlags("apply")
	_ = flags.Parse(args)
	store, done, err := openStore(*directory)
	if err != nil {
		return err
	}
	defer done()
	if !serviceInstalled() {
		return errors.New("the systemd service is not installed; apply from the running Web manager instead")
	}
	cfg, err := store.load()
	if err != nil {
		return err
	}
	result, err := store.apply(cfg["revision"], &systemdController{store: store})
	if err != nil {
		return err
	}
	fmt.Println("Applied revision", result["appliedRevision"])
	return nil
}

func cmdStatus(args []string) error {
	flags, directory := newFlags("status")
	_ = flags.Parse(args)
	store, err := NewStore(*directory, role)
	if err != nil {
		return err
	}
	status, err := store.status()
	if err != nil {
		return err
	}
	data, err := encodeJSON(status)
	if err != nil {
		return err
	}
	_, err = os.Stdout.Write(data)
	return err
}

func cmdCheck(command string, args []string) error {
	flags, directory := newFlags(command)
	output := flags.String("output", "generated", "render: output directory")
	_ = flags.Parse(args)
	store, err := NewStore(*directory, role)
	if err != nil {
		return err
	}
	cfg, err := store.load()
	if err != nil {
		return err
	}
	values, err := store.secrets()
	if err != nil {
		return err
	}
	plan, err := store.plan(cfg, values)
	if err != nil {
		var configError *ConfigError
		if !errors.As(err, &configError) {
			logRedacted("%v", values, err)
			return cfgErr("componentCheckFailed", "组件配置校验失败；请检查证书、凭据与内置组件配置。")
		}
		return err
	}
	if command == "render" {
		absolute, _ := filepath.Abs(*output)
		if err = writeRendered(plan, absolute, store.frpName()); err != nil {
			return err
		}
		fmt.Println("Rendered revision", cfg["revision"], "to", absolute, "(files contain credentials)")
		return nil
	}
	fmt.Println("Revision", cfg["revision"], "passed sing-box and", store.frpName(), "checks.")
	return nil
}

func cmdImportLegacy(args []string) error {
	flags, directory := newFlags("import-legacy")
	file := flags.String("file", "", "old deployment.json (required)")
	homeID := flags.String("home-id", "", "stable home ID (default: from the file, or home-main)")
	_ = flags.Parse(args)
	if *file == "" {
		return errors.New("--file is required")
	}
	store, done, err := openStore(*directory)
	if err != nil {
		return err
	}
	defer done()
	raw, err := readObj(*file)
	if err != nil {
		return err
	}
	if _, err = store.importLegacy(raw, *homeID); err != nil {
		return err
	}
	fmt.Println("Imported into", store.path, "; not applied.")
	return nil
}

func cmdRenewBootstrap(args []string) error {
	flags, directory := newFlags("renew-bootstrap")
	_ = flags.Parse(args)
	store, done, err := openStore(*directory)
	if err != nil {
		return err
	}
	defer done()
	if err = NewAdmin(store.dir).bootstrap(true); err != nil {
		return err
	}
	fmt.Println("Renewed local bootstrap credential file; expires in 15 minutes.")
	return nil
}

func cmdEnableLAN(args []string) error {
	flags, directory := newFlags("enable-lan")
	_ = flags.Parse(args)
	store, done, err := openStore(*directory)
	if err != nil {
		return err
	}
	defer done()
	cfg, err := store.enableLAN()
	if err != nil {
		return err
	}
	fmt.Println("Saved Home LAN management access on port", cfg["management"].(obj)["port"], "; restart the service to use it.")
	return nil
}
