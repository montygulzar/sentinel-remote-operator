// Command sentinel-agent is the Windows-side Sentinel agent (spec §1). It runs
// the authenticated control API for an owner's Operator client.
//
// Subcommands:
//
//	run         Run the agent in the foreground (default).
//	credential  Print this agent's device credential for Operator provisioning.
//	version     Print version information.
//
// Windows service installation and quiet (no-console) startup are Milestone 8
// packaging concerns; this binary runs correctly in the foreground today.
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/agent"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/config"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "sentinel-agent:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "run"
	rest := args
	if len(args) > 0 && !isFlag(args[0]) {
		cmd, rest = args[0], args[1:]
	}

	switch cmd {
	case "run":
		return cmdRun(rest)
	case "credential":
		return cmdCredential(rest)
	case "version":
		fmt.Printf("sentinel-agent %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (use run, credential, or version)", cmd)
	}
}

func isFlag(s string) bool { return len(s) > 0 && s[0] == '-' }

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultConfigPath(), "path to config file (created with defaults if missing)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	app, err := agent.Build(*configPath)
	if err != nil {
		return err
	}
	defer app.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	return app.Run(ctx)
}

// cmdCredential ensures the device credential exists and prints it so the owner
// can provision their Operator client. This is the one intentional place the
// secret is emitted; it goes to stdout, never to the audit log.
func cmdCredential(args []string) error {
	fs := flag.NewFlagSet("credential", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}
	cred, _, err := auth.NewFileStore(cfg.CredentialPath()).Ensure()
	if err != nil {
		return err
	}

	fmt.Println("Sentinel device credential (provision this into Operator; keep it secret):")
	fmt.Printf("  deviceId: %s\n", cred.DeviceID)
	fmt.Printf("  key:      %s\n", base64.StdEncoding.EncodeToString(cred.Key))
	return nil
}
