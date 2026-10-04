// Command sentinel-agent is the Windows-side Sentinel agent (spec §1). It runs
// the authenticated control API for an owner's Operator client, and provides
// local owner tooling to pair and manage Operator devices.
//
// Subcommands:
//
//	run              Run the agent in the foreground (default).
//	pair             Open a pairing window and print the one-time code for an Operator.
//	devices          List authorized Operator devices.
//	revoke           Revoke an Operator device by id.
//	diagnose-screen  Locally capture one screen frame to a file (field verification).
//	version          Print version information.
//
// The pair/devices/revoke commands talk to the running agent over loopback and
// authenticate with the owner/admin key read from the protected local store;
// they never print or transmit a permanent device secret.
//
// Windows service installation and quiet (no-console) startup are Milestone 8
// packaging concerns; this binary runs correctly in the foreground today.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/agent"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/config"
)

// version is overridable at build time via -ldflags "-X main.version=...".
var version = "0.2.0-dev"

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
	case "pair":
		return cmdPair(rest)
	case "devices":
		return cmdDevices(rest)
	case "revoke":
		return cmdRevoke(rest)
	case "diagnose-screen":
		return cmdDiagnoseScreen(rest)
	case "version":
		fmt.Printf("sentinel-agent %s\n", version)
		return nil
	default:
		return fmt.Errorf("unknown command %q (use run, pair, devices, revoke, diagnose-screen, or version)", cmd)
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

// cmdPair opens a pairing window on the running agent and prints the one-time
// code the owner enters into their Operator. The code is short-lived pairing
// material, not a permanent secret.
func cmdPair(args []string) error {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	addr := fs.String("addr", "", "agent admin address (default: loopback + configured port)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	var out struct {
		Code      string    `json:"code"`
		ExpiresAt time.Time `json:"expiresAt"`
	}
	if err := adminCall(cfg, *addr, http.MethodPost, "/v1/admin/pairing/start", nil, &out); err != nil {
		return err
	}
	fmt.Println("Pairing window open. In Operator, enter this one-time code:")
	fmt.Printf("\n    %s\n\n", out.Code)
	fmt.Printf("Expires at %s. The code is single-use.\n", out.ExpiresAt.Local().Format(time.RFC1123))
	return nil
}

func cmdDevices(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	addr := fs.String("addr", "", "agent admin address (default: loopback + configured port)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	var out struct {
		Devices []auth.Info `json:"devices"`
	}
	if err := adminCall(cfg, *addr, http.MethodGet, "/v1/admin/devices", nil, &out); err != nil {
		return err
	}
	if len(out.Devices) == 0 {
		fmt.Println("No authorized devices.")
		return nil
	}
	fmt.Printf("%-14s  %-20s  %-8s  %s\n", "ID", "NAME", "STATE", "CREATED")
	for _, d := range out.Devices {
		state := "active"
		if !d.Enabled {
			state = "revoked"
		}
		fmt.Printf("%-14s  %-20s  %-8s  %s\n", d.ID, d.DisplayName, state, d.CreatedAt.Local().Format(time.RFC3339))
	}
	return nil
}

func cmdRevoke(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	configPath := fs.String("config", config.DefaultConfigPath(), "path to config file")
	addr := fs.String("addr", "", "agent admin address (default: loopback + configured port)")
	id := fs.String("id", "", "device id to revoke")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *id == "" {
		return fmt.Errorf("revoke requires -id <deviceId>")
	}
	cfg, err := config.Load(*configPath)
	if err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]string{"deviceId": *id})
	var out struct {
		OK      bool `json:"ok"`
		Revoked bool `json:"revoked"`
	}
	if err := adminCall(cfg, *addr, http.MethodPost, "/v1/admin/devices/revoke", body, &out); err != nil {
		return err
	}
	if !out.Revoked {
		return fmt.Errorf("device %s not found", *id)
	}
	fmt.Printf("Device %s revoked.\n", *id)
	return nil
}

// adminCall signs and sends an admin request to the running agent and decodes
// the JSON response into out. The admin key is read from the protected local
// store, proving local owner access; it is used only to sign and is never sent.
func adminCall(cfg config.Config, addr, method, path string, body []byte, out any) error {
	key, err := loadAdminKey(cfg)
	if err != nil {
		return err
	}
	if addr == "" {
		addr = adminAddr(cfg.Listen)
	}

	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce, err := randomNonce()
	if err != nil {
		return err
	}
	sig := auth.Signature(key, auth.SignedRequest{
		DeviceID:  "admin",
		Method:    method,
		Path:      path,
		Timestamp: ts,
		Nonce:     nonce,
		Body:      body,
	})

	req, err := http.NewRequest(method, "http://"+addr+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set(auth.HeaderDevice, "admin")
	req.Header.Set(auth.HeaderTimestamp, ts)
	req.Header.Set(auth.HeaderNonce, nonce)
	req.Header.Set(auth.HeaderSignature, sig)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return fmt.Errorf("contact agent at %s: %w (is the agent running?)", addr, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("agent returned %d: %s", resp.StatusCode, bytesTrim(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			return fmt.Errorf("decode agent response: %w", err)
		}
	}
	return nil
}

// loadAdminKey loads (or, on very first use, creates) the protected owner/admin
// key shared with the agent via the same path and protector.
func loadAdminKey(cfg config.Config) ([]byte, error) {
	key, _, err := auth.EnsureSecret(cfg.AdminKeyPath(), auth.NewProtector(), 32)
	return key, err
}

// adminAddr returns a loopback host:port for reaching the agent's admin
// endpoints, derived from the configured listen address.
func adminAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return "127.0.0.1:8787"
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func randomNonce() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func bytesTrim(b []byte) string {
	const max = 200
	if len(b) > max {
		b = b[:max]
	}
	return string(bytes.TrimSpace(b))
}
