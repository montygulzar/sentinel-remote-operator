// Package agent wires the Sentinel components into a runnable service:
// configuration, audit log, host provider, device registry, admin key, request
// authenticator, pairing manager, control services and the HTTP control
// surface. It owns process lifecycle (start, graceful shutdown) but no business
// logic of its own.
package agent

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/api"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/config"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/control"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

// App is a fully-wired, runnable agent instance.
type App struct {
	cfg      config.Config
	log      *audit.Logger
	registry *auth.Registry
	server   *http.Server
}

// Build loads configuration from configPath and assembles the agent. The
// authorized-device registry and the owner/admin key are loaded (the admin key
// generated on first run), both protected at rest. No secret is ever logged.
func Build(configPath string) (*App, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, err
	}

	log, err := audit.New(cfg.LogsDir(), cfg.Log.RetentionDays)
	if err != nil {
		return nil, fmt.Errorf("init audit log: %w", err)
	}

	provider := platform.New(cfg.DeviceName)
	protector := auth.NewProtector()

	registry, err := auth.OpenRegistry(cfg.DevicesPath(), protector)
	if err != nil {
		log.Close()
		return nil, fmt.Errorf("open device registry: %w", err)
	}

	adminKey, created, err := auth.EnsureSecret(cfg.AdminKeyPath(), protector, 32)
	if err != nil {
		log.Close()
		return nil, fmt.Errorf("init admin key: %w", err)
	}
	if created {
		log.Log(audit.ClassSecurity, "generated owner/admin key")
	}

	skew := time.Duration(cfg.Auth.TimestampSkew)
	authn := auth.NewAuthenticator(registry, adminKey, skew)
	pairing := auth.NewPairingManager(registry, log, time.Duration(cfg.Pairing.TTL), skew)
	panicSvc := control.NewPanicService(provider, log, cfg.Panic.CloseApps)
	handler := api.New(provider, log, authn, pairing, registry, panicSvc, cfg.AdminLoopbackOnly).Handler()

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return &App{cfg: cfg, log: log, registry: registry, server: server}, nil
}

// Run serves the control API until ctx is cancelled, then shuts down gracefully.
// It fails safe: any listener error other than a clean shutdown is returned so
// the supervising service can react (spec §10).
func (a *App) Run(ctx context.Context) error {
	a.log.Log(audit.ClassInfo, "Sentinel Agent listening on %s (%d authorized device(s))", a.cfg.Listen, a.registry.Count())
	if !listenIsLoopback(a.cfg.Listen) {
		// Binding beyond loopback is a deliberate choice for overlay-network
		// reach. Authentication is unchanged and still required for every
		// request; this note records the wider exposure without any secret.
		a.log.Log(audit.ClassSecurity, "listening on non-loopback address %s; every request still requires device authentication over the private overlay", a.cfg.Listen)
	}

	errCh := make(chan error, 1)
	go func() {
		err := a.server.ListenAndServe()
		if err != nil && err != http.ErrServerClosed {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		a.log.Log(audit.ClassInfo, "Sentinel Agent stopping")
		if err := a.server.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("graceful shutdown: %w", err)
		}
		return nil
	case err := <-errCh:
		if err != nil {
			a.log.Log(audit.ClassError, "listener failed: %v", err)
		}
		return err
	}
}

// Close releases the agent's resources: it persists the device registry (so
// last-seen times survive) and closes the audit log file.
func (a *App) Close() {
	if a.registry != nil {
		if err := a.registry.Save(); err != nil && a.log != nil {
			a.log.Log(audit.ClassError, "persist device registry on shutdown: %v", err)
		}
	}
	if a.log != nil {
		a.log.Close()
	}
}

// Config exposes the loaded configuration (used by the CLI for diagnostics).
func (a *App) Config() config.Config { return a.cfg }

// listenIsLoopback reports whether addr binds only to a loopback interface. A
// hostless address (e.g. ":8787") or a wildcard binds to all interfaces.
func listenIsLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
