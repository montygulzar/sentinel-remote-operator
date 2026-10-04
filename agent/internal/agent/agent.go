// Package agent wires the Sentinel components into a runnable service:
// configuration, audit log, host provider, device credential, request verifier,
// control services and the HTTP control surface. It owns process lifecycle
// (start, graceful shutdown) but no business logic of its own.
package agent

import (
	"context"
	"fmt"
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
	cfg    config.Config
	log    *audit.Logger
	server *http.Server
}

// Build loads configuration from configPath and assembles the agent. A device
// credential is created on first run (spec §13). The raw credential key is
// never logged.
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

	cred, created, err := auth.NewFileStore(cfg.CredentialPath()).Ensure()
	if err != nil {
		log.Close()
		return nil, fmt.Errorf("init device credential: %w", err)
	}
	if created {
		log.Log(audit.ClassSecurity, "generated new device credential %s", cred.DeviceID)
	}

	verifier := auth.NewVerifier(cred, time.Duration(cfg.Auth.TimestampSkew))
	panicSvc := control.NewPanicService(provider, log, cfg.Panic.CloseApps)
	handler := api.New(provider, log, verifier, panicSvc).Handler()

	server := &http.Server{
		Addr:              cfg.Listen,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	return &App{cfg: cfg, log: log, server: server}, nil
}

// Run serves the control API until ctx is cancelled, then shuts down gracefully.
// It fails safe: any listener error other than a clean shutdown is returned so
// the supervising service can react (spec §10).
func (a *App) Run(ctx context.Context) error {
	a.log.Log(audit.ClassInfo, "Sentinel Agent started on %s", a.cfg.Listen)

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

// Close releases the agent's resources (currently the audit log file).
func (a *App) Close() {
	if a.log != nil {
		a.log.Close()
	}
}

// Config exposes the loaded configuration (used by the CLI for diagnostics).
func (a *App) Config() config.Config { return a.cfg }
