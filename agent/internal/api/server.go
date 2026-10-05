// Package api exposes the Sentinel control surface over HTTP. The route set is
// deliberately narrow and fully typed (spec §15, §18). Device routes require a
// valid per-device signature; owner/admin routes (pairing, device management)
// require the admin key and, by default, a local-machine origin. The pairing
// route authenticates with the one-time pairing code itself.
package api

import (
	"net/http"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/control"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

// Server holds the agent's HTTP dependencies.
type Server struct {
	provider          platform.Provider
	log               *audit.Logger
	auth              *auth.Authenticator
	pairing           *auth.PairingManager
	registry          *auth.Registry
	panic             *control.PanicService
	adminLoopbackOnly bool
}

// New constructs a Server from its collaborators.
func New(
	p platform.Provider,
	log *audit.Logger,
	authn *auth.Authenticator,
	pairing *auth.PairingManager,
	registry *auth.Registry,
	panicSvc *control.PanicService,
	adminLoopbackOnly bool,
) *Server {
	return &Server{
		provider:          p,
		log:               log,
		auth:              authn,
		pairing:           pairing,
		registry:          registry,
		panic:             panicSvc,
		adminLoopbackOnly: adminLoopbackOnly,
	}
}

// Handler returns the fully-routed HTTP handler. Go's method + path routing
// gives a correct 405 for a known path hit with the wrong method and 404 for an
// unknown path, with no custom dispatch code.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Device control surface (spec §15): status, activity, logs; lock, mute,
	// panic. Each requires a valid per-device signature.
	mux.HandleFunc("GET /v1/status", s.deviceAuth(s.handleStatus))
	mux.HandleFunc("GET /v1/activity", s.deviceAuth(s.handleActivity))
	mux.HandleFunc("GET /v1/logs", s.deviceAuth(s.handleLogs))
	mux.HandleFunc("GET /v1/screen/grab", s.deviceAuth(s.handleScreenGrab))
	mux.HandleFunc("POST /v1/control/lock", s.deviceAuth(s.handleLock))
	mux.HandleFunc("POST /v1/control/mute", s.deviceAuth(s.handleMute))
	mux.HandleFunc("POST /v1/control/panic", s.deviceAuth(s.handlePanic))

	// Pairing: authenticated by the one-time pairing code (spec §13).
	mux.HandleFunc("POST /v1/pair", s.handlePair)

	// Owner/admin surface: pairing initiation and device management.
	mux.HandleFunc("POST /v1/admin/pairing/start", s.adminAuth(s.handlePairingStart))
	mux.HandleFunc("POST /v1/admin/pairing/cancel", s.adminAuth(s.handlePairingCancel))
	mux.HandleFunc("GET /v1/admin/devices", s.adminAuth(s.handleDevicesList))
	mux.HandleFunc("POST /v1/admin/devices/revoke", s.adminAuth(s.handleDevicesRevoke))

	return mux
}
