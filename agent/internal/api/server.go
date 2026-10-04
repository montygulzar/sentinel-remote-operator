// Package api exposes the Sentinel control surface over HTTP. The route set is
// deliberately narrow and fully typed (spec §15, §18); every route is
// authenticated. Read routes return the real host read-models; control routes
// return structured results.
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
	provider platform.Provider
	log      *audit.Logger
	verifier *auth.Verifier
	panic    *control.PanicService
}

// New constructs a Server from its collaborators.
func New(p platform.Provider, log *audit.Logger, verifier *auth.Verifier, panicSvc *control.PanicService) *Server {
	return &Server{provider: p, log: log, verifier: verifier, panic: panicSvc}
}

// Handler returns the fully-routed, authenticated HTTP handler. Go's method +
// path routing gives a correct 405 for a known path hit with the wrong method
// and 404 for an unknown path, with no custom dispatch code.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// Milestone 1 surface (spec §15): status, activity, logs; lock, mute, panic.
	mux.HandleFunc("GET /v1/status", s.authenticated(s.handleStatus))
	mux.HandleFunc("GET /v1/activity", s.authenticated(s.handleActivity))
	mux.HandleFunc("GET /v1/logs", s.authenticated(s.handleLogs))
	mux.HandleFunc("POST /v1/control/lock", s.authenticated(s.handleLock))
	mux.HandleFunc("POST /v1/control/mute", s.authenticated(s.handleMute))
	mux.HandleFunc("POST /v1/control/panic", s.authenticated(s.handlePanic))

	return mux
}
