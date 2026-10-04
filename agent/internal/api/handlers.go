package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/platform"
)

// statusResponse is the GET /v1/status shape (spec §19). Optional metrics are
// pointers so an unavailable value is JSON null (rendered UNAVAILABLE by the
// Operator) rather than a misleading zero.
type statusResponse struct {
	DeviceName     string                `json:"deviceName"`
	Online         bool                  `json:"online"`
	Session        platform.SessionState `json:"session"`
	IdleSeconds    *int64                `json:"idleSeconds"`
	BatteryPercent *int                  `json:"batteryPercent"`
	CPUPercent     *int                  `json:"cpuPercent"`
	RAMPercent     *int                  `json:"ramPercent"`
	UptimeSeconds  *int64                `json:"uptimeSeconds"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	info, err := s.provider.System()
	if err != nil {
		s.log.Log(audit.ClassError, "status sample failed: %v", err)
		writeReject(w, http.StatusInternalServerError, "status unavailable")
		return
	}
	// online is true because the agent itself is answering this request.
	writeJSON(w, http.StatusOK, statusResponse{
		DeviceName:     info.DeviceName,
		Online:         true,
		Session:        info.Session,
		IdleSeconds:    info.IdleSeconds,
		BatteryPercent: info.BatteryPercent,
		CPUPercent:     info.CPUPercent,
		RAMPercent:     info.RAMPercent,
		UptimeSeconds:  info.UptimeSeconds,
	})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	act, err := s.provider.Activity()
	if err != nil {
		s.log.Log(audit.ClassError, "activity sample failed: %v", err)
		writeReject(w, http.StatusInternalServerError, "activity unavailable")
		return
	}
	writeJSON(w, http.StatusOK, act)
}

// logsResponse wraps the audit event slice returned by GET /v1/logs.
type logsResponse struct {
	Events []audit.Event `json:"events"`
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if raw := r.URL.Query().Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 0 {
			writeReject(w, http.StatusBadRequest, "limit must be a non-negative integer")
			return
		}
		limit = n
	}
	var classes []audit.Class
	if raw := r.URL.Query().Get("class"); raw != "" {
		classes = append(classes, audit.Class(raw))
	}
	writeJSON(w, http.StatusOK, logsResponse{Events: s.log.Recent(limit, classes...)})
}

func (s *Server) handleLock(w http.ResponseWriter, r *http.Request) {
	err := s.provider.Lock()
	if err != nil {
		s.log.Log(audit.ClassError, "lock failed: %v", err)
	} else {
		s.log.Log(audit.ClassAction, "workstation locked")
	}
	writeActionResult(w, err)
}

// muteRequest is the optional body for POST /v1/control/mute. Absent body means
// mute (the common intent); an explicit {"muted":false} unmutes.
type muteRequest struct {
	Muted *bool `json:"muted"`
}

func (s *Server) handleMute(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeOptionalJSON[muteRequest](w, r)
	if !ok {
		return
	}
	muted := true
	if req.Muted != nil {
		muted = *req.Muted
	}
	err := s.provider.SetMuted(muted)
	if err != nil {
		s.log.Log(audit.ClassError, "set muted=%t failed: %v", muted, err)
	} else {
		s.log.Log(audit.ClassCommand, "system audio muted=%t", muted)
	}
	writeActionResult(w, err)
}

func (s *Server) handlePanic(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.panic.Execute())
}

// decodeOptionalJSON decodes a JSON body into T. An empty body yields the zero
// value and ok=true. A malformed or oversized body is rejected with 400 and
// ok=false. Unknown fields are rejected to catch client/contract drift early.
func decodeOptionalJSON[T any](w http.ResponseWriter, r *http.Request) (T, bool) {
	var v T
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeReject(w, http.StatusBadRequest, "could not read request body")
		return v, false
	}
	if len(body) == 0 {
		return v, true
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&v); err != nil {
		writeReject(w, http.StatusBadRequest, "invalid request body")
		return v, false
	}
	if dec.More() {
		writeReject(w, http.StatusBadRequest, "unexpected trailing data in request body")
		return v, false
	}
	return v, true
}
