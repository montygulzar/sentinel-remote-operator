package api

import (
	"bytes"
	"io"
	"net/http"
	"time"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/audit"
	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
)

// handlePair completes device pairing. It is authenticated by the one-time
// pairing code (verified inside the PairingManager), not by a device or the
// admin key. On success a new authorized device exists and the Operator
// receives the material to derive its own permanent key.
func (s *Server) handlePair(w http.ResponseWriter, r *http.Request) {
	sr, body, ok := s.readSigned(w, r)
	if !ok {
		return
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	req, ok := decodeOptionalJSON[auth.PairRequest](w, r)
	if !ok {
		return
	}
	res, err := s.pairing.Complete(sr, r.Header.Get(auth.HeaderSignature), req)
	if err != nil {
		// The PairingManager logs the specific reason; the response is opaque
		// so a caller cannot distinguish a wrong code from an expired window.
		writeReject(w, http.StatusUnauthorized, "pairing failed")
		return
	}
	writeJSON(w, http.StatusOK, res)
}

// pairingStartResponse carries the one-time code back to the owner's local
// tooling. The code is a short-lived secret; it is returned only over the
// admin channel and is never written to the audit log.
type pairingStartResponse struct {
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expiresAt"`
}

func (s *Server) handlePairingStart(w http.ResponseWriter, r *http.Request) {
	code, expiresAt, err := s.pairing.Start()
	if err != nil {
		s.log.Log(audit.ClassError, "pairing start failed: %v", err)
		writeReject(w, http.StatusInternalServerError, "could not start pairing")
		return
	}
	writeJSON(w, http.StatusOK, pairingStartResponse{Code: code, ExpiresAt: expiresAt})
}

func (s *Server) handlePairingCancel(w http.ResponseWriter, r *http.Request) {
	s.pairing.Cancel()
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

type devicesListResponse struct {
	Devices []auth.Info `json:"devices"`
}

func (s *Server) handleDevicesList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, devicesListResponse{Devices: s.registry.List()})
}

type revokeRequest struct {
	DeviceID string `json:"deviceId"`
}

type revokeResponse struct {
	OK      bool `json:"ok"`
	Revoked bool `json:"revoked"`
}

func (s *Server) handleDevicesRevoke(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeOptionalJSON[revokeRequest](w, r)
	if !ok {
		return
	}
	if req.DeviceID == "" {
		writeReject(w, http.StatusBadRequest, "deviceId is required")
		return
	}
	found, err := s.registry.Revoke(req.DeviceID, time.Now())
	if err != nil {
		s.log.Log(audit.ClassError, "revoke %s failed: %v", req.DeviceID, err)
		writeReject(w, http.StatusInternalServerError, "could not revoke device")
		return
	}
	if found {
		s.log.Log(audit.ClassSecurity, "DEVICE_REVOKED id=%s", req.DeviceID)
	}
	writeJSON(w, http.StatusOK, revokeResponse{OK: true, Revoked: found})
}
