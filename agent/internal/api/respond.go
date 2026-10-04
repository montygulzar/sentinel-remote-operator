package api

import (
	"encoding/json"
	"net/http"
)

// errorResponse is the uniform rejection envelope. A request that is refused
// (bad auth, malformed, wrong method/route) returns a non-2xx status with this
// body; a request that is accepted but whose host action fails returns 200 with
// a result whose ok field is false (spec §18: structured success/error).
type errorResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

// okResponse is the minimal positive acknowledgement for control actions that
// carry no data of their own.
type okResponse struct {
	OK bool `json:"ok"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
}

// writeReject writes a refusal with the given HTTP status and message.
func writeReject(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, errorResponse{OK: false, Error: message})
}

// writeActionResult writes the outcome of a host action that the agent accepted
// and attempted. Success or failure, the HTTP status is 200 and the structured
// body conveys the real result so the Operator never has to infer it.
func writeActionResult(w http.ResponseWriter, err error) {
	if err != nil {
		writeJSON(w, http.StatusOK, errorResponse{OK: false, Error: err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}
