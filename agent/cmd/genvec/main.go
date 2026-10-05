// Command genvec regenerates the locked cross-language signing test vectors
// from the verified Go implementation. It is a developer tool, run by hand when
// the canonical signing algorithm intentionally changes; its output is checked
// in and the Go and Swift test suites verify against it. It is not part of the
// agent.
//
//	go run ./cmd/genvec > internal/auth/testdata/signing_vectors.json
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"

	"github.com/montygulzar/sentinel-remote-operator/agent/internal/auth"
)

type vector struct {
	Name              string `json:"name"`
	DeviceID          string `json:"deviceId"`
	KeyBase64         string `json:"keyBase64"`
	Method            string `json:"method"`
	Path              string `json:"path"`
	Timestamp         string `json:"timestamp"`
	Nonce             string `json:"nonce"`
	Body              string `json:"body"`
	ExpectedSignature string `json:"expectedSignature"`
}

type file struct {
	Description string   `json:"description"`
	Algorithm   string   `json:"algorithm"`
	Canonical   []string `json:"canonical"`
	Vectors     []vector `json:"vectors"`
}

// key returns a deterministic 32-byte key seeded by b, so vectors are stable
// across regenerations.
func key(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b + byte(i)
	}
	return k
}

func main() {
	inputs := []vector{
		{Name: "status-get-empty-body", DeviceID: "dev-7Qx2", KeyBase64: b64(key(0x11)), Method: "GET", Path: "/v1/status", Timestamp: "1700000000", Nonce: "nonce-aaaa", Body: ""},
		{Name: "mute-post-json-body", DeviceID: "dev-7Qx2", KeyBase64: b64(key(0x11)), Method: "POST", Path: "/v1/control/mute", Timestamp: "1700000123", Nonce: "nonce-bbbb", Body: `{"muted":true}`},
		{Name: "panic-post-empty-body", DeviceID: "dev-7Qx2", KeyBase64: b64(key(0x11)), Method: "POST", Path: "/v1/control/panic", Timestamp: "1700000200", Nonce: "nonce-cccc", Body: ""},
		{Name: "screen-grab-with-query", DeviceID: "dev-K9z", KeyBase64: b64(key(0x5a)), Method: "GET", Path: "/v1/screen/grab?display=DISPLAY2&format=png", Timestamp: "1700000300", Nonce: "nonce-dddd", Body: ""},
		{Name: "unicode-body", DeviceID: "dev-K9z", KeyBase64: b64(key(0x5a)), Method: "POST", Path: "/v1/pair", Timestamp: "1700000400", Nonce: "nonce-eeee", Body: `{"displayName":"café ☕"}`},
		{Name: "admin-devices-list", DeviceID: "admin", KeyBase64: b64(key(0xa3)), Method: "GET", Path: "/v1/admin/devices", Timestamp: "1700000500", Nonce: "nonce-ffff", Body: ""},
	}

	out := file{
		Description: "Locked HMAC-SHA256 request-signing vectors shared by the Go agent and the Swift Operator. Both implementations must reproduce each expectedSignature exactly. Regenerate with `go run ./cmd/genvec`.",
		Algorithm:   "signature = hex(HMAC_SHA256(key, canonical)); key = base64decode(keyBase64); bodyHash = hex(SHA256(utf8(body)))",
		Canonical:   []string{"deviceId", "UPPERCASE(method)", "path (incl. query)", "timestamp", "nonce", "hex(sha256(body))", "joined with \\n"},
	}
	for _, v := range inputs {
		kb, err := base64.StdEncoding.DecodeString(v.KeyBase64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad key:", err)
			os.Exit(1)
		}
		v.ExpectedSignature = auth.Signature(kb, auth.SignedRequest{
			DeviceID:  v.DeviceID,
			Method:    v.Method,
			Path:      v.Path,
			Timestamp: v.Timestamp,
			Nonce:     v.Nonce,
			Body:      []byte(v.Body),
		})
		out.Vectors = append(out.Vectors, v)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }
