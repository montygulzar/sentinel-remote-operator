package auth

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// signingVectorFile mirrors testdata/signing_vectors.json. The vectors are the
// cross-language contract (THIRD ARTILLERY ORDER): each expectedSignature is a
// fixed, checked-in value, and both the Go agent and the Swift Operator must
// reproduce it exactly. This test holds the Go side to that contract; the Swift
// test (operator/Tests/SentinelKitTests) holds the Swift side to the same file.
type signingVectorFile struct {
	Vectors []struct {
		Name              string `json:"name"`
		DeviceID          string `json:"deviceId"`
		KeyBase64         string `json:"keyBase64"`
		Method            string `json:"method"`
		Path              string `json:"path"`
		Timestamp         string `json:"timestamp"`
		Nonce             string `json:"nonce"`
		Body              string `json:"body"`
		ExpectedSignature string `json:"expectedSignature"`
	} `json:"vectors"`
}

const vectorsPath = "testdata/signing_vectors.json"

// operatorVectorsCopy is the Swift test resource, relative to this package
// directory (agent/internal/auth → repo root → operator/...).
const operatorVectorsCopy = "../../../operator/Tests/SentinelKitTests/Resources/signing_vectors.json"

func loadVectors(t *testing.T) signingVectorFile {
	t.Helper()
	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var vf signingVectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("no vectors loaded")
	}
	return vf
}

// TestSigningVectorsAreReproducedExactly is the authoritative check: the Go
// implementation must compute each locked signature bit-for-bit. If the
// canonical form or HMAC ever changes, this fails until the vectors are
// deliberately regenerated (go run ./cmd/genvec).
func TestSigningVectorsAreReproducedExactly(t *testing.T) {
	vf := loadVectors(t)
	for _, v := range vf.Vectors {
		v := v
		t.Run(v.Name, func(t *testing.T) {
			if v.ExpectedSignature == "" {
				t.Fatalf("vector %q has no locked expectedSignature", v.Name)
			}
			key, err := base64.StdEncoding.DecodeString(v.KeyBase64)
			if err != nil {
				t.Fatalf("decode key: %v", err)
			}
			got := Signature(key, SignedRequest{
				DeviceID:  v.DeviceID,
				Method:    v.Method,
				Path:      v.Path,
				Timestamp: v.Timestamp,
				Nonce:     v.Nonce,
				Body:      []byte(v.Body),
			})
			if got != v.ExpectedSignature {
				t.Fatalf("signature mismatch\n got:  %s\n want: %s", got, v.ExpectedSignature)
			}
		})
	}
}

// TestOperatorVectorCopyMatches guards against the Go and Swift copies of the
// vector file drifting apart: the Swift suite reads its own resource, so a
// divergence would silently weaken the parity guarantee. The files must be
// byte-identical.
func TestOperatorVectorCopyMatches(t *testing.T) {
	canonical, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read canonical vectors: %v", err)
	}
	copyPath := filepath.FromSlash(operatorVectorsCopy)
	operatorCopy, err := os.ReadFile(copyPath)
	if err != nil {
		t.Fatalf("read operator vector copy at %s: %v (keep it in sync with %s)", copyPath, err, vectorsPath)
	}
	if string(canonical) != string(operatorCopy) {
		t.Fatalf("operator signing-vector copy has drifted from %s; recopy it", vectorsPath)
	}
}
