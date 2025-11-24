package authsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"

	"github.com/gowebpki/jcs"
)

// Payload represents the canonical structure that is signed by an authorization key.
// It must be canonicalized using RFC 8785 prior to signing.
type Payload struct {
	Version        string            `json:"version"`
	Method         string            `json:"method"`
	URL            string            `json:"url"`
	Body           string            `json:"body"`
	Headers        map[string]string `json:"headers"`
	AppID          string            `json:"app_id"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
}

// Canonicalize returns RFC 8785 canonical JSON bytes and its SHA256 digest hex string.
func Canonicalize(p Payload) ([]byte, string, error) {
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, "", fmt.Errorf("marshal payload: %w", err)
	}

	canonical, err := jcs.Transform(raw)
	if err != nil {
		return nil, "", fmt.Errorf("canonicalize payload: %w", err)
	}

	digest := sha256.Sum256(canonical)
	return canonical, hex.EncodeToString(digest[:]), nil
}

// VerifyP256Signature verifies a base64-encoded DER or raw r||s signature over the canonical payload hash.
func VerifyP256Signature(publicKeyBytes, canonicalPayload []byte, signatureB64 string) error {
	sigBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return fmt.Errorf("decode signature: %w", err)
	}

	// Accept 65-byte uncompressed or 33-byte compressed P-256 public keys
	if len(publicKeyBytes) != 65 && len(publicKeyBytes) != 33 {
		return fmt.Errorf("invalid P-256 public key length: %d", len(publicKeyBytes))
	}

	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil {
		return fmt.Errorf("failed to parse P-256 public key")
	}

	pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}

	hash := sha256.Sum256(canonicalPayload)

	// Try DER first
	var ecdsaSig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(sigBytes, &ecdsaSig); err == nil {
		if ecdsaSig.R == nil || ecdsaSig.S == nil {
			return fmt.Errorf("invalid DER signature")
		}
		if ecdsa.Verify(pub, hash[:], ecdsaSig.R, ecdsaSig.S) {
			return nil
		}
		return fmt.Errorf("signature verification failed")
	}

	// Fallback to raw r||s
	if len(sigBytes) != 64 {
		return fmt.Errorf("invalid signature length: %d", len(sigBytes))
	}
	r := new(big.Int).SetBytes(sigBytes[:32])
	s := new(big.Int).SetBytes(sigBytes[32:])
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return fmt.Errorf("signature verification failed")
	}
	return nil
}

// ParseSignatures splits a comma-delimited signature header into trimmed values.
func ParseSignatures(header string) []string {
	parts := strings.Split(header, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
