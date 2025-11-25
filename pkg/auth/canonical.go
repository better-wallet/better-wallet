package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
)

// CanonicalPayload represents the standardized request format for signature verification
// following RFC 8785 canonical JSON specification
type CanonicalPayload struct {
	Version string            `json:"version"`
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Body    string            `json:"body"`
	Headers map[string]string `json:"headers"`
}

// BuildCanonicalPayload constructs a canonical payload from an HTTP request
// This payload will be signed/verified using P-256 ECDSA signatures
func BuildCanonicalPayload(r *http.Request) (*CanonicalPayload, []byte, error) {
	// Read the request body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read request body: %w", err)
	}

	// Restore the body for subsequent handlers
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

	// Build the full URL
	// Use the path and query string only, without host
	// This allows signatures to be portable across different deployment environments
	fullURL := r.URL.RequestURI()

	// Extract relevant headers (only those that should be signed)
	headers := make(map[string]string)
	if appID := r.Header.Get("x-app-id"); appID != "" {
		headers["x-app-id"] = appID
	}
	if idempotencyKey := r.Header.Get("x-idempotency-key"); idempotencyKey != "" {
		headers["x-idempotency-key"] = idempotencyKey
	}

	payload := &CanonicalPayload{
		Version: "v1",
		Method:  r.Method,
		URL:     fullURL,
		Body:    string(bodyBytes),
		Headers: headers,
	}

	// Serialize to canonical JSON (RFC 8785)
	canonicalBytes, err := SerializeCanonical(payload)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to serialize canonical payload: %w", err)
	}

	return payload, canonicalBytes, nil
}

// SerializeCanonical serializes a payload to RFC 8785 canonical JSON
// This ensures consistent JSON formatting for signature verification
func SerializeCanonical(payload *CanonicalPayload) ([]byte, error) {
	// Marshal to JSON with sorted keys
	jsonBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Parse and re-serialize to ensure canonical format
	var intermediate map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &intermediate); err != nil {
		return nil, err
	}

	return canonicalJSON(intermediate)
}

// canonicalJSON produces RFC 8785 canonical JSON encoding
func canonicalJSON(v interface{}) ([]byte, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		return canonicalObject(val)
	case []interface{}:
		return canonicalArray(val)
	default:
		// For primitive types, use standard JSON encoding
		return json.Marshal(v)
	}
}

// canonicalObject encodes a JSON object in canonical form
func canonicalObject(obj map[string]interface{}) ([]byte, error) {
	// Sort keys
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonical representation
	var buf bytes.Buffer
	buf.WriteString("{")

	for i, key := range keys {
		if i > 0 {
			buf.WriteString(",")
		}

		// Encode key
		keyJSON, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.Write(keyJSON)
		buf.WriteString(":")

		// Encode value
		valJSON, err := canonicalJSON(obj[key])
		if err != nil {
			return nil, err
		}
		buf.Write(valJSON)
	}

	buf.WriteString("}")
	return buf.Bytes(), nil
}

// canonicalArray encodes a JSON array in canonical form
func canonicalArray(arr []interface{}) ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString("[")

	for i, item := range arr {
		if i > 0 {
			buf.WriteString(",")
		}

		itemJSON, err := canonicalJSON(item)
		if err != nil {
			return nil, err
		}
		buf.Write(itemJSON)
	}

	buf.WriteString("]")
	return buf.Bytes(), nil
}

// HashPayload creates a SHA-256 hash of the canonical payload
// This can be used for idempotency checking
func HashPayload(canonicalBytes []byte) string {
	hash := sha256.Sum256(canonicalBytes)
	return hex.EncodeToString(hash[:])
}

// ExtractSignatures parses the x-authorization-signature header
// Returns a slice of base64-encoded signatures (comma-separated)
func ExtractSignatures(r *http.Request) []string {
	sigHeader := r.Header.Get("x-authorization-signature")
	if sigHeader == "" {
		return []string{}
	}

	if sigHeader == "" {
		return nil
	}

	// Split by comma for multiple signatures
	signatures := make([]string, 0)
	for i := 0; i < len(sigHeader); {
		// Skip whitespace
		for i < len(sigHeader) && sigHeader[i] == ' ' {
			i++
		}
		if i >= len(sigHeader) {
			break
		}

		// Find next comma
		start := i
		for i < len(sigHeader) && sigHeader[i] != ',' {
			i++
		}

		sig := sigHeader[start:i]
		if sig != "" {
			signatures = append(signatures, sig)
		}

		if i < len(sigHeader) && sigHeader[i] == ',' {
			i++
		}
	}

	return signatures
}

// CanonicalPayloadFromBytes reconstructs a canonical payload for verification
// This is useful when you need to verify a signature against stored data
func CanonicalPayloadFromBytes(data []byte) (*CanonicalPayload, error) {
	var payload CanonicalPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("failed to unmarshal canonical payload: %w", err)
	}
	return &payload, nil
}
