package auth

import (
	"strings"
	"testing"
)

func FuzzSerializeCanonicalRoundTrip(f *testing.F) {
	f.Add("v1", "POST", "https://example.com/v1/wallets", `{"chain_type":"ethereum"}`, "x-app-id", "app-123")
	f.Add("v1", "GET", "/v1/wallets?cursor=abc", "", "x-idempotency-key", "idem-1")

	f.Fuzz(func(t *testing.T, version, method, url, body, headerKey, headerVal string) {
		version = strings.ToValidUTF8(version, "")
		method = strings.ToValidUTF8(method, "")
		url = strings.ToValidUTF8(url, "")
		body = strings.ToValidUTF8(body, "")
		headerKey = strings.ToValidUTF8(headerKey, "")
		headerVal = strings.ToValidUTF8(headerVal, "")

		if headerKey == "" {
			headerKey = "x-app-id"
		}

		payload := &CanonicalPayload{
			Version: version,
			Method:  method,
			URL:     url,
			Body:    body,
			Headers: map[string]string{
				headerKey: headerVal,
			},
		}

		canonical, err := SerializeCanonical(payload)
		if err != nil {
			// Serialization should not fail for string fields; fail fast if it does.
			t.Fatalf("SerializeCanonical failed: %v", err)
		}

		reconstructed, err := CanonicalPayloadFromBytes(canonical)
		if err != nil {
			t.Fatalf("CanonicalPayloadFromBytes failed: %v", err)
		}

		if reconstructed.Version != payload.Version ||
			reconstructed.Method != payload.Method ||
			reconstructed.URL != payload.URL ||
			reconstructed.Body != payload.Body {
			t.Fatalf("roundtrip mismatch: got=%+v want=%+v", reconstructed, payload)
		}

		if reconstructed.Headers == nil || reconstructed.Headers[headerKey] != headerVal {
			t.Fatalf("headers mismatch: got=%v want=%s:%s", reconstructed.Headers, headerKey, headerVal)
		}
	})
}
