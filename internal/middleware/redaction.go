package middleware

import (
	"net/http"
	"strings"
)

const redactedValue = "[REDACTED]"

var redactHeaderKeys = []string{
	"Authorization",
	"Cookie",
	"Set-Cookie",
	"X-App-Secret",
	"X-API-Key",
	"X-Authorization-Signature",
	"X-User-JWT",
	"X-User-Authorization",
}

var stripCredentialHeaderKeys = []string{
	"Authorization",
	"X-App-Secret",
	"X-API-Key",
	"X-User-JWT",
	"X-User-Authorization",
}

func isHeaderInList(key string, keys []string) bool {
	lower := strings.ToLower(strings.TrimSpace(key))
	for _, k := range keys {
		if strings.ToLower(k) == lower {
			return true
		}
	}
	return false
}

func redactHeaderValue(key, value string) string {
	if strings.EqualFold(key, "Authorization") {
		parts := strings.SplitN(strings.TrimSpace(value), " ", 2)
		if len(parts) == 2 && parts[0] != "" {
			return parts[0] + " " + redactedValue
		}
		return redactedValue
	}
	return redactedValue
}

// RedactHeaders returns a copy of h with sensitive values replaced by a constant.
// Use this for safe logging/telemetry.
func RedactHeaders(h http.Header) http.Header {
	if h == nil {
		return nil
	}

	out := make(http.Header, len(h))
	for key, values := range h {
		if !isHeaderInList(key, redactHeaderKeys) {
			copied := make([]string, len(values))
			copy(copied, values)
			out[key] = copied
			continue
		}

		redacted := make([]string, len(values))
		for i := range values {
			redacted[i] = redactHeaderValue(key, values[i])
		}
		out[key] = redacted
	}
	return out
}

// StripCredentialHeaders removes long-lived credentials from h in-place.
// Use this after authentication to reduce the risk of accidental leakage via logs/telemetry.
//
// Note: this does not remove x-authorization-signature because handlers still need it.
func StripCredentialHeaders(h http.Header) {
	if h == nil {
		return
	}
	for _, key := range stripCredentialHeaderKeys {
		h.Del(key)
	}
}
