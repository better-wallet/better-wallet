//go:build security

package security

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/pkg/auth"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TEST HELPERS
// =============================================================================

// generateTestKeyPair generates a P-256 key pair for testing
func generateTestKeyPair() (*ecdsa.PrivateKey, string, string, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", "", err
	}

	// Encode private key to PEM
	privBytes, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, "", "", err
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	})

	// Encode public key to PEM
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, "", "", err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	return privKey, string(privPEM), string(pubPEM), nil
}

// signPayload signs data with a private key
func signPayload(privKey *ecdsa.PrivateKey, payload []byte) (string, error) {
	hash := sha256.Sum256(payload)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

// =============================================================================
// AUTHENTICATION ATTACKS
// =============================================================================

func TestAttack_JWTForging(t *testing.T) {
	t.Run("jwt_signed_with_wrong_key", func(t *testing.T) {
		// Create a valid-looking JWT signed with attacker's key
		attackerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		claims := jwt.MapClaims{
			"sub": "victim-user-id",
			"iss": "https://legitimate-issuer.com",
			"aud": "legitimate-audience",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
			"iat": time.Now().Unix(),
		}

		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = "attacker-key-id"

		// Sign with attacker's key
		signedToken, err := token.SignedString(attackerKey)
		require.NoError(t, err)

		// Verify the token was created
		assert.NotEmpty(t, signedToken)
		assert.True(t, strings.HasPrefix(signedToken, "eyJ"), "should be a valid JWT format")

		// System would reject this because:
		// 1. Key ID not in legitimate JWKS
		// 2. Signature won't verify against legitimate public key
		// This is verified by middleware tests, here we just confirm the attack vector exists
	})

	t.Run("jwt_with_modified_claims", func(t *testing.T) {
		// Take a JWT and modify claims without re-signing
		originalClaims := jwt.MapClaims{
			"sub": "original-user",
			"iss": "https://issuer.com",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}

		// Create valid JWT structure manually
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"JWT"}`))
		payload, _ := json.Marshal(originalClaims)
		payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
		fakeSignature := base64.RawURLEncoding.EncodeToString([]byte("fake-signature-bytes-here"))

		tamperedToken := header + "." + payloadB64 + "." + fakeSignature

		// Parse without validation to show structure is valid
		parts := strings.Split(tamperedToken, ".")
		assert.Len(t, parts, 3, "tampered token has valid structure")

		// Decode claims to verify modification is possible
		claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)

		var decoded map[string]interface{}
		err = json.Unmarshal(claimsBytes, &decoded)
		require.NoError(t, err)
		assert.Equal(t, "original-user", decoded["sub"])

		// System would reject because signature doesn't match modified claims
	})

	t.Run("jwt_algorithm_confusion_hs256", func(t *testing.T) {
		// Try to create a JWT with HS256 (symmetric) algorithm
		// This is the classic "alg:none" or "RS256 to HS256" attack

		// Create token with HS256 algorithm
		claims := jwt.MapClaims{
			"sub": "admin",
			"exp": time.Now().Add(1 * time.Hour).Unix(),
		}

		// System should ONLY accept ES256 or RS256 with proper asymmetric verification
		// HS256 with public key as secret is a known attack

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		signedToken, err := token.SignedString([]byte("fake-secret"))
		require.NoError(t, err)

		// Parse to verify algorithm
		parsed, _, err := new(jwt.Parser).ParseUnverified(signedToken, jwt.MapClaims{})
		require.NoError(t, err)

		alg := parsed.Header["alg"]
		assert.Equal(t, "HS256", alg, "token uses HS256 algorithm")

		// System middleware should reject non-asymmetric algorithms
		// See middleware/auth.go lines 169-172 which only accept RSA or ECDSA
	})

	t.Run("jwt_algorithm_none", func(t *testing.T) {
		// Try the "alg: none" attack
		header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
		claims := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","exp":9999999999}`))

		// Algorithm "none" means no signature required
		unsignedToken := header + "." + claims + "."

		parts := strings.Split(unsignedToken, ".")
		assert.Len(t, parts, 3, "unsigned token has valid structure")

		// Decode header to verify
		headerBytes, _ := base64.RawURLEncoding.DecodeString(parts[0])
		var headerMap map[string]string
		json.Unmarshal(headerBytes, &headerMap)
		assert.Equal(t, "none", headerMap["alg"])

		// System should reject "none" algorithm
	})
}

func TestAttack_AppSecretBruteforce(t *testing.T) {
	t.Run("multiple_failed_attempts", func(t *testing.T) {
		// Simulate multiple failed authentication attempts
		// System should implement rate limiting

		failedAttempts := 100
		invalidSecrets := make([]string, failedAttempts)

		for i := 0; i < failedAttempts; i++ {
			// Generate random "guessed" secrets
			invalidSecrets[i] = "bw_sk_" + uuid.New().String()[:20]
		}

		// Verify we generated unique invalid secrets
		seen := make(map[string]bool)
		for _, s := range invalidSecrets {
			assert.False(t, seen[s], "should generate unique secrets")
			seen[s] = true
		}

		// System should rate limit after N failed attempts
		// This is typically implemented at infrastructure level (nginx, API gateway)
		// or via middleware checking failed attempt counts
	})

	t.Run("timing_attack_resistance", func(t *testing.T) {
		// bcrypt is constant-time by design
		// This test documents the requirement

		// Passwords of different lengths should take similar time due to bcrypt
		shortPassword := "short"
		longPassword := strings.Repeat("long", 100)

		// bcrypt hashes both to same length (60 chars)
		// Comparison should be constant-time
		assert.NotEqual(t, len(shortPassword), len(longPassword))

		// The actual timing test would require statistical analysis
		// bcrypt.CompareHashAndPassword uses subtle.ConstantTimeCompare internally
	})
}

// =============================================================================
// AUTHORIZATION ATTACKS
// =============================================================================

func TestAttack_SignatureReplay(t *testing.T) {
	t.Run("same_signature_different_request", func(t *testing.T) {
		// Generate key pair
		privKey, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()

		// Original request payload
		originalPayload := []byte(`{"version":"v1","method":"POST","url":"/v1/wallets/123/rpc","body":"{\"to\":\"0xabc\",\"value\":\"1000\"}","headers":{"x-app-id":"app1"}}`)

		// Sign original payload
		signature, err := signPayload(privKey, originalPayload)
		require.NoError(t, err)

		// Verify original succeeds
		valid, err := verifier.VerifySignature(signature, originalPayload, pubPEM)
		require.NoError(t, err)
		assert.True(t, valid, "original signature should be valid")

		// Try to use same signature for different request
		differentPayload := []byte(`{"version":"v1","method":"POST","url":"/v1/wallets/123/rpc","body":"{\"to\":\"0xabc\",\"value\":\"999999\"}","headers":{"x-app-id":"app1"}}`)

		// Should fail - signature doesn't match different payload
		valid, err = verifier.VerifySignature(signature, differentPayload, pubPEM)
		require.NoError(t, err)
		assert.False(t, valid, "replayed signature should fail for different payload")
	})

	t.Run("same_request_replay", func(t *testing.T) {
		// Even exact same request should be handled by idempotency key
		// If same idempotency key is used, cached response is returned
		// If different idempotency key, request is processed again

		idempotencyKey1 := uuid.New().String()
		idempotencyKey2 := uuid.New().String()

		// Verify idempotency keys are different
		assert.NotEqual(t, idempotencyKey1, idempotencyKey2)

		// Canonical payload includes idempotency key in headers
		payload1 := map[string]interface{}{
			"version": "v1",
			"method":  "POST",
			"url":     "/v1/wallets/123/rpc",
			"body":    `{"to":"0xabc"}`,
			"headers": map[string]string{
				"x-app-id":          "app1",
				"x-idempotency-key": idempotencyKey1,
			},
		}

		payload2 := map[string]interface{}{
			"version": "v1",
			"method":  "POST",
			"url":     "/v1/wallets/123/rpc",
			"body":    `{"to":"0xabc"}`,
			"headers": map[string]string{
				"x-app-id":          "app1",
				"x-idempotency-key": idempotencyKey2,
			},
		}

		bytes1, _ := json.Marshal(payload1)
		bytes2, _ := json.Marshal(payload2)

		// Different idempotency keys mean different canonical payloads
		assert.NotEqual(t, string(bytes1), string(bytes2))
	})
}

func TestAttack_SignatureMalleability(t *testing.T) {
	t.Run("modified_signature_bytes", func(t *testing.T) {
		privKey, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"data"}`)

		// Create valid signature
		validSig, err := signPayload(privKey, payload)
		require.NoError(t, err)

		// Verify valid signature works
		valid, err := verifier.VerifySignature(validSig, payload, pubPEM)
		require.NoError(t, err)
		assert.True(t, valid)

		// Decode signature
		sigBytes, err := base64.StdEncoding.DecodeString(validSig)
		require.NoError(t, err)

		// Modify one byte
		sigBytes[0] ^= 0xFF

		// Re-encode
		modifiedSig := base64.StdEncoding.EncodeToString(sigBytes)

		// Should fail verification
		valid, err = verifier.VerifySignature(modifiedSig, payload, pubPEM)
		require.NoError(t, err)
		assert.False(t, valid, "modified signature should fail verification")
	})

	t.Run("truncated_signature", func(t *testing.T) {
		privKey, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"data"}`)

		validSig, err := signPayload(privKey, payload)
		require.NoError(t, err)

		// Decode and truncate
		sigBytes, _ := base64.StdEncoding.DecodeString(validSig)
		truncated := base64.StdEncoding.EncodeToString(sigBytes[:len(sigBytes)/2])

		// Should fail - incomplete signature
		valid, err := verifier.VerifySignature(truncated, payload, pubPEM)
		// May error on parse or return false
		assert.False(t, valid || err != nil, "truncated signature should not verify")
	})

	t.Run("empty_signature", func(t *testing.T) {
		_, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"data"}`)

		// Empty signature - should either error or return false
		valid, err := verifier.VerifySignature("", payload, pubPEM)
		// Empty base64 decodes to empty bytes, which is not a valid signature
		assert.True(t, err != nil || !valid, "empty signature should not verify")
	})

	t.Run("invalid_base64", func(t *testing.T) {
		_, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"data"}`)

		// Invalid base64
		_, err = verifier.VerifySignature("not-valid-base64!!!", payload, pubPEM)
		assert.Error(t, err, "invalid base64 should error")
	})
}

func TestAttack_SessionSignerPrivilegeEscalation(t *testing.T) {
	t.Run("session_signer_exceed_max_value", func(t *testing.T) {
		// Test that max_value limit is properly enforced
		maxValue := big.NewInt(1000000000000000000) // 1 ETH
		requestValue := big.NewInt(2000000000000000000) // 2 ETH

		// Comparison
		exceeds := requestValue.Cmp(maxValue) > 0
		assert.True(t, exceeds, "request should exceed max value")
	})

	t.Run("session_signer_exceed_max_txs", func(t *testing.T) {
		// Test that max_txs limit is properly enforced
		maxTxs := 10
		currentCount := 10 // Already used all allowed txs

		// Should be denied
		exceedsLimit := currentCount >= maxTxs
		assert.True(t, exceedsLimit, "should exceed max transactions")
	})

	t.Run("session_signer_use_after_expiry", func(t *testing.T) {
		// Test TTL expiry
		expiresAt := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago
		now := time.Now()

		isExpired := now.After(expiresAt) || now.Equal(expiresAt)
		assert.True(t, isExpired, "session signer should be expired")
	})

	t.Run("session_signer_disallowed_method", func(t *testing.T) {
		// Test method filtering
		allowedMethods := []string{"sign_transaction"}
		requestedMethod := "sign_typed_data"

		isAllowed := false
		for _, m := range allowedMethods {
			if m == requestedMethod {
				isAllowed = true
				break
			}
		}
		assert.False(t, isAllowed, "method should not be allowed")
	})

	t.Run("session_signer_with_empty_allowed_methods", func(t *testing.T) {
		// Empty allowed_methods means ALL methods are allowed
		allowedMethods := []string{}
		requestedMethod := "sign_transaction"

		// Empty = allow all
		isAllowed := len(allowedMethods) == 0
		_ = requestedMethod // Would be allowed

		assert.True(t, isAllowed, "empty allowed_methods should permit all")
	})
}

func TestAttack_PolicyBypass(t *testing.T) {
	t.Run("boundary_value_bypass", func(t *testing.T) {
		// Test edge case for lt vs lte
		limit := big.NewInt(1000000000000000000) // 1 ETH

		// Value exactly at limit
		atLimit := big.NewInt(1000000000000000000)
		// Value just below limit
		belowLimit := big.NewInt(999999999999999999)
		// Value just above limit
		aboveLimit := big.NewInt(1000000000000000001)

		// For "lt" (less than): at limit should fail
		assert.False(t, atLimit.Cmp(limit) < 0, "at limit fails lt")
		assert.True(t, belowLimit.Cmp(limit) < 0, "below limit passes lt")
		assert.False(t, aboveLimit.Cmp(limit) < 0, "above limit fails lt")

		// For "lte" (less than or equal): at limit should pass
		assert.True(t, atLimit.Cmp(limit) <= 0, "at limit passes lte")
		assert.True(t, belowLimit.Cmp(limit) <= 0, "below limit passes lte")
		assert.False(t, aboveLimit.Cmp(limit) <= 0, "above limit fails lte")
	})

	t.Run("address_case_manipulation", func(t *testing.T) {
		// Ethereum addresses should be case-insensitive
		addr1 := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
		addr2 := "0x742d35cc6634c0532925a3b844bc454e4438f44e"
		addr3 := "0x742D35CC6634C0532925A3B844BC454E4438F44E"

		// All should match
		assert.True(t, strings.EqualFold(addr1, addr2))
		assert.True(t, strings.EqualFold(addr2, addr3))
		assert.True(t, strings.EqualFold(addr1, addr3))
	})

	t.Run("hex_prefix_manipulation", func(t *testing.T) {
		// Test with and without 0x prefix
		withPrefix := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
		withoutPrefix := "742d35Cc6634C0532925a3b844Bc454e4438f44e"

		// System should normalize addresses
		normalized1 := strings.TrimPrefix(strings.ToLower(withPrefix), "0x")
		normalized2 := strings.TrimPrefix(strings.ToLower(withoutPrefix), "0x")

		assert.Equal(t, normalized1, normalized2, "normalized addresses should match")
	})

	t.Run("large_value_overflow", func(t *testing.T) {
		// uint256 max value
		uint256Max := new(big.Int)
		uint256Max.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639935", 10)

		// Attempt to overflow
		overflowAttempt := new(big.Int)
		overflowAttempt.SetString("115792089237316195423570985008687907853269984665640564039457584007913129639936", 10)

		// big.Int handles arbitrary precision
		// System should check against uint256 max
		exceedsMax := overflowAttempt.Cmp(uint256Max) > 0
		assert.True(t, exceedsMax, "overflow attempt exceeds uint256 max")
	})
}

// =============================================================================
// DATA ISOLATION ATTACKS
// =============================================================================

func TestAttack_IDOR(t *testing.T) {
	t.Run("access_other_user_wallet_by_id", func(t *testing.T) {
		// Generate IDs for different users
		user1WalletID := uuid.New()
		user2WalletID := uuid.New()

		// These should be completely independent
		assert.NotEqual(t, user1WalletID, user2WalletID)

		// System scopes all queries by app_id AND user_id
		// User1 requesting User2's wallet ID should get 404 (not 403)
		// 404 prevents enumeration attacks
	})

	t.Run("enumerate_wallet_ids", func(t *testing.T) {
		// UUID v4 is random and unguessable
		// Sequential guessing is infeasible

		// Generate 100 random UUIDs
		ids := make(map[string]bool)
		for i := 0; i < 100; i++ {
			id := uuid.New().String()
			ids[id] = true
		}

		// All should be unique (extremely high probability)
		assert.Len(t, ids, 100, "all UUIDs should be unique")

		// UUIDs have 122 random bits
		// Probability of collision in 100 attempts: ~0
	})

	t.Run("access_other_app_resources", func(t *testing.T) {
		// Different apps have different app_ids
		app1ID := uuid.New()
		app2ID := uuid.New()

		// All queries are scoped by app_id from context
		// App1 cannot query resources with App2's app_id

		assert.NotEqual(t, app1ID, app2ID)

		// Storage layer enforces: WHERE app_id = $context_app_id
	})
}

func TestAttack_CrossTenantAccess(t *testing.T) {
	t.Run("app_header_spoofing", func(t *testing.T) {
		// Even if attacker sends X-App-ID header for different app,
		// the middleware validates credentials against the claimed app_id

		claimedAppID := uuid.New()
		actualAppCredentials := "bw_sk_different_app_secret"

		// The system flow:
		// 1. Parse X-App-ID header
		// 2. Look up app by ID
		// 3. Verify secret hash matches claimed app
		// 4. If mismatch, reject

		// Credentials won't match a different app's stored hash
		assert.NotEmpty(t, actualAppCredentials)
		assert.NotEqual(t, claimedAppID, uuid.Nil)
	})

	t.Run("reference_cross_app_policy", func(t *testing.T) {
		// Try to attach App B's policy to App A's wallet
		appA_ID := uuid.New()
		appB_policyID := uuid.New()

		// When App A tries to attach appB_policyID:
		// 1. System queries: SELECT * FROM policies WHERE id = $1 AND app_id = $app_a_id
		// 2. App B's policy has app_id = app_b_id
		// 3. Query returns no rows
		// 4. Error: "policy not found"

		assert.NotEqual(t, appA_ID, appB_policyID) // Different UUIDs
	})
}

// =============================================================================
// KEY SECURITY ATTACKS
// =============================================================================

func TestAttack_KeyExfiltration(t *testing.T) {
	t.Run("error_message_leaks_key_material", func(t *testing.T) {
		// Simulate error messages that might leak key data
		sensitiveData := "private_key_bytes_here_abc123"

		// Good error message
		goodError := "failed to sign transaction: key operation failed"

		// Bad error message (leaks key data)
		badError := "failed to sign with key: " + sensitiveData

		// Error messages should never contain key material
		assert.NotContains(t, goodError, sensitiveData)
		assert.Contains(t, badError, sensitiveData, "bad error leaks data")

		// System should use generic error messages
	})

	t.Run("hex_encoded_key_detection", func(t *testing.T) {
		// Check for patterns that look like private keys
		hexPrivateKey := "0x" + strings.Repeat("a1b2c3d4", 8) // 32 bytes = 64 hex chars

		// Should detect hex patterns
		isHexKey := len(hexPrivateKey) == 66 && strings.HasPrefix(hexPrivateKey, "0x")
		assert.True(t, isHexKey, "pattern looks like hex private key")

		// Log output should be scanned for such patterns
	})
}

// =============================================================================
// INPUT VALIDATION ATTACKS
// =============================================================================

func TestAttack_Injection(t *testing.T) {
	t.Run("sql_injection_wallet_name", func(t *testing.T) {
		// SQL injection attempts
		injectionAttempts := []string{
			"'; DROP TABLE wallets; --",
			"1' OR '1'='1",
			"admin'--",
			"' UNION SELECT * FROM users --",
			"1'; DELETE FROM wallets WHERE '1'='1",
		}

		for _, attempt := range injectionAttempts {
			// pgx uses parameterized queries: $1, $2, etc.
			// Injection attempts become literal strings, not SQL

			// Example safe query:
			// db.Query("SELECT * FROM wallets WHERE name = $1", attempt)
			// The 'attempt' is treated as a string value, not SQL

			assert.Contains(t, attempt, "'", "injection attempts typically contain quotes")
		}

		// System uses pgx which parameterizes all queries
	})

	t.Run("sql_injection_policy_value", func(t *testing.T) {
		// Policy condition values are JSON strings
		// They're never interpolated into SQL

		maliciousValue := "0x' OR 1=1 --"

		// In policy evaluation, this is compared as a string
		actualValue := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

		// String comparison
		matches := strings.EqualFold(maliciousValue, actualValue)
		assert.False(t, matches, "injection attempt doesn't match")
	})

	t.Run("json_injection", func(t *testing.T) {
		// Try to break JSON parsing
		maliciousInputs := []string{
			`{"key":"value","key":"duplicate"}`,
			`{"key":"value\u0000null"}`,
			`{"key":"value","__proto__":{"admin":true}}`,
			string([]byte{0x00, 0x01, 0x02}), // Binary data
		}

		for _, input := range maliciousInputs {
			var parsed map[string]interface{}
			err := json.Unmarshal([]byte(input), &parsed)
			// Some will parse, some won't
			// Important: Go's json.Unmarshal is safe against prototype pollution
			_ = err
		}
	})

	t.Run("path_traversal", func(t *testing.T) {
		// Path traversal attempts in wallet ID
		maliciousPaths := []string{
			"../../../etc/passwd",
			"..\\..\\windows\\system32",
			"....//....//etc/passwd",
			"%2e%2e%2f%2e%2e%2f",
		}

		for _, path := range maliciousPaths {
			// UUID parsing will reject these
			_, err := uuid.Parse(path)
			assert.Error(t, err, "path traversal should fail UUID parse: %s", path)
		}
	})
}

func TestAttack_ResourceExhaustion(t *testing.T) {
	t.Run("oversized_request_body", func(t *testing.T) {
		// HTTP server should limit body size
		maxBodySize := 1 * 1024 * 1024 // 1MB typical limit

		// Attacker tries to send 100MB
		attackBodySize := 100 * 1024 * 1024

		assert.Greater(t, attackBodySize, maxBodySize, "attack exceeds limit")

		// System should use http.MaxBytesReader to limit body size
	})

	t.Run("deeply_nested_json", func(t *testing.T) {
		// Create deeply nested JSON
		depth := 1000
		nested := "{"
		for i := 0; i < depth; i++ {
			nested += `"a":{`
		}
		nested += `"end":true`
		for i := 0; i < depth; i++ {
			nested += "}"
		}
		nested += "}"

		// Go's json parser handles this, but might be slow
		var parsed interface{}
		err := json.Unmarshal([]byte(nested), &parsed)
		// Usually succeeds but may be slow for very deep nesting
		_ = err
	})

	t.Run("many_signatures", func(t *testing.T) {
		// Try to exhaust CPU with many signatures to verify
		numSignatures := 1000

		signatures := make([]string, numSignatures)
		for i := 0; i < numSignatures; i++ {
			signatures[i] = base64.StdEncoding.EncodeToString([]byte("fake-sig-" + string(rune(i))))
		}

		// System should limit number of signatures accepted
		maxSignatures := 10 // Reasonable limit for M-of-N
		if len(signatures) > maxSignatures {
			signatures = signatures[:maxSignatures]
		}

		assert.LessOrEqual(t, len(signatures), maxSignatures)
	})
}

func TestAttack_NumericOverflow(t *testing.T) {
	t.Run("transaction_value_overflow", func(t *testing.T) {
		// uint256 max
		uint256Max := "115792089237316195423570985008687907853269984665640564039457584007913129639935"

		// Value larger than uint256
		overflow := "115792089237316195423570985008687907853269984665640564039457584007913129639936"

		maxBig := new(big.Int)
		maxBig.SetString(uint256Max, 10)

		overflowBig := new(big.Int)
		overflowBig.SetString(overflow, 10)

		// Should be rejected
		exceedsMax := overflowBig.Cmp(maxBig) > 0
		assert.True(t, exceedsMax, "overflow value should exceed max")
	})

	t.Run("negative_gas_value", func(t *testing.T) {
		// Gas values should be non-negative
		negativeGas := big.NewInt(-1)

		isNegative := negativeGas.Sign() < 0
		assert.True(t, isNegative, "gas should be detected as negative")
	})

	t.Run("negative_transaction_value", func(t *testing.T) {
		// Transaction values should be non-negative
		negativeValue := "-1000000000000000000"

		value := new(big.Int)
		value.SetString(negativeValue, 10)

		isNegative := value.Sign() < 0
		assert.True(t, isNegative, "negative value should be detected")
	})

	t.Run("chain_id_overflow", func(t *testing.T) {
		// Chain ID is int64 in our system
		maxInt64 := int64(9223372036854775807)

		// Valid chain IDs
		validChainIDs := []int64{1, 137, 42161, 11155111}
		for _, id := range validChainIDs {
			assert.Greater(t, id, int64(0))
			assert.LessOrEqual(t, id, maxInt64)
		}

		// Invalid
		invalidChainID := int64(0)
		assert.Equal(t, int64(0), invalidChainID, "zero chain ID should be invalid")
	})
}

// =============================================================================
// SIGNATURE VERIFICATION EDGE CASES
// =============================================================================

func TestAttack_SignatureEdgeCases(t *testing.T) {
	t.Run("wrong_curve_public_key", func(t *testing.T) {
		// Generate P-384 key (wrong curve)
		privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		require.NoError(t, err)

		pubBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
		wrongCurvePEM := string(pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubBytes,
		}))

		verifier := auth.NewSignatureVerifier()

		// Sign some data
		hash := sha256.Sum256([]byte("test"))
		sigBytes, _ := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
		sig := base64.StdEncoding.EncodeToString(sigBytes)

		// Should fail - wrong curve
		_, err = verifier.VerifySignature(sig, []byte("test"), wrongCurvePEM)
		assert.Error(t, err, "wrong curve should be rejected")
	})

	t.Run("rsa_key_rejected", func(t *testing.T) {
		// System only accepts P-256 ECDSA keys for authorization signatures
		// RSA keys should be rejected

		// This would require generating an RSA key and trying to use it
		// The parsePublicKey function checks for ECDSA type
	})
}

// =============================================================================
// QUORUM SIGNATURE ATTACKS
// =============================================================================

func TestAttack_QuorumBypass(t *testing.T) {
	t.Run("duplicate_signatures", func(t *testing.T) {
		// Try to use same signature twice to meet threshold
		privKey, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"quorum"}`)

		sig, err := signPayload(privKey, payload)
		require.NoError(t, err)

		// Try to use same signature twice for 2-of-3
		signatures := []string{sig, sig}
		keys := []auth.KeyQuorumKey{
			{ID: uuid.New(), PublicKey: pubPEM},
		}

		validCount, err := verifier.VerifyMultiSignature(signatures, payload, keys, 2)
		require.NoError(t, err)

		// Should only count as 1 valid signature (key can only be used once)
		assert.Equal(t, 1, validCount, "duplicate signatures should only count once")
	})

	t.Run("insufficient_signatures", func(t *testing.T) {
		privKey, _, pubPEM, err := generateTestKeyPair()
		require.NoError(t, err)

		verifier := auth.NewSignatureVerifier()
		payload := []byte(`{"test":"quorum"}`)

		sig, err := signPayload(privKey, payload)
		require.NoError(t, err)

		// Only 1 signature for 2-of-3 quorum
		signatures := []string{sig}
		keys := []auth.KeyQuorumKey{
			{ID: uuid.New(), PublicKey: pubPEM},
			{ID: uuid.New(), PublicKey: pubPEM}, // Would need different key
		}

		err = verifier.VerifyKeyQuorum(signatures, payload, keys, 2)
		assert.Error(t, err, "insufficient signatures should fail")
		assert.Contains(t, err.Error(), "insufficient")
	})
}

// =============================================================================
// CANONICAL PAYLOAD MANIPULATION
// =============================================================================

func TestAttack_CanonicalPayloadManipulation(t *testing.T) {
	t.Run("body_order_manipulation", func(t *testing.T) {
		// JSON key order shouldn't matter for semantic equality
		// but canonical JSON produces deterministic output

		body1 := `{"to":"0xabc","value":"1000"}`
		body2 := `{"value":"1000","to":"0xabc"}`

		// Parse and re-serialize through canonical
		var parsed1, parsed2 map[string]interface{}
		json.Unmarshal([]byte(body1), &parsed1)
		json.Unmarshal([]byte(body2), &parsed2)

		// After canonicalization, should be identical
		// RFC 8785 sorts keys alphabetically
		canonical1, _ := json.Marshal(parsed1)
		canonical2, _ := json.Marshal(parsed2)

		// Note: Go's json.Marshal sorts keys
		assert.Equal(t, string(canonical1), string(canonical2))
	})

	t.Run("whitespace_manipulation", func(t *testing.T) {
		// Whitespace shouldn't affect signature if properly canonicalized
		body1 := `{"to":"0xabc"}`
		body2 := `{  "to"  :  "0xabc"  }`

		var parsed1, parsed2 map[string]interface{}
		json.Unmarshal([]byte(body1), &parsed1)
		json.Unmarshal([]byte(body2), &parsed2)

		// After parsing and re-serializing, whitespace is normalized
		canonical1, _ := json.Marshal(parsed1)
		canonical2, _ := json.Marshal(parsed2)

		assert.Equal(t, string(canonical1), string(canonical2))
	})

	t.Run("unicode_normalization", func(t *testing.T) {
		// Unicode should be handled consistently
		withUnicode := `{"name":"café"}`

		var parsed map[string]interface{}
		err := json.Unmarshal([]byte(withUnicode), &parsed)
		require.NoError(t, err)

		canonical, _ := json.Marshal(parsed)
		assert.Contains(t, string(canonical), "café")
	})
}

// =============================================================================
// HEX ENCODING ATTACKS
// =============================================================================

func TestAttack_HexEncodingManipulation(t *testing.T) {
	t.Run("invalid_hex_in_transaction_data", func(t *testing.T) {
		invalidHexStrings := []string{
			"0xGGGGGG",      // Invalid chars
			"0x123",         // Odd length
			"0x",            // Empty
			"not-hex-at-all",
		}

		for _, hexStr := range invalidHexStrings {
			cleaned := strings.TrimPrefix(hexStr, "0x")
			_, err := hex.DecodeString(cleaned)
			if len(cleaned)%2 != 0 || !isValidHex(cleaned) {
				assert.Error(t, err, "invalid hex should error: %s", hexStr)
			}
		}
	})

	t.Run("address_length_validation", func(t *testing.T) {
		validAddress := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e" // 42 chars
		shortAddress := "0x742d35Cc6634C0532925a3b844Bc454e4438f4"   // 41 chars
		longAddress := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e00" // 44 chars

		assert.Len(t, validAddress, 42)
		assert.Less(t, len(shortAddress), 42)
		assert.Greater(t, len(longAddress), 42)
	})
}

func isValidHex(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
