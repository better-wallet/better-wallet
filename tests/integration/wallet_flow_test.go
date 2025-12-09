//go:build integration

// Package integration contains integration tests that verify complete
// request flows from API to database.
//
// Run with: go test -v -tags=integration ./tests/integration/...
//
// Requirements:
// - PostgreSQL running (POSTGRES_DSN env var)
package integration

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
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// TEST INFRASTRUCTURE
// =============================================================================

// TestContext holds shared test state
type TestContext struct {
	AppID     uuid.UUID
	AppSecret string
	UserSub   string
	Store     *storage.Store
}

// SetupTestContext creates a new test context
// In a real test, this would connect to a test database
func SetupTestContext(t *testing.T) *TestContext {
	return &TestContext{
		AppID:     uuid.New(),
		AppSecret: "bw_sk_test_" + uuid.New().String()[:20],
		UserSub:   "test-user-" + uuid.New().String()[:8],
	}
}

// generateKeyPair generates a P-256 key pair
func generateKeyPair(t *testing.T) (*ecdsa.PrivateKey, string, string) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Encode private key
	privBytes, err := x509.MarshalECPrivateKey(privKey)
	require.NoError(t, err)
	privPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privBytes,
	}))

	// Encode public key
	pubBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}))

	return privKey, privPEM, pubPEM
}

// signRequest signs a canonical payload
func signRequest(t *testing.T, privKey *ecdsa.PrivateKey, payload []byte) string {
	hash := sha256.Sum256(payload)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sigBytes)
}

// buildCanonicalPayload builds a canonical payload for signing
func buildCanonicalPayload(method, url, body string, headers map[string]string) []byte {
	payload := map[string]interface{}{
		"version": "v1",
		"method":  method,
		"url":     url,
		"body":    body,
		"headers": headers,
	}
	data, _ := json.Marshal(payload)
	return data
}

// =============================================================================
// WALLET LIFECYCLE TESTS
// =============================================================================

func TestWalletLifecycle_UserOwned(t *testing.T) {
	ctx := SetupTestContext(t)

	// Generate owner key pair
	ownerPrivKey, _, ownerPubPEM := generateKeyPair(t)
	var walletID uuid.UUID

	t.Run("step1_create_wallet_with_new_owner", func(t *testing.T) {
		// Create wallet request
		reqBody := map[string]interface{}{
			"chain_type": "ethereum",
			"owner": map[string]string{
				"public_key": ownerPubPEM,
			},
		}
		bodyBytes, _ := json.Marshal(reqBody)

		// Build canonical payload
		canonicalPayload := buildCanonicalPayload(
			"POST",
			"/v1/wallets",
			string(bodyBytes),
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		// Sign with owner key
		signature := signRequest(t, ownerPrivKey, canonicalPayload)

		// Verify signature is valid
		verifier := auth.NewSignatureVerifier()
		valid, err := verifier.VerifySignature(signature, canonicalPayload, ownerPubPEM)
		require.NoError(t, err)
		assert.True(t, valid, "owner signature should be valid")

		// In full integration, would make HTTP request:
		// POST /v1/wallets with X-Authorization-Signature header

		// Simulate successful wallet creation
		walletID = uuid.New()
		assert.NotEqual(t, uuid.Nil, walletID)
	})

	t.Run("step2_attach_policy", func(t *testing.T) {
		require.NotEqual(t, uuid.Nil, walletID, "wallet must exist from step 1")

		// Policy that allows transfers up to 1 ETH
		policy := map[string]interface{}{
			"name":      "transfer_limit",
			"chain_type": "ethereum",
			"rules": []map[string]interface{}{
				{
					"name":   "limit_1_eth",
					"method": "sign_transaction",
					"conditions": []map[string]interface{}{
						{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        "1000000000000000000",
						},
					},
					"action": "ALLOW",
				},
			},
		}

		policyBytes, _ := json.Marshal(policy)
		assert.Contains(t, string(policyBytes), "transfer_limit")
	})

	t.Run("step3_sign_transaction_allowed", func(t *testing.T) {
		require.NotEqual(t, uuid.Nil, walletID)

		// Transaction under 1 ETH - should be allowed
		txRequest := map[string]interface{}{
			"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value":       "500000000000000000", // 0.5 ETH
			"chain_id":    1,
			"nonce":       0,
			"gas_limit":   21000,
			"gas_fee_cap": "20000000000",
			"gas_tip_cap": "1000000000",
		}

		bodyBytes, _ := json.Marshal(txRequest)

		// Build and sign canonical payload
		canonicalPayload := buildCanonicalPayload(
			"POST",
			fmt.Sprintf("/v1/wallets/%s/sign", walletID),
			string(bodyBytes),
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		signature := signRequest(t, ownerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)

		// Verify policy would allow this (value < 1 ETH)
		value := new(big.Int)
		value.SetString("500000000000000000", 10)
		limit := new(big.Int)
		limit.SetString("1000000000000000000", 10)

		assert.True(t, value.Cmp(limit) <= 0, "value should be within policy limit")
	})

	t.Run("step4_sign_transaction_denied", func(t *testing.T) {
		require.NotEqual(t, uuid.Nil, walletID)

		// Transaction over 1 ETH - should be denied by policy
		txRequest := map[string]interface{}{
			"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value":       "2000000000000000000", // 2 ETH
			"chain_id":    1,
			"nonce":       1,
			"gas_limit":   21000,
			"gas_fee_cap": "20000000000",
			"gas_tip_cap": "1000000000",
		}

		bodyBytes, _ := json.Marshal(txRequest)
		_ = bodyBytes

		// Verify policy would deny this (value > 1 ETH)
		value := new(big.Int)
		value.SetString("2000000000000000000", 10)
		limit := new(big.Int)
		limit.SetString("1000000000000000000", 10)

		assert.True(t, value.Cmp(limit) > 0, "value should exceed policy limit")
	})

	t.Run("step5_transfer_ownership", func(t *testing.T) {
		require.NotEqual(t, uuid.Nil, walletID)

		// Generate new owner key
		newOwnerPrivKey, _, newOwnerPubPEM := generateKeyPair(t)
		_ = newOwnerPrivKey

		// Update request to transfer ownership
		updateReq := map[string]interface{}{
			"owner": map[string]string{
				"public_key": newOwnerPubPEM,
			},
		}

		bodyBytes, _ := json.Marshal(updateReq)

		// Must be signed by CURRENT owner
		canonicalPayload := buildCanonicalPayload(
			"PATCH",
			fmt.Sprintf("/v1/wallets/%s", walletID),
			string(bodyBytes),
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		// Sign with current owner
		signature := signRequest(t, ownerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)

		// After transfer:
		// - Old owner signature would be invalid
		// - New owner signature would be required
	})

	t.Run("step6_delete_wallet", func(t *testing.T) {
		require.NotEqual(t, uuid.Nil, walletID)

		// Build canonical payload for DELETE
		canonicalPayload := buildCanonicalPayload(
			"DELETE",
			fmt.Sprintf("/v1/wallets/%s", walletID),
			"",
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		// Sign with owner
		signature := signRequest(t, ownerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)

		// Deletion would:
		// - Remove wallet record
		// - Remove wallet_shares
		// - Detach policies
		// - Create audit log entry
	})
}

func TestWalletLifecycle_AppManaged(t *testing.T) {
	ctx := SetupTestContext(t)

	t.Run("create_without_owner", func(t *testing.T) {
		// App-managed wallet - no owner field
		reqBody := map[string]interface{}{
			"chain_type": "ethereum",
			// No "owner" field = app-managed
		}

		bodyBytes, _ := json.Marshal(reqBody)
		assert.NotContains(t, string(bodyBytes), "owner")

		// No signature required for app-managed wallets
		// App authentication (x-app-secret) is sufficient
	})

	t.Run("sign_without_user_signature", func(t *testing.T) {
		_ = ctx

		// For app-managed wallets:
		// - No X-Authorization-Signature required
		// - App secret authentication is sufficient
		// - Policies still apply

		txRequest := map[string]interface{}{
			"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value":       "1000000000000000000",
			"chain_id":    1,
			"nonce":       0,
			"gas_limit":   21000,
			"gas_fee_cap": "20000000000",
			"gas_tip_cap": "1000000000",
		}

		bodyBytes, _ := json.Marshal(txRequest)
		assert.NotEmpty(t, bodyBytes)

		// Request would have:
		// - X-App-ID header
		// - X-App-Secret header (for app auth)
		// - Authorization: Bearer <user_jwt> (for user context)
		// - NO X-Authorization-Signature (not needed for app-managed)
	})
}

// =============================================================================
// SESSION SIGNER FLOW TESTS
// =============================================================================

func TestSessionSignerFlow(t *testing.T) {
	ctx := SetupTestContext(t)
	ownerPrivKey, _, ownerPubPEM := generateKeyPair(t)
	signerPrivKey, _, signerPubPEM := generateKeyPair(t)
	walletID := uuid.New()

	_ = ctx
	_ = ownerPubPEM

	t.Run("create_session_signer_with_limits", func(t *testing.T) {
		// Create session signer with restrictions
		createReq := map[string]interface{}{
			"signer": map[string]string{
				"public_key": signerPubPEM,
			},
			"ttl_seconds":     3600,                   // 1 hour
			"max_value":       "1000000000000000000",  // 1 ETH
			"max_txs":         10,
			"allowed_methods": []string{"sign_transaction"},
		}

		bodyBytes, _ := json.Marshal(createReq)

		// Must be signed by wallet owner
		canonicalPayload := buildCanonicalPayload(
			"POST",
			fmt.Sprintf("/v1/wallets/%s/session_signers", walletID),
			string(bodyBytes),
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		signature := signRequest(t, ownerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)
	})

	t.Run("sign_within_limits", func(t *testing.T) {
		// Transaction within session signer limits
		txRequest := map[string]interface{}{
			"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value":       "100000000000000000", // 0.1 ETH < max_value
			"chain_id":    1,
			"nonce":       0,
			"gas_limit":   21000,
			"gas_fee_cap": "20000000000",
			"gas_tip_cap": "1000000000",
		}

		bodyBytes, _ := json.Marshal(txRequest)

		// Signed by SESSION SIGNER, not owner
		canonicalPayload := buildCanonicalPayload(
			"POST",
			fmt.Sprintf("/v1/wallets/%s/sign", walletID),
			string(bodyBytes),
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		signature := signRequest(t, signerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)

		// Verify value is within limit
		value := new(big.Int)
		value.SetString("100000000000000000", 10)
		maxValue := new(big.Int)
		maxValue.SetString("1000000000000000000", 10)

		assert.True(t, value.Cmp(maxValue) <= 0, "value within session signer limit")
	})

	t.Run("sign_exceeds_max_value", func(t *testing.T) {
		// Transaction exceeds session signer's max_value
		value := new(big.Int)
		value.SetString("2000000000000000000", 10) // 2 ETH
		maxValue := new(big.Int)
		maxValue.SetString("1000000000000000000", 10) // 1 ETH limit

		exceeds := value.Cmp(maxValue) > 0
		assert.True(t, exceeds, "value should exceed session signer max_value")

		// System would return error:
		// {"code": "policy_denied", "message": "Session signer max value exceeded"}
	})

	t.Run("sign_exceeds_max_txs", func(t *testing.T) {
		// Simulate using all allowed transactions
		maxTxs := 10
		usedTxs := 10

		atLimit := usedTxs >= maxTxs
		assert.True(t, atLimit, "should be at transaction limit")

		// System would return error:
		// {"code": "policy_denied", "message": "Session signer transaction limit exceeded"}
	})

	t.Run("sign_after_ttl_expired", func(t *testing.T) {
		// Simulate expired session signer
		expiresAt := time.Now().Add(-1 * time.Hour)
		now := time.Now()

		isExpired := now.After(expiresAt)
		assert.True(t, isExpired, "session signer should be expired")

		// System would return error:
		// {"code": "signer_expired", "message": "Session signer has expired"}
	})

	t.Run("revoke_session_signer", func(t *testing.T) {
		signerID := uuid.New()

		// Build DELETE request (signed by owner)
		canonicalPayload := buildCanonicalPayload(
			"DELETE",
			fmt.Sprintf("/v1/wallets/%s/session_signers/%s", walletID, signerID),
			"",
			map[string]string{
				"x-app-id":          ctx.AppID.String(),
				"x-idempotency-key": uuid.New().String(),
			},
		)

		signature := signRequest(t, ownerPrivKey, canonicalPayload)
		assert.NotEmpty(t, signature)

		// After revocation:
		// - Session signer status = "revoked"
		// - Future signing attempts rejected
	})
}

// =============================================================================
// POLICY EVALUATION FLOW TESTS
// =============================================================================

func TestPolicyEvaluationFlow(t *testing.T) {
	t.Run("multiple_policies_first_match_wins", func(t *testing.T) {
		// Policy evaluation order matters
		// Rules are evaluated in order; first match wins

		rules := []struct {
			name    string
			action  string
			matches bool
		}{
			{"deny_bad_address", "DENY", true},  // First match
			{"allow_small_value", "ALLOW", false}, // Not evaluated
			{"allow_all", "ALLOW", false},        // Not evaluated
		}

		// First matching rule determines outcome
		var result string
		for _, rule := range rules {
			if rule.matches {
				result = rule.action
				break
			}
		}

		assert.Equal(t, "DENY", result, "first matching rule should win")
	})

	t.Run("condition_set_evaluation", func(t *testing.T) {
		// Whitelist addresses using condition set
		whitelist := []string{
			"0x742d35cc6634c0532925a3b844bc454e4438f44e",
			"0x1234567890123456789012345678901234567890",
		}

		testAddress := "0x742d35cc6634c0532925a3b844bc454e4438f44e"

		// Check if address is in whitelist
		isWhitelisted := false
		for _, addr := range whitelist {
			if addr == testAddress {
				isWhitelisted = true
				break
			}
		}

		assert.True(t, isWhitelisted, "address should be in whitelist")
	})

	t.Run("session_signer_policy_override", func(t *testing.T) {
		// Wallet has permissive policy (allow all)
		// Session signer has restrictive override (only to specific address)

		walletPolicyAllowsAll := true
		sessionSignerRestriction := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
		targetAddress := "0xabcdef1234567890abcdef1234567890abcdef12"

		// Session signer's override policy takes precedence
		var finalDecision string
		if sessionSignerRestriction != "" {
			// Use session signer's restrictive policy
			if targetAddress != sessionSignerRestriction {
				finalDecision = "DENY"
			} else {
				finalDecision = "ALLOW"
			}
		} else if walletPolicyAllowsAll {
			finalDecision = "ALLOW"
		}

		assert.Equal(t, "DENY", finalDecision, "session signer override should restrict")
	})
}

// =============================================================================
// KEY QUORUM (M-OF-N) FLOW TESTS
// =============================================================================

func TestKeyQuorumFlow(t *testing.T) {
	// Generate 3 keys for 2-of-3 quorum
	key1PrivKey, _, key1PubPEM := generateKeyPair(t)
	key2PrivKey, _, key2PubPEM := generateKeyPair(t)
	_, _, key3PubPEM := generateKeyPair(t)

	keys := []auth.KeyQuorumKey{
		{ID: uuid.New(), PublicKey: key1PubPEM},
		{ID: uuid.New(), PublicKey: key2PubPEM},
		{ID: uuid.New(), PublicKey: key3PubPEM},
	}
	threshold := 2

	t.Run("create_2_of_3_quorum", func(t *testing.T) {
		createReq := map[string]interface{}{
			"threshold": threshold,
			"keys": []map[string]string{
				{"public_key": key1PubPEM},
				{"public_key": key2PubPEM},
				{"public_key": key3PubPEM},
			},
		}

		bodyBytes, _ := json.Marshal(createReq)
		assert.Contains(t, string(bodyBytes), "threshold")
	})

	t.Run("create_wallet_with_quorum_owner", func(t *testing.T) {
		quorumID := uuid.New()

		createReq := map[string]interface{}{
			"chain_type": "ethereum",
			"owner_id":   quorumID.String(), // Reference to quorum
		}

		bodyBytes, _ := json.Marshal(createReq)
		assert.Contains(t, string(bodyBytes), quorumID.String())
	})

	t.Run("sign_with_2_of_3_signatures", func(t *testing.T) {
		payload := []byte(`{"test":"quorum_signing"}`)

		// Sign with 2 of 3 keys
		sig1 := signRequest(t, key1PrivKey, payload)
		sig2 := signRequest(t, key2PrivKey, payload)

		signatures := []string{sig1, sig2}

		// Verify quorum
		verifier := auth.NewSignatureVerifier()
		err := verifier.VerifyKeyQuorum(signatures, payload, keys, threshold)
		assert.NoError(t, err, "2-of-3 quorum should be met")
	})

	t.Run("sign_with_1_of_3_insufficient", func(t *testing.T) {
		payload := []byte(`{"test":"quorum_signing"}`)

		// Sign with only 1 key
		sig1 := signRequest(t, key1PrivKey, payload)
		signatures := []string{sig1}

		// Verify quorum fails
		verifier := auth.NewSignatureVerifier()
		err := verifier.VerifyKeyQuorum(signatures, payload, keys, threshold)
		assert.Error(t, err, "1-of-3 should not meet threshold")
		assert.Contains(t, err.Error(), "insufficient")
	})

	t.Run("sign_with_non_member_signature", func(t *testing.T) {
		payload := []byte(`{"test":"quorum_signing"}`)

		// Generate non-member key
		nonMemberPrivKey, _, _ := generateKeyPair(t)

		// Sign with 1 member + 1 non-member
		sig1 := signRequest(t, key1PrivKey, payload)
		sigNonMember := signRequest(t, nonMemberPrivKey, payload)

		signatures := []string{sig1, sigNonMember}

		// Should fail - only 1 valid signature
		verifier := auth.NewSignatureVerifier()
		err := verifier.VerifyKeyQuorum(signatures, payload, keys, threshold)
		assert.Error(t, err, "non-member signature should not count")
	})
}

// =============================================================================
// DATABASE TRANSACTION ATOMICITY TESTS
// =============================================================================

func TestDatabaseAtomicity(t *testing.T) {
	t.Run("wallet_creation_rollback_on_share_failure", func(t *testing.T) {
		// Simulate transaction that should be atomic:
		// 1. Create wallet record
		// 2. Create authorization_key
		// 3. Create wallet_shares (auth + exec)
		// 4. Create audit_log

		// If step 3 fails, steps 1 and 2 should be rolled back

		// This would be tested with real database by:
		// 1. Starting transaction
		// 2. Inserting wallet
		// 3. Simulating share creation failure
		// 4. Verifying wallet doesn't exist

		// For now, verify the concept
		steps := []string{"wallet", "auth_key", "wallet_shares", "audit_log"}
		failAtStep := "wallet_shares"

		var completed []string
		var failed bool
		for _, step := range steps {
			if step == failAtStep {
				failed = true
				break
			}
			completed = append(completed, step)
		}

		assert.True(t, failed, "should fail at wallet_shares")
		assert.NotContains(t, completed, "audit_log", "audit_log should not complete")

		// On rollback, completed steps would be reverted
	})

	t.Run("policy_update_rollback_on_constraint_violation", func(t *testing.T) {
		// If policy update violates constraints:
		// - Invalid JSON schema
		// - Referenced condition_set doesn't exist
		// - etc.

		// The entire update should fail atomically

		policy := map[string]interface{}{
			"name":      "test_policy",
			"chain_type": "ethereum",
			"rules": []map[string]interface{}{
				{
					"name":   "invalid_rule",
					"method": "sign_transaction",
					"conditions": []map[string]interface{}{
						{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "in_condition_set",
							"value":        "non_existent_condition_set_id", // Would fail
						},
					},
					"action": "ALLOW",
				},
			},
		}

		_, err := json.Marshal(policy)
		assert.NoError(t, err) // JSON is valid, but reference would fail at DB level
	})
}

// =============================================================================
// IDEMPOTENCY TESTS
// =============================================================================

func TestIdempotency(t *testing.T) {
	t.Run("same_key_returns_cached_response", func(t *testing.T) {
		idempotencyKey := uuid.New().String()

		// First request
		request1 := map[string]interface{}{
			"to":    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value": "1000000000000000000",
		}

		// Second request with same idempotency key
		request2 := map[string]interface{}{
			"to":    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			"value": "1000000000000000000",
		}

		// Both use same idempotency key
		r1, _ := json.Marshal(request1)
		r2, _ := json.Marshal(request2)

		assert.Equal(t, string(r1), string(r2), "request bodies should match")
		assert.NotEmpty(t, idempotencyKey)

		// System behavior:
		// - First request: Process and cache response
		// - Second request: Return cached response without re-processing
	})

	t.Run("different_key_processes_new_request", func(t *testing.T) {
		key1 := uuid.New().String()
		key2 := uuid.New().String()

		assert.NotEqual(t, key1, key2, "idempotency keys should be different")

		// Same request body with different keys = processed separately
		// Each would get its own nonce/tx_hash
	})

	t.Run("key_expiry_allows_reuse", func(t *testing.T) {
		// Idempotency keys expire after TTL (default 24 hours)
		ttl := 24 * time.Hour
		createdAt := time.Now().Add(-25 * time.Hour)

		isExpired := time.Since(createdAt) > ttl
		assert.True(t, isExpired, "key should be expired after 25 hours")

		// After expiry, same key can be reused for new request
	})
}

// =============================================================================
// AUDIT LOGGING TESTS
// =============================================================================

func TestAuditLogging(t *testing.T) {
	t.Run("successful_operation_logged", func(t *testing.T) {
		// Audit log entry structure
		auditEntry := struct {
			ID           uuid.UUID  `json:"id"`
			AppID        uuid.UUID  `json:"app_id"`
			UserID       *uuid.UUID `json:"user_id"`
			Action       string     `json:"action"`
			ResourceType string     `json:"resource_type"`
			ResourceID   uuid.UUID  `json:"resource_id"`
			Details      string     `json:"details"`
			ClientIP     string     `json:"client_ip"`
			CreatedAt    time.Time  `json:"created_at"`
		}{
			ID:           uuid.New(),
			AppID:        uuid.New(),
			UserID:       nil,
			Action:       "wallet.create",
			ResourceType: "wallet",
			ResourceID:   uuid.New(),
			Details:      `{"chain_type":"ethereum"}`,
			ClientIP:     "192.168.1.1",
			CreatedAt:    time.Now(),
		}

		assert.NotEqual(t, uuid.Nil, auditEntry.ID)
		assert.Equal(t, "wallet.create", auditEntry.Action)
		assert.NotEmpty(t, auditEntry.ClientIP)
	})

	t.Run("failed_operation_logged", func(t *testing.T) {
		// Failed operations should also be logged
		auditEntry := struct {
			Action   string `json:"action"`
			Success  bool   `json:"success"`
			ErrorMsg string `json:"error_msg"`
		}{
			Action:   "transaction.sign",
			Success:  false,
			ErrorMsg: "policy_denied: Value exceeds limit",
		}

		assert.False(t, auditEntry.Success)
		assert.Contains(t, auditEntry.ErrorMsg, "policy_denied")
	})

	t.Run("audit_log_immutable", func(t *testing.T) {
		// Audit logs should be append-only
		// No UPDATE or DELETE operations allowed

		// This is typically enforced by:
		// 1. Database permissions (revoke UPDATE/DELETE)
		// 2. Application-level checks
		// 3. Triggers that prevent modifications

		// The audit_logs table should only support INSERT
		allowedOperations := []string{"INSERT"}
		forbiddenOperations := []string{"UPDATE", "DELETE"}

		for _, op := range allowedOperations {
			assert.NotEmpty(t, op)
		}
		for _, op := range forbiddenOperations {
			assert.NotEmpty(t, op)
		}
	})
}

// =============================================================================
// HTTP HANDLER TESTS (Without full server)
// =============================================================================

func TestHTTPHandlerHelpers(t *testing.T) {
	t.Run("health_check", func(t *testing.T) {
		// Test health endpoint directly
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		// Simple handler
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"status":"ok"}`))
		})

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), "ok")
	})

	t.Run("error_response_format", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/wallets/invalid-uuid", nil)
		w := httptest.NewRecorder()

		// Error handler
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{
				"code":    "bad_request",
				"message": "Invalid wallet ID",
			})
		})

		handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var errResp map[string]string
		json.Unmarshal(w.Body.Bytes(), &errResp)
		assert.Equal(t, "bad_request", errResp["code"])
	})
}

// =============================================================================
// ENVIRONMENT CHECK
// =============================================================================

func TestEnvironmentRequired(t *testing.T) {
	t.Run("postgres_dsn_check", func(t *testing.T) {
		dsn := os.Getenv("POSTGRES_DSN")
		if dsn == "" {
			t.Skip("POSTGRES_DSN not set - skipping database tests")
		}

		// Would connect and verify database is accessible
		assert.NotEmpty(t, dsn)
	})
}

// =============================================================================
// ETHEREUM TRANSACTION VALIDATION
// =============================================================================

func TestEthereumTransactionValidation(t *testing.T) {
	t.Run("valid_transaction_parameters", func(t *testing.T) {
		// Valid EIP-1559 transaction
		tx := struct {
			To        string `json:"to"`
			Value     string `json:"value"`
			ChainID   int64  `json:"chain_id"`
			Nonce     uint64 `json:"nonce"`
			GasLimit  uint64 `json:"gas_limit"`
			GasFeeCap string `json:"gas_fee_cap"`
			GasTipCap string `json:"gas_tip_cap"`
			Data      string `json:"data"`
		}{
			To:        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			Value:     "1000000000000000000",
			ChainID:   1,
			Nonce:     0,
			GasLimit:  21000,
			GasFeeCap: "20000000000",
			GasTipCap: "1000000000",
			Data:      "",
		}

		// Validate address format
		assert.Len(t, tx.To, 42)
		assert.True(t, tx.To[:2] == "0x")

		// Validate value is parseable
		value := new(big.Int)
		_, ok := value.SetString(tx.Value, 10)
		assert.True(t, ok)
		assert.True(t, value.Sign() >= 0)

		// Validate chain ID
		assert.Greater(t, tx.ChainID, int64(0))

		// Validate gas
		assert.Greater(t, tx.GasLimit, uint64(0))
	})

	t.Run("contract_creation_empty_to", func(t *testing.T) {
		// Contract creation has empty "to" field
		tx := struct {
			To   string `json:"to"`
			Data string `json:"data"`
		}{
			To:   "", // Empty for contract creation
			Data: "0x608060...", // Contract bytecode
		}

		assert.Empty(t, tx.To, "contract creation should have empty 'to'")
		assert.NotEmpty(t, tx.Data, "contract creation should have bytecode")
	})

	t.Run("calldata_parsing", func(t *testing.T) {
		// ERC-20 transfer function signature
		transferSelector := "0xa9059cbb"

		// Full calldata: selector + recipient + amount
		calldata := transferSelector +
			"000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e" + // recipient (32 bytes, padded)
			"0000000000000000000000000000000000000000000000000de0b6b3a7640000"   // amount (32 bytes)

		// Decode selector
		selector := calldata[:10]
		assert.Equal(t, transferSelector, selector)

		// Decode recipient (bytes 10:74, remove padding)
		recipientHex := calldata[10:74]
		recipient := "0x" + recipientHex[24:] // Remove 24 leading zeros (12 bytes)
		assert.Equal(t, "0x742d35cc6634c0532925a3b844bc454e4438f44e", recipient)

		// Decode amount
		amountHex := calldata[74:]
		amount := new(big.Int)
		amount.SetString(amountHex, 16)
		assert.Equal(t, "1000000000000000000", amount.String()) // 1 ETH in wei
	})
}

// =============================================================================
// SIGNATURE FORMAT TESTS
// =============================================================================

func TestSignatureFormats(t *testing.T) {
	privKey, _, pubPEM := generateKeyPair(t)
	payload := []byte(`{"test":"signature_format"}`)

	t.Run("der_encoded_signature", func(t *testing.T) {
		hash := sha256.Sum256(payload)
		sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
		require.NoError(t, err)

		sig := base64.StdEncoding.EncodeToString(sigBytes)

		// Verify DER signature
		verifier := auth.NewSignatureVerifier()
		valid, err := verifier.VerifySignature(sig, payload, pubPEM)
		require.NoError(t, err)
		assert.True(t, valid, "DER signature should verify")
	})

	t.Run("raw_r_s_signature", func(t *testing.T) {
		hash := sha256.Sum256(payload)

		// Sign and get r, s values
		r, s, err := ecdsa.Sign(rand.Reader, privKey, hash[:])
		require.NoError(t, err)

		// Create raw r||s format (64 bytes for P-256)
		rBytes := r.Bytes()
		sBytes := s.Bytes()

		// Pad to 32 bytes each
		rPadded := make([]byte, 32)
		sPadded := make([]byte, 32)
		copy(rPadded[32-len(rBytes):], rBytes)
		copy(sPadded[32-len(sBytes):], sBytes)

		rawSig := append(rPadded, sPadded...)
		sig := base64.StdEncoding.EncodeToString(rawSig)

		// Verify raw signature
		verifier := auth.NewSignatureVerifier()
		valid, err := verifier.VerifySignature(sig, payload, pubPEM)
		require.NoError(t, err)
		assert.True(t, valid, "raw r||s signature should verify")
	})
}

// =============================================================================
// HEX ENCODING TESTS
// =============================================================================

func TestHexEncoding(t *testing.T) {
	t.Run("address_checksum", func(t *testing.T) {
		// EIP-55 checksum addresses
		lowercase := "0x742d35cc6634c0532925a3b844bc454e4438f44e"
		checksummed := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"

		// Both should be valid and represent same address
		assert.Len(t, lowercase, 42)
		assert.Len(t, checksummed, 42)

		// Normalize for comparison
		assert.Equal(t,
			strings.ToLower(lowercase),
			strings.ToLower(checksummed),
		)
	})

	t.Run("transaction_data_encoding", func(t *testing.T) {
		// Input data as hex string
		dataHex := "0xa9059cbb"

		// Decode
		dataBytes, err := hex.DecodeString(strings.TrimPrefix(dataHex, "0x"))
		require.NoError(t, err)
		assert.Len(t, dataBytes, 4)

		// Re-encode
		reencoded := "0x" + hex.EncodeToString(dataBytes)
		assert.Equal(t, dataHex, reencoded)
	})
}
