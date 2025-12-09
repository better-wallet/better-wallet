package app

import (
	"math/big"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

// =============================================================================
// Pure Function Tests - No dependencies required
// =============================================================================

func TestIsAppManagedWallet(t *testing.T) {
	tests := []struct {
		name     string
		wallet   *types.Wallet
		expected bool
	}{
		{
			name: "app_managed_nil_owner",
			wallet: &types.Wallet{
				ID:      uuid.New(),
				OwnerID: nil,
			},
			expected: true,
		},
		{
			name: "user_owned_with_owner",
			wallet: &types.Wallet{
				ID:      uuid.New(),
				OwnerID: ptrUUID(uuid.New()),
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsAppManagedWallet(tt.wallet)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// =============================================================================
// Session Signer Method Filtering Tests
// =============================================================================

func TestSessionSignerAllowsMethod(t *testing.T) {
	// Create a minimal WalletService for testing (we only need the method)
	service := &WalletService{}

	tests := []struct {
		name           string
		sessionSigner  *types.SessionSigner
		requestedMethod types.SigningMethod
		expected       bool
	}{
		{
			name: "empty_allowed_methods_allows_all",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{},
			},
			requestedMethod: types.SignMethodTransaction,
			expected:       true,
		},
		{
			name: "nil_allowed_methods_allows_all",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: nil,
			},
			requestedMethod: types.SignMethodPersonal,
			expected:       true,
		},
		{
			name: "sign_transaction_allowed",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{string(types.SignMethodTransaction)},
			},
			requestedMethod: types.SignMethodTransaction,
			expected:       true,
		},
		{
			name: "sign_transaction_not_in_list",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{string(types.SignMethodPersonal)},
			},
			requestedMethod: types.SignMethodTransaction,
			expected:       false,
		},
		{
			name: "personal_sign_allowed",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{string(types.SignMethodPersonal)},
			},
			requestedMethod: types.SignMethodPersonal,
			expected:       true,
		},
		{
			name: "multiple_methods_allowed",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{
					string(types.SignMethodTransaction),
					string(types.SignMethodPersonal),
					string(types.SignMethodTypedData),
				},
			},
			requestedMethod: types.SignMethodTypedData,
			expected:       true,
		},
		{
			name: "method_not_in_multiple",
			sessionSigner: &types.SessionSigner{
				ID:             uuid.New(),
				AllowedMethods: []string{
					string(types.SignMethodTransaction),
					string(types.SignMethodPersonal),
				},
			},
			requestedMethod: types.SignMethodTypedData,
			expected:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := service.sessionSignerAllowsMethod(tt.sessionSigner, tt.requestedMethod)
			assert.Equal(t, tt.expected, result, "method filtering mismatch")
		})
	}
}

// =============================================================================
// Session Signer Limit Validation Tests
// =============================================================================

func TestSessionSignerValueLimit(t *testing.T) {
	tests := []struct {
		name          string
		maxValue      *string
		requestValue  *big.Int
		shouldExceed  bool
	}{
		{
			name:         "no_limit_allows_any",
			maxValue:     nil,
			requestValue: big.NewInt(1000000000000000000), // 1 ETH
			shouldExceed: false,
		},
		{
			name:         "within_limit",
			maxValue:     ptrString("1000000000000000000"), // 1 ETH
			requestValue: big.NewInt(500000000000000000),   // 0.5 ETH
			shouldExceed: false,
		},
		{
			name:         "exactly_at_limit",
			maxValue:     ptrString("1000000000000000000"),
			requestValue: big.NewInt(1000000000000000000),
			shouldExceed: false,
		},
		{
			name:         "exceeds_limit",
			maxValue:     ptrString("1000000000000000000"),
			requestValue: big.NewInt(2000000000000000000), // 2 ETH
			shouldExceed: true,
		},
		{
			name:         "zero_value_always_allowed",
			maxValue:     ptrString("1000000000000000000"),
			requestValue: big.NewInt(0),
			shouldExceed: false,
		},
		{
			name:         "large_limit_large_value",
			maxValue:     ptrString("115792089237316195423570985008687907853269984665640564039457584007913129639935"),
			requestValue: mustParseBigInt("115792089237316195423570985008687907853269984665640564039457584007913129639934"),
			shouldExceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceeds := checkValueExceedsLimit(tt.maxValue, tt.requestValue)
			assert.Equal(t, tt.shouldExceed, exceeds, "value limit check mismatch")
		})
	}
}

// checkValueExceedsLimit is a helper that mimics the logic in SignTransaction
func checkValueExceedsLimit(maxValue *string, requestValue *big.Int) bool {
	if maxValue == nil {
		return false
	}
	max := new(big.Int)
	if _, ok := max.SetString(*maxValue, 10); !ok {
		return false // Invalid max value format
	}
	return requestValue.Cmp(max) > 0
}

func TestSessionSignerTxCountLimit(t *testing.T) {
	tests := []struct {
		name          string
		maxTxs        *int
		currentCount  int
		shouldExceed  bool
	}{
		{
			name:         "no_limit",
			maxTxs:       nil,
			currentCount: 100,
			shouldExceed: false,
		},
		{
			name:         "within_limit",
			maxTxs:       ptrInt(10),
			currentCount: 5,
			shouldExceed: false,
		},
		{
			name:         "at_limit",
			maxTxs:       ptrInt(10),
			currentCount: 10,
			shouldExceed: true,
		},
		{
			name:         "exceeds_limit",
			maxTxs:       ptrInt(10),
			currentCount: 15,
			shouldExceed: true,
		},
		{
			name:         "zero_count",
			maxTxs:       ptrInt(10),
			currentCount: 0,
			shouldExceed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exceeds := checkTxCountExceedsLimit(tt.maxTxs, tt.currentCount)
			assert.Equal(t, tt.shouldExceed, exceeds, "tx count limit check mismatch")
		})
	}
}

func checkTxCountExceedsLimit(maxTxs *int, currentCount int) bool {
	if maxTxs == nil {
		return false
	}
	return currentCount >= *maxTxs
}

// =============================================================================
// Session Signer TTL Validation Tests
// =============================================================================

func TestSessionSignerTTLExpiry(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		checkTime time.Time
		isExpired bool
	}{
		{
			name:      "not_expired",
			expiresAt: time.Now().Add(1 * time.Hour),
			checkTime: time.Now(),
			isExpired: false,
		},
		{
			name:      "expired",
			expiresAt: time.Now().Add(-1 * time.Hour),
			checkTime: time.Now(),
			isExpired: true,
		},
		{
			name:      "exactly_at_expiry",
			expiresAt: time.Now(),
			checkTime: time.Now(),
			isExpired: true, // At expiry time means expired
		},
		{
			name:      "far_future",
			expiresAt: time.Now().Add(365 * 24 * time.Hour),
			checkTime: time.Now(),
			isExpired: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expired := !tt.checkTime.Before(tt.expiresAt)
			assert.Equal(t, tt.isExpired, expired, "TTL expiry check mismatch")
		})
	}
}

// =============================================================================
// Signature Validation Edge Cases
// =============================================================================

func TestSignatureArrayValidation(t *testing.T) {
	tests := []struct {
		name       string
		signatures []string
		expectErr  bool
	}{
		{
			name:       "empty_array_should_fail",
			signatures: []string{},
			expectErr:  true,
		},
		{
			name:       "nil_array_should_fail",
			signatures: nil,
			expectErr:  true,
		},
		{
			name:       "single_signature_valid",
			signatures: []string{"signature1"},
			expectErr:  false,
		},
		{
			name:       "multiple_signatures_valid",
			signatures: []string{"sig1", "sig2", "sig3"},
			expectErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignaturesPresent(tt.signatures)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func validateSignaturesPresent(signatures []string) error {
	if len(signatures) == 0 {
		return assert.AnError
	}
	return nil
}

// =============================================================================
// Quorum Threshold Validation Tests
// =============================================================================

func TestQuorumThresholdValidation(t *testing.T) {
	tests := []struct {
		name              string
		threshold         int
		totalKeys         int
		verifiedCount     int
		meetsThreshold    bool
	}{
		{
			name:           "2_of_3_met",
			threshold:      2,
			totalKeys:      3,
			verifiedCount:  2,
			meetsThreshold: true,
		},
		{
			name:           "2_of_3_exceeded",
			threshold:      2,
			totalKeys:      3,
			verifiedCount:  3,
			meetsThreshold: true,
		},
		{
			name:           "2_of_3_not_met",
			threshold:      2,
			totalKeys:      3,
			verifiedCount:  1,
			meetsThreshold: false,
		},
		{
			name:           "1_of_1_met",
			threshold:      1,
			totalKeys:      1,
			verifiedCount:  1,
			meetsThreshold: true,
		},
		{
			name:           "3_of_5_exactly_met",
			threshold:      3,
			totalKeys:      5,
			verifiedCount:  3,
			meetsThreshold: true,
		},
		{
			name:           "zero_signatures_never_meets",
			threshold:      2,
			totalKeys:      3,
			verifiedCount:  0,
			meetsThreshold: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			meets := tt.verifiedCount >= tt.threshold
			assert.Equal(t, tt.meetsThreshold, meets, "quorum threshold check mismatch")
		})
	}
}

// =============================================================================
// Input Validation Tests - Transaction Parameters
// =============================================================================

func TestTransactionValueValidation(t *testing.T) {
	tests := []struct {
		name      string
		value     *big.Int
		isValid   bool
	}{
		{
			name:    "zero_value_valid",
			value:   big.NewInt(0),
			isValid: true,
		},
		{
			name:    "positive_value_valid",
			value:   big.NewInt(1000000000000000000),
			isValid: true,
		},
		{
			name:    "negative_value_invalid",
			value:   big.NewInt(-1),
			isValid: false,
		},
		{
			name:    "nil_value_could_be_valid", // Depends on context
			value:   nil,
			isValid: true, // nil might mean 0 value transaction
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := validateTransactionValue(tt.value)
			assert.Equal(t, tt.isValid, valid, "transaction value validation mismatch")
		})
	}
}

func validateTransactionValue(value *big.Int) bool {
	if value == nil {
		return true // nil can be treated as 0
	}
	return value.Sign() >= 0 // Value must be non-negative
}

func TestAddressValidation(t *testing.T) {
	tests := []struct {
		name    string
		address string
		isValid bool
	}{
		{
			name:    "valid_lowercase",
			address: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			isValid: true,
		},
		{
			name:    "valid_checksum",
			address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			isValid: true,
		},
		{
			name:    "invalid_too_short",
			address: "0x742d35Cc6634C0532925a3b844Bc454e4438f4",
			isValid: false,
		},
		{
			name:    "invalid_too_long",
			address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e00",
			isValid: false,
		},
		{
			name:    "invalid_no_prefix",
			address: "742d35Cc6634C0532925a3b844Bc454e4438f44e",
			isValid: false,
		},
		{
			name:    "invalid_chars",
			address: "0x742d35Cc6634C0532925a3b844Bc454e4438fGGG",
			isValid: false,
		},
		{
			name:    "empty_string",
			address: "",
			isValid: false,
		},
		{
			name:    "zero_address",
			address: "0x0000000000000000000000000000000000000000",
			isValid: true, // Zero address is technically valid
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := isValidEthereumAddress(tt.address)
			assert.Equal(t, tt.isValid, valid, "address validation mismatch for %s", tt.address)
		})
	}
}

func isValidEthereumAddress(address string) bool {
	if len(address) != 42 {
		return false
	}
	if address[:2] != "0x" {
		return false
	}
	for _, c := range address[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// =============================================================================
// Helper Functions
// =============================================================================

func ptrUUID(u uuid.UUID) *uuid.UUID {
	return &u
}

func ptrString(s string) *string {
	return &s
}

func ptrInt(i int) *int {
	return &i
}

func mustParseBigInt(s string) *big.Int {
	n := new(big.Int)
	n.SetString(s, 10)
	return n
}
