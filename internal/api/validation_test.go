package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// API Request Validation Tests
// =============================================================================

// Note: Value parsing tests moved to TestParseHexBigInt which tests the actual
// /rpc endpoint behavior (accepts both 0x hex and decimal for backward compatibility)

func TestTransactionData_HexParsing(t *testing.T) {
	tests := []struct {
		name        string
		data        string
		expectValid bool
		expectLen   int
	}{
		{
			name:        "empty_data",
			data:        "",
			expectValid: true,
			expectLen:   0,
		},
		{
			name:        "valid_hex_no_prefix",
			data:        "a9059cbb",
			expectValid: true,
			expectLen:   4,
		},
		{
			name:        "valid_hex_with_prefix",
			data:        "0xa9059cbb",
			expectValid: true,
			expectLen:   4,
		},
		{
			name:        "valid_transfer_calldata",
			data:        "0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000a",
			expectValid: true,
			expectLen:   68,
		},
		{
			name:        "invalid_odd_length",
			data:        "0xa9059cb",
			expectValid: false,
		},
		{
			name:        "invalid_non_hex_chars",
			data:        "0xGGGGGG",
			expectValid: false,
		},
		{
			name:        "valid_all_zeros",
			data:        "0x00000000",
			expectValid: true,
			expectLen:   4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var data []byte
			var err error

			if tt.data != "" {
				dataStr := strings.TrimPrefix(tt.data, "0x")
				data, err = hex.DecodeString(dataStr)
			}

			if tt.expectValid {
				assert.NoError(t, err, "expected valid hex data")
				assert.Equal(t, tt.expectLen, len(data), "unexpected data length")
			} else {
				assert.Error(t, err, "expected invalid hex data")
			}
		})
	}
}

func TestSignMessageRequest_Validation(t *testing.T) {
	tests := []struct {
		name          string
		message       string
		encoding      string
		expectError   bool
		errorContains string
	}{
		{
			name:        "valid_utf8_message",
			message:     "Hello, World!",
			encoding:    "utf8",
			expectError: false,
		},
		{
			name:        "valid_default_encoding",
			message:     "Test message",
			encoding:    "",
			expectError: false,
		},
		{
			name:        "valid_hex_encoding",
			message:     "48656c6c6f",
			encoding:    "hex",
			expectError: false,
		},
		{
			name:          "empty_message",
			message:       "",
			encoding:      "utf8",
			expectError:   true,
			errorContains: "empty",
		},
		{
			name:          "invalid_encoding",
			message:       "test",
			encoding:      "base64",
			expectError:   true,
			errorContains: "encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSignMessageRequest(tt.message, tt.encoding)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, strings.ToLower(err.Error()), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// validateSignMessageRequest simulates the validation logic in handleSignMessage
func validateSignMessageRequest(message, encoding string) error {
	if message == "" {
		return &ValidationError{Field: "message", Reason: "cannot be empty"}
	}

	// Default encoding
	if encoding == "" {
		encoding = "utf8"
	}

	if encoding != "utf8" && encoding != "hex" {
		return &ValidationError{Field: "encoding", Reason: "must be 'utf8' or 'hex'"}
	}

	return nil
}

// ValidationError represents a field validation error
type ValidationError struct {
	Field  string
	Reason string
}

func (e *ValidationError) Error() string {
	return e.Field + ": " + e.Reason
}

// =============================================================================
// Wallet ID Parsing Tests
// =============================================================================

func TestWalletID_Parsing(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectValid bool
	}{
		{
			name:        "valid_uuid",
			input:       "550e8400-e29b-41d4-a716-446655440000",
			expectValid: true,
		},
		{
			name:        "valid_uuid_uppercase",
			input:       "550E8400-E29B-41D4-A716-446655440000",
			expectValid: true,
		},
		{
			name:        "invalid_too_short",
			input:       "550e8400-e29b-41d4",
			expectValid: false,
		},
		{
			name:        "invalid_empty",
			input:       "",
			expectValid: false,
		},
		{
			name:        "invalid_random_string",
			input:       "not-a-uuid",
			expectValid: false,
		},
		{
			name:        "invalid_sql_injection",
			input:       "'; DROP TABLE wallets; --",
			expectValid: false,
		},
		{
			name:        "invalid_with_extra_chars",
			input:       "550e8400-e29b-41d4-a716-446655440000extra",
			expectValid: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := uuid.Parse(tt.input)
			if tt.expectValid {
				assert.NoError(t, err, "expected valid UUID")
			} else {
				assert.Error(t, err, "expected invalid UUID")
			}
		})
	}
}

// =============================================================================
// Request Body JSON Parsing Tests
// =============================================================================

func TestCreateWalletRequest_JSONParsing(t *testing.T) {
	tests := []struct {
		name           string
		jsonBody       string
		expectError    bool
		expectChain    string
		expectOwnerNil bool
	}{
		{
			name: "valid_with_owner",
			jsonBody: `{
				"chain_type": "ethereum",
				"owner": {
					"public_key": "04abc123..."
				}
			}`,
			expectError:    false,
			expectChain:    "ethereum",
			expectOwnerNil: false,
		},
		{
			name: "valid_app_managed_minimal",
			jsonBody: `{
				"chain_type": "ethereum"
			}`,
			expectError:    false,
			expectChain:    "ethereum",
			expectOwnerNil: true,
		},
		{
			name: "valid_empty_object",
			jsonBody: `{}`,
			expectError:    false,
			expectChain:    "", // Will default to ethereum in handler
			expectOwnerNil: true,
		},
		{
			name:        "invalid_json",
			jsonBody:    `{chain_type: ethereum}`, // Missing quotes
			expectError: true,
		},
		{
			name: "valid_with_policy_ids",
			jsonBody: `{
				"chain_type": "ethereum",
				"policy_ids": ["550e8400-e29b-41d4-a716-446655440000"]
			}`,
			expectError:    false,
			expectChain:    "ethereum",
			expectOwnerNil: true, // No owner specified
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CreateWalletRequest
			err := json.Unmarshal([]byte(tt.jsonBody), &req)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectChain, req.ChainType)
				if tt.expectOwnerNil {
					assert.Nil(t, req.Owner)
				} else {
					assert.NotNil(t, req.Owner)
				}
			}
		})
	}
}

// =============================================================================
// Response Serialization Tests
// =============================================================================

func TestWalletResponse_Serialization(t *testing.T) {
	walletID := uuid.MustParse("550e8400-e29b-41d4-a716-446655440000")
	ownerID := uuid.MustParse("660e8400-e29b-41d4-a716-446655440000")

	resp := WalletResponse{
		ID:                walletID,
		Address:           "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		ChainType:         "ethereum",
		PolicyIDs:         []uuid.UUID{},
		OwnerID:           &ownerID,
		AdditionalSigners: []AdditionalSigner{},
		CreatedAt:         1704067200000,
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	// Verify JSON contains expected fields
	jsonStr := string(data)
	assert.Contains(t, jsonStr, `"id":"550e8400-e29b-41d4-a716-446655440000"`)
	assert.Contains(t, jsonStr, `"address":"0x742d35Cc6634C0532925a3b844Bc454e4438f44e"`)
	assert.Contains(t, jsonStr, `"chain_type":"ethereum"`)
	assert.Contains(t, jsonStr, `"owner_id":"660e8400-e29b-41d4-a716-446655440000"`)
	assert.Contains(t, jsonStr, `"created_at":1704067200000`)

	// Verify round-trip
	var decoded WalletResponse
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, resp.ID, decoded.ID)
	assert.Equal(t, resp.Address, decoded.Address)
}

// =============================================================================
// HTTP Request/Response Helpers Tests
// =============================================================================

func TestWriteJSON_ContentType(t *testing.T) {
	recorder := httptest.NewRecorder()

	w := recorder
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})

	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.Equal(t, http.StatusOK, recorder.Code)
}

// =============================================================================
// Gas Parameter Validation Tests
// =============================================================================

func TestGasParameters_Validation(t *testing.T) {
	tests := []struct {
		name        string
		gasLimit    uint64
		gasFeeCap   string
		gasTipCap   string
		expectValid bool
	}{
		{
			name:        "valid_standard_tx",
			gasLimit:    21000,
			gasFeeCap:   "20000000000",
			gasTipCap:   "1000000000",
			expectValid: true,
		},
		{
			name:        "valid_contract_call",
			gasLimit:    100000,
			gasFeeCap:   "50000000000",
			gasTipCap:   "2000000000",
			expectValid: true,
		},
		{
			name:        "valid_zero_gas_price",
			gasLimit:    21000,
			gasFeeCap:   "0",
			gasTipCap:   "0",
			expectValid: true,
		},
		{
			name:        "invalid_gas_fee_cap",
			gasLimit:    21000,
			gasFeeCap:   "not_a_number",
			gasTipCap:   "0",
			expectValid: false,
		},
		{
			name:        "invalid_gas_tip_cap",
			gasLimit:    21000,
			gasFeeCap:   "0",
			gasTipCap:   "invalid",
			expectValid: false,
		},
		{
			name:        "tip_cap_exceeds_fee_cap_allowed_at_parsing",
			gasLimit:    21000,
			gasFeeCap:   "1000000000",
			gasTipCap:   "2000000000",
			expectValid: true, // Validation happens at transaction level, not parsing
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, feeCapOk := new(big.Int).SetString(tt.gasFeeCap, 10)
			_, tipCapOk := new(big.Int).SetString(tt.gasTipCap, 10)

			isValid := feeCapOk && tipCapOk
			assert.Equal(t, tt.expectValid, isValid, "gas parameter validation mismatch")
		})
	}
}

// =============================================================================
// Path Parsing Tests
// =============================================================================

func TestPathParsing_WalletOperations(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		expectedParts  []string
		expectWalletID bool
	}{
		{
			name:           "wallet_id_only",
			path:           "/v1/wallets/550e8400-e29b-41d4-a716-446655440000",
			expectedParts:  []string{"550e8400-e29b-41d4-a716-446655440000"},
			expectWalletID: true,
		},
		{
			name:           "wallet_rpc",
			path:           "/v1/wallets/550e8400-e29b-41d4-a716-446655440000/rpc",
			expectedParts:  []string{"550e8400-e29b-41d4-a716-446655440000", "rpc"},
			expectWalletID: true,
		},
		{
			name:           "session_signers",
			path:           "/v1/wallets/550e8400-e29b-41d4-a716-446655440000/session_signers",
			expectedParts:  []string{"550e8400-e29b-41d4-a716-446655440000", "session_signers"},
			expectWalletID: true,
		},
		{
			name:           "authenticate_global",
			path:           "/v1/wallets/authenticate",
			expectedParts:  []string{"authenticate"},
			expectWalletID: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pathParts := strings.Split(strings.TrimPrefix(tt.path, "/v1/wallets/"), "/")
			assert.Equal(t, tt.expectedParts, pathParts)

			if tt.expectWalletID && len(pathParts) > 0 {
				_, err := uuid.Parse(pathParts[0])
				assert.NoError(t, err, "expected valid wallet UUID in path")
			}
		})
	}
}

// =============================================================================
// ChainID Validation Tests
// =============================================================================

func TestChainID_Validation(t *testing.T) {
	tests := []struct {
		name        string
		chainID     int64
		expectValid bool
		network     string
	}{
		{
			name:        "mainnet",
			chainID:     1,
			expectValid: true,
			network:     "Ethereum Mainnet",
		},
		{
			name:        "sepolia",
			chainID:     11155111,
			expectValid: true,
			network:     "Sepolia Testnet",
		},
		{
			name:        "polygon",
			chainID:     137,
			expectValid: true,
			network:     "Polygon Mainnet",
		},
		{
			name:        "arbitrum",
			chainID:     42161,
			expectValid: true,
			network:     "Arbitrum One",
		},
		{
			name:        "zero_chainid",
			chainID:     0,
			expectValid: false, // ChainID 0 is invalid
			network:     "",
		},
		{
			name:        "negative_chainid",
			chainID:     -1,
			expectValid: false,
			network:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isValid := tt.chainID > 0
			assert.Equal(t, tt.expectValid, isValid)
		})
	}
}

// =============================================================================
// Export Request Validation Tests
// =============================================================================

func TestExportWalletRequest_Validation(t *testing.T) {
	tests := []struct {
		name           string
		encryptionType string
		recipientKey   string
		expectError    bool
	}{
		{
			name:           "valid_hpke",
			encryptionType: "HPKE",
			recipientKey:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
			expectError:    false,
		},
		{
			name:           "valid_empty_defaults_to_hpke",
			encryptionType: "",
			recipientKey:   "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE...",
			expectError:    false,
		},
		{
			name:           "invalid_encryption_type",
			encryptionType: "AES",
			recipientKey:   "...",
			expectError:    true,
		},
		{
			name:           "missing_recipient_key",
			encryptionType: "HPKE",
			recipientKey:   "",
			expectError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateExportRequest(tt.encryptionType, tt.recipientKey)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func validateExportRequest(encryptionType, recipientKey string) error {
	if encryptionType == "" {
		encryptionType = "HPKE"
	}
	if encryptionType != "HPKE" {
		return &ValidationError{Field: "encryption_type", Reason: "only HPKE is supported"}
	}
	if recipientKey == "" {
		return &ValidationError{Field: "recipient_public_key", Reason: "required for HPKE encryption"}
	}
	return nil
}

// =============================================================================
// Limit and Pagination Validation Tests
// =============================================================================

func TestPaginationParameters(t *testing.T) {
	tests := []struct {
		name          string
		limitStr      string
		expectLimit   int
		defaultLimit  int
	}{
		{
			name:         "default_when_empty",
			limitStr:     "",
			expectLimit:  100,
			defaultLimit: 100,
		},
		{
			name:         "valid_limit",
			limitStr:     "50",
			expectLimit:  50,
			defaultLimit: 100,
		},
		{
			name:         "exceeds_max_uses_max",
			limitStr:     "200",
			expectLimit:  100, // Should cap at 100
			defaultLimit: 100,
		},
		{
			name:         "zero_uses_default",
			limitStr:     "0",
			expectLimit:  100,
			defaultLimit: 100,
		},
		{
			name:         "negative_uses_default",
			limitStr:     "-10",
			expectLimit:  100,
			defaultLimit: 100,
		},
		{
			name:         "invalid_non_numeric",
			limitStr:     "abc",
			expectLimit:  100,
			defaultLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			limit := tt.defaultLimit
			if tt.limitStr != "" {
				var l int
				_, err := parseLimit(tt.limitStr)
				if err == nil {
					l, _ = parseLimit(tt.limitStr)
					if l > 0 && l <= 100 {
						limit = l
					}
				}
			}
			assert.Equal(t, tt.expectLimit, limit)
		})
	}
}

func parseLimit(s string) (int, error) {
	var i int
	_, err := bytes.NewBufferString(s).Read(make([]byte, 0))
	if err != nil {
		return 0, err
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			if c == '-' && i == 0 {
				continue
			}
			return 0, &ValidationError{Field: "limit", Reason: "must be a number"}
		}
		i = i*10 + int(c-'0')
	}
	if s != "" && s[0] == '-' {
		i = -i
	}
	return i, nil
}

// =============================================================================
// Hex Parsing Tests (for 0x prefixed values in /rpc)
// =============================================================================

func TestParseHexBigInt(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectVal   string
		expectError bool
	}{
		{
			name:      "hex_zero",
			input:     "0x0",
			expectVal: "0",
		},
		{
			name:      "hex_small_value",
			input:     "0x64",
			expectVal: "100",
		},
		{
			name:      "hex_1_ether",
			input:     "0xde0b6b3a7640000",
			expectVal: "1000000000000000000",
		},
		{
			name:      "hex_uppercase",
			input:     "0xDE0B6B3A7640000",
			expectVal: "1000000000000000000",
		},
		{
			name:      "hex_uppercase_prefix",
			input:     "0XDE0B6B3A7640000",
			expectVal: "1000000000000000000",
		},
		{
			name:      "decimal_fallback",
			input:     "1000000000",
			expectVal: "1000000000",
		},
		{
			name:      "empty_string",
			input:     "",
			expectVal: "0",
		},
		{
			name:        "invalid_hex_chars",
			input:       "0xGGGG",
			expectError: true,
		},
		{
			name:        "invalid_mixed",
			input:       "0x12g4",
			expectError: true,
		},
		{
			name:        "invalid_decimal",
			input:       "abc",
			expectError: true,
		},
		{
			name:        "invalid_float",
			input:       "1.5",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHexBigInt(tt.input)
			if tt.expectError {
				assert.Error(t, err, "expected error for input: %s", tt.input)
			} else {
				require.NoError(t, err, "unexpected error for input: %s", tt.input)
				assert.Equal(t, tt.expectVal, result.String(), "value mismatch for input: %s", tt.input)
			}
		})
	}
}

func TestParseHexUint64(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expectVal   uint64
		expectError bool
	}{
		{
			name:      "hex_21000_gas",
			input:     "0x5208",
			expectVal: 21000,
		},
		{
			name:      "hex_zero",
			input:     "0x0",
			expectVal: 0,
		},
		{
			name:      "decimal_fallback",
			input:     "21000",
			expectVal: 21000,
		},
		{
			name:      "empty_string",
			input:     "",
			expectVal: 0,
		},
		{
			name:      "hex_max_uint64",
			input:     "0xffffffffffffffff",
			expectVal: 18446744073709551615,
		},
		{
			name:        "overflow_uint64",
			input:       "0x10000000000000000", // 2^64
			expectError: true,
		},
		{
			name:        "invalid_hex",
			input:       "0xZZZZ",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseHexUint64(tt.input)
			if tt.expectError {
				assert.Error(t, err, "expected error for input: %s", tt.input)
			} else {
				require.NoError(t, err, "unexpected error for input: %s", tt.input)
				assert.Equal(t, tt.expectVal, result, "value mismatch for input: %s", tt.input)
			}
		})
	}
}
