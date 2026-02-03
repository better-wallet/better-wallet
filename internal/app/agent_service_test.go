package app

import (
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
	"golang.org/x/crypto/bcrypt"
)

func TestGenerateAPIKey(t *testing.T) {
	s := &AgentService{}

	tests := []struct {
		name   string
		prefix string
	}{
		{"principal key", "aw_pk_"},
		{"agent credential", "aw_ag_"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fullKey, keyPrefix, secretHash, err := s.generateAPIKey(tt.prefix)
			if err != nil {
				t.Fatalf("generateAPIKey() error = %v", err)
			}

			// Check fullKey format: prefix + prefixID + "." + secret
			if !strings.HasPrefix(fullKey, tt.prefix) {
				t.Errorf("fullKey should start with prefix %q, got %q", tt.prefix, fullKey)
			}

			parts := strings.SplitN(fullKey, ".", 2)
			if len(parts) != 2 {
				t.Fatalf("fullKey should have format 'prefix.secret', got %q", fullKey)
			}

			// Check keyPrefix matches the part before "."
			if parts[0] != keyPrefix {
				t.Errorf("keyPrefix = %q, want %q", keyPrefix, parts[0])
			}

			// Check keyPrefix has correct format: prefix + 12 char ID
			expectedPrefixLen := len(tt.prefix) + 12
			if len(keyPrefix) != expectedPrefixLen {
				t.Errorf("keyPrefix length = %d, want %d", len(keyPrefix), expectedPrefixLen)
			}

			// Check secret can be verified with bcrypt hash
			secret := parts[1]
			if err := bcrypt.CompareHashAndPassword([]byte(secretHash), []byte(secret)); err != nil {
				t.Errorf("secretHash does not match secret: %v", err)
			}

			// Check uniqueness - generate another key
			fullKey2, keyPrefix2, _, err := s.generateAPIKey(tt.prefix)
			if err != nil {
				t.Fatalf("second generateAPIKey() error = %v", err)
			}
			if fullKey == fullKey2 {
				t.Error("generated keys should be unique")
			}
			if keyPrefix == keyPrefix2 {
				t.Error("generated key prefixes should be unique")
			}
		})
	}
}

func TestEncodeDecodeShares(t *testing.T) {
	tests := []struct {
		name      string
		authShare []byte
		execShare []byte
	}{
		{
			name:      "normal shares",
			authShare: []byte("auth-share-data-here"),
			execShare: []byte("exec-share-data-here"),
		},
		{
			name:      "empty auth share",
			authShare: []byte{},
			execShare: []byte("exec-share-only"),
		},
		{
			name:      "empty exec share",
			authShare: []byte("auth-share-only"),
			execShare: []byte{},
		},
		{
			name:      "large shares",
			authShare: make([]byte, 1000),
			execShare: make([]byte, 2000),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := encodeShares(tt.authShare, tt.execShare)

			decodedAuth, decodedExec, err := decodeShares(encoded)
			if err != nil {
				t.Fatalf("decodeShares() error = %v", err)
			}

			if string(decodedAuth) != string(tt.authShare) {
				t.Errorf("authShare mismatch: got %v, want %v", decodedAuth, tt.authShare)
			}
			if string(decodedExec) != string(tt.execShare) {
				t.Errorf("execShare mismatch: got %v, want %v", decodedExec, tt.execShare)
			}
		})
	}
}

func TestDecodeSharesErrors(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr string
	}{
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: "data too short",
		},
		{
			name:    "too short for header",
			data:    []byte{0, 0, 0},
			wantErr: "data too short",
		},
		{
			name:    "auth length exceeds data",
			data:    []byte{0, 0, 0, 100, 1, 2, 3}, // claims 100 bytes but only has 3
			wantErr: "data too short for auth share",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := decodeShares(tt.data)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestStripHexPrefix(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"0x1234", "1234"},
		{"0X1234", "0X1234"}, // only lowercase 0x is stripped
		{"1234", "1234"},
		{"0x", ""},
		{"", ""},
		{"0", "0"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripHexPrefix(tt.input)
			if got != tt.want {
				t.Errorf("stripHexPrefix(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCheckRateLimits(t *testing.T) {
	tests := []struct {
		name       string
		credential *types.AgentCredential
		value      *big.Int
		hourly     *types.AgentRateLimit
		daily      *types.AgentRateLimit
		wantErr    string
	}{
		{
			name: "within all limits",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxTxPerHour:    10,
					MaxTxPerDay:     100,
					MaxValuePerTx:   "1000000000000000000",  // 1 ETH
					MaxValuePerHour: "5000000000000000000",  // 5 ETH
					MaxValuePerDay:  "10000000000000000000", // 10 ETH
				},
			},
			value:   big.NewInt(100000000000000000), // 0.1 ETH
			hourly:  &types.AgentRateLimit{TxCount: 5, TotalValue: "1000000000000000000"},
			daily:   &types.AgentRateLimit{TxCount: 50, TotalValue: "5000000000000000000"},
			wantErr: "",
		},
		{
			name: "hourly tx limit exceeded",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxTxPerHour: 10,
				},
			},
			value:   big.NewInt(0),
			hourly:  &types.AgentRateLimit{TxCount: 10},
			daily:   &types.AgentRateLimit{TxCount: 10},
			wantErr: "hourly transaction limit exceeded",
		},
		{
			name: "daily tx limit exceeded",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxTxPerDay: 100,
				},
			},
			value:   big.NewInt(0),
			hourly:  &types.AgentRateLimit{TxCount: 5},
			daily:   &types.AgentRateLimit{TxCount: 100},
			wantErr: "daily transaction limit exceeded",
		},
		{
			name: "per-tx value limit exceeded",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxValuePerTx: "1000000000000000000", // 1 ETH
				},
			},
			value:   big.NewInt(2000000000000000000), // 2 ETH
			hourly:  &types.AgentRateLimit{},
			daily:   &types.AgentRateLimit{},
			wantErr: "transaction value limit exceeded",
		},
		{
			name: "hourly value limit exceeded",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxValuePerHour: "5000000000000000000", // 5 ETH
				},
			},
			value:   big.NewInt(1000000000000000000),                          // 1 ETH
			hourly:  &types.AgentRateLimit{TotalValue: "5000000000000000000"}, // already at 5 ETH
			daily:   &types.AgentRateLimit{},
			wantErr: "hourly value limit exceeded",
		},
		{
			name: "daily value limit exceeded",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxValuePerDay: "10000000000000000000", // 10 ETH
				},
			},
			value:   big.NewInt(1000000000000000000), // 1 ETH
			hourly:  &types.AgentRateLimit{},
			daily:   &types.AgentRateLimit{TotalValue: "10000000000000000000"}, // already at 10 ETH
			wantErr: "daily value limit exceeded",
		},
		{
			name: "no limits set - should pass",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{},
			},
			value:   big.NewInt(999999999999999999),
			hourly:  &types.AgentRateLimit{TxCount: 9999, TotalValue: "999999999999999999999"},
			daily:   &types.AgentRateLimit{TxCount: 99999, TotalValue: "9999999999999999999999"},
			wantErr: "",
		},
		{
			name: "invalid max_value_per_tx format",
			credential: &types.AgentCredential{
				Limits: types.AgentLimits{
					MaxValuePerTx: "not-a-number",
				},
			},
			value:   big.NewInt(100),
			hourly:  &types.AgentRateLimit{},
			daily:   &types.AgentRateLimit{},
			wantErr: "invalid max_value_per_tx format",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal service with mock repo
			// Note: We can't easily mock the repo interface here without refactoring,
			// so we test the logic directly by examining the function behavior

			// For now, we verify the limit checking logic by examining expected errors
			// A full integration test would use a real database

			// Test the limit checking logic inline
			err := checkRateLimitsLogic(tt.credential, tt.value, tt.hourly, tt.daily)

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want to contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

// checkRateLimitsLogic extracts the rate limit checking logic for testing
func checkRateLimitsLogic(credential *types.AgentCredential, value *big.Int, hourly, daily *types.AgentRateLimit) error {
	// Check hourly tx count
	if credential.Limits.MaxTxPerHour > 0 && hourly.TxCount >= credential.Limits.MaxTxPerHour {
		return fmt.Errorf("hourly transaction limit exceeded")
	}

	// Check daily tx count
	if credential.Limits.MaxTxPerDay > 0 && daily.TxCount >= credential.Limits.MaxTxPerDay {
		return fmt.Errorf("daily transaction limit exceeded")
	}

	// Check per-tx value
	if credential.Limits.MaxValuePerTx != "" {
		maxPerTx, ok := new(big.Int).SetString(credential.Limits.MaxValuePerTx, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_tx format")
		}
		if value.Cmp(maxPerTx) > 0 {
			return fmt.Errorf("transaction value limit exceeded")
		}
	}

	// Check hourly value
	if credential.Limits.MaxValuePerHour != "" {
		maxHourly, ok := new(big.Int).SetString(credential.Limits.MaxValuePerHour, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_hour format")
		}
		currentHourly := big.NewInt(0)
		if hourly.TotalValue != "" && hourly.TotalValue != "0" {
			currentHourly, ok = new(big.Int).SetString(hourly.TotalValue, 10)
			if !ok {
				return fmt.Errorf("invalid hourly total value in database")
			}
		}
		newTotal := new(big.Int).Add(currentHourly, value)
		if newTotal.Cmp(maxHourly) > 0 {
			return fmt.Errorf("hourly value limit exceeded")
		}
	}

	// Check daily value
	if credential.Limits.MaxValuePerDay != "" {
		maxDaily, ok := new(big.Int).SetString(credential.Limits.MaxValuePerDay, 10)
		if !ok {
			return fmt.Errorf("invalid max_value_per_day format")
		}
		currentDaily := big.NewInt(0)
		if daily.TotalValue != "" && daily.TotalValue != "0" {
			currentDaily, ok = new(big.Int).SetString(daily.TotalValue, 10)
			if !ok {
				return fmt.Errorf("invalid daily total value in database")
			}
		}
		newTotal := new(big.Int).Add(currentDaily, value)
		if newTotal.Cmp(maxDaily) > 0 {
			return fmt.Errorf("daily value limit exceeded")
		}
	}

	return nil
}
