package validation

import (
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateEthereumAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid lowercase address",
			address: "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			wantErr: false,
		},
		{
			name:    "valid uppercase address",
			address: "0x742D35CC6634C0532925A3B844BC454E4438F44E",
			wantErr: false,
		},
		{
			name:    "valid mixed case address",
			address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			wantErr: false,
		},
		{
			name:    "empty address",
			address: "",
			wantErr: true,
			errMsg:  "address cannot be empty",
		},
		{
			name:    "missing 0x prefix",
			address: "742d35cc6634c0532925a3b844bc454e4438f44e",
			wantErr: true,
			errMsg:  "invalid Ethereum address format",
		},
		{
			name:    "too short address",
			address: "0x742d35cc6634c0532925a3b844bc454e4438f4",
			wantErr: true,
			errMsg:  "invalid Ethereum address format",
		},
		{
			name:    "too long address",
			address: "0x742d35cc6634c0532925a3b844bc454e4438f44e00",
			wantErr: true,
			errMsg:  "invalid Ethereum address format",
		},
		{
			name:    "invalid characters",
			address: "0x742d35cc6634c0532925a3b844bc454e4438fXYZ",
			wantErr: true,
			errMsg:  "invalid Ethereum address format",
		},
		{
			name:    "zero address",
			address: "0x0000000000000000000000000000000000000000",
			wantErr: true,
			errMsg:  "cannot send to zero address",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateEthereumAddress(tt.address)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateChainID(t *testing.T) {
	tests := []struct {
		name    string
		chainID int64
		wantErr bool
		errMsg  string
	}{
		{
			name:    "Ethereum Mainnet",
			chainID: 1,
			wantErr: false,
		},
		{
			name:    "Sepolia testnet",
			chainID: 11155111,
			wantErr: false,
		},
		{
			name:    "Polygon",
			chainID: 137,
			wantErr: false,
		},
		{
			name:    "Arbitrum One",
			chainID: 42161,
			wantErr: false,
		},
		{
			name:    "Base",
			chainID: 8453,
			wantErr: false,
		},
		{
			name:    "unknown chain ID (should pass)",
			chainID: 999999,
			wantErr: false,
		},
		{
			name:    "zero chain ID",
			chainID: 0,
			wantErr: true,
			errMsg:  "chain ID must be positive",
		},
		{
			name:    "negative chain ID",
			chainID: -1,
			wantErr: true,
			errMsg:  "chain ID must be positive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateChainID(tt.chainID)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTransactionValue(t *testing.T) {
	tests := []struct {
		name     string
		value    *big.Int
		maxValue *big.Int
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "zero value",
			value:    big.NewInt(0),
			maxValue: nil,
			wantErr:  false,
		},
		{
			name:     "positive value",
			value:    big.NewInt(1000000000000000000), // 1 ETH
			maxValue: nil,
			wantErr:  false,
		},
		{
			name:     "nil value",
			value:    nil,
			maxValue: nil,
			wantErr:  true,
			errMsg:   "value cannot be nil",
		},
		{
			name:     "negative value",
			value:    big.NewInt(-1),
			maxValue: nil,
			wantErr:  true,
			errMsg:   "value cannot be negative",
		},
		{
			name:     "value within max",
			value:    big.NewInt(500),
			maxValue: big.NewInt(1000),
			wantErr:  false,
		},
		{
			name:     "value equals max",
			value:    big.NewInt(1000),
			maxValue: big.NewInt(1000),
			wantErr:  false,
		},
		{
			name:     "value exceeds max",
			value:    big.NewInt(1001),
			maxValue: big.NewInt(1000),
			wantErr:  true,
			errMsg:   "value exceeds maximum allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTransactionValue(tt.value, tt.maxValue)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateGasParameters(t *testing.T) {
	tests := []struct {
		name      string
		gasLimit  uint64
		gasFeeCap *big.Int
		gasTipCap *big.Int
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid gas parameters",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(100000000000), // 100 Gwei
			gasTipCap: big.NewInt(2000000000),   // 2 Gwei
			wantErr:   false,
		},
		{
			name:      "zero gas limit",
			gasLimit:  0,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: big.NewInt(2000000000),
			wantErr:   true,
			errMsg:    "gas limit cannot be zero",
		},
		{
			name:      "gas limit too low",
			gasLimit:  20999,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: big.NewInt(2000000000),
			wantErr:   true,
			errMsg:    "gas limit too low",
		},
		{
			name:      "gas limit too high",
			gasLimit:  30000001,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: big.NewInt(2000000000),
			wantErr:   true,
			errMsg:    "gas limit too high",
		},
		{
			name:      "nil gas fee cap",
			gasLimit:  21000,
			gasFeeCap: nil,
			gasTipCap: big.NewInt(2000000000),
			wantErr:   true,
			errMsg:    "gas fee cap cannot be nil",
		},
		{
			name:      "nil gas tip cap",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: nil,
			wantErr:   true,
			errMsg:    "gas tip cap cannot be nil",
		},
		{
			name:      "zero gas fee cap",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(0),
			gasTipCap: big.NewInt(0),
			wantErr:   true,
			errMsg:    "gas fee cap must be positive",
		},
		{
			name:      "negative gas tip cap",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: big.NewInt(-1),
			wantErr:   true,
			errMsg:    "gas tip cap cannot be negative",
		},
		{
			name:      "tip cap exceeds fee cap",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(100000000000),
			gasTipCap: big.NewInt(200000000000),
			wantErr:   true,
			errMsg:    "gas tip cap cannot exceed gas fee cap",
		},
		{
			name:      "gas fee cap too high",
			gasLimit:  21000,
			gasFeeCap: big.NewInt(100000000000001), // > 100000 Gwei
			gasTipCap: big.NewInt(2000000000),
			wantErr:   true,
			errMsg:    "gas fee cap too high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGasParameters(tt.gasLimit, tt.gasFeeCap, tt.gasTipCap)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateNonce(t *testing.T) {
	tests := []struct {
		name    string
		nonce   uint64
		wantErr bool
	}{
		{
			name:    "zero nonce (first tx)",
			nonce:   0,
			wantErr: false,
		},
		{
			name:    "positive nonce",
			nonce:   100,
			wantErr: false,
		},
		{
			name:    "large nonce",
			nonce:   1000000,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateNonce(tt.nonce)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTransactionData(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		maxDataSize int
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "empty data",
			data:        []byte{},
			maxDataSize: 0,
			wantErr:     false,
		},
		{
			name:        "valid data with no limit",
			data:        []byte("some transaction data"),
			maxDataSize: 0,
			wantErr:     false,
		},
		{
			name:        "data within limit",
			data:        []byte("hello"),
			maxDataSize: 100,
			wantErr:     false,
		},
		{
			name:        "data at limit",
			data:        []byte("12345"),
			maxDataSize: 5,
			wantErr:     false,
		},
		{
			name:        "data exceeds limit",
			data:        []byte("123456"),
			maxDataSize: 5,
			wantErr:     true,
			errMsg:      "transaction data too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTransactionData(tt.data, tt.maxDataSize)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestValidateTransaction(t *testing.T) {
	validGasFeeCap := big.NewInt(100000000000)
	validGasTipCap := big.NewInt(2000000000)

	tests := []struct {
		name      string
		to        string
		value     *big.Int
		data      []byte
		chainID   int64
		nonce     uint64
		gasLimit  uint64
		gasFeeCap *big.Int
		gasTipCap *big.Int
		config    *TransactionValidationConfig
		wantErr   bool
		errMsg    string
	}{
		{
			name:      "valid transaction",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(1000000000000000000),
			data:      []byte{},
			chainID:   1,
			nonce:     0,
			gasLimit:  21000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config:    nil,
			wantErr:   false,
		},
		{
			name:      "invalid recipient address",
			to:        "invalid-address",
			value:     big.NewInt(1000),
			data:      []byte{},
			chainID:   1,
			nonce:     0,
			gasLimit:  21000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config:    nil,
			wantErr:   true,
			errMsg:    "invalid recipient address",
		},
		{
			name:      "invalid chain ID",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(1000),
			data:      []byte{},
			chainID:   0,
			nonce:     0,
			gasLimit:  21000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config:    nil,
			wantErr:   true,
			errMsg:    "invalid chain ID",
		},
		{
			name:      "chain ID not allowed",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(1000),
			data:      []byte{},
			chainID:   137, // Polygon
			nonce:     0,
			gasLimit:  21000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config: &TransactionValidationConfig{
				AllowedChainIDs: []int64{1, 5}, // Only Mainnet and Goerli
			},
			wantErr: true,
			errMsg:  "chain ID 137 not allowed",
		},
		{
			name:      "value exceeds max",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(2000000000000000000), // 2 ETH
			data:      []byte{},
			chainID:   1,
			nonce:     0,
			gasLimit:  21000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config: &TransactionValidationConfig{
				MaxValue: big.NewInt(1000000000000000000), // 1 ETH max
			},
			wantErr: true,
			errMsg:  "invalid value",
		},
		{
			name:      "data exceeds max size",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(0),
			data:      []byte(strings.Repeat("x", 1000)),
			chainID:   1,
			nonce:     0,
			gasLimit:  100000,
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config: &TransactionValidationConfig{
				MaxDataSize: 100,
			},
			wantErr: true,
			errMsg:  "invalid data",
		},
		{
			name:      "invalid gas parameters",
			to:        "0x742d35cc6634c0532925a3b844bc454e4438f44e",
			value:     big.NewInt(1000),
			data:      []byte{},
			chainID:   1,
			nonce:     0,
			gasLimit:  100, // Too low
			gasFeeCap: validGasFeeCap,
			gasTipCap: validGasTipCap,
			config:    nil,
			wantErr:   true,
			errMsg:    "invalid gas parameters",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTransaction(
				tt.to,
				tt.value,
				tt.data,
				tt.chainID,
				tt.nonce,
				tt.gasLimit,
				tt.gasFeeCap,
				tt.gasTipCap,
				tt.config,
			)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestEthereumAddressPattern(t *testing.T) {
	// Test the regex pattern directly
	tests := []struct {
		address string
		match   bool
	}{
		{"0x742d35cc6634c0532925a3b844bc454e4438f44e", true},
		{"0x742D35CC6634C0532925A3B844BC454E4438F44E", true},
		{"0x0000000000000000000000000000000000000000", true},
		{"742d35cc6634c0532925a3b844bc454e4438f44e", false},  // no 0x
		{"0x742d35cc6634c0532925a3b844bc454e4438f4", false},  // too short
		{"0x742d35cc6634c0532925a3b844bc454e4438f44e1", false}, // too long
		{"0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG", false}, // invalid hex
	}

	for _, tt := range tests {
		t.Run(tt.address, func(t *testing.T) {
			assert.Equal(t, tt.match, EthereumAddressPattern.MatchString(tt.address))
		})
	}
}
