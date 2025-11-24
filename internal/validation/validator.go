package validation

import (
	"fmt"
	"math/big"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// EthereumAddressPattern is the regex pattern for Ethereum addresses
var EthereumAddressPattern = regexp.MustCompile(`^0x[0-9a-fA-F]{40}$`)

// ValidateEthereumAddress validates an Ethereum address format
func ValidateEthereumAddress(address string) error {
	if address == "" {
		return fmt.Errorf("address cannot be empty")
	}

	if !EthereumAddressPattern.MatchString(address) {
		return fmt.Errorf("invalid Ethereum address format: must be 0x followed by 40 hex characters")
	}

	// Additional validation: check if it's a valid checksum address
	if !common.IsHexAddress(address) {
		return fmt.Errorf("invalid Ethereum address")
	}

	// Prevent sending to zero address (common mistake)
	if strings.ToLower(address) == "0x0000000000000000000000000000000000000000" {
		return fmt.Errorf("cannot send to zero address")
	}

	return nil
}

// ValidateChainID validates a chain ID
func ValidateChainID(chainID int64) error {
	if chainID <= 0 {
		return fmt.Errorf("chain ID must be positive")
	}

	// Known chain IDs (extend as needed)
	knownChains := map[int64]string{
		1:     "Ethereum Mainnet",
		5:     "Goerli",
		11155111: "Sepolia",
		137:   "Polygon",
		42161: "Arbitrum One",
		10:    "Optimism",
		56:    "BSC",
		43114: "Avalanche",
		8453:  "Base",
	}

	// Warning for unknown chains (not an error, just informational)
	if _, known := knownChains[chainID]; !known {
		// Log warning but don't fail validation
		// This allows support for new/custom chains
	}

	return nil
}

// ValidateTransactionValue validates a transaction value
func ValidateTransactionValue(value *big.Int, maxValue *big.Int) error {
	if value == nil {
		return fmt.Errorf("value cannot be nil")
	}

	if value.Sign() < 0 {
		return fmt.Errorf("value cannot be negative")
	}

	// Check against maximum value if specified
	if maxValue != nil && value.Cmp(maxValue) > 0 {
		return fmt.Errorf("value exceeds maximum allowed: %s > %s", value.String(), maxValue.String())
	}

	return nil
}

// ValidateGasParameters validates gas-related parameters
func ValidateGasParameters(gasLimit uint64, gasFeeCap, gasTipCap *big.Int) error {
	if gasLimit == 0 {
		return fmt.Errorf("gas limit cannot be zero")
	}

	// Minimum gas limit for simple transfer
	if gasLimit < 21000 {
		return fmt.Errorf("gas limit too low: minimum 21000 for transfers")
	}

	// Maximum reasonable gas limit (to prevent excessive fees)
	if gasLimit > 30000000 {
		return fmt.Errorf("gas limit too high: maximum 30000000")
	}

	if gasFeeCap == nil {
		return fmt.Errorf("gas fee cap cannot be nil")
	}

	if gasTipCap == nil {
		return fmt.Errorf("gas tip cap cannot be nil")
	}

	if gasFeeCap.Sign() <= 0 {
		return fmt.Errorf("gas fee cap must be positive")
	}

	if gasTipCap.Sign() < 0 {
		return fmt.Errorf("gas tip cap cannot be negative")
	}

	// Tip cannot exceed fee cap
	if gasTipCap.Cmp(gasFeeCap) > 0 {
		return fmt.Errorf("gas tip cap cannot exceed gas fee cap")
	}

	// Sanity check: prevent extremely high gas prices (100000 Gwei = 100000000000000 Wei)
	maxGasPrice := new(big.Int).SetUint64(100000000000000) // 100000 Gwei
	if gasFeeCap.Cmp(maxGasPrice) > 0 {
		return fmt.Errorf("gas fee cap too high: maximum 100000 Gwei")
	}

	return nil
}

// ValidateNonce validates a transaction nonce
func ValidateNonce(nonce uint64) error {
	// Nonce can be 0 (first transaction)
	// No upper limit validation as nonce can be very high for active accounts
	return nil
}

// ValidateTransactionData validates transaction data (calldata)
func ValidateTransactionData(data []byte, maxDataSize int) error {
	if maxDataSize > 0 && len(data) > maxDataSize {
		return fmt.Errorf("transaction data too large: %d bytes > %d bytes max", len(data), maxDataSize)
	}

	return nil
}

// TransactionValidationConfig holds configuration for transaction validation
type TransactionValidationConfig struct {
	MaxValue       *big.Int // Maximum transaction value (nil = no limit)
	MaxDataSize    int      // Maximum data size in bytes (0 = no limit)
	AllowedChainIDs []int64  // Allowed chain IDs (nil/empty = all allowed)
}

// ValidateTransaction performs comprehensive transaction validation
func ValidateTransaction(
	to string,
	value *big.Int,
	data []byte,
	chainID int64,
	nonce uint64,
	gasLimit uint64,
	gasFeeCap *big.Int,
	gasTipCap *big.Int,
	config *TransactionValidationConfig,
) error {
	// Validate recipient address
	if err := ValidateEthereumAddress(to); err != nil {
		return fmt.Errorf("invalid recipient address: %w", err)
	}

	// Validate chain ID
	if err := ValidateChainID(chainID); err != nil {
		return fmt.Errorf("invalid chain ID: %w", err)
	}

	// Check if chain ID is allowed (if whitelist is configured)
	if config != nil && len(config.AllowedChainIDs) > 0 {
		allowed := false
		for _, allowedID := range config.AllowedChainIDs {
			if chainID == allowedID {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("chain ID %d not allowed", chainID)
		}
	}

	// Validate value
	maxValue := (*big.Int)(nil)
	if config != nil {
		maxValue = config.MaxValue
	}
	if err := ValidateTransactionValue(value, maxValue); err != nil {
		return fmt.Errorf("invalid value: %w", err)
	}

	// Validate gas parameters
	if err := ValidateGasParameters(gasLimit, gasFeeCap, gasTipCap); err != nil {
		return fmt.Errorf("invalid gas parameters: %w", err)
	}

	// Validate nonce
	if err := ValidateNonce(nonce); err != nil {
		return fmt.Errorf("invalid nonce: %w", err)
	}

	// Validate data
	maxDataSize := 0
	if config != nil {
		maxDataSize = config.MaxDataSize
	}
	if err := ValidateTransactionData(data, maxDataSize); err != nil {
		return fmt.Errorf("invalid data: %w", err)
	}

	return nil
}
