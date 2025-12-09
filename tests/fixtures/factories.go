// Package fixtures provides test data factories for creating test objects.
package fixtures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// =============================================================================
// APP FIXTURES
// =============================================================================

// TestApp represents a test application with all necessary fields.
type TestApp struct {
	ID           uuid.UUID
	Name         string
	Secret       string              // Plain text secret for testing
	SecretHash   string              // bcrypt hash for database
	Settings     map[string]interface{}
	Status       string
	CreatedAt    time.Time
}

// NewTestApp creates a new test app with default values.
func NewTestApp() *TestApp {
	secret := GenerateRandomSecret(32)
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	return &TestApp{
		ID:         uuid.New(),
		Name:       fmt.Sprintf("test-app-%s", uuid.New().String()[:8]),
		Secret:     secret,
		SecretHash: string(hash),
		Settings: map[string]interface{}{
			"jwt_issuer":   "https://test-issuer.example.com",
			"jwt_audience": "test-audience",
		},
		Status:    "active",
		CreatedAt: time.Now(),
	}
}

// NewSuspendedApp creates a suspended test app.
func NewSuspendedApp() *TestApp {
	app := NewTestApp()
	app.Status = "suspended"
	return app
}

// =============================================================================
// USER FIXTURES
// =============================================================================

// TestUser represents a test user.
type TestUser struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	Subject   string // JWT sub claim
	Email     string
	CreatedAt time.Time
}

// NewTestUser creates a new test user.
func NewTestUser(appID uuid.UUID) *TestUser {
	sub := fmt.Sprintf("user_%s", uuid.New().String()[:8])
	return &TestUser{
		ID:        uuid.New(),
		AppID:     appID,
		Subject:   sub,
		Email:     fmt.Sprintf("%s@test.example.com", sub),
		CreatedAt: time.Now(),
	}
}

// =============================================================================
// KEY FIXTURES
// =============================================================================

// TestKeyPair holds a P-256 key pair for testing.
type TestKeyPair struct {
	PrivateKey    *ecdsa.PrivateKey
	PublicKey     *ecdsa.PublicKey
	PrivateKeyPEM string
	PublicKeyPEM  string
	PublicKeyDER  []byte
}

// NewTestKeyPair generates a new P-256 key pair.
func NewTestKeyPair() (*TestKeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encode private key to PEM
	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	// Encode public key to PEM and DER
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return &TestKeyPair{
		PrivateKey:    privateKey,
		PublicKey:     &privateKey.PublicKey,
		PrivateKeyPEM: string(privKeyPEM),
		PublicKeyPEM:  string(pubKeyPEM),
		PublicKeyDER:  pubKeyBytes,
	}, nil
}

// =============================================================================
// AUTHORIZATION KEY FIXTURES
// =============================================================================

// TestAuthorizationKey represents a test authorization key.
type TestAuthorizationKey struct {
	ID           uuid.UUID
	AppID        uuid.UUID
	UserID       uuid.UUID
	PublicKeyPEM string
	KeyPair      *TestKeyPair
	Status       string
	CreatedAt    time.Time
}

// NewTestAuthorizationKey creates a new test authorization key.
func NewTestAuthorizationKey(appID, userID uuid.UUID) (*TestAuthorizationKey, error) {
	keyPair, err := NewTestKeyPair()
	if err != nil {
		return nil, err
	}

	return &TestAuthorizationKey{
		ID:           uuid.New(),
		AppID:        appID,
		UserID:       userID,
		PublicKeyPEM: keyPair.PublicKeyPEM,
		KeyPair:      keyPair,
		Status:       "active",
		CreatedAt:    time.Now(),
	}, nil
}

// =============================================================================
// WALLET FIXTURES
// =============================================================================

// TestWallet represents a test wallet.
type TestWallet struct {
	ID          uuid.UUID
	AppID       uuid.UUID
	UserID      *uuid.UUID // nil for app-managed wallets
	OwnerID     *uuid.UUID // AuthorizationKey or KeyQuorum ID
	Address     string
	ChainType   string
	ExecBackend string
	CreatedAt   time.Time
}

// NewTestWallet creates a new user-owned test wallet.
func NewTestWallet(appID uuid.UUID, userID, ownerID uuid.UUID) *TestWallet {
	return &TestWallet{
		ID:          uuid.New(),
		AppID:       appID,
		UserID:      &userID,
		OwnerID:     &ownerID,
		Address:     GenerateRandomAddress(),
		ChainType:   "ethereum",
		ExecBackend: "kms",
		CreatedAt:   time.Now(),
	}
}

// NewAppManagedWallet creates an app-managed wallet (no user owner).
func NewAppManagedWallet(appID uuid.UUID) *TestWallet {
	return &TestWallet{
		ID:          uuid.New(),
		AppID:       appID,
		UserID:      nil,
		OwnerID:     nil,
		Address:     GenerateRandomAddress(),
		ChainType:   "ethereum",
		ExecBackend: "kms",
		CreatedAt:   time.Now(),
	}
}

// =============================================================================
// POLICY FIXTURES
// =============================================================================

// TestPolicy represents a test policy.
type TestPolicy struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	OwnerID   uuid.UUID
	Name      string
	ChainType string
	Version   string
	Rules     map[string]interface{}
	CreatedAt time.Time
}

// NewAllowAllPolicy creates a policy that allows all transactions.
func NewAllowAllPolicy(appID, ownerID uuid.UUID) *TestPolicy {
	return &TestPolicy{
		ID:        uuid.New(),
		AppID:     appID,
		OwnerID:   ownerID,
		Name:      "Allow All",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":       "Allow all transactions",
					"method":     "*",
					"action":     "ALLOW",
					"conditions": []interface{}{},
				},
			},
		},
		CreatedAt: time.Now(),
	}
}

// NewDenyAllPolicy creates a policy that denies all transactions.
func NewDenyAllPolicy(appID, ownerID uuid.UUID) *TestPolicy {
	return &TestPolicy{
		ID:        uuid.New(),
		AppID:     appID,
		OwnerID:   ownerID,
		Name:      "Deny All",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":       "Deny all transactions",
					"method":     "*",
					"action":     "DENY",
					"conditions": []interface{}{},
				},
			},
		},
		CreatedAt: time.Now(),
	}
}

// NewWhitelistPolicy creates a policy that allows transactions to specific addresses.
func NewWhitelistPolicy(appID, ownerID uuid.UUID, addresses []string) *TestPolicy {
	return &TestPolicy{
		ID:        uuid.New(),
		AppID:     appID,
		OwnerID:   ownerID,
		Name:      "Whitelist Addresses",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Allow whitelisted addresses",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "to",
							"operator":     "in",
							"value":        addresses,
						},
					},
				},
			},
		},
		CreatedAt: time.Now(),
	}
}

// NewValueLimitPolicy creates a policy that limits transaction value.
func NewValueLimitPolicy(appID, ownerID uuid.UUID, maxValue string) *TestPolicy {
	return &TestPolicy{
		ID:        uuid.New(),
		AppID:     appID,
		OwnerID:   ownerID,
		Name:      "Value Limit",
		ChainType: "ethereum",
		Version:   "1.0",
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":   "Limit transaction value",
					"method": "eth_sendTransaction",
					"action": "ALLOW",
					"conditions": []interface{}{
						map[string]interface{}{
							"field_source": "ethereum_transaction",
							"field":        "value",
							"operator":     "lte",
							"value":        maxValue,
						},
					},
				},
			},
		},
		CreatedAt: time.Now(),
	}
}

// =============================================================================
// SESSION SIGNER FIXTURES
// =============================================================================

// TestSessionSigner represents a test session signer.
type TestSessionSigner struct {
	ID               uuid.UUID
	WalletID         uuid.UUID
	SignerID         uuid.UUID
	AuthKey          *TestAuthorizationKey
	TTLExpiresAt     time.Time
	PolicyOverrideID *uuid.UUID
	MaxValue         *string
	MaxTxs           *int
	AllowedMethods   []string
	Status           string
	CreatedAt        time.Time
}

// NewTestSessionSigner creates a new test session signer.
func NewTestSessionSigner(walletID uuid.UUID, authKey *TestAuthorizationKey, ttl time.Duration) *TestSessionSigner {
	return &TestSessionSigner{
		ID:             uuid.New(),
		WalletID:       walletID,
		SignerID:       authKey.ID,
		AuthKey:        authKey,
		TTLExpiresAt:   time.Now().Add(ttl),
		AllowedMethods: []string{"sign_transaction", "personal_sign", "sign_typed_data"},
		Status:         "active",
		CreatedAt:      time.Now(),
	}
}

// WithMaxValue sets the max value limit.
func (s *TestSessionSigner) WithMaxValue(value string) *TestSessionSigner {
	s.MaxValue = &value
	return s
}

// WithMaxTxs sets the max transactions limit.
func (s *TestSessionSigner) WithMaxTxs(count int) *TestSessionSigner {
	s.MaxTxs = &count
	return s
}

// WithPolicyOverride sets the policy override.
func (s *TestSessionSigner) WithPolicyOverride(policyID uuid.UUID) *TestSessionSigner {
	s.PolicyOverrideID = &policyID
	return s
}

// WithAllowedMethods sets the allowed methods.
func (s *TestSessionSigner) WithAllowedMethods(methods []string) *TestSessionSigner {
	s.AllowedMethods = methods
	return s
}

// =============================================================================
// KEY QUORUM FIXTURES
// =============================================================================

// TestKeyQuorum represents a test key quorum (M-of-N).
type TestKeyQuorum struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	Name      string
	Threshold int
	Keys      []*TestAuthorizationKey
	CreatedAt time.Time
}

// NewTestKeyQuorum creates a new test key quorum.
func NewTestKeyQuorum(appID uuid.UUID, threshold, totalKeys int) (*TestKeyQuorum, error) {
	keys := make([]*TestAuthorizationKey, totalKeys)
	for i := 0; i < totalKeys; i++ {
		key, err := NewTestAuthorizationKey(appID, uuid.New())
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}

	return &TestKeyQuorum{
		ID:        uuid.New(),
		AppID:     appID,
		Name:      fmt.Sprintf("Test Quorum %d-of-%d", threshold, totalKeys),
		Threshold: threshold,
		Keys:      keys,
		CreatedAt: time.Now(),
	}, nil
}

// =============================================================================
// TRANSACTION FIXTURES
// =============================================================================

// TestTransaction represents a test Ethereum transaction.
type TestTransaction struct {
	To       string
	Value    string // Wei as string
	Data     string // Hex-encoded
	Gas      uint64
	GasPrice string
	Nonce    uint64
	ChainID  int64
}

// NewTestTransaction creates a simple ETH transfer transaction.
func NewTestTransaction(to string, valueWei string) *TestTransaction {
	return &TestTransaction{
		To:       to,
		Value:    valueWei,
		Data:     "0x",
		Gas:      21000,
		GasPrice: "20000000000", // 20 Gwei
		Nonce:    0,
		ChainID:  1, // Mainnet
	}
}

// NewContractCallTransaction creates a contract call transaction.
func NewContractCallTransaction(to, data string) *TestTransaction {
	return &TestTransaction{
		To:       to,
		Value:    "0",
		Data:     data,
		Gas:      100000,
		GasPrice: "20000000000",
		Nonce:    0,
		ChainID:  1,
	}
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

// GenerateRandomAddress generates a random Ethereum address.
func GenerateRandomAddress() string {
	bytes := make([]byte, 20)
	rand.Read(bytes)
	return "0x" + hex.EncodeToString(bytes)
}

// GenerateRandomSecret generates a random secret string.
func GenerateRandomSecret(length int) string {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

// WellKnownAddresses contains commonly used test addresses.
var WellKnownAddresses = struct {
	USDC     string
	USDT     string
	WETH     string
	Uniswap  string
	Aave     string
	Attacker string
}{
	USDC:     "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
	USDT:     "0xdAC17F958D2ee523a2206206994597C13D831ec7",
	WETH:     "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
	Uniswap:  "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
	Aave:     "0x7d2768dE32b0b80b7a3454c06BdAc94A69DDc7A9",
	Attacker: "0xBAD0000000000000000000000000000000000BAD",
}

// Common values for testing
var (
	OneEther     = "1000000000000000000"      // 1 ETH in Wei
	HalfEther    = "500000000000000000"       // 0.5 ETH
	TenEther     = "10000000000000000000"     // 10 ETH
	HundredEther = "100000000000000000000"    // 100 ETH
	OneGwei      = "1000000000"               // 1 Gwei
	TwentyGwei   = "20000000000"              // 20 Gwei
)
