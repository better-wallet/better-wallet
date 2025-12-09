// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// MockApp represents an app in the mock repository.
type MockApp struct {
	ID          uuid.UUID
	Name        string
	Description string
	OwnerUserID *uuid.UUID
	Status      string // "active", "suspended", "deleted"
	Settings    *MockAppSettings
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// MockAppSettings contains app configuration.
type MockAppSettings struct {
	Auth *MockAppAuthSettings
}

// MockAppAuthSettings contains auth configuration.
type MockAppAuthSettings struct {
	Issuer   string
	Audience string
	JWKSURI  string
}

// MockAppSecret represents an app secret.
type MockAppSecret struct {
	ID           uuid.UUID
	AppID        uuid.UUID
	SecretPrefix string // First 14 characters
	SecretHash   string // bcrypt hash
	LastUsedAt   *time.Time
	CreatedAt    time.Time
}

// MockUser represents a user.
type MockUser struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	Subject   string // JWT sub claim
	Email     string
	CreatedAt time.Time
}

// MockWallet represents a wallet.
type MockWallet struct {
	ID          uuid.UUID
	AppID       uuid.UUID
	UserID      *uuid.UUID
	OwnerID     *uuid.UUID
	Address     string
	ChainType   string
	ExecBackend string
	Status      string
	CreatedAt   time.Time
}

// MockPolicy represents a policy.
type MockPolicy struct {
	ID        uuid.UUID
	AppID     uuid.UUID
	OwnerID   uuid.UUID
	Name      string
	ChainType string
	Version   string
	Rules     []byte // JSON
	CreatedAt time.Time
}

// MockAuthorizationKey represents an authorization key.
type MockAuthorizationKey struct {
	ID           uuid.UUID
	AppID        uuid.UUID
	UserID       uuid.UUID
	PublicKeyPEM string
	Status       string
	CreatedAt    time.Time
}

// MockSessionSigner represents a session signer.
type MockSessionSigner struct {
	ID               uuid.UUID
	WalletID         uuid.UUID
	SignerID         uuid.UUID
	TTLExpiresAt     time.Time
	PolicyOverrideID *uuid.UUID
	MaxValue         *string
	MaxTxs           *int
	AllowedMethods   []string
	UsedTxCount      int
	Status           string
	CreatedAt        time.Time
}

// MockAppRepository provides mock app storage.
type MockAppRepository struct {
	mu   sync.RWMutex
	apps map[uuid.UUID]*MockApp
}

// NewMockAppRepository creates a new mock app repository.
func NewMockAppRepository() *MockAppRepository {
	return &MockAppRepository{
		apps: make(map[uuid.UUID]*MockApp),
	}
}

// AddApp adds an app to the mock repository.
func (r *MockAppRepository) AddApp(app *MockApp) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apps[app.ID] = app
}

// GetByID retrieves an app by ID.
func (r *MockAppRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockApp, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	app, ok := r.apps[id]
	if !ok {
		return nil, fmt.Errorf("app not found")
	}
	return app, nil
}

// Reset clears all data.
func (r *MockAppRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.apps = make(map[uuid.UUID]*MockApp)
}

// MockAppSecretRepository provides mock app secret storage.
type MockAppSecretRepository struct {
	mu      sync.RWMutex
	secrets map[string][]*MockAppSecret // prefix -> secrets
}

// NewMockAppSecretRepository creates a new mock app secret repository.
func NewMockAppSecretRepository() *MockAppSecretRepository {
	return &MockAppSecretRepository{
		secrets: make(map[string][]*MockAppSecret),
	}
}

// AddSecret adds a secret to the mock repository.
func (r *MockAppSecretRepository) AddSecret(appID uuid.UUID, plainSecret string) (*MockAppSecret, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if len(plainSecret) < 14 {
		return nil, fmt.Errorf("secret too short")
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(plainSecret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}

	secret := &MockAppSecret{
		ID:           uuid.New(),
		AppID:        appID,
		SecretPrefix: plainSecret[:14],
		SecretHash:   string(hash),
		CreatedAt:    time.Now(),
	}

	r.secrets[secret.SecretPrefix] = append(r.secrets[secret.SecretPrefix], secret)
	return secret, nil
}

// GetBySecretPrefix retrieves secrets by prefix.
func (r *MockAppSecretRepository) GetBySecretPrefix(ctx context.Context, prefix string) ([]*MockAppSecret, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.secrets[prefix], nil
}

// Reset clears all data.
func (r *MockAppSecretRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets = make(map[string][]*MockAppSecret)
}

// MockUserRepository provides mock user storage.
type MockUserRepository struct {
	mu    sync.RWMutex
	users map[uuid.UUID]*MockUser
	bySub map[string]*MockUser
}

// NewMockUserRepository creates a new mock user repository.
func NewMockUserRepository() *MockUserRepository {
	return &MockUserRepository{
		users: make(map[uuid.UUID]*MockUser),
		bySub: make(map[string]*MockUser),
	}
}

// AddUser adds a user to the mock repository.
func (r *MockUserRepository) AddUser(user *MockUser) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users[user.ID] = user
	r.bySub[user.Subject] = user
}

// GetByID retrieves a user by ID.
func (r *MockUserRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.users[id]
	if !ok {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// GetBySubject retrieves a user by JWT subject.
func (r *MockUserRepository) GetBySubject(ctx context.Context, appID uuid.UUID, subject string) (*MockUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	user, ok := r.bySub[subject]
	if !ok || user.AppID != appID {
		return nil, fmt.Errorf("user not found")
	}
	return user, nil
}

// Reset clears all data.
func (r *MockUserRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.users = make(map[uuid.UUID]*MockUser)
	r.bySub = make(map[string]*MockUser)
}

// MockWalletRepository provides mock wallet storage.
type MockWalletRepository struct {
	mu      sync.RWMutex
	wallets map[uuid.UUID]*MockWallet
}

// NewMockWalletRepository creates a new mock wallet repository.
func NewMockWalletRepository() *MockWalletRepository {
	return &MockWalletRepository{
		wallets: make(map[uuid.UUID]*MockWallet),
	}
}

// AddWallet adds a wallet to the mock repository.
func (r *MockWalletRepository) AddWallet(wallet *MockWallet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wallets[wallet.ID] = wallet
}

// GetByID retrieves a wallet by ID.
func (r *MockWalletRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockWallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	wallet, ok := r.wallets[id]
	if !ok {
		return nil, fmt.Errorf("wallet not found")
	}
	return wallet, nil
}

// GetByAppID retrieves wallets for an app.
func (r *MockWalletRepository) GetByAppID(ctx context.Context, appID uuid.UUID) ([]*MockWallet, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*MockWallet
	for _, w := range r.wallets {
		if w.AppID == appID {
			result = append(result, w)
		}
	}
	return result, nil
}

// Reset clears all data.
func (r *MockWalletRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.wallets = make(map[uuid.UUID]*MockWallet)
}

// MockAuthorizationKeyRepository provides mock auth key storage.
type MockAuthorizationKeyRepository struct {
	mu   sync.RWMutex
	keys map[uuid.UUID]*MockAuthorizationKey
}

// NewMockAuthorizationKeyRepository creates a new mock auth key repository.
func NewMockAuthorizationKeyRepository() *MockAuthorizationKeyRepository {
	return &MockAuthorizationKeyRepository{
		keys: make(map[uuid.UUID]*MockAuthorizationKey),
	}
}

// AddKey adds an authorization key to the mock repository.
func (r *MockAuthorizationKeyRepository) AddKey(key *MockAuthorizationKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys[key.ID] = key
}

// GetByID retrieves an authorization key by ID.
func (r *MockAuthorizationKeyRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockAuthorizationKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key, ok := r.keys[id]
	if !ok {
		return nil, fmt.Errorf("authorization key not found")
	}
	return key, nil
}

// Reset clears all data.
func (r *MockAuthorizationKeyRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = make(map[uuid.UUID]*MockAuthorizationKey)
}

// MockSessionSignerRepository provides mock session signer storage.
type MockSessionSignerRepository struct {
	mu      sync.RWMutex
	signers map[uuid.UUID]*MockSessionSigner
}

// NewMockSessionSignerRepository creates a new mock session signer repository.
func NewMockSessionSignerRepository() *MockSessionSignerRepository {
	return &MockSessionSignerRepository{
		signers: make(map[uuid.UUID]*MockSessionSigner),
	}
}

// AddSigner adds a session signer to the mock repository.
func (r *MockSessionSignerRepository) AddSigner(signer *MockSessionSigner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signers[signer.ID] = signer
}

// GetByID retrieves a session signer by ID.
func (r *MockSessionSignerRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockSessionSigner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	signer, ok := r.signers[id]
	if !ok {
		return nil, fmt.Errorf("session signer not found")
	}
	return signer, nil
}

// GetBySignerID retrieves session signers by signer key ID.
func (r *MockSessionSignerRepository) GetBySignerID(ctx context.Context, signerID uuid.UUID) ([]*MockSessionSigner, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*MockSessionSigner
	for _, s := range r.signers {
		if s.SignerID == signerID {
			result = append(result, s)
		}
	}
	return result, nil
}

// IncrementUsedTxCount increments the transaction count for a session signer.
func (r *MockSessionSignerRepository) IncrementUsedTxCount(ctx context.Context, id uuid.UUID) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	signer, ok := r.signers[id]
	if !ok {
		return fmt.Errorf("session signer not found")
	}
	signer.UsedTxCount++
	return nil
}

// Reset clears all data.
func (r *MockSessionSignerRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.signers = make(map[uuid.UUID]*MockSessionSigner)
}

// MockPolicyRepository provides mock policy storage.
type MockPolicyRepository struct {
	mu       sync.RWMutex
	policies map[uuid.UUID]*MockPolicy
}

// NewMockPolicyRepository creates a new mock policy repository.
func NewMockPolicyRepository() *MockPolicyRepository {
	return &MockPolicyRepository{
		policies: make(map[uuid.UUID]*MockPolicy),
	}
}

// AddPolicy adds a policy to the mock repository.
func (r *MockPolicyRepository) AddPolicy(policy *MockPolicy) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies[policy.ID] = policy
}

// GetByID retrieves a policy by ID.
func (r *MockPolicyRepository) GetByID(ctx context.Context, id uuid.UUID) (*MockPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	policy, ok := r.policies[id]
	if !ok {
		return nil, fmt.Errorf("policy not found")
	}
	return policy, nil
}

// GetByAppID retrieves policies for an app.
func (r *MockPolicyRepository) GetByAppID(ctx context.Context, appID uuid.UUID) ([]*MockPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*MockPolicy
	for _, p := range r.policies {
		if p.AppID == appID {
			result = append(result, p)
		}
	}
	return result, nil
}

// Reset clears all data.
func (r *MockPolicyRepository) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policies = make(map[uuid.UUID]*MockPolicy)
}

// TestDataStore holds all mock repositories for comprehensive testing.
type TestDataStore struct {
	Apps           *MockAppRepository
	AppSecrets     *MockAppSecretRepository
	Users          *MockUserRepository
	Wallets        *MockWalletRepository
	AuthKeys       *MockAuthorizationKeyRepository
	SessionSigners *MockSessionSignerRepository
	Policies       *MockPolicyRepository
}

// NewTestDataStore creates a new test data store with all repositories.
func NewTestDataStore() *TestDataStore {
	return &TestDataStore{
		Apps:           NewMockAppRepository(),
		AppSecrets:     NewMockAppSecretRepository(),
		Users:          NewMockUserRepository(),
		Wallets:        NewMockWalletRepository(),
		AuthKeys:       NewMockAuthorizationKeyRepository(),
		SessionSigners: NewMockSessionSignerRepository(),
		Policies:       NewMockPolicyRepository(),
	}
}

// Reset clears all data from all repositories.
func (s *TestDataStore) Reset() {
	s.Apps.Reset()
	s.AppSecrets.Reset()
	s.Users.Reset()
	s.Wallets.Reset()
	s.AuthKeys.Reset()
	s.SessionSigners.Reset()
	s.Policies.Reset()
}

// CreateTestApp creates a test app with a secret.
func (s *TestDataStore) CreateTestApp(name string) (*MockApp, string, error) {
	app := &MockApp{
		ID:        uuid.New(),
		Name:      name,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
		Settings: &MockAppSettings{
			Auth: &MockAppAuthSettings{
				Issuer:   "https://test-issuer.example.com",
				Audience: "test-audience",
				JWKSURI:  "https://test-issuer.example.com/.well-known/jwks.json",
			},
		},
	}
	s.Apps.AddApp(app)

	// Create secret (format: bw_sk_XXXXXXXX + random)
	secret := fmt.Sprintf("bw_sk_%s%s", uuid.New().String()[:8], uuid.New().String())
	_, err := s.AppSecrets.AddSecret(app.ID, secret)
	if err != nil {
		return nil, "", err
	}

	return app, secret, nil
}

// CreateTestUser creates a test user for an app.
func (s *TestDataStore) CreateTestUser(appID uuid.UUID, subject string) *MockUser {
	user := &MockUser{
		ID:        uuid.New(),
		AppID:     appID,
		Subject:   subject,
		Email:     fmt.Sprintf("%s@test.example.com", subject),
		CreatedAt: time.Now(),
	}
	s.Users.AddUser(user)
	return user
}

// CreateTestWallet creates a test wallet.
func (s *TestDataStore) CreateTestWallet(appID uuid.UUID, userID, ownerID *uuid.UUID) *MockWallet {
	// Generate a random 20-byte address (40 hex chars)
	addrBytes := make([]byte, 20)
	rand.Read(addrBytes)

	wallet := &MockWallet{
		ID:          uuid.New(),
		AppID:       appID,
		UserID:      userID,
		OwnerID:     ownerID,
		Address:     fmt.Sprintf("0x%x", addrBytes),
		ChainType:   "ethereum",
		ExecBackend: "kms",
		Status:      "active",
		CreatedAt:   time.Now(),
	}
	s.Wallets.AddWallet(wallet)
	return wallet
}
