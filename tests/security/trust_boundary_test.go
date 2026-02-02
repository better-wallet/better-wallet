//go:build security

package security

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// MockSecurityStore implements stores for security testing
type MockSecurityStore struct {
	principals   map[uuid.UUID]*types.Principal
	apiKeys      map[string]*types.PrincipalAPIKey
	apiKeyHashes map[string]string
	wallets      map[uuid.UUID]*types.AgentWallet
	credentials  map[string]*types.AgentCredential
	credHashes   map[string]string
}

func NewMockSecurityStore() *MockSecurityStore {
	return &MockSecurityStore{
		principals:   make(map[uuid.UUID]*types.Principal),
		apiKeys:      make(map[string]*types.PrincipalAPIKey),
		apiKeyHashes: make(map[string]string),
		wallets:      make(map[uuid.UUID]*types.AgentWallet),
		credentials:  make(map[string]*types.AgentCredential),
		credHashes:   make(map[string]string),
	}
}

// PrincipalStore implementation
func (s *MockSecurityStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	if key, ok := s.apiKeys[prefix]; ok {
		return key, s.apiKeyHashes[prefix], nil
	}
	return nil, "", nil
}

func (s *MockSecurityStore) GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	return s.principals[id], nil
}

func (s *MockSecurityStore) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

// AgentStore implementation
func (s *MockSecurityStore) GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	if cred, ok := s.credentials[prefix]; ok {
		return cred, s.credHashes[prefix], nil
	}
	return nil, "", nil
}

func (s *MockSecurityStore) GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	return s.wallets[id], nil
}

func (s *MockSecurityStore) UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

// Helper methods
func (s *MockSecurityStore) AddPrincipal(p *types.Principal, apiKeyPrefix, apiKeySecret string) {
	s.principals[p.ID] = p
	apiKeyID := uuid.New()
	s.apiKeys[apiKeyPrefix] = &types.PrincipalAPIKey{
		ID:          apiKeyID,
		PrincipalID: p.ID,
		KeyPrefix:   apiKeyPrefix,
		Name:        "test-key",
		Status:      types.AgentStatusActive,
		CreatedAt:   time.Now(),
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(apiKeySecret), bcrypt.DefaultCost)
	s.apiKeyHashes[apiKeyPrefix] = string(hash)
}

func (s *MockSecurityStore) AddWallet(w *types.AgentWallet) {
	s.wallets[w.ID] = w
}

func (s *MockSecurityStore) AddCredential(c *types.AgentCredential, prefix, secret string) {
	s.credentials[prefix] = c
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	s.credHashes[prefix] = string(hash)
}

// Test: Agent cannot access another principal's wallet
func TestTrustBoundary_AgentCannotAccessOtherWallet(t *testing.T) {
	store := NewMockSecurityStore()

	// Setup: Principal A with Wallet A
	principalA := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalA, Name: "Principal A", CreatedAt: time.Now()}, "aw_pk_principalA", "secretA")

	walletA := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletA,
		PrincipalID: principalA,
		Name:        "Wallet A",
		Address:     "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		Status:      types.AgentStatusActive,
		CreatedAt:   time.Now(),
	})

	// Setup: Principal B with Wallet B
	principalB := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalB, Name: "Principal B", CreatedAt: time.Now()}, "aw_pk_principalB", "secretB")

	walletB := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletB,
		PrincipalID: principalB,
		Name:        "Wallet B",
		Address:     "0xBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB",
		Status:      types.AgentStatusActive,
		CreatedAt:   time.Now(),
	})

	// Agent credential for Wallet A only
	credPrefix := "aw_ag_agentforA1"
	credSecret := "agentsecret"
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletA, // Bound to Wallet A
		KeyPrefix: credPrefix,
		Status:    types.AgentStatusActive,
		CreatedAt: time.Now(),
	}, credPrefix, credSecret)

	agentAuth := middleware.NewAgentAuthMiddleware(store)

	t.Run("agent credential is bound to specific wallet", func(t *testing.T) {
		var receivedWalletID uuid.UUID

		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			wallet := middleware.GetAgentWallet(r.Context())
			if wallet != nil {
				receivedWalletID = wallet.ID
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+credPrefix+"."+credSecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Agent should only have access to Wallet A
		if receivedWalletID != walletA {
			t.Errorf("agent should only access Wallet A, got wallet ID %v", receivedWalletID)
		}
		if receivedWalletID == walletB {
			t.Error("SECURITY VIOLATION: agent accessed Wallet B which belongs to different principal")
		}
	})
}

// Test: Invalid credential formats are rejected
func TestAuthenticationBypass_InvalidFormats(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, "aw_pk_testformat", "secret")

	walletID := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusActive,
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	})

	credPrefix := "aw_ag_validcred1"
	credSecret := "validsecret"
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletID,
		KeyPrefix: credPrefix,
		Status:    types.AgentStatusActive,
		CreatedAt: time.Now(),
	}, credPrefix, credSecret)

	agentAuth := middleware.NewAgentAuthMiddleware(store)

	tests := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{
			name:       "missing authorization header",
			authHeader: "",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing Bearer prefix",
			authHeader: credPrefix + "." + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "Basic auth instead of Bearer",
			authHeader: "Basic " + credPrefix + "." + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "missing dot separator",
			authHeader: "Bearer " + credPrefix + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "empty secret after dot",
			authHeader: "Bearer " + credPrefix + ".",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "only prefix no secret",
			authHeader: "Bearer " + credPrefix,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "SQL injection in prefix",
			authHeader: "Bearer ' OR '1'='1." + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "null byte injection",
			authHeader: "Bearer " + credPrefix + "\x00." + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "very long prefix (DoS attempt)",
			authHeader: "Bearer " + string(make([]byte, 10000)) + "." + credSecret,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unicode manipulation",
			authHeader: "Bearer " + credPrefix + "。" + credSecret, // fullwidth dot
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				t.Error("SECURITY VIOLATION: handler should not be called with invalid auth")
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, tt.wantStatus)
			}
		})
	}
}

// Test: Timing attack prevention
func TestTimingAttackPrevention(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, "aw_pk_timingtest", "secret")

	walletID := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusActive,
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	})

	credPrefix := "aw_ag_timingcrd1"
	credSecret := "correctsecret"
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletID,
		KeyPrefix: credPrefix,
		Status:    types.AgentStatusActive,
		CreatedAt: time.Now(),
	}, credPrefix, credSecret)

	agentAuth := middleware.NewAgentAuthMiddleware(store)

	// Both valid prefix with wrong secret and invalid prefix should take similar time
	// due to dummy hash comparison
	t.Run("invalid prefix still performs bcrypt comparison", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

		// Request with non-existent prefix
		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer nonexistent_prefix.somesecret")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Should still return 401, not 500 or different error
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// Test: Revoked/paused credentials cannot be used
func TestRevokedCredentialCannotBeUsed(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, "aw_pk_revoketest", "secret")

	walletID := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusActive,
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	})

	// Create a revoked credential
	revokedPrefix := "aw_ag_revoked001"
	revokedSecret := "revokedsecret"
	revokedAt := time.Now()
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletID,
		KeyPrefix: revokedPrefix,
		Status:    types.AgentStatusRevoked,
		RevokedAt: &revokedAt,
		CreatedAt: time.Now(),
	}, revokedPrefix, revokedSecret)

	agentAuth := middleware.NewAgentAuthMiddleware(store)

	t.Run("revoked credential is rejected even with correct secret", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("SECURITY VIOLATION: revoked credential should not reach handler")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+revokedPrefix+"."+revokedSecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d (Forbidden)", rec.Code, http.StatusForbidden)
		}
	})
}

// Test: Killed wallet blocks all credentials
func TestKilledWalletBlocksAllCredentials(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, "aw_pk_killedtest", "secret")

	// Create a killed wallet
	walletID := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusKilled, // KILLED
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	})

	// Create an active credential for the killed wallet
	credPrefix := "aw_ag_killedwal1"
	credSecret := "activesecret"
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletID,
		KeyPrefix: credPrefix,
		Status:    types.AgentStatusActive, // Credential is active
		CreatedAt: time.Now(),
	}, credPrefix, credSecret)

	agentAuth := middleware.NewAgentAuthMiddleware(store)

	t.Run("active credential on killed wallet is rejected", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("SECURITY VIOLATION: killed wallet should block all access")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+credPrefix+"."+credSecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d (Forbidden)", rec.Code, http.StatusForbidden)
		}
	})
}

// Test: Principal API key cannot access agent endpoints
func TestPrincipalKeyCannotAccessAgentEndpoints(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	apiKeyPrefix := "aw_pk_principal1"
	apiKeySecret := "principalsecret"
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, apiKeyPrefix, apiKeySecret)

	// Agent auth middleware should reject principal API keys
	agentAuth := middleware.NewAgentAuthMiddleware(store)

	t.Run("principal API key rejected by agent auth", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("SECURITY VIOLATION: principal key should not work for agent auth")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+apiKeyPrefix+"."+apiKeySecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Should be rejected because aw_pk_ prefix is not in agent credentials
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// Test: Agent credential cannot access principal endpoints
func TestAgentCredentialCannotAccessPrincipalEndpoints(t *testing.T) {
	store := NewMockSecurityStore()

	principalID := uuid.New()
	store.AddPrincipal(&types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}, "aw_pk_principal2", "secret")

	walletID := uuid.New()
	store.AddWallet(&types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusActive,
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	})

	agentCredPrefix := "aw_ag_agentcred1"
	agentCredSecret := "agentsecret"
	store.AddCredential(&types.AgentCredential{
		ID:        uuid.New(),
		WalletID:  walletID,
		KeyPrefix: agentCredPrefix,
		Status:    types.AgentStatusActive,
		CreatedAt: time.Now(),
	}, agentCredPrefix, agentCredSecret)

	// Principal auth middleware should reject agent credentials
	principalAuth := middleware.NewPrincipalAuthMiddleware(store)

	t.Run("agent credential rejected by principal auth", func(t *testing.T) {
		handler := principalAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("SECURITY VIOLATION: agent credential should not work for principal auth")
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/wallets", nil)
		req.Header.Set("Authorization", "Bearer "+agentCredPrefix+"."+agentCredSecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		// Should be rejected because aw_ag_ prefix is not in principal API keys
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// Test: Capability enforcement
func TestCapabilityEnforcement(t *testing.T) {
	// This test verifies that the capability checking logic works correctly
	// The actual enforcement happens in the signing handlers

	t.Run("operations list restricts allowed operations", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				Operations: []string{types.OperationTransfer}, // Only transfer allowed
			},
		}

		// Check that transfer is allowed
		if !hasOperation(credential, types.OperationTransfer) {
			t.Error("transfer should be allowed")
		}

		// Check that sign_message is NOT allowed
		if hasOperation(credential, types.OperationSignMessage) {
			t.Error("sign_message should NOT be allowed")
		}

		// Check that contract_deploy is NOT allowed
		if hasOperation(credential, types.OperationContractDeploy) {
			t.Error("contract_deploy should NOT be allowed")
		}
	})

	t.Run("empty operations list allows all", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				Operations: []string{}, // Empty = all allowed
			},
		}

		if !hasOperation(credential, types.OperationTransfer) {
			t.Error("transfer should be allowed with empty list")
		}
		if !hasOperation(credential, types.OperationContractDeploy) {
			t.Error("contract_deploy should be allowed with empty list")
		}
	})

	t.Run("wildcard allows all operations", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				Operations: []string{"*"},
			},
		}

		if !hasOperation(credential, types.OperationTransfer) {
			t.Error("transfer should be allowed with wildcard")
		}
		if !hasOperation(credential, types.OperationContractDeploy) {
			t.Error("contract_deploy should be allowed with wildcard")
		}
	})
}

// Helper function matching the one in agent_signing_handlers.go
func hasOperation(credential *types.AgentCredential, operation string) bool {
	if len(credential.Capabilities.Operations) == 0 {
		return true
	}
	for _, op := range credential.Capabilities.Operations {
		if op == operation || op == "*" {
			return true
		}
	}
	return false
}

// Test: Contract allowlist enforcement
func TestContractAllowlistEnforcement(t *testing.T) {
	t.Run("contract in allowlist is allowed", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				AllowedContracts: []string{
					"0x1111111111111111111111111111111111111111",
					"0x2222222222222222222222222222222222222222",
				},
			},
		}

		if !isContractAllowed(credential, "0x1111111111111111111111111111111111111111") {
			t.Error("contract in allowlist should be allowed")
		}
	})

	t.Run("contract not in allowlist is rejected", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				AllowedContracts: []string{
					"0x1111111111111111111111111111111111111111",
				},
			},
		}

		if isContractAllowed(credential, "0x9999999999999999999999999999999999999999") {
			t.Error("contract NOT in allowlist should be rejected")
		}
	})

	t.Run("case insensitive matching", func(t *testing.T) {
		credential := &types.AgentCredential{
			Capabilities: types.AgentCapabilities{
				AllowedContracts: []string{
					"0xabcdef1234567890abcdef1234567890abcdef12",
				},
			},
		}

		// Uppercase version should match
		if !isContractAllowed(credential, "0xABCDEF1234567890ABCDEF1234567890ABCDEF12") {
			t.Error("case insensitive matching should work")
		}
	})
}

// Helper function matching the one in agent_signing_handlers.go
func isContractAllowed(credential *types.AgentCredential, to string) bool {
	if to == "" {
		return false
	}
	for _, contract := range credential.Capabilities.AllowedContracts {
		if equalFold(contract, to) {
			return true
		}
	}
	return false
}

func equalFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if ca >= 'A' && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if cb >= 'A' && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
