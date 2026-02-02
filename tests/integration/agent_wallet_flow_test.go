//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/api"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// MockStore implements both PrincipalStore and AgentStore for testing
type MockStore struct {
	principals   map[uuid.UUID]*types.Principal
	apiKeys      map[string]*types.PrincipalAPIKey
	apiKeyHashes map[string]string
	wallets      map[uuid.UUID]*types.AgentWallet
	credentials  map[string]*types.AgentCredential
	credHashes   map[string]string
	rateLimits   map[uuid.UUID]*types.AgentRateLimit
}

func NewMockStore() *MockStore {
	return &MockStore{
		principals:   make(map[uuid.UUID]*types.Principal),
		apiKeys:      make(map[string]*types.PrincipalAPIKey),
		apiKeyHashes: make(map[string]string),
		wallets:      make(map[uuid.UUID]*types.AgentWallet),
		credentials:  make(map[string]*types.AgentCredential),
		credHashes:   make(map[string]string),
		rateLimits:   make(map[uuid.UUID]*types.AgentRateLimit),
	}
}

// PrincipalStore implementation
func (s *MockStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	if key, ok := s.apiKeys[prefix]; ok {
		return key, s.apiKeyHashes[prefix], nil
	}
	return nil, "", nil
}

func (s *MockStore) GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	return s.principals[id], nil
}

func (s *MockStore) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

// AgentStore implementation
func (s *MockStore) GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	if cred, ok := s.credentials[prefix]; ok {
		return cred, s.credHashes[prefix], nil
	}
	return nil, "", nil
}

func (s *MockStore) GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	return s.wallets[id], nil
}

func (s *MockStore) UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

// Helper to add test data
func (s *MockStore) AddPrincipal(p *types.Principal, apiKeyPrefix, apiKeySecret string) {
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

func (s *MockStore) AddWallet(w *types.AgentWallet) {
	s.wallets[w.ID] = w
}

func (s *MockStore) AddCredential(c *types.AgentCredential, prefix, secret string) {
	s.credentials[prefix] = c
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	s.credHashes[prefix] = string(hash)
}

// Test: Complete Agent Wallet flow - Principal creates wallet, grants credential, agent signs
func TestAgentWalletFlow_Complete(t *testing.T) {
	store := NewMockStore()

	// Setup: Create principal with API key
	principalID := uuid.New()
	principal := &types.Principal{
		ID:        principalID,
		Name:      "Test Principal",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
	}
	apiKeyPrefix := "aw_pk_testprefix1"
	apiKeySecret := "testsecret123"
	store.AddPrincipal(principal, apiKeyPrefix, apiKeySecret)

	// Setup: Create wallet owned by principal
	walletID := uuid.New()
	wallet := &types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Name:        "Test Wallet",
		ChainType:   "evm",
		Address:     "0x1234567890123456789012345678901234567890",
		Status:      types.AgentStatusActive,
		CreatedAt:   time.Now(),
	}
	store.AddWallet(wallet)

	// Setup: Create credential for agent
	credentialID := uuid.New()
	credPrefix := "aw_ag_testcred01"
	credSecret := "agentsecret456"
	credential := &types.AgentCredential{
		ID:        credentialID,
		WalletID:  walletID,
		Name:      "Test Agent Credential",
		KeyPrefix: credPrefix,
		Capabilities: types.AgentCapabilities{
			Operations: []string{types.OperationTransfer, types.OperationSignMessage},
		},
		Limits: types.AgentLimits{
			MaxTxPerHour:  10,
			MaxTxPerDay:   100,
			MaxValuePerTx: "1000000000000000000", // 1 ETH
		},
		Status:    types.AgentStatusActive,
		CreatedAt: time.Now(),
	}
	store.AddCredential(credential, credPrefix, credSecret)

	// Create middleware
	agentAuth := middleware.NewAgentAuthMiddleware(store)

	// Test: Agent authenticates and accesses protected endpoint
	t.Run("agent can authenticate with valid credential", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred := middleware.GetAgentCredential(r.Context())
			wallet := middleware.GetAgentWallet(r.Context())

			if cred == nil {
				t.Error("credential should be in context")
				return
			}
			if wallet == nil {
				t.Error("wallet should be in context")
				return
			}
			if cred.ID != credentialID {
				t.Errorf("credential ID = %v, want %v", cred.ID, credentialID)
			}
			if wallet.ID != walletID {
				t.Errorf("wallet ID = %v, want %v", wallet.ID, walletID)
			}

			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+credPrefix+"."+credSecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d, body: %s", rec.Code, http.StatusOK, rec.Body.String())
		}
	})

	// Test: Agent with wrong secret is rejected
	t.Run("agent with wrong secret is rejected", func(t *testing.T) {
		handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}))

		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
		req.Header.Set("Authorization", "Bearer "+credPrefix+".wrongsecret")

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// Test: Principal authentication flow
func TestPrincipalAuthFlow(t *testing.T) {
	store := NewMockStore()

	// Setup principal
	principalID := uuid.New()
	principal := &types.Principal{
		ID:        principalID,
		Name:      "Test Principal",
		Email:     "test@example.com",
		CreatedAt: time.Now(),
	}
	apiKeyPrefix := "aw_pk_principal1"
	apiKeySecret := "principalsecret"
	store.AddPrincipal(principal, apiKeyPrefix, apiKeySecret)

	principalAuth := middleware.NewPrincipalAuthMiddleware(store)

	t.Run("principal can authenticate with valid API key", func(t *testing.T) {
		handler := principalAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			p := middleware.GetPrincipal(r.Context())
			if p == nil {
				t.Error("principal should be in context")
				return
			}
			if p.ID != principalID {
				t.Errorf("principal ID = %v, want %v", p.ID, principalID)
			}
			w.WriteHeader(http.StatusOK)
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/wallets", nil)
		req.Header.Set("Authorization", "Bearer "+apiKeyPrefix+"."+apiKeySecret)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("missing authorization header returns 401", func(t *testing.T) {
		handler := principalAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Error("handler should not be called")
		}))

		req := httptest.NewRequest(http.MethodGet, "/api/wallets", nil)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})
}

// Test: JSON-RPC request handling
func TestJSONRPCRequestHandling(t *testing.T) {
	t.Run("valid JSON-RPC request structure", func(t *testing.T) {
		reqBody := api.JSONRPCRequest{
			JSONRPC: "2.0",
			Method:  "eth_accounts",
			Params:  []any{},
			ID:      1,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/agent/rpc", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")

		var parsed api.JSONRPCRequest
		if err := json.NewDecoder(req.Body).Decode(&parsed); err != nil {
			t.Fatalf("failed to parse request: %v", err)
		}

		if parsed.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q, want %q", parsed.JSONRPC, "2.0")
		}
		if parsed.Method != "eth_accounts" {
			t.Errorf("method = %q, want %q", parsed.Method, "eth_accounts")
		}
	})

	t.Run("JSON-RPC response structure", func(t *testing.T) {
		resp := api.JSONRPCResponse{
			JSONRPC: "2.0",
			Result:  []string{"0x1234567890123456789012345678901234567890"},
			ID:      1,
		}

		body, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal response: %v", err)
		}

		var parsed api.JSONRPCResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if parsed.JSONRPC != "2.0" {
			t.Errorf("jsonrpc = %q, want %q", parsed.JSONRPC, "2.0")
		}
		if parsed.Error != nil {
			t.Errorf("error should be nil, got %v", parsed.Error)
		}
	})

	t.Run("JSON-RPC error response structure", func(t *testing.T) {
		resp := api.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &api.JSONRPCError{
				Code:    -32600,
				Message: "Invalid Request",
			},
			ID: 1,
		}

		body, _ := json.Marshal(resp)

		var parsed api.JSONRPCResponse
		json.Unmarshal(body, &parsed)

		if parsed.Error == nil {
			t.Fatal("error should not be nil")
		}
		if parsed.Error.Code != -32600 {
			t.Errorf("error code = %d, want %d", parsed.Error.Code, -32600)
		}
	})
}

// Test: Credential status handling
func TestCredentialStatusHandling(t *testing.T) {
	store := NewMockStore()

	// Setup principal and wallet
	principalID := uuid.New()
	principal := &types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}
	store.AddPrincipal(principal, "aw_pk_test123456", "secret")

	walletID := uuid.New()
	wallet := &types.AgentWallet{
		ID:          walletID,
		PrincipalID: principalID,
		Status:      types.AgentStatusActive,
		Address:     "0x1234567890123456789012345678901234567890",
		CreatedAt:   time.Now(),
	}
	store.AddWallet(wallet)

	tests := []struct {
		name           string
		credStatus     string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "active credential succeeds",
			credStatus:     types.AgentStatusActive,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "paused credential returns 403",
			credStatus:     types.AgentStatusPaused,
			expectedStatus: http.StatusForbidden,
			expectedCode:   "CREDENTIAL_PAUSED",
		},
		{
			name:           "revoked credential returns 403",
			credStatus:     types.AgentStatusRevoked,
			expectedStatus: http.StatusForbidden,
			expectedCode:   "CREDENTIAL_REVOKED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create credential with specific status
			credPrefix := "aw_ag_" + tt.credStatus[:6]
			credSecret := "secret123"
			credential := &types.AgentCredential{
				ID:        uuid.New(),
				WalletID:  walletID,
				KeyPrefix: credPrefix,
				Status:    tt.credStatus,
				CreatedAt: time.Now(),
			}
			store.AddCredential(credential, credPrefix, credSecret)

			agentAuth := middleware.NewAgentAuthMiddleware(store)
			handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
			req.Header.Set("Authorization", "Bearer "+credPrefix+"."+credSecret)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, tt.expectedStatus, rec.Body.String())
			}

			if tt.expectedCode != "" {
				var resp map[string]string
				json.Unmarshal(rec.Body.Bytes(), &resp)
				if resp["code"] != tt.expectedCode {
					t.Errorf("code = %q, want %q", resp["code"], tt.expectedCode)
				}
			}
		})
	}
}

// Test: Wallet status handling
func TestWalletStatusHandling(t *testing.T) {
	store := NewMockStore()

	principalID := uuid.New()
	principal := &types.Principal{ID: principalID, Name: "Test", CreatedAt: time.Now()}
	store.AddPrincipal(principal, "aw_pk_wallettest", "secret")

	tests := []struct {
		name           string
		walletStatus   string
		expectedStatus int
		expectedCode   string
	}{
		{
			name:           "active wallet succeeds",
			walletStatus:   types.AgentStatusActive,
			expectedStatus: http.StatusOK,
		},
		{
			name:           "paused wallet returns 403",
			walletStatus:   types.AgentStatusPaused,
			expectedStatus: http.StatusForbidden,
			expectedCode:   "WALLET_PAUSED",
		},
		{
			name:           "killed wallet returns 403",
			walletStatus:   types.AgentStatusKilled,
			expectedStatus: http.StatusForbidden,
			expectedCode:   "WALLET_KILLED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			walletID := uuid.New()
			wallet := &types.AgentWallet{
				ID:          walletID,
				PrincipalID: principalID,
				Status:      tt.walletStatus,
				Address:     "0x1234567890123456789012345678901234567890",
				CreatedAt:   time.Now(),
			}
			store.AddWallet(wallet)

			credPrefix := "aw_ag_w" + tt.walletStatus[:4]
			credSecret := "secret123"
			credential := &types.AgentCredential{
				ID:        uuid.New(),
				WalletID:  walletID,
				KeyPrefix: credPrefix,
				Status:    types.AgentStatusActive,
				CreatedAt: time.Now(),
			}
			store.AddCredential(credential, credPrefix, credSecret)

			agentAuth := middleware.NewAgentAuthMiddleware(store)
			handler := agentAuth.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))

			req := httptest.NewRequest(http.MethodPost, "/agent/rpc", nil)
			req.Header.Set("Authorization", "Bearer "+credPrefix+"."+credSecret)

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.expectedStatus {
				t.Errorf("status = %d, want %d, body: %s", rec.Code, tt.expectedStatus, rec.Body.String())
			}

			if tt.expectedCode != "" {
				var resp map[string]string
				json.Unmarshal(rec.Body.Bytes(), &resp)
				if resp["code"] != tt.expectedCode {
					t.Errorf("code = %q, want %q", resp["code"], tt.expectedCode)
				}
			}
		})
	}
}
