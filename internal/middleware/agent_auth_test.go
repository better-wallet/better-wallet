package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type mockAgentStore struct {
	credential *types.AgentCredential
	keyHash    string
	wallet     *types.AgentWallet
}

func (m *mockAgentStore) GetCredentialByPrefix(ctx context.Context, prefix string) (*types.AgentCredential, string, error) {
	if m.credential != nil && m.credential.KeyPrefix == prefix {
		return m.credential, m.keyHash, nil
	}
	return nil, "", nil
}

func (m *mockAgentStore) GetWalletByID(ctx context.Context, id uuid.UUID) (*types.AgentWallet, error) {
	if m.wallet != nil && m.wallet.ID == id {
		return m.wallet, nil
	}
	return nil, nil
}

func (m *mockAgentStore) UpdateCredentialLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func TestAgentAuthMiddleware_ValidCredential(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.AgentStatusActive,
			Capabilities: types.AgentCapabilities{
				Chains:     []string{"ethereum"},
				Operations: []string{"transfer"},
			},
			Limits: types.AgentLimits{
				MaxValuePerTx:   "1000000000000000000",
				MaxValuePerHour: "10000000000000000000",
				MaxValuePerDay:  "100000000000000000000",
				MaxTxPerHour:    100,
				MaxTxPerDay:     1000,
			},
			CreatedAt: time.Now(),
		},
		keyHash: string(hash),
		wallet: &types.AgentWallet{
			ID:        walletID,
			Status:    types.AgentStatusActive,
			ChainType: "ethereum",
			Address:   "0x1234567890123456789012345678901234567890",
		},
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cred := GetAgentCredential(r.Context())
		if cred == nil {
			t.Error("expected credential in context")
			return
		}
		if cred.ID != credentialID {
			t.Errorf("expected credential ID %s, got %s", credentialID, cred.ID)
		}
		wallet := GetAgentWallet(r.Context())
		if wallet == nil {
			t.Error("expected wallet in context")
			return
		}
		if wallet.ID != walletID {
			t.Errorf("expected wallet ID %s, got %s", walletID, wallet.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestAgentAuthMiddleware_PausedCredential(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	pausedAt := time.Now()

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.AgentStatusPaused,
			PausedAt:  &pausedAt,
		},
		keyHash: string(hash),
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestAgentAuthMiddleware_RevokedCredential(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	revokedAt := time.Now()

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.AgentStatusRevoked,
			RevokedAt: &revokedAt,
		},
		keyHash: string(hash),
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestAgentAuthMiddleware_PausedWallet(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.AgentStatusActive,
		},
		keyHash: string(hash),
		wallet: &types.AgentWallet{
			ID:     walletID,
			Status: types.AgentStatusPaused,
		},
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}

func TestAgentAuthMiddleware_KilledWallet(t *testing.T) {
	walletID := uuid.New()
	credentialID := uuid.New()
	secret := "test_agent_secret"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockAgentStore{
		credential: &types.AgentCredential{
			ID:        credentialID,
			WalletID:  walletID,
			KeyPrefix: "aw_ag_test",
			Status:    types.AgentStatusActive,
		},
		keyHash: string(hash),
		wallet: &types.AgentWallet{
			ID:     walletID,
			Status: types.AgentStatusKilled,
		},
	}

	middleware := NewAgentAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_ag_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected status 403, got %d", rec.Code)
	}
}
