package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type mockPrincipalStore struct {
	apiKey    *types.PrincipalAPIKey
	keyHash   string
	principal *types.Principal
}

func (m *mockPrincipalStore) GetAPIKeyByPrefix(ctx context.Context, prefix string) (*types.PrincipalAPIKey, string, error) {
	if m.apiKey != nil && m.apiKey.KeyPrefix == prefix {
		return m.apiKey, m.keyHash, nil
	}
	return nil, "", nil
}

func (m *mockPrincipalStore) GetPrincipalByID(ctx context.Context, id uuid.UUID) (*types.Principal, error) {
	if m.principal != nil && m.principal.ID == id {
		return m.principal, nil
	}
	return nil, nil
}

func (m *mockPrincipalStore) UpdateAPIKeyLastUsed(ctx context.Context, id uuid.UUID) error {
	return nil
}

func TestPrincipalAuthMiddleware_ValidKey(t *testing.T) {
	principalID := uuid.New()
	apiKeyID := uuid.New()
	secret := "test_secret_key"
	hash, _ := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

	store := &mockPrincipalStore{
		apiKey: &types.PrincipalAPIKey{
			ID:          apiKeyID,
			PrincipalID: principalID,
			KeyPrefix:   "aw_pk_test",
			Status:      types.AgentStatusActive,
		},
		keyHash: string(hash),
		principal: &types.Principal{
			ID:    principalID,
			Name:  "Test Principal",
			Email: "test@example.com",
		},
	}

	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal := GetPrincipal(r.Context())
		if principal == nil {
			t.Error("expected principal in context")
			return
		}
		if principal.ID != principalID {
			t.Errorf("expected principal ID %s, got %s", principalID, principal.ID)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_pk_test."+secret)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rec.Code)
	}
}

func TestPrincipalAuthMiddleware_MissingHeader(t *testing.T) {
	store := &mockPrincipalStore{}
	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestPrincipalAuthMiddleware_InvalidKey(t *testing.T) {
	store := &mockPrincipalStore{}
	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer invalid_key")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}

func TestPrincipalAuthMiddleware_WrongSecret(t *testing.T) {
	principalID := uuid.New()
	apiKeyID := uuid.New()
	hash, _ := bcrypt.GenerateFromPassword([]byte("correct_secret"), bcrypt.DefaultCost)

	store := &mockPrincipalStore{
		apiKey: &types.PrincipalAPIKey{
			ID:          apiKeyID,
			PrincipalID: principalID,
			KeyPrefix:   "aw_pk_test",
			Status:      types.AgentStatusActive,
		},
		keyHash: string(hash),
	}

	middleware := NewPrincipalAuthMiddleware(store)

	handler := middleware.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer aw_pk_test.wrong_secret")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("expected status 401, got %d", rec.Code)
	}
}
