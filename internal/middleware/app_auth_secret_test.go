package middleware

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type mockAppRepo struct {
	app *types.App
}

func (m *mockAppRepo) GetByID(_ context.Context, id uuid.UUID) (*types.App, error) {
	if m.app != nil && m.app.ID == id {
		return m.app, nil
	}
	return nil, fmt.Errorf("not found")
}

type mockAppSecretRepo struct {
	appID  uuid.UUID
	secret string
	hash   string
}

func (m *mockAppSecretRepo) GetBySecretPrefix(_ context.Context, prefix string) ([]*types.AppSecret, error) {
	if len(m.secret) < 14 || prefix != m.secret[:14] {
		return []*types.AppSecret{}, nil
	}
	return []*types.AppSecret{
		{
			ID:           uuid.New(),
			AppID:        m.appID,
			SecretHash:   m.hash,
			SecretPrefix: prefix,
			Status:       types.StatusActive,
			CreatedAt:    time.Now(),
		},
	}, nil
}

func (m *mockAppSecretRepo) UpdateLastUsed(_ context.Context, _ uuid.UUID) error {
	return nil
}

func TestAppAuthMiddleware_AllowsXAppSecretWithBearerAuthHeader(t *testing.T) {
	appID := uuid.New()
	secret := "bw_sk_abcdefgh1234567890"
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)

	m := &AppAuthMiddleware{
		appRepo: &mockAppRepo{
			app: &types.App{
				ID:     appID,
				Name:   "test-app",
				Status: types.AppStatusActive,
				Settings: types.AppSettings{
					Auth: &types.AppAuthSettings{
						Issuer:   "https://issuer.example.com",
						Audience: "aud",
						JWKSURI:  "https://issuer.example.com/jwks",
					},
				},
			},
		},
		secretRepo: &mockAppSecretRepo{
			appID:  appID,
			secret: secret,
			hash:   string(hashBytes),
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// App context is set
		require.NotNil(t, GetApp(r.Context()))
		require.Equal(t, appID.String(), GetAppID(r.Context()))

		// Secret should not be available downstream
		require.Empty(t, r.Header.Get("X-App-Secret"))

		// Storage app scope is set (uuid)
		gotAppID, err := storage.RequireAppID(r.Context())
		require.NoError(t, err)
		require.Equal(t, appID, gotAppID)

		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-App-Id", appID.String())
	req.Header.Set("X-App-Secret", secret)
	req.Header.Set("Authorization", "Bearer user.jwt.token")
	rec := httptest.NewRecorder()

	m.Authenticate(handler).ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestAppAuthMiddleware_RejectsBasicAuth(t *testing.T) {
	appID := uuid.New()
	secret := "bw_sk_abcdefgh1234567890"
	hashBytes, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)

	creds := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", appID.String(), secret)))

	m := &AppAuthMiddleware{
		appRepo: &mockAppRepo{
			app: &types.App{
				ID:     appID,
				Name:   "test-app",
				Status: types.AppStatusActive,
				Settings: types.AppSettings{
					Auth: &types.AppAuthSettings{
						Issuer:   "https://issuer.example.com",
						Audience: "aud",
						JWKSURI:  "https://issuer.example.com/jwks",
					},
				},
			},
		},
		secretRepo: &mockAppSecretRepo{
			appID:  appID,
			secret: secret,
			hash:   string(hashBytes),
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-App-Id", appID.String())
	req.Header.Set("Authorization", "Basic "+creds)
	rec := httptest.NewRecorder()

	m.Authenticate(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).ServeHTTP(rec, req)

	require.Equal(t, http.StatusUnauthorized, rec.Code)
	require.Contains(t, rec.Body.String(), "Basic is not supported")
}
