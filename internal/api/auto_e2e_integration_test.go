//go:build integration

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/better-wallet/better-wallet/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

type seededApp struct {
	appID       uuid.UUID
	appSecret   string
	userID      uuid.UUID
	userSub     string
	dashboardID string
	walletUser  uuid.UUID
}

func TestE2E_AutoSeededFlow(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}

	store, err := storage.New(dsn)
	require.NoError(t, err)
	defer store.Close()

	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err = jwksServer.AddRSAKey("test-key-1")
	require.NoError(t, err)

	userSub := "user-" + uuid.New().String()
	token, err := jwksServer.CreateValidJWT(userSub, nil)
	require.NoError(t, err)

	app1, cleanup1 := seedApp(t, store, jwksServer, userSub)
	defer cleanup1()

	app2, cleanup2 := seedApp(t, store, jwksServer, userSub)
	defer cleanup2()

	keyExec, err := keyexec.NewKMSExecutor(&keyexec.KMSConfig{
		Provider:          "local",
		LocalMasterKeyHex: "test-master-key-32-bytes-long!!",
	})
	require.NoError(t, err)

	policyEng := policy.NewEngine()
	walletService := app.NewWalletService(store, keyExec, policyEng)
	appAuth := middleware.NewAppAuthMiddleware(store)
	userAuth := middleware.NewAuthMiddleware()
	idempotency := middleware.NewIdempotencyMiddleware(storage.NewIdempotencyRepo(store))

	srv := &Server{
		config:                &config.Config{Port: 0},
		walletService:         walletService,
		appAuthMiddleware:     appAuth,
		userAuthMiddleware:    userAuth,
		idempotencyMiddleware: idempotency,
		store:                 store,
	}

	h := buildHandler(srv)
	testServer := httptest.NewServer(h)
	defer testServer.Close()

	healthResp, err := http.Get(testServer.URL + "/health")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, healthResp.StatusCode)

	walletBody := []byte(`{"chain_type":"ethereum"}`)
	createReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/wallets", bytes.NewReader(walletBody))
	require.NoError(t, err)
	addAppHeaders(createReq, app1.appID, app1.appSecret)
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)

	listReqNoJWT, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/wallets", nil)
	require.NoError(t, err)
	addAppHeaders(listReqNoJWT, app1.appID, app1.appSecret)
	listRespNoJWT, err := http.DefaultClient.Do(listReqNoJWT)
	require.NoError(t, err)
	require.Equal(t, http.StatusUnauthorized, listRespNoJWT.StatusCode)

	listReq, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/wallets", nil)
	require.NoError(t, err)
	addAppHeaders(listReq, app1.appID, app1.appSecret)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listResp.StatusCode)

	// Cross-tenant isolation: app2 should not see app1 wallets
	listReqApp2, err := http.NewRequest(http.MethodGet, testServer.URL+"/v1/wallets", nil)
	require.NoError(t, err)
	addAppHeaders(listReqApp2, app2.appID, app2.appSecret)
	listReqApp2.Header.Set("Authorization", "Bearer "+token)
	listRespApp2, err := http.DefaultClient.Do(listReqApp2)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, listRespApp2.StatusCode)

	var listBody struct {
		Data []map[string]interface{} `json:"data"`
	}
	_ = json.NewDecoder(listRespApp2.Body).Decode(&listBody)
	require.Len(t, listBody.Data, 0)
}

func buildHandler(s *Server) http.Handler {
	rootMux := http.NewServeMux()
	rootMux.HandleFunc("/health", s.handleHealth)

	v1Mux := http.NewServeMux()
	v1Mux.Handle("/v1/wallets", http.HandlerFunc(s.handleWallets))
	v1Mux.Handle("/v1/wallets/", http.HandlerFunc(s.handleWalletOperationsRouter))
	v1Mux.Handle("/v1/policies", http.HandlerFunc(s.handlePolicies))
	v1Mux.Handle("/v1/policies/", http.HandlerFunc(s.handlePolicyOperations))
	v1Mux.Handle("/v1/key-quorums", http.HandlerFunc(s.handleKeyQuorums))
	v1Mux.Handle("/v1/key-quorums/", http.HandlerFunc(s.handleKeyQuorumOperations))
	v1Mux.Handle("/v1/users", http.HandlerFunc(s.handleUsers))
	v1Mux.Handle("/v1/users/", http.HandlerFunc(s.handleUserOperations))
	v1Mux.Handle("/v1/transactions", http.HandlerFunc(s.handleTransactions))
	v1Mux.Handle("/v1/transactions/", http.HandlerFunc(s.handleTransactionOperations))
	v1Mux.Handle("/v1/authorization-keys", http.HandlerFunc(s.handleAuthorizationKeys))
	v1Mux.Handle("/v1/authorization-keys/", http.HandlerFunc(s.handleAuthorizationKeyOperations))
	v1Mux.Handle("/v1/condition_sets", http.HandlerFunc(s.handleConditionSets))
	v1Mux.Handle("/v1/condition_sets/", http.HandlerFunc(s.handleConditionSetOperations))

	v1Handler := s.appAuthMiddleware.Authenticate(
		s.userAuthMiddleware.Authenticate(
			s.requireUserMiddleware(
				s.idempotencyMiddleware.Handle(v1Mux),
			),
		),
	)
	rootMux.Handle("/v1/", v1Handler)

	return middleware.AuditContext(s.loggingMiddleware(rootMux))
}

func addAppHeaders(req *http.Request, appID uuid.UUID, appSecret string) {
	req.Header.Set("X-App-Id", appID.String())
	req.Header.Set("X-App-Secret", appSecret)
	req.Header.Set("Content-Type", "application/json")
}

func seedApp(t *testing.T, store *storage.Store, jwks *mocks.MockJWKSServer, userSub string) (seededApp, func()) {
	t.Helper()
	ctx := context.Background()

	dashboardID := "dash-" + uuid.New().String()
	walletUserID := uuid.New()
	appID := uuid.New()
	userID := uuid.New()
	appSecret := "bw_sk_" + uuid.New().String() + uuid.New().String()[:6]
	secretPrefix := appSecret[:14]
	hash, err := bcrypt.GenerateFromPassword([]byte(appSecret), bcrypt.DefaultCost)
	require.NoError(t, err)

	settings := types.AppSettings{
		Auth: &types.AppAuthSettings{
			Kind:     types.AuthKindOIDC,
			Issuer:   jwks.Issuer(),
			Audience: jwks.Audience(),
			JWKSURI:  jwks.JWKSURI(),
		},
	}
	settingsJSON, err := json.Marshal(settings)
	require.NoError(t, err)

	_, err = store.DB().Exec(ctx, `INSERT INTO "user" (id, name, email, email_verified, created_at, updated_at) VALUES ($1, $2, $3, $4, NOW(), NOW())`,
		dashboardID,
		"Test User",
		dashboardID+"@example.com",
		true,
	)
	require.NoError(t, err)

	_, err = store.DB().Exec(ctx, `INSERT INTO wallet_users (id, dashboard_user_id, created_at) VALUES ($1, $2, NOW())`,
		walletUserID,
		dashboardID,
	)
	require.NoError(t, err)

	_, err = store.DB().Exec(ctx, `INSERT INTO apps (id, name, description, owner_id, status, settings, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())`,
		appID,
		"Test App",
		"integration",
		walletUserID,
		"active",
		settingsJSON,
	)
	require.NoError(t, err)

	_, err = store.DB().Exec(ctx, `INSERT INTO app_secrets (id, app_id, secret_hash, secret_prefix, status, created_at) VALUES ($1, $2, $3, $4, $5, NOW())`,
		uuid.New(),
		appID,
		string(hash),
		secretPrefix,
		"active",
	)
	require.NoError(t, err)

	_, err = store.DB().Exec(ctx, `INSERT INTO users (id, external_sub, app_id, created_at) VALUES ($1, $2, $3, NOW())`,
		userID,
		userSub,
		appID,
	)
	require.NoError(t, err)

	cleanup := func() {
		_, _ = store.DB().Exec(ctx, `DELETE FROM wallet_shares WHERE wallet_id IN (SELECT id FROM wallets WHERE app_id = $1)`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM wallets WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM authorization_keys WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM key_quorums WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM policies WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM condition_sets WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM users WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM app_secrets WHERE app_id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM apps WHERE id = $1`, appID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM wallet_users WHERE id = $1`, walletUserID)
		_, _ = store.DB().Exec(ctx, `DELETE FROM "user" WHERE id = $1`, dashboardID)
	}

	return seededApp{
		appID:       appID,
		appSecret:   appSecret,
		userID:      userID,
		userSub:     userSub,
		dashboardID: dashboardID,
		walletUser:  walletUserID,
	}, cleanup
}
