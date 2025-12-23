//go:build integration

package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/config"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/better-wallet/better-wallet/tests/mocks"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

func TestEndpointCoverage(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}

	store, err := storage.New(dsn)
	require.NoError(t, err)
	defer store.Close()

	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "coverage-audience")
	defer jwksServer.Close()

	_, err = jwksServer.AddRSAKey("coverage-key-1")
	require.NoError(t, err)

	userSub := "user-" + uuid.New().String()
	token, err := jwksServer.CreateValidJWT(userSub, nil)
	require.NoError(t, err)

	appSeed, cleanup := seedApp(t, store, jwksServer, userSub)
	defer cleanup()
	defer func() {
		_, _ = store.DB().Exec(context.Background(), `DELETE FROM transactions WHERE app_id = $1`, appSeed.appID)
	}()

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

	server := httptest.NewServer(buildHandler(srv))
	defer server.Close()

	appCtx := storage.WithAppID(context.Background(), appSeed.appID)

	ownerPrivKey, ownerPubKeyHex := generateP256KeyPairForCoverage(t)
	walletID := seedUserOwnedWalletForCoverage(t, appCtx, walletService, userSub, ownerPubKeyHex, uuid.Nil)
	walletDeleteID := seedUserOwnedWalletForCoverage(t, appCtx, walletService, userSub, ownerPubKeyHex, uuid.Nil)

	policyPrivKey, policyKeyID := createAuthKey(t, appCtx, store, userSub)
	quorumPrivKey1, quorumKeyID1 := createAuthKey(t, appCtx, store, userSub)
	_, quorumKeyID2 := createAuthKey(t, appCtx, store, userSub)

	t.Run("wallet_get_patch_delete", func(t *testing.T) {
		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/wallets/"+walletID.String(), nil, appSeed, token)
		resp := doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		patchBody, err := json.Marshal(map[string]interface{}{"policy_ids": []uuid.UUID{}})
		require.NoError(t, err)
		patchReq := newAuthedRequest(t, http.MethodPatch, server.URL+"/v1/wallets/"+walletID.String(), patchBody, appSeed, token)
		signRequest(t, patchReq, ownerPrivKey)
		resp = doRequest(t, patchReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		deleteReq := newAuthedRequest(t, http.MethodDelete, server.URL+"/v1/wallets/"+walletDeleteID.String(), nil, appSeed, token)
		signRequest(t, deleteReq, ownerPrivKey)
		resp = doRequest(t, deleteReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()
	})

	var policyID uuid.UUID
	t.Run("policies_create_list_get_update_delete", func(t *testing.T) {
		createBody := map[string]interface{}{
			"name":       "policy-allow-personal",
			"chain_type": types.ChainTypeEthereum,
			"owner_id":   policyKeyID.String(),
			"rules": []map[string]interface{}{
				{
					"name":       "allow personal_sign",
					"method":     "personal_sign",
					"conditions": []map[string]interface{}{},
					"action":     string(types.ActionAllow),
				},
			},
		}
		bodyBytes, err := json.Marshal(createBody)
		require.NoError(t, err)
		createReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/policies", bodyBytes, appSeed, token)
		signRequest(t, createReq, policyPrivKey)
		resp := doRequest(t, createReq)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var policyResp PolicyResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&policyResp))
		_ = resp.Body.Close()
		policyID = policyResp.ID

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/policies", nil, appSeed, token)
		resp = doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/policies/"+policyID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		updateBody := map[string]interface{}{"name": "policy-updated"}
		bodyBytes, err = json.Marshal(updateBody)
		require.NoError(t, err)
		patchReq := newAuthedRequest(t, http.MethodPatch, server.URL+"/v1/policies/"+policyID.String(), bodyBytes, appSeed, token)
		signRequest(t, patchReq, policyPrivKey)
		resp = doRequest(t, patchReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		deleteReq := newAuthedRequest(t, http.MethodDelete, server.URL+"/v1/policies/"+policyID.String(), nil, appSeed, token)
		signRequest(t, deleteReq, policyPrivKey)
		resp = doRequest(t, deleteReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("condition_sets_create_list_get_update_delete", func(t *testing.T) {
		createBody := map[string]interface{}{
			"name":        "condition-set-1",
			"description": "test",
			"owner_id":    policyKeyID.String(),
			"values":      []string{"0xabc"},
		}
		bodyBytes, err := json.Marshal(createBody)
		require.NoError(t, err)
		createReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/condition_sets", bodyBytes, appSeed, token)
		signRequest(t, createReq, policyPrivKey)
		resp := doRequest(t, createReq)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var csResp ConditionSetResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&csResp))
		_ = resp.Body.Close()

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/condition_sets", nil, appSeed, token)
		resp = doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/condition_sets/"+csResp.ID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		updateBody := map[string]interface{}{"description": "updated"}
		bodyBytes, err = json.Marshal(updateBody)
		require.NoError(t, err)
		patchReq := newAuthedRequest(t, http.MethodPatch, server.URL+"/v1/condition_sets/"+csResp.ID.String(), bodyBytes, appSeed, token)
		signRequest(t, patchReq, policyPrivKey)
		resp = doRequest(t, patchReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		deleteReq := newAuthedRequest(t, http.MethodDelete, server.URL+"/v1/condition_sets/"+csResp.ID.String(), nil, appSeed, token)
		signRequest(t, deleteReq, policyPrivKey)
		resp = doRequest(t, deleteReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("key_quorums_create_list_get_update_delete", func(t *testing.T) {
		createBody := map[string]interface{}{
			"threshold": 1,
			"key_ids":   []string{quorumKeyID1.String(), quorumKeyID2.String()},
		}
		bodyBytes, err := json.Marshal(createBody)
		require.NoError(t, err)
		createReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/key-quorums", bodyBytes, appSeed, token)
		signRequest(t, createReq, quorumPrivKey1)
		resp := doRequest(t, createReq)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var kqResp KeyQuorumResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&kqResp))
		_ = resp.Body.Close()

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/key-quorums", nil, appSeed, token)
		resp = doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/key-quorums/"+kqResp.ID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		updateBody := map[string]interface{}{"status": types.StatusInactive}
		bodyBytes, err = json.Marshal(updateBody)
		require.NoError(t, err)
		patchReq := newAuthedRequest(t, http.MethodPatch, server.URL+"/v1/key-quorums/"+kqResp.ID.String(), bodyBytes, appSeed, token)
		signRequest(t, patchReq, quorumPrivKey1)
		resp = doRequest(t, patchReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		deleteReq := newAuthedRequest(t, http.MethodDelete, server.URL+"/v1/key-quorums/"+kqResp.ID.String(), nil, appSeed, token)
		signRequest(t, deleteReq, quorumPrivKey1)
		resp = doRequest(t, deleteReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("authorization_keys_create_list_get_rotate_revoke", func(t *testing.T) {
		_, authPubHex := generateP256KeyPairForCoverage(t)
		createBody := map[string]interface{}{
			"public_key": authPubHex,
		}
		bodyBytes, err := json.Marshal(createBody)
		require.NoError(t, err)

		createReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/authorization-keys", bodyBytes, appSeed, token)
		resp := doRequest(t, createReq)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var keyResp AuthorizationKeyResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&keyResp))
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/authorization-keys/"+keyResp.ID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/authorization-keys", nil, appSeed, token)
		resp = doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		rotateReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/authorization-keys/"+keyResp.ID.String()+"/rotate", nil, appSeed, token)
		resp = doRequest(t, rotateReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		revokeReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/authorization-keys/"+keyResp.ID.String()+"/revoke", nil, appSeed, token)
		resp = doRequest(t, revokeReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()

	})

	t.Run("session_signers_create_list_delete", func(t *testing.T) {
		_, signerPubHex := generateP256KeyPairForCoverage(t)
		createBody := map[string]interface{}{
			"signer_public_key": signerPubHex,
			"allowed_methods":   []string{"sign_transaction"},
			"ttl_seconds":       3600,
		}
		bodyBytes, err := json.Marshal(createBody)
		require.NoError(t, err)

		createReq := newAuthedRequest(t, http.MethodPost, server.URL+"/v1/wallets/"+walletID.String()+"/session_signers", bodyBytes, appSeed, token)
		resp := doRequest(t, createReq)
		require.Equal(t, http.StatusCreated, resp.StatusCode)
		var sessionResp SessionSignerResponse
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&sessionResp))
		_ = resp.Body.Close()

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/wallets/"+walletID.String()+"/session_signers", nil, appSeed, token)
		resp = doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		deleteReq := newAuthedRequest(t, http.MethodDelete, server.URL+"/v1/wallets/"+walletID.String()+"/session_signers/"+sessionResp.ID, nil, appSeed, token)
		resp = doRequest(t, deleteReq)
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		_ = resp.Body.Close()

	})

	t.Run("users_list_get", func(t *testing.T) {
		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/users", nil, appSeed, token)
		resp := doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/users/"+appSeed.userID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	})

	t.Run("transactions_list_get", func(t *testing.T) {
		txRepo := storage.NewTransactionRepository(store)
		toAddr := "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
		value := "1000"
		txID := uuid.New()
		tx := &storage.Transaction{
			ID:        txID,
			WalletID:  walletID,
			ChainID:   1,
			Status:    "submitted",
			Method:    "eth_sendTransaction",
			ToAddress: &toAddr,
			Value:     &value,
		}
		require.NoError(t, txRepo.Create(appCtx, tx))

		listReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/transactions?wallet_id="+walletID.String(), nil, appSeed, token)
		resp := doRequest(t, listReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()

		getReq := newAuthedRequest(t, http.MethodGet, server.URL+"/v1/transactions/"+txID.String(), nil, appSeed, token)
		resp = doRequest(t, getReq)
		require.Equal(t, http.StatusOK, resp.StatusCode)
		_ = resp.Body.Close()
	})
}

func newAuthedRequest(t *testing.T, method, url string, body []byte, appSeed seededApp, token string) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-App-Id", appSeed.appID.String())
	req.Header.Set("X-App-Secret", appSeed.appSecret)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if method == http.MethodPost || method == http.MethodPatch || method == http.MethodDelete {
		req.Header.Set("X-Idempotency-Key", uuid.New().String())
	}
	return req
}

func signRequest(t *testing.T, req *http.Request, privKey *ecdsa.PrivateKey) {
	t.Helper()
	if req.Body == nil {
		req.Body = io.NopCloser(bytes.NewReader(nil))
	}
	_, canonical, err := auth.BuildCanonicalPayload(req)
	require.NoError(t, err)

	hash := sha256.Sum256(canonical)
	sigBytes, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	req.Header.Set("X-Authorization-Signature", base64.StdEncoding.EncodeToString(sigBytes))
}

func doRequest(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	require.NoError(t, err)
	return resp
}

func createAuthKey(t *testing.T, ctx context.Context, store *storage.Store, ownerEntity string) (*ecdsa.PrivateKey, uuid.UUID) {
	t.Helper()
	privKey, pubHex := generateP256KeyPairForCoverage(t)
	publicKeyBytes, err := hex.DecodeString(pubHex[2:])
	require.NoError(t, err)

	key := &types.AuthorizationKey{
		ID:          uuid.New(),
		PublicKey:   publicKeyBytes,
		Algorithm:   types.AlgorithmP256,
		OwnerEntity: ownerEntity,
		Status:      types.StatusActive,
	}
	repo := storage.NewAuthorizationKeyRepository(store)
	require.NoError(t, repo.Create(ctx, key))

	return privKey, key.ID
}

func seedUserOwnedWalletForCoverage(t *testing.T, ctx context.Context, walletService *app.WalletService, userSub, ownerPublicKeyHex string, policyID uuid.UUID) uuid.UUID {
	t.Helper()
	policyIDs := []uuid.UUID{}
	if policyID != uuid.Nil {
		policyIDs = []uuid.UUID{policyID}
	}
	resp, err := walletService.CreateWallet(ctx, &app.CreateWalletRequest{
		UserSub:        userSub,
		ChainType:      types.ChainTypeEthereum,
		OwnerPublicKey: ownerPublicKeyHex,
		OwnerAlgorithm: types.AlgorithmP256,
		ExecBackend:    types.ExecBackendKMS,
		PolicyIDs:      policyIDs,
	})
	require.NoError(t, err)
	return resp.Wallet.ID
}

func generateP256KeyPairForCoverage(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	return privKey, "0x" + hex.EncodeToString(pubBytes)
}
