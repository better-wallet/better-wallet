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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"sync"
	"sync/atomic"
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

func TestPerfBaseline(t *testing.T) {
	dsn := os.Getenv("POSTGRES_DSN")
	if dsn == "" {
		t.Skip("POSTGRES_DSN not set")
	}

	store, err := storage.New(dsn)
	require.NoError(t, err)
	defer store.Close()

	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err = jwksServer.AddRSAKey("perf-key-1")
	require.NoError(t, err)

	userSub := "user-" + uuid.New().String()
	token, err := jwksServer.CreateValidJWT(userSub, nil)
	require.NoError(t, err)

	appSeed, cleanup := seedApp(t, store, jwksServer, userSub)
	defer cleanup()

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

	// Create one app-managed wallet so list endpoint has data.
	walletBody := []byte(`{"chain_type":"ethereum"}`)
	createReq, err := http.NewRequest(http.MethodPost, testServer.URL+"/v1/wallets", bytes.NewReader(walletBody))
	require.NoError(t, err)
	addAppHeaders(createReq, appSeed.appID, appSeed.appSecret)
	createResp, err := http.DefaultClient.Do(createReq)
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, createResp.StatusCode)
	_ = createResp.Body.Close()

	appCtx := storage.WithAppID(context.Background(), appSeed.appID)
	policyID := seedAllowPersonalSignPolicy(t, appCtx, store)
	ownerPrivKey, ownerPubKeyHex := generateP256KeyPair(t)
	ownedWalletID := seedUserOwnedWallet(t, appCtx, walletService, userSub, ownerPubKeyHex, policyID)

	// Use RPC endpoint with eth_signTypedData_v4 for signing perf test
	signBody := []byte(`{"method":"eth_signTypedData_v4","params":{"typed_data":{"types":{"EIP712Domain":[{"name":"name","type":"string"}],"Message":[{"name":"content","type":"string"}]},"primary_type":"Message","domain":{"name":"PerfTest"},"message":{"content":"perf smoke"}}}}`)
	signURL := testServer.URL + "/v1/wallets/" + ownedWalletID.String() + "/rpc"
	canonicalReq, err := http.NewRequest(http.MethodPost, signURL, bytes.NewReader(signBody))
	require.NoError(t, err)
	addAppHeaders(canonicalReq, appSeed.appID, appSeed.appSecret)
	canonicalReq.Header.Set("Authorization", "Bearer "+token)
	_, canonicalPayload, err := auth.BuildCanonicalPayload(canonicalReq)
	require.NoError(t, err)
	signature := signPerfCanonicalPayload(t, ownerPrivKey, canonicalPayload)

	client := &http.Client{Timeout: 5 * time.Second}

	measure := func(name, method, url string, body []byte, headers func(*http.Request), expectedStatuses ...int) {
		const total = 200
		durations := make([]time.Duration, total)
		var statusFailures int64
		wg := sync.WaitGroup{}
		wg.Add(total)
		for i := 0; i < total; i++ {
			go func(idx int) {
				defer wg.Done()
				start := time.Now()
				var bodyReader io.Reader
				if body != nil {
					bodyReader = bytes.NewReader(body)
				}
				req, err := http.NewRequest(method, url, bodyReader)
				if err != nil {
					durations[idx] = time.Since(start)
					return
				}
				if headers != nil {
					headers(req)
				}
				resp, err := client.Do(req)
				if err == nil {
					if len(expectedStatuses) > 0 {
						match := false
						for _, status := range expectedStatuses {
							if resp.StatusCode == status {
								match = true
								break
							}
						}
						if !match {
							atomic.AddInt64(&statusFailures, 1)
						}
					}
					_ = resp.Body.Close()
				}
				durations[idx] = time.Since(start)
			}(i)
		}
		wg.Wait()

		if statusFailures > 0 {
			t.Fatalf("perf %s had %d unexpected status responses", name, statusFailures)
		}

		sort.Slice(durations, func(i, j int) bool { return durations[i] < durations[j] })
		p95 := durations[int(float64(total)*0.95)-1]
		p99 := durations[int(float64(total)*0.99)-1]
		t.Logf("perf %s p95=%s p99=%s", name, p95, p99)

		// Fail only on extreme regressions.
		if p99 > 5*time.Second {
			t.Fatalf("perf regression: %s p99=%s", name, p99)
		}
	}

	measure("health", http.MethodGet, testServer.URL+"/health", nil, nil, http.StatusOK)
	measure("list-wallets", http.MethodGet, testServer.URL+"/v1/wallets", nil, func(req *http.Request) {
		addAppHeaders(req, appSeed.appID, appSeed.appSecret)
		req.Header.Set("Authorization", "Bearer "+token)
	}, http.StatusOK)
	measure("sign-typed-data", http.MethodPost, signURL, signBody, func(req *http.Request) {
		addAppHeaders(req, appSeed.appID, appSeed.appSecret)
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("X-Authorization-Signature", signature)
	}, http.StatusOK)
}

func seedAllowPersonalSignPolicy(t *testing.T, ctx context.Context, store *storage.Store) uuid.UUID {
	t.Helper()

	policyRepo := storage.NewPolicyRepository(store)
	policyEngine := policy.NewEngine()
	policyID := uuid.New()
	perfPolicy := &types.Policy{
		ID:        policyID,
		Name:      "perf-allow-personal-sign",
		ChainType: types.ChainTypeEthereum,
		Version:   types.PolicyVersion,
		Rules: map[string]interface{}{
			"rules": []interface{}{
				map[string]interface{}{
					"name":       "allow personal_sign",
					"method":     "personal_sign",
					"conditions": []interface{}{},
					"action":     string(types.ActionAllow),
				},
			},
		},
	}

	require.NoError(t, policyEngine.ValidatePolicy(perfPolicy))
	require.NoError(t, policyRepo.Create(ctx, perfPolicy))

	return policyID
}

func seedUserOwnedWallet(t *testing.T, ctx context.Context, walletService *app.WalletService, userSub, ownerPublicKeyHex string, policyID uuid.UUID) uuid.UUID {
	t.Helper()

	resp, err := walletService.CreateWallet(ctx, &app.CreateWalletRequest{
		UserSub:        userSub,
		ChainType:      types.ChainTypeEthereum,
		OwnerPublicKey: ownerPublicKeyHex,
		OwnerAlgorithm: types.AlgorithmP256,
		ExecBackend:    types.ExecBackendKMS,
		PolicyIDs:      []uuid.UUID{policyID},
	})
	require.NoError(t, err)

	return resp.Wallet.ID
}

func generateP256KeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	t.Helper()

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	pubBytes := elliptic.Marshal(elliptic.P256(), privKey.PublicKey.X, privKey.PublicKey.Y)
	return privKey, "0x" + hex.EncodeToString(pubBytes)
}

func signPerfCanonicalPayload(t *testing.T, privKey *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()

	hash := sha256.Sum256(payload)
	signature, err := ecdsa.SignASN1(rand.Reader, privKey, hash[:])
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(signature)
}
