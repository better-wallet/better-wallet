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
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/auth"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/better-wallet/better-wallet/tests/mocks"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type mockWalletService struct {
	CreateWalletFn func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error)
	GetOwnerFn     func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error)
	SignTxFn       func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error)
	SignMsgFn      func(ctx context.Context, userSub string, req *app.SignMessageRequest) (string, error)
}

var errNotImplemented = errors.New("not implemented")

func (m *mockWalletService) CreateWallet(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
	return m.CreateWalletFn(ctx, req)
}
func (m *mockWalletService) GetWallet(ctx context.Context, walletID uuid.UUID, userSub string) (*types.Wallet, error) {
	return nil, errNotImplemented
}
func (m *mockWalletService) ListWallets(ctx context.Context, req *app.ListWalletsRequest) ([]*types.Wallet, *string, error) {
	return nil, nil, errNotImplemented
}
func (m *mockWalletService) UpdateWallet(ctx context.Context, req *app.UpdateWalletRequest) (*types.Wallet, error) {
	return nil, errNotImplemented
}
func (m *mockWalletService) DeleteWallet(ctx context.Context, walletID uuid.UUID, userSub string) error {
	return errNotImplemented
}
func (m *mockWalletService) SignTransaction(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
	return m.SignTxFn(ctx, userSub, req)
}
func (m *mockWalletService) SignMessage(ctx context.Context, userSub string, req *app.SignMessageRequest) (string, error) {
	if m.SignMsgFn == nil {
		return "", errNotImplemented
	}
	return m.SignMsgFn(ctx, userSub, req)
}
func (m *mockWalletService) SignTypedData(ctx context.Context, userSub string, req *app.SignTypedDataRequest) (string, error) {
	return "", errNotImplemented
}
func (m *mockWalletService) GetOwner(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
	return m.GetOwnerFn(ctx, ownerID)
}
func (m *mockWalletService) ExportWallet(ctx context.Context, userSub string, req *app.ExportWalletRequest) ([]byte, error) {
	return nil, errNotImplemented
}
func (m *mockWalletService) CreateSessionSigner(ctx context.Context, req *app.CreateSessionSignerRequest) (*types.SessionSigner, *types.AuthorizationKey, error) {
	return nil, nil, errNotImplemented
}
func (m *mockWalletService) ListSessionSigners(ctx context.Context, userSub string, walletID uuid.UUID) ([]app.SessionSignerWithKey, error) {
	return nil, errNotImplemented
}
func (m *mockWalletService) DeleteSessionSigner(ctx context.Context, userSub string, walletID, signerID uuid.UUID) error {
	return errNotImplemented
}

func signCanonical(t *testing.T, priv *ecdsa.PrivateKey, canonical []byte) string {
	t.Helper()
	digest := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(sig)
}

func TestHandleCreateWallet_NewOwnerRequiresValidSignature(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ecdhPub, err := priv.PublicKey.ECDH()
	require.NoError(t, err)
	pubBytes := ecdhPub.Bytes()
	pubHex := "0x" + hex.EncodeToString(pubBytes)

	now := time.Unix(1734000000, 0).UTC()
	createdWallet := &types.Wallet{
		ID:        uuid.New(),
		Address:   "0x1111111111111111111111111111111111111111",
		ChainType: types.ChainTypeEthereum,
		CreatedAt: now,
	}

	var gotCreate *app.CreateWalletRequest
	svc := &mockWalletService{
		CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
			gotCreate = req
			return &app.CreateWalletResponse{Wallet: createdWallet}, nil
		},
		GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
			return nil, errNotImplemented
		},
		SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
			return nil, errNotImplemented
		},
	}

	server := &Server{walletService: svc}

	body := map[string]any{
		"chain_type": "ethereum",
		"owner": map[string]any{
			"public_key": pubHex,
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets", bytes.NewReader(bodyBytes))
	req.Header.Set("x-app-id", uuid.New().String())
	req.Header.Set("x-idempotency-key", "idem-123")

	_, canonical, err := auth.BuildCanonicalPayload(req)
	require.NoError(t, err)
	req.Header.Set("x-authorization-signature", signCanonical(t, priv, canonical))

	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleCreateWallet(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotNil(t, gotCreate)
	require.Equal(t, "user-123", gotCreate.UserSub)
	require.Equal(t, pubHex, gotCreate.OwnerPublicKey)
}

func TestHandleCreateWallet_NewOwnerMissingSignatureRejected(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	_ = priv

	body := map[string]any{
		"chain_type": "ethereum",
		"owner": map[string]any{
			"public_key": "0x" + hex.EncodeToString([]byte("not-a-real-pubkey")),
		},
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	called := false
	server := &Server{
		walletService: &mockWalletService{
			CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
				called = true
				return nil, nil
			},
			GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
				return nil, errNotImplemented
			},
			SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
				return nil, errNotImplemented
			},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets", bytes.NewReader(bodyBytes))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleCreateWallet(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
	require.False(t, called, "CreateWallet should not be called when signature is missing/invalid")
}

func TestHandleCreateWallet_AppManagedDoesNotRequireUserOrSignature(t *testing.T) {
	now := time.Unix(1734000000, 0).UTC()
	createdWallet := &types.Wallet{
		ID:        uuid.New(),
		Address:   "0x2222222222222222222222222222222222222222",
		ChainType: types.ChainTypeEthereum,
		CreatedAt: now,
	}

	var gotCreate *app.CreateWalletRequest
	server := &Server{
		walletService: &mockWalletService{
			CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
				gotCreate = req
				return &app.CreateWalletResponse{Wallet: createdWallet}, nil
			},
			GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
				return nil, errNotImplemented
			},
			SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
				return nil, errNotImplemented
			},
		},
	}

	bodyBytes, err := json.Marshal(map[string]any{
		"chain_type": "ethereum",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()

	server.handleCreateWallet(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)
	require.NotNil(t, gotCreate)
	require.Empty(t, gotCreate.UserSub)
	require.Empty(t, gotCreate.OwnerPublicKey)
	require.Nil(t, gotCreate.OwnerID)
}

func TestHandleSignTransaction_ParsesFieldsAndReturnsSignedTx(t *testing.T) {
	walletID := uuid.New()

	var gotReq *app.SignTransactionRequest
	svc := &mockWalletService{
		CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
			return nil, errNotImplemented
		},
		GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
			return nil, errNotImplemented
		},
		SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
			gotReq = req
			tx := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
				ChainID:   big.NewInt(req.ChainID),
				Nonce:     req.Nonce,
				GasTipCap: req.GasTipCap,
				GasFeeCap: req.GasFeeCap,
				Gas:       req.GasLimit,
				To:        nil,
				Value:     req.Value,
				Data:      req.Data,
			})
			return tx, nil
		},
	}
	server := &Server{walletService: svc}

	bodyBytes, err := json.Marshal(map[string]any{
		"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"value":       "1000",
		"data":        "0xa9059cbb",
		"chain_id":    1,
		"nonce":       7,
		"gas_limit":   21000,
		"gas_fee_cap": "20000000000",
		"gas_tip_cap": "1000000000",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/"+walletID.String()+"/sign", bytes.NewReader(bodyBytes))
	req.Header.Set("x-app-id", "app-123")
	req.Header.Set("x-idempotency-key", "idem-abc")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleSignTransaction(rec, req, walletID)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, gotReq)
	require.Equal(t, walletID, gotReq.WalletID)
	require.Equal(t, "eth_signTransaction", gotReq.Method)
	require.Equal(t, "idem-abc", gotReq.IdempotencyKey)
	require.Equal(t, "app-123", gotReq.AppID)
	require.NotEmpty(t, gotReq.CanonicalPayload)
}

func TestHandleSignTransaction_InvalidValueRejected(t *testing.T) {
	walletID := uuid.New()
	called := false

	server := &Server{
		walletService: &mockWalletService{
			CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
				return nil, errNotImplemented
			},
			GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
				return nil, errNotImplemented
			},
			SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
				called = true
				return nil, nil
			},
		},
	}

	bodyBytes, err := json.Marshal(map[string]any{
		"to":          "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
		"value":       "not-a-number",
		"chain_id":    1,
		"nonce":       0,
		"gas_limit":   21000,
		"gas_fee_cap": "1",
		"gas_tip_cap": "1",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/"+walletID.String()+"/sign", bytes.NewReader(bodyBytes))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleSignTransaction(rec, req, walletID)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.False(t, called)
}

func TestHandleSignMessage_SuccessPassesCanonicalAndSignatures(t *testing.T) {
	walletID := uuid.New()

	var gotReq *app.SignMessageRequest
	server := &Server{
		walletService: &mockWalletService{
			CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
				return nil, errNotImplemented
			},
			GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
				return nil, errNotImplemented
			},
			SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
				return nil, errNotImplemented
			},
			SignMsgFn: func(ctx context.Context, userSub string, req *app.SignMessageRequest) (string, error) {
				gotReq = req
				return "0xdeadbeef", nil
			},
		},
	}

	bodyBytes, err := json.Marshal(map[string]any{
		"message":  "hello",
		"encoding": "utf8",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/"+walletID.String()+"/sign-message", bytes.NewReader(bodyBytes))
	req.Header.Set("x-app-id", "app-123")
	req.Header.Set("x-idempotency-key", "idem-xyz")
	req.Header.Set("x-authorization-signature", "sig1,sig2")
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleSignMessage(rec, req, walletID)

	require.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, gotReq)
	require.Equal(t, walletID, gotReq.WalletID)
	require.Equal(t, "hello", gotReq.Message)
	require.Equal(t, "utf8", gotReq.Encoding)
	require.Len(t, gotReq.Signatures, 2)
	require.NotEmpty(t, gotReq.CanonicalPayload)
}

func TestHandleSignMessage_InvalidEncodingRejected(t *testing.T) {
	walletID := uuid.New()
	called := false

	server := &Server{
		walletService: &mockWalletService{
			CreateWalletFn: func(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error) {
				return nil, errNotImplemented
			},
			GetOwnerFn: func(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
				return nil, errNotImplemented
			},
			SignTxFn: func(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error) {
				return nil, errNotImplemented
			},
			SignMsgFn: func(ctx context.Context, userSub string, req *app.SignMessageRequest) (string, error) {
				called = true
				return "", nil
			},
		},
	}

	bodyBytes, err := json.Marshal(map[string]any{
		"message":  "hello",
		"encoding": "base64",
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/"+walletID.String()+"/sign-message", bytes.NewReader(bodyBytes))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	rec := httptest.NewRecorder()

	server.handleSignMessage(rec, req, walletID)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	require.False(t, called)
}

func TestHandleWalletsAuthenticate_UserJWTMismatchRejected(t *testing.T) {
	jwksServer := mocks.NewMockJWKSServer("https://issuer.example.com", "test-audience")
	defer jwksServer.Close()

	_, err := jwksServer.AddRSAKey("test-key-1")
	require.NoError(t, err)

	token, err := jwksServer.CreateValidJWT("user-other", nil)
	require.NoError(t, err)

	server := &Server{userAuthMiddleware: middleware.NewAuthMiddleware()}

	app := &types.App{
		Settings: types.AppSettings{
			Auth: &types.AppAuthSettings{
				Kind:     types.AuthKindOIDC,
				Issuer:   jwksServer.Issuer(),
				Audience: jwksServer.Audience(),
				JWKSURI:  jwksServer.JWKSURI(),
			},
		},
	}

	body := map[string]any{
		"user_jwt": token,
	}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/authenticate", bytes.NewReader(bodyBytes))
	req = req.WithContext(context.WithValue(req.Context(), middleware.UserSubKey, "user-123"))
	req = req.WithContext(context.WithValue(req.Context(), middleware.AppKey, app))
	rec := httptest.NewRecorder()

	server.handleWalletsAuthenticate(rec, req)

	require.Equal(t, http.StatusForbidden, rec.Code)
}
