package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

type fakeAuthKeyStore struct {
	keysByApp map[uuid.UUID][]*types.AuthorizationKey
	keys      []*types.AuthorizationKey
	err       error
	lastAppID uuid.UUID
}

func (f *fakeAuthKeyStore) GetActiveByAppID(ctx context.Context, appID uuid.UUID) ([]*types.AuthorizationKey, error) {
	f.lastAppID = appID
	if f.keysByApp != nil {
		return f.keysByApp[appID], f.err
	}
	return f.keys, f.err
}

func signCanonicalPayload(t *testing.T, req *http.Request, priv *ecdsa.PrivateKey) string {
	t.Helper()

	_, canonical, err := auth.BuildCanonicalPayload(req)
	require.NoError(t, err)

	hash := sha256.Sum256(canonical)
	sig, err := ecdsa.SignASN1(rand.Reader, priv, hash[:])
	require.NoError(t, err)

	return base64.StdEncoding.EncodeToString(sig)
}

func TestVerifyAppAuthorizationSignature(t *testing.T) {
	appID := uuid.New()
	body := map[string]any{"action": "test"}
	bodyBytes, err := json.Marshal(body)
	require.NoError(t, err)

	newRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/wallets/"+uuid.New().String()+"/rpc", bytes.NewReader(bodyBytes))
		req.Header.Set("x-app-id", appID.String())
		req.Header.Set("x-idempotency-key", "idem-123")
		return req
	}

	t.Run("missing_signature", func(t *testing.T) {
		req := newRequest()
		req = req.WithContext(storage.WithAppID(req.Context(), appID))

		s := &Server{authKeyStore: &fakeAuthKeyStore{keys: []*types.AuthorizationKey{}}}
		err := s.verifyAppAuthorizationSignature(req)
		appErr, ok := apperrors.IsAppError(err)
		require.True(t, ok)
		require.Equal(t, http.StatusUnauthorized, appErr.StatusCode)
	})

	t.Run("missing_app_context", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		req := newRequest()
		req.Header.Set("x-authorization-signature", signCanonicalPayload(t, req, priv))

		s := &Server{authKeyStore: &fakeAuthKeyStore{keys: []*types.AuthorizationKey{}}}
		err = s.verifyAppAuthorizationSignature(req)
		appErr, ok := apperrors.IsAppError(err)
		require.True(t, ok)
		require.Equal(t, http.StatusUnauthorized, appErr.StatusCode)
	})

	t.Run("no_active_keys", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		req := newRequest()
		req.Header.Set("x-authorization-signature", signCanonicalPayload(t, req, priv))
		req = req.WithContext(storage.WithAppID(req.Context(), appID))

		s := &Server{authKeyStore: &fakeAuthKeyStore{keys: []*types.AuthorizationKey{}}}
		err = s.verifyAppAuthorizationSignature(req)
		appErr, ok := apperrors.IsAppError(err)
		require.True(t, ok)
		require.Equal(t, http.StatusForbidden, appErr.StatusCode)
	})

	t.Run("invalid_signature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecdhPub, err := priv.PublicKey.ECDH()
		require.NoError(t, err)
		publicKey := ecdhPub.Bytes()

		req := newRequest()
		req.Header.Set("x-authorization-signature", signCanonicalPayload(t, req, otherPriv))
		req = req.WithContext(storage.WithAppID(req.Context(), appID))

		s := &Server{authKeyStore: &fakeAuthKeyStore{keys: []*types.AuthorizationKey{
			{
				ID:        uuid.New(),
				PublicKey: publicKey,
				Algorithm: types.AlgorithmP256,
				Status:    types.StatusActive,
				AppID:     &appID,
			},
		}}}

		err = s.verifyAppAuthorizationSignature(req)
		appErr, ok := apperrors.IsAppError(err)
		require.True(t, ok)
		require.Equal(t, http.StatusForbidden, appErr.StatusCode)
	})

	t.Run("valid_signature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecdhPub, err := priv.PublicKey.ECDH()
		require.NoError(t, err)
		publicKey := ecdhPub.Bytes()

		req := newRequest()
		req.Header.Set("x-authorization-signature", signCanonicalPayload(t, req, priv))
		req = req.WithContext(storage.WithAppID(req.Context(), appID))

		s := &Server{authKeyStore: &fakeAuthKeyStore{keys: []*types.AuthorizationKey{
			{
				ID:        uuid.New(),
				PublicKey: publicKey,
				Algorithm: types.AlgorithmP256,
				Status:    types.StatusActive,
				AppID:     &appID,
			},
		}}}

		err = s.verifyAppAuthorizationSignature(req)
		require.NoError(t, err)
	})

	t.Run("signature_rejected_for_different_app", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		ecdhPub, err := priv.PublicKey.ECDH()
		require.NoError(t, err)
		publicKey := ecdhPub.Bytes()

		appA := uuid.New()
		appB := uuid.New()

		req := newRequest()
		req.Header.Set("x-authorization-signature", signCanonicalPayload(t, req, priv))
		req = req.WithContext(storage.WithAppID(req.Context(), appB))

		store := &fakeAuthKeyStore{
			keysByApp: map[uuid.UUID][]*types.AuthorizationKey{
				appA: {
					{
						ID:        uuid.New(),
						PublicKey: publicKey,
						Algorithm: types.AlgorithmP256,
						Status:    types.StatusActive,
						AppID:     &appA,
					},
				},
			},
		}
		s := &Server{authKeyStore: store}

		err = s.verifyAppAuthorizationSignature(req)
		appErr, ok := apperrors.IsAppError(err)
		require.True(t, ok)
		require.Equal(t, http.StatusForbidden, appErr.StatusCode)
		require.Equal(t, appB, store.lastAppID)
	})
}
