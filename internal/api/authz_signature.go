package api

import (
	"net/http"

	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
)

func (s *Server) verifyAppAuthorizationSignature(r *http.Request) error {
	// Build canonical payload (RFC 8785)
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		return err
	}

	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		return apperrors.New(
			apperrors.ErrCodeUnauthorized,
			"No authorization signatures provided",
			http.StatusUnauthorized,
		)
	}

	appID, err := storage.RequireAppID(r.Context())
	if err != nil {
		return apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing app context",
			err.Error(),
			http.StatusUnauthorized,
		)
	}

	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	keys, err := authKeyRepo.GetActiveByAppID(r.Context(), appID)
	if err != nil {
		return apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to load authorization keys",
			err.Error(),
			http.StatusInternalServerError,
		)
	}
	if len(keys) == 0 {
		return apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"No authorization keys registered",
			"Register at least one P-256 authorization key for this app to sign privileged requests.",
			http.StatusForbidden,
		)
	}

	verifier := auth.NewSignatureVerifier()
	for _, sig := range signatures {
		for _, key := range keys {
			if key == nil || key.Status != types.StatusActive {
				continue
			}

			publicKeyPEM, err := auth.PublicKeyToPEM(key.PublicKey)
			if err != nil {
				continue
			}

			if verified, err := verifier.VerifySignature(sig, canonicalBytes, publicKeyPEM); err == nil && verified {
				return nil
			}
		}
	}

	return apperrors.New(
		apperrors.ErrCodeForbidden,
		"Authorization signature verification failed",
		http.StatusForbidden,
	)
}
