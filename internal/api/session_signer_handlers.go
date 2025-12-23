package api

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/google/uuid"
)

// CreateSessionSignerRequest API schema
type CreateSessionSignerRequest struct {
	SignerPublicKey  string     `json:"signer_public_key"`
	PolicyOverrideID *uuid.UUID `json:"policy_override_id,omitempty"`
	AllowedMethods   []string   `json:"allowed_methods,omitempty"`
	MaxValue         *string    `json:"max_value,omitempty"` // decimal string
	MaxTxs           *int       `json:"max_txs,omitempty"`
	TTLSeconds       int        `json:"ttl_seconds"`
}

type SessionSignerResponse struct {
	ID               string     `json:"id"`
	SignerPublicKey  string     `json:"signer_public_key"`
	PolicyOverrideID *uuid.UUID `json:"policy_override_id,omitempty"`
	AllowedMethods   []string   `json:"allowed_methods,omitempty"`
	MaxValue         *string    `json:"max_value,omitempty"`
	MaxTxs           *int       `json:"max_txs,omitempty"`
	TTLExpiresAt     time.Time  `json:"ttl_expires_at"`
	CreatedAt        time.Time  `json:"created_at"`
	RevokedAt        *time.Time `json:"revoked_at,omitempty"`
}

func (s *Server) handleCreateSessionSigner(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := middleware.GetUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req CreateSessionSignerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	if req.TTLSeconds <= 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid ttl_seconds",
			"Must be positive",
			http.StatusBadRequest,
		))
		return
	}

	// Create session signer (app-scoped by context automatically)
	ss, authKey, err := s.walletService.CreateSessionSigner(r.Context(), &app.CreateSessionSignerRequest{
		UserSub:          userSub,
		WalletID:         walletID,
		SignerPublicKey:  req.SignerPublicKey,
		PolicyOverrideID: req.PolicyOverrideID,
		AllowedMethods:   req.AllowedMethods,
		MaxValue:         stringToBigIntPtr(req.MaxValue),
		MaxTxs:           req.MaxTxs,
		TTL:              time.Duration(req.TTLSeconds) * time.Second,
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create session signer",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	resp := SessionSignerResponse{
		ID:               ss.ID.String(),
		SignerPublicKey:  hex.EncodeToString(authKey.PublicKey),
		PolicyOverrideID: ss.PolicyOverrideID,
		AllowedMethods:   ss.AllowedMethods,
		MaxValue:         ss.MaxValue,
		MaxTxs:           ss.MaxTxs,
		TTLExpiresAt:     ss.TTLExpiresAt,
		CreatedAt:        ss.CreatedAt,
		RevokedAt:        ss.RevokedAt,
	}

	s.writeJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleListSessionSigners(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := middleware.GetUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	signers, err := s.walletService.ListSessionSigners(r.Context(), userSub, walletID)
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list session signers",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	resp := make([]SessionSignerResponse, 0, len(signers))
	for _, item := range signers {
		resp = append(resp, SessionSignerResponse{
			ID:               item.Signer.ID.String(),
			SignerPublicKey:  hex.EncodeToString(item.PublicKey),
			PolicyOverrideID: item.Signer.PolicyOverrideID,
			AllowedMethods:   item.Signer.AllowedMethods,
			MaxValue:         item.Signer.MaxValue,
			MaxTxs:           item.Signer.MaxTxs,
			TTLExpiresAt:     item.Signer.TTLExpiresAt,
			CreatedAt:        item.Signer.CreatedAt,
			RevokedAt:        item.Signer.RevokedAt,
		})
	}

	s.writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleDeleteSessionSigner(w http.ResponseWriter, r *http.Request, walletID, signerID uuid.UUID) {
	userSub, ok := middleware.GetUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	if err := s.walletService.DeleteSessionSigner(r.Context(), userSub, walletID, signerID); err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to delete session signer",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func stringToBigIntPtr(s *string) *big.Int {
	if s == nil {
		return nil
	}
	bi, ok := new(big.Int).SetString(*s, 10)
	if !ok {
		return nil
	}
	return bi
}
