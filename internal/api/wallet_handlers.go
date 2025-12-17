package api

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// WalletResponse represents a wallet in API responses
type WalletResponse struct {
	ID                uuid.UUID          `json:"id"`
	Address           string             `json:"address"`
	PublicKey         string             `json:"public_key,omitempty"`
	ChainType         string             `json:"chain_type"`
	PolicyIDs         []uuid.UUID        `json:"policy_ids"`
	OwnerID           *uuid.UUID         `json:"owner_id,omitempty"`
	AdditionalSigners []AdditionalSigner `json:"additional_signers"`
	CreatedAt         int64              `json:"created_at"` // Unix timestamp in milliseconds
	ExportedAt        *int64             `json:"exported_at,omitempty"`
	ImportedAt        *int64             `json:"imported_at,omitempty"`
}

// AdditionalSigner represents a session signer on a wallet
type AdditionalSigner struct {
	SignerID          uuid.UUID   `json:"signer_id"`
	OverridePolicyIDs []uuid.UUID `json:"override_policy_ids,omitempty"`
}

// CreateWalletRequest represents the wallet creation request
type CreateWalletRequest struct {
	ChainType         string             `json:"chain_type"`
	PolicyIDs         []uuid.UUID        `json:"policy_ids,omitempty"`
	Owner             *OwnerInput        `json:"owner,omitempty"`
	OwnerID           *uuid.UUID         `json:"owner_id,omitempty"`
	AdditionalSigners []AdditionalSigner `json:"additional_signers,omitempty"`
	RecoveryMethod    string             `json:"recovery_method,omitempty"`    // password, cloud_backup, passkey
	RecoveryHint      string             `json:"recovery_hint,omitempty"`      // Optional hint for password recovery
}

// OwnerInput for creating a new owner
type OwnerInput struct {
	PublicKey string     `json:"public_key,omitempty"`
	UserID    *uuid.UUID `json:"user_id,omitempty"`
}

// UpdateWalletRequest for updating wallet configuration
type UpdateWalletRequest struct {
	PolicyIDs         *[]uuid.UUID        `json:"policy_ids,omitempty"`
	OwnerID           *uuid.UUID          `json:"owner_id,omitempty"`
	Owner             *OwnerInput         `json:"owner,omitempty"`
	AdditionalSigners *[]AdditionalSigner `json:"additional_signers,omitempty"`
}

// ListWalletsResponse for paginated wallet listing
type ListWalletsResponse struct {
	Data       []WalletResponse `json:"data"`
	NextCursor *string          `json:"next_cursor,omitempty"`
}

// SignTransactionRequest represents the API request to sign a transaction
type SignTransactionRequest struct {
	To        string `json:"to"`
	Value     string `json:"value"`
	Data      string `json:"data,omitempty"`
	ChainID   int64  `json:"chain_id"`
	Nonce     uint64 `json:"nonce"`
	GasLimit  uint64 `json:"gas_limit"`
	GasFeeCap string `json:"gas_fee_cap"`
	GasTipCap string `json:"gas_tip_cap"`
}

// SignTransactionResponse represents the API response for transaction signing
type SignTransactionResponse struct {
	TxHash   string `json:"tx_hash"`
	SignedTx string `json:"signed_tx"`
}

// SignMessageAPIRequest represents the API request to sign a personal message
type SignMessageAPIRequest struct {
	Message  string `json:"message"`           // The message to sign
	Encoding string `json:"encoding,omitempty"` // "utf8" (default) or "hex"
}

// SignMessageResponse represents the API response for message signing
type SignMessageResponse struct {
	Signature string `json:"signature"` // 0x-prefixed hex signature
}

// handleWallets handles wallet list and creation
func (s *Server) handleWallets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListWallets(w, r)
	case http.MethodPost:
		s.handleCreateWallet(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleWalletOperationsRouter routes wallet operations to appropriate handlers
func (s *Server) handleWalletOperationsRouter(w http.ResponseWriter, r *http.Request) {
	// Extract path from /v1/wallets/...
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/wallets/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	// Handle global /v1/wallets/authenticate endpoint
	if pathParts[0] == "authenticate" && r.Method == http.MethodPost {
		s.handleWalletsAuthenticate(w, r)
		return
	}

	// Otherwise, expect a wallet ID
	walletID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid wallet ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Single wallet operations
	if len(pathParts) == 1 {
		switch r.Method {
		case http.MethodGet:
			s.handleGetWallet(w, r, walletID)
			return
		case http.MethodPatch:
			s.handleUpdateWallet(w, r, walletID)
			return
		case http.MethodDelete:
			s.handleDeleteWallet(w, r, walletID)
			return
		}
	}

	// Sub-resource operations
	if len(pathParts) >= 2 {
		switch pathParts[1] {
		case "rpc":
			if r.Method == http.MethodPost {
				s.handleRPC(w, r, walletID)
				return
			}
		case "sign":
			if r.Method == http.MethodPost {
				s.handleSignTransaction(w, r, walletID)
				return
			}
		case "sign-message":
			if r.Method == http.MethodPost {
				s.handleSignMessage(w, r, walletID)
				return
			}
		case "session_signers":
			if r.Method == http.MethodPost && len(pathParts) == 2 {
				s.handleCreateSessionSigner(w, r, walletID)
				return
			}
			if r.Method == http.MethodGet && len(pathParts) == 2 {
				s.handleListSessionSigners(w, r, walletID)
				return
			}
			if r.Method == http.MethodDelete && len(pathParts) == 3 {
				signerID, err := uuid.Parse(pathParts[2])
				if err != nil {
					s.writeError(w, apperrors.NewWithDetail(
						apperrors.ErrCodeBadRequest,
						"Invalid session signer ID",
						err.Error(),
						http.StatusBadRequest,
					))
					return
				}
				s.handleDeleteSessionSigner(w, r, walletID, signerID)
				return
			}
		case "export":
			if r.Method == http.MethodPost {
				s.handleExportWallet(w, r, walletID)
				return
			}
		case "authenticate":
			if r.Method == http.MethodPost {
				s.handleAuthenticateWallet(w, r, walletID)
				return
			}
		}
	}

	s.writeError(w, apperrors.ErrNotFound)
}

// handleGetWallet retrieves a single wallet by ID
func (s *Server) handleGetWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.writeError(w, apperrors.WalletNotFound(walletID.String()))
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertWalletToResponse(wallet)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListWallets lists wallets with pagination and filtering
func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Parse query parameters
	query := r.URL.Query()

	// Pagination
	cursor := query.Get("cursor")
	limit := 100 // Default
	if limitStr := query.Get("limit"); limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Filters
	chainType := query.Get("chain_type")

	// SECURITY: user_id filter is ignored for user-authenticated requests
	// Users can only see their own wallets + app-managed wallets
	// The user_id filter is only used internally for admin/backend operations

	// Fetch wallets (app-scoped by context automatically)
	wallets, nextCursor, err := s.walletService.ListWallets(r.Context(), &app.ListWalletsRequest{
		UserSub:      userSub,
		Cursor:       cursor,
		Limit:        limit,
		ChainType:    chainType,
		FilterUserID: nil, // Always nil for user requests - enforces per-user isolation
	})
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list wallets",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Convert to response
	data := make([]WalletResponse, len(wallets))
	for i, w := range wallets {
		data[i] = convertWalletToResponse(w)
	}

	response := ListWalletsResponse{
		Data:       data,
		NextCursor: nextCursor,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleCreateWallet handles wallet creation
// For app-managed wallets (no owner), userSub may be empty - only app auth is required
func (s *Server) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	// userSub is optional for app-managed wallets
	userSub, _ := getUserSub(r.Context())

	var req CreateWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Validate chain type
	if req.ChainType == "" {
		req.ChainType = types.ChainTypeEthereum
	}

	// For app-managed wallets (no owner), no owner verification is needed - app secret auth is sufficient
	// For user-owned wallets, verify authorization signature against the owner key
	if req.Owner != nil || req.OwnerID != nil {
		// User-owned wallet - signature verification required
		if req.OwnerID != nil {
			// If using existing owner, verify signature against that owner
			if err := s.verifySignatureAgainstOwner(r, *req.OwnerID); err != nil {
				s.writeError(w, apperrors.NewWithDetail(
					apperrors.ErrCodeForbidden,
					"Invalid authorization signature",
					err.Error(),
					http.StatusForbidden,
				))
				return
			}
		} else if req.Owner != nil && req.Owner.PublicKey != "" {
			// If creating new owner, verify signature against the provided public key
			if err := s.verifySignatureAgainstPublicKey(r, req.Owner.PublicKey); err != nil {
				s.writeError(w, apperrors.NewWithDetail(
					apperrors.ErrCodeForbidden,
					"Invalid authorization signature",
					err.Error(),
					http.StatusForbidden,
				))
				return
			}
		}
	}

	// Prepare create wallet request
	var ownerPublicKey string
	if req.Owner != nil {
		ownerPublicKey = req.Owner.PublicKey
	}

	// Convert AdditionalSigners from API format to app format
	additionalSigners := make([]app.AdditionalSigner, len(req.AdditionalSigners))
	for i, signer := range req.AdditionalSigners {
		additionalSigners[i] = app.AdditionalSigner{
			SignerID:          signer.SignerID,
			OverridePolicyIDs: signer.OverridePolicyIDs,
		}
	}

	// Create wallet (app-scoped by context automatically)
	createResult, err := s.walletService.CreateWallet(r.Context(), &app.CreateWalletRequest{
		UserSub:           userSub,
		ChainType:         req.ChainType,
		OwnerPublicKey:    ownerPublicKey,
		OwnerAlgorithm:    types.AlgorithmP256,
		OwnerID:           req.OwnerID,
		ExecBackend:       types.ExecBackendKMS,
		PolicyIDs:         req.PolicyIDs,
		AdditionalSigners: additionalSigners,
		RecoveryMethod:    req.RecoveryMethod,
		RecoveryHint:      req.RecoveryHint,
	})
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertWalletToResponse(createResult.Wallet)
	s.writeJSON(w, http.StatusCreated, response)
}

// handleUpdateWallet updates a wallet's configuration (requires authorization signature)
func (s *Server) handleUpdateWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Read body
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Failed to read request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Parse request
	var req UpdateWalletRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Verify authorization signature
	if err := s.verifyAuthorizationSignature(r, walletID); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
		return
	}

	// Update wallet (app-scoped by context automatically)
	wallet, err := s.walletService.UpdateWallet(r.Context(), &app.UpdateWalletRequest{
		UserSub:           userSub,
		WalletID:          walletID,
		PolicyIDs:         req.PolicyIDs,
		OwnerID:           req.OwnerID,
		Owner:             convertOwnerInput(req.Owner),
		AdditionalSigners: convertAdditionalSigners(req.AdditionalSigners),
	})
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.writeError(w, apperrors.WalletNotFound(walletID.String()))
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to update wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertWalletToResponse(wallet)
	s.writeJSON(w, http.StatusOK, response)
}

// handleDeleteWallet deletes a wallet (requires authorization signature)
func (s *Server) handleDeleteWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Verify authorization signature
	if err := s.verifyAuthorizationSignature(r, walletID); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
		return
	}

	// Delete wallet (app-scoped by context automatically)
	err := s.walletService.DeleteWallet(r.Context(), walletID, userSub)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			s.writeError(w, apperrors.WalletNotFound(walletID.String()))
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to delete wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// handleSignTransaction handles transaction signing
func (s *Server) handleSignTransaction(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	var req SignTransactionRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Parse value
	value, ok := new(big.Int).SetString(req.Value, 10)
	if !ok {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid value",
			"Value must be a valid integer",
			http.StatusBadRequest,
		))
		return
	}

	// Parse gas parameters
	gasFeeCap, ok := new(big.Int).SetString(req.GasFeeCap, 10)
	if !ok {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid gas_fee_cap",
			"",
			http.StatusBadRequest,
		))
		return
	}

	gasTipCap, ok := new(big.Int).SetString(req.GasTipCap, 10)
	if !ok {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid gas_tip_cap",
			"",
			http.StatusBadRequest,
		))
		return
	}

	// Parse data (hex string)
	var data []byte
	if req.Data != "" {
		dataStr := strings.TrimPrefix(req.Data, "0x")
		var err error
		data, err = hex.DecodeString(dataStr)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid transaction data",
				"Data must be a valid hex string",
				http.StatusBadRequest,
			))
			return
		}
	}

	// Build authorization signature payload (for user-owned wallets)
	// For app-managed wallets, signatures are not required - app secret auth is sufficient
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Failed to build canonical payload",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Extract signatures (may be empty for app-managed wallets)
	signatures := auth.ExtractSignatures(r)

	signedTx, err := s.walletService.SignTransaction(r.Context(), userSub, &app.SignTransactionRequest{
		WalletID:         walletID,
		To:               req.To,
		Value:            value,
		Data:             data,
		ChainID:          req.ChainID,
		Nonce:            req.Nonce,
		GasLimit:         req.GasLimit,
		GasFeeCap:        gasFeeCap,
		GasTipCap:        gasTipCap,
		Signatures:       signatures,
		CanonicalPayload: canonicalBytes,
		IdempotencyKey:   r.Header.Get("x-idempotency-key"),
		AppID:            r.Header.Get("x-app-id"),
		HTTPMethod:       r.Method,
		URLPath:          r.URL.Path,
		RequestDigest:    "",
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}

		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Serialize the transaction to RLP-encoded bytes
	txBytes, err := signedTx.MarshalBinary()
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to serialize transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := SignTransactionResponse{
		TxHash:   signedTx.Hash().Hex(),
		SignedTx: hex.EncodeToString(txBytes),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleSignMessage handles personal_sign message signing requests
func (s *Server) handleSignMessage(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req SignMessageAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Validate message is not empty
	if req.Message == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid message",
			"Message cannot be empty",
			http.StatusBadRequest,
		))
		return
	}

	// Default encoding to utf8
	if req.Encoding == "" {
		req.Encoding = "utf8"
	}
	if req.Encoding != "utf8" && req.Encoding != "hex" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid encoding",
			"Encoding must be 'utf8' or 'hex'",
			http.StatusBadRequest,
		))
		return
	}

	// Build canonical payload for authorization verification
	_, canonicalPayload, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to build canonical payload",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Extract signatures from headers
	signatures := auth.ExtractSignatures(r)

	// Call the service
	signature, err := s.walletService.SignMessage(r.Context(), userSub, &app.SignMessageRequest{
		WalletID:         walletID,
		Message:          req.Message,
		Encoding:         req.Encoding,
		Signatures:       signatures,
		CanonicalPayload: canonicalPayload,
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign message",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	s.writeJSON(w, http.StatusOK, SignMessageResponse{
		Signature: signature,
	})
}

// verifyAuthorizationSignature verifies the x-authorization-signature header
// Returns nil for app-managed wallets (no owner) as they don't require signature verification
func (s *Server) verifyAuthorizationSignature(r *http.Request, walletID uuid.UUID) error {
	// Get wallet to determine owner
	userSub, _ := getUserSub(r.Context())
	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		return err
	}

	// App-managed wallets (no owner) don't require authorization signature
	// App secret authentication is sufficient
	if wallet.OwnerID == nil {
		return nil
	}

	// Build canonical payload
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		return err
	}

	// Extract signatures
	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		return apperrors.New(
			apperrors.ErrCodeUnauthorized,
			"No authorization signatures provided",
			401,
		)
	}

	// Get owner information
	owner, err := s.walletService.GetOwner(r.Context(), *wallet.OwnerID)
	if err != nil {
		return err
	}

	// Verify signature
	verifier := auth.NewSignatureVerifier()
	return verifier.VerifyOwnerSignature(signatures, canonicalBytes, owner)
}

// verifySignatureAgainstOwner verifies signature against an existing owner
func (s *Server) verifySignatureAgainstOwner(r *http.Request, ownerID uuid.UUID) error {
	// Build canonical payload
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		return err
	}

	// Extract signatures
	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		return apperrors.New(
			apperrors.ErrCodeUnauthorized,
			"No authorization signatures provided",
			401,
		)
	}

	// Get owner information
	owner, err := s.walletService.GetOwner(r.Context(), ownerID)
	if err != nil {
		return err
	}

	// Verify signature
	verifier := auth.NewSignatureVerifier()
	return verifier.VerifyOwnerSignature(signatures, canonicalBytes, owner)
}

// verifySignatureAgainstPublicKey verifies signature against a public key
func (s *Server) verifySignatureAgainstPublicKey(r *http.Request, publicKeyHex string) error {
	// Build canonical payload
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		return err
	}

	// Extract signatures
	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		return apperrors.New(
			apperrors.ErrCodeUnauthorized,
			"No authorization signatures provided",
			401,
		)
	}

	// Create a temporary owner struct for verification (single key type)
	owner := &auth.Owner{
		Type:      auth.OwnerTypeSingleKey,
		PublicKey: publicKeyHex,
	}

	// Verify signature
	verifier := auth.NewSignatureVerifier()
	return verifier.VerifyOwnerSignature(signatures, canonicalBytes, owner)
}

// Helper functions

func convertWalletToResponse(w *types.Wallet) WalletResponse {
	resp := WalletResponse{
		ID:                w.ID,
		Address:           w.Address,
		ChainType:         w.ChainType,
		PolicyIDs:         []uuid.UUID{},
		AdditionalSigners: []AdditionalSigner{},
		CreatedAt:         w.CreatedAt.UnixMilli(),
	}

	if w.OwnerID != nil {
		resp.OwnerID = w.OwnerID
	}

	// TODO: Load policy IDs and additional signers from database

	return resp
}

func convertOwnerInput(input *OwnerInput) *app.OwnerInput {
	if input == nil {
		return nil
	}
	return &app.OwnerInput{
		PublicKey: input.PublicKey,
		UserID:    input.UserID,
	}
}

func convertAdditionalSigners(signers *[]AdditionalSigner) *[]app.AdditionalSigner {
	if signers == nil {
		return nil
	}
	result := make([]app.AdditionalSigner, len(*signers))
	for i, s := range *signers {
		result[i] = app.AdditionalSigner{
			SignerID:          s.SignerID,
			OverridePolicyIDs: s.OverridePolicyIDs,
		}
	}
	return &result
}

// ExportWalletRequest represents the request to export a wallet with HPKE encryption
type ExportWalletRequest struct {
	EncryptionType     string `json:"encryption_type"`      // Must be "HPKE"
	RecipientPublicKey string `json:"recipient_public_key"` // Base64-encoded P-256 public key
}

// ExportWalletResponse represents the encrypted wallet export response
type ExportWalletResponse struct {
	ID              uuid.UUID `json:"id"`
	EncryptionType  string    `json:"encryption_type"`  // Always "HPKE"
	Ciphertext      string    `json:"ciphertext"`       // Base64-encoded encrypted private key
	EncapsulatedKey string    `json:"encapsulated_key"` // Base64-encoded ephemeral public key
	ExportedAt      int64     `json:"exported_at"`      // Unix timestamp in milliseconds
}

// handleExportWallet exports the private key for a wallet with HPKE encryption
// POST /v1/wallets/{id}/export
func (s *Server) handleExportWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Parse request body
	var req ExportWalletRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Validate encryption type
	if req.EncryptionType == "" {
		req.EncryptionType = "HPKE"
	}
	if req.EncryptionType != "HPKE" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid encryption type",
			"Only HPKE encryption is supported",
			http.StatusBadRequest,
		))
		return
	}

	// Validate recipient public key
	if req.RecipientPublicKey == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Missing recipient public key",
			"recipient_public_key is required for HPKE encryption",
			http.StatusBadRequest,
		))
		return
	}

	// Get wallet and verify ownership (app-scoped by context automatically)
	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if wallet == nil {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	// For app-managed wallets (no owner), skip signature verification - app secret auth is sufficient
	// For user-owned wallets, require owner signature verification
	var signatures []string
	var canonicalBytes []byte
	if wallet.OwnerID != nil {
		// Build and extract canonical payload for signature verification
		_, canonicalBytes, err = auth.BuildCanonicalPayload(r)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Failed to build canonical payload",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}

		// Extract signatures from header
		signatures = auth.ExtractSignatures(r)
		if len(signatures) == 0 {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"No authorization signature provided",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Verify owner signature
		owner, err := s.walletService.GetOwner(r.Context(), *wallet.OwnerID)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeInternalError,
				"Failed to get owner",
				err.Error(),
				http.StatusInternalServerError,
			))
			return
		}

		verifier := auth.NewSignatureVerifier()
		if err := verifier.VerifyOwnerSignature(signatures, canonicalBytes, owner); err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"Invalid authorization signature",
				err.Error(),
				http.StatusForbidden,
			))
			return
		}
	}

	// Export wallet (retrieve private key from key executor)
	// This is a sensitive operation that should be carefully controlled
	privateKeyBytes, err := s.walletService.ExportWallet(r.Context(), userSub, &app.ExportWalletRequest{
		WalletID:         walletID,
		Signatures:       signatures,
		CanonicalPayload: canonicalBytes,
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to export wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Encrypt the private key with HPKE
	encrypted, err := s.hpkeEncrypt(req.RecipientPublicKey, privateKeyBytes)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to encrypt private key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Mark wallet as exported
	now := time.Now()
	if _, err := s.store.DB().Exec(
		r.Context(),
		`UPDATE wallets SET exported_at = $1 WHERE id = $2`,
		now,
		walletID,
	); err != nil {
		// Log but don't fail - export succeeded
	}

	response := ExportWalletResponse{
		ID:              walletID,
		EncryptionType:  encrypted.EncryptionType,
		Ciphertext:      encrypted.Ciphertext,
		EncapsulatedKey: encrypted.EncapsulatedKey,
		ExportedAt:      now.UnixMilli(),
	}

	s.writeJSON(w, http.StatusOK, response)
}

// AuthenticateRequest represents the request to obtain a session key
type AuthenticateRequest struct {
	UserJWT            string `json:"user_jwt,omitempty"`
	EncryptionType     string `json:"encryption_type,omitempty"`
	RecipientPublicKey string `json:"recipient_public_key,omitempty"`
}

// AuthenticateResponse represents the response with encrypted authorization key
type AuthenticateResponse struct {
	EncryptedAuthorizationKey *EncryptedAuthKey       `json:"encrypted_authorization_key,omitempty"`
	AuthorizationKey          string                  `json:"authorization_key,omitempty"` // Only returned if no encryption
	ExpiresAt                 int64                   `json:"expires_at"`
	Wallets                   []AuthenticateWalletRef `json:"wallets,omitempty"` // Wallets accessible with this session
}

// AuthenticateWalletRef represents a wallet reference in authenticate response
type AuthenticateWalletRef struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	ChainType string `json:"chain_type"`
}

// EncryptedAuthKey represents an HPKE-encrypted authorization key
type EncryptedAuthKey struct {
	EncryptionType  string `json:"encryption_type"`
	EncapsulatedKey string `json:"encapsulated_key"`
	Ciphertext      string `json:"ciphertext"`
}

// handleWalletsAuthenticate obtains a session key for wallet access
// POST /v1/wallets/authenticate
func (s *Server) handleWalletsAuthenticate(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Parse request
	var req AuthenticateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Validate user_jwt if provided
	// The user_jwt allows clients to provide an identity assertion in the request body
	// This is validated to ensure the caller has valid authentication
	if req.UserJWT != "" {
		// Get app from context for auth settings
		app := middleware.GetApp(r.Context())
		if app == nil || app.Settings.Auth == nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Auth not configured",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Validate the JWT using the user auth middleware's validator
		jwtUserSub, err := s.userAuthMiddleware.ValidateJWT(req.UserJWT, app.Settings.Auth)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid user_jwt",
				err.Error(),
				http.StatusUnauthorized,
			))
			return
		}

		// Verify the JWT subject matches the authenticated user
		if jwtUserSub != userSub {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"user_jwt does not match authenticated user",
				"",
				http.StatusForbidden,
			))
			return
		}
	}

	// Generate ephemeral P256 key pair for signing
	ephemeralPrivKey, ephemeralPubKey, err := auth.GenerateP256KeyPair()
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to generate ephemeral key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Set expiration (default 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour).UnixMilli()

	// Store the ephemeral key in database for later verification
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	ephemeralAuthKey := &types.AuthorizationKey{
		ID:          uuid.New(),
		PublicKey:   ephemeralPubKey,
		Algorithm:   types.AlgorithmP256,
		Status:      types.StatusActive,
		OwnerEntity: userSub,
		CreatedAt:   time.Now(),
	}
	if err := authKeyRepo.Create(r.Context(), ephemeralAuthKey); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to store ephemeral key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Fetch user's wallets to include in response
	wallets, _, err := s.walletService.ListWallets(r.Context(), &app.ListWalletsRequest{
		UserSub: userSub,
		Limit:   100, // Include up to 100 wallets
	})
	if err != nil {
		// Log error but don't fail - wallets are optional in response
		wallets = []*types.Wallet{}
	}

	// Build wallet references for response
	walletRefs := make([]AuthenticateWalletRef, len(wallets))
	for i, w := range wallets {
		walletRefs[i] = AuthenticateWalletRef{
			ID:        w.ID.String(),
			Address:   w.Address,
			ChainType: w.ChainType,
		}
	}

	var response AuthenticateResponse
	response.ExpiresAt = expiresAt
	response.Wallets = walletRefs

	// If encryption requested, encrypt the private key with HPKE
	if req.EncryptionType == "HPKE" && req.RecipientPublicKey != "" {
		// Decode recipient public key (base64)
		recipientPubKeyBytes, err := base64.StdEncoding.DecodeString(req.RecipientPublicKey)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid recipient public key",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}

		// Encrypt ephemeral private key using HPKE
		encapsulatedKey, ciphertext, err := auth.EncryptWithHPKE(ephemeralPrivKey, recipientPubKeyBytes)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeInternalError,
				"Failed to encrypt authorization key",
				err.Error(),
				http.StatusInternalServerError,
			))
			return
		}

		response.EncryptedAuthorizationKey = &EncryptedAuthKey{
			EncryptionType:  "HPKE",
			EncapsulatedKey: base64.StdEncoding.EncodeToString(encapsulatedKey),
			Ciphertext:      base64.StdEncoding.EncodeToString(ciphertext),
		}
	} else {
		// Return unencrypted (for testing/development only)
		response.AuthorizationKey = hex.EncodeToString(ephemeralPrivKey)
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleAuthenticateWallet generates an authentication proof for a wallet
// POST /v1/wallets/{id}/authenticate
func (s *Server) handleAuthenticateWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Verify authorization signature
	if err := s.verifyAuthorizationSignature(r, walletID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"Invalid authorization signature",
			err.Error(),
			http.StatusForbidden,
		))
		return
	}

	// Parse request
	var req struct {
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	if req.Message == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Message is required",
			"",
			http.StatusBadRequest,
		))
		return
	}

	// Get wallet and verify ownership (app-scoped by context automatically)
	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if wallet == nil {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	// Build canonical payload for authorization verification
	_, canonicalPayload, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to build canonical payload",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Extract signatures from headers
	signatures := auth.ExtractSignatures(r)

	// Sign the message with the wallet's private key (app-scoped by context automatically)
	signature, err := s.walletService.SignMessage(r.Context(), userSub, &app.SignMessageRequest{
		WalletID:         walletID,
		Message:          req.Message,
		Encoding:         "utf8",
		Signatures:       signatures,
		CanonicalPayload: canonicalPayload,
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign message",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := map[string]interface{}{
		"wallet_id": walletID,
		"message":   req.Message,
		"signature": signature,
		"address":   wallet.Address,
	}

	s.writeJSON(w, http.StatusOK, response)
}

func getUserSub(ctx context.Context) (string, bool) {
	userSub, ok := ctx.Value("user_sub").(string)
	if !ok || userSub == "" {
		return "", false
	}
	return userSub, true
}

// writeJSON writes a JSON response
func (s *Server) writeJSON(w http.ResponseWriter, statusCode int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(data)
}

// writeError writes an error response
func (s *Server) writeError(w http.ResponseWriter, err *apperrors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(err)
}
