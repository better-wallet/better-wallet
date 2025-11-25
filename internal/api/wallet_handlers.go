package api

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
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
	// Extract wallet ID from path: /v1/wallets/{id}/...
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/wallets/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

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
	userIDStr := query.Get("user_id")

	var filterUserID *uuid.UUID
	if userIDStr != "" {
		uid, err := uuid.Parse(userIDStr)
		if err == nil {
			filterUserID = &uid
		}
	}

	// Fetch wallets
	wallets, nextCursor, err := s.walletService.ListWallets(r.Context(), &app.ListWalletsRequest{
		UserSub:      userSub,
		Cursor:       cursor,
		Limit:        limit,
		ChainType:    chainType,
		FilterUserID: filterUserID,
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
func (s *Server) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

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

	// Validate owner - must provide either owner or owner_id
	if req.Owner == nil && req.OwnerID == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Owner is required",
			"Must provide either 'owner' or 'owner_id'",
			http.StatusBadRequest,
		))
		return
	}

	// For now, use existing CreateWallet service method
	// TODO: Extend to support policy_ids and additional_signers
	var ownerPublicKey string
	if req.Owner != nil {
		ownerPublicKey = req.Owner.PublicKey
	}

	wallet, err := s.walletService.CreateWallet(r.Context(), &app.CreateWalletRequest{
		UserSub:        userSub,
		ChainType:      req.ChainType,
		OwnerPublicKey: ownerPublicKey,
		OwnerAlgorithm: types.AlgorithmP256,
		ExecBackend:    types.ExecBackendKMS,
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

	response := convertWalletToResponse(wallet)
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

	// Update wallet
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

	// Delete wallet
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

	// Build authorization signature payload
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

	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing authorization signature",
			"x-authorization-signature header required",
			http.StatusUnauthorized,
		))
		return
	}

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

// verifyAuthorizationSignature verifies the x-authorization-signature header
func (s *Server) verifyAuthorizationSignature(r *http.Request, walletID uuid.UUID) error {
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

	// Get wallet to determine owner
	userSub, _ := getUserSub(r.Context())
	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		return err
	}

	// Get owner information
	owner, err := s.walletService.GetOwner(r.Context(), wallet.OwnerID)
	if err != nil {
		return err
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

	if w.OwnerID != uuid.Nil {
		resp.OwnerID = &w.OwnerID
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

// handleExportWallet exports the private key for a wallet
// POST /v1/wallets/{id}/export
func (s *Server) handleExportWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Build and extract canonical payload for signature verification
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

	// Extract signatures from header
	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"No authorization signature provided",
			"",
			http.StatusUnauthorized,
		))
		return
	}

	// Get wallet and verify ownership
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

	// Verify owner signature
	owner, err := s.walletService.GetOwner(r.Context(), wallet.OwnerID)
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

	// Export wallet (retrieve private key from key executor)
	// This is a sensitive operation that should be carefully controlled
	privateKeyHex, err := s.walletService.ExportWallet(r.Context(), walletID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to export wallet",
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

	response := map[string]interface{}{
		"id":          walletID,
		"private_key": privateKeyHex,
		"exported_at": now.UnixMilli(),
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

	// Get wallet and verify ownership
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

	// Sign the message with the wallet's private key
	signature, err := s.walletService.SignMessage(r.Context(), walletID, req.Message)
	if err != nil {
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
