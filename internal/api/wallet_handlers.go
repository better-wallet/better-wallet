package api

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/authsig"
	"github.com/better-wallet/better-wallet/internal/middleware"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// CreateWalletRequest represents the API request to create a wallet
type CreateWalletRequest struct {
	ChainType      string `json:"chain_type"`
	ExecBackend    string `json:"exec_backend,omitempty"`
	OwnerPublicKey string `json:"owner_public_key"` // Hex-encoded public key
	OwnerAlgorithm string `json:"owner_algorithm"`  // "secp256k1" or "ed25519"
}

// CreateWalletResponse represents the API response for wallet creation
type CreateWalletResponse struct {
	ID        string `json:"id"`
	Address   string `json:"address"`
	ChainType string `json:"chain_type"`
	OwnerID   string `json:"owner_id"` // Authorization key ID for signing
	CreatedAt string `json:"created_at"`
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
// with selective owner signature verification for sensitive operations
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

	// Check for sign operation
	if len(pathParts) >= 2 && pathParts[1] == "sign" && r.Method == http.MethodPost {
		s.handleSignTransaction(w, r, walletID)
		return
	}

	s.writeError(w, apperrors.ErrNotFound)
}

// handleListWallets handles listing wallets for a user
func (s *Server) handleListWallets(w http.ResponseWriter, r *http.Request) {
	userSub, ok := middleware.GetUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	appID := middleware.GetAppID(r.Context())
	if appID == "" {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	wallets, err := s.walletService.GetWallets(r.Context(), userSub)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get wallets",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	s.writeJSON(w, http.StatusOK, wallets)
}

// handleCreateWallet handles wallet creation
func (s *Server) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	userSub, ok := middleware.GetUserSub(r.Context())
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

	// Validate exec backend
	if req.ExecBackend == "" {
		req.ExecBackend = types.ExecBackendKMS
	}

	// Validate owner public key is provided
	if req.OwnerPublicKey == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Owner public key is required",
			"owner_public_key field must be provided",
			http.StatusBadRequest,
		))
		return
	}

	// Validate algorithm - only P-256 is supported
	if req.OwnerAlgorithm == "" {
		req.OwnerAlgorithm = types.AlgorithmP256 // Default to P-256 (NIST standard)
	}

	// Only P-256 is supported for production use
	if req.OwnerAlgorithm != types.AlgorithmP256 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid owner algorithm",
			"owner_algorithm must be 'p256' (only P-256 is supported)",
			http.StatusBadRequest,
		))
		return
	}

	wallet, err := s.walletService.CreateWallet(r.Context(), &app.CreateWalletRequest{
		UserSub:        userSub,
		ChainType:      req.ChainType,
		OwnerPublicKey: req.OwnerPublicKey,
		OwnerAlgorithm: req.OwnerAlgorithm,
		ExecBackend:    req.ExecBackend,
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

	response := CreateWalletResponse{
		ID:        wallet.ID.String(),
		Address:   wallet.Address,
		ChainType: wallet.ChainType,
		OwnerID:   wallet.OwnerID.String(),
		CreatedAt: wallet.CreatedAt.Format(time.RFC3339),
	}

	s.writeJSON(w, http.StatusCreated, response)
}

// handleSignTransaction handles transaction signing
func (s *Server) handleSignTransaction(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := middleware.GetUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	appID := middleware.GetAppID(r.Context())
	if appID == "" {
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
		// Remove 0x prefix if present
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
	idemKey := r.Header.Get("X-Idempotency-Key")
	sigHeader := r.Header.Get("X-Authorization-Signature")
	signatures := authsig.ParseSignatures(sigHeader)
	if len(signatures) == 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing X-Authorization-Signature",
			"At least one authorization signature is required",
			http.StatusUnauthorized,
		))
		return
	}

	payload := authsig.Payload{
		Version: "v1",
		Method:  r.Method,
		URL:     r.URL.Path,
		Body:    string(bodyBytes),
		Headers: map[string]string{
			"x-app-id": appID,
		},
		AppID:          appID,
		IdempotencyKey: idemKey,
	}

	if idemKey != "" {
		payload.Headers["x-idempotency-key"] = idemKey
	}

	canonicalPayload, digest, err := authsig.Canonicalize(payload)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Failed to canonicalize request",
			err.Error(),
			http.StatusBadRequest,
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
		CanonicalPayload: canonicalPayload,
		IdempotencyKey:   idemKey,
		AppID:            appID,
		HTTPMethod:       r.Method,
		URLPath:          r.URL.Path,
		RequestDigest:    digest,
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

	// Return both the hash and the RLP-encoded transaction
	response := SignTransactionResponse{
		TxHash:   signedTx.Hash().Hex(),
		SignedTx: hex.EncodeToString(txBytes),
	}

	s.writeJSON(w, http.StatusOK, response)
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
