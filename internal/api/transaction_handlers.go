package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/google/uuid"
)

// TransactionResponse represents a transaction in API responses
type TransactionResponse struct {
	ID                   string  `json:"id"`
	Hash                 *string `json:"hash,omitempty"`           // Transaction hash
	CAIP2                *string `json:"caip2,omitempty"`          // CAIP-2 chain identifier (e.g., "eip155:1")
	WalletID             string  `json:"wallet_id"`
	ChainID              int64   `json:"chain_id"`
	Status               string  `json:"status"`
	Method               string  `json:"method"`
	ToAddress            *string `json:"to,omitempty"`
	Value                *string `json:"value,omitempty"`
	Data                 *string `json:"data,omitempty"`
	Nonce                *int64  `json:"nonce,omitempty"`
	GasLimit             *int64  `json:"gas_limit,omitempty"`
	MaxFeePerGas         *string `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas *string `json:"max_priority_fee_per_gas,omitempty"`
	ErrorMessage         *string `json:"error_message,omitempty"`
	CreatedAt            int64   `json:"created_at"`
	UpdatedAt            int64   `json:"updated_at"`
}

// ListTransactionsResponse for paginated transaction listing
type ListTransactionsResponse struct {
	Data       []TransactionResponse `json:"data"`
	NextCursor *string               `json:"next_cursor,omitempty"`
}

// handleTransactions handles transaction list operations
func (s *Server) handleTransactions(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListTransactions(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleTransactionOperations routes transaction operations
func (s *Server) handleTransactionOperations(w http.ResponseWriter, r *http.Request) {
	// Extract transaction ID from path: /v1/transactions/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/transactions/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	txID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid transaction ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetTransaction(w, r, txID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetTransaction retrieves a single transaction by ID
func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request, txID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get transaction
	txRepo := storage.NewTransactionRepository(s.store)
	tx, err := txRepo.GetByID(r.Context(), txID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	if tx == nil {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	// Verify user has access to this transaction's wallet
	wallet, err := s.walletService.GetWallet(r.Context(), tx.WalletID, userSub)
	if err != nil || wallet == nil {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertTransactionToResponse(tx)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListTransactions lists transactions with filtering
func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	walletIDStr := query.Get("wallet_id")
	limitStr := query.Get("limit")

	limit := 100
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	txRepo := storage.NewTransactionRepository(s.store)

	var transactions []*storage.Transaction
	var err error

	if walletIDStr != "" {
		// Filter by specific wallet
		walletID, parseErr := uuid.Parse(walletIDStr)
		if parseErr != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid wallet_id",
				parseErr.Error(),
				http.StatusBadRequest,
			))
			return
		}

		// Verify user owns the wallet
		wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
		if err != nil || wallet == nil {
			s.writeError(w, apperrors.ErrForbidden)
			return
		}

		transactions, err = txRepo.ListByWalletID(r.Context(), walletID, limit)
	} else {
		// List all transactions for user's wallets
		wallets, _, err := s.walletService.ListWallets(r.Context(), &app.ListWalletsRequest{
			UserSub: userSub,
			Limit:   1000, // Get all wallets for the user
		})
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeInternalError,
				"Failed to get user wallets",
				err.Error(),
				http.StatusInternalServerError,
			))
			return
		}

		// Collect wallet IDs
		walletIDs := make([]uuid.UUID, len(wallets))
		for i, w := range wallets {
			walletIDs[i] = w.ID
		}

		// Get transactions for all user wallets
		if len(walletIDs) > 0 {
			transactions, err = txRepo.ListByWalletIDs(r.Context(), walletIDs, limit)
		} else {
			transactions = []*storage.Transaction{}
		}
	}

	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list transactions",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Convert to response format
	data := make([]TransactionResponse, len(transactions))
	for i, tx := range transactions {
		data[i] = convertTransactionToResponse(tx)
	}

	response := ListTransactionsResponse{
		Data: data,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// convertTransactionToResponse converts a storage Transaction to API response
func convertTransactionToResponse(tx *storage.Transaction) TransactionResponse {
	// Build CAIP-2 chain identifier (e.g., "eip155:1" for Ethereum mainnet)
	var caip2 *string
	if tx.ChainID > 0 {
		caip2Str := fmt.Sprintf("eip155:%d", tx.ChainID)
		caip2 = &caip2Str
	}

	return TransactionResponse{
		ID:                   tx.ID.String(),
		Hash:                 tx.TxHash,
		CAIP2:                caip2,
		WalletID:             tx.WalletID.String(),
		ChainID:              tx.ChainID,
		Status:               tx.Status,
		Method:               tx.Method,
		ToAddress:            tx.ToAddress,
		Value:                tx.Value,
		Data:                 tx.Data,
		Nonce:                tx.Nonce,
		GasLimit:             tx.GasLimit,
		MaxFeePerGas:         tx.MaxFeePerGas,
		MaxPriorityFeePerGas: tx.MaxPriorityFeePerGas,
		ErrorMessage:         tx.ErrorMessage,
		CreatedAt:            tx.CreatedAt.UnixMilli(),
		UpdatedAt:            tx.UpdatedAt.UnixMilli(),
	}
}
