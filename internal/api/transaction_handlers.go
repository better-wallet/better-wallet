package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
)

// TransactionResponse represents a transaction in API responses
type TransactionResponse struct {
	ID            int64   `json:"id"`
	Actor         string  `json:"actor"`
	Action        string  `json:"action"`
	ResourceType  string  `json:"resource_type"`
	ResourceID    string  `json:"resource_id"`
	PolicyResult  *string `json:"policy_result,omitempty"`
	SignerID      *string `json:"signer_id,omitempty"`
	TxHash        *string `json:"tx_hash,omitempty"`
	RequestDigest *string `json:"request_digest,omitempty"`
	ClientIP      *string `json:"client_ip,omitempty"`
	UserAgent     *string `json:"user_agent,omitempty"`
	CreatedAt     int64   `json:"created_at"` // Unix timestamp in milliseconds
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

	txID, err := strconv.ParseInt(pathParts[0], 10, 64)
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
func (s *Server) handleGetTransaction(w http.ResponseWriter, r *http.Request, txID int64) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get user to verify ownership
	userRepo := storage.NewUserRepository(s.store)
	user, err := userRepo.GetByExternalSub(r.Context(), userSub)
	if err != nil || user == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get user",
			"",
			http.StatusInternalServerError,
		))
		return
	}

	// Get audit log entry (transaction record)
	auditRepo := storage.NewAuditRepository(s.store)
	auditLog, err := auditRepo.GetByID(r.Context(), txID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if auditLog == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Transaction not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify the transaction belongs to this user
	// Actor should match the user's external_sub
	if auditLog.Actor != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertAuditLogToTransactionResponse(auditLog)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListTransactions lists transactions with filtering
func (s *Server) handleListTransactions(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get user to verify ownership
	userRepo := storage.NewUserRepository(s.store)
	user, err := userRepo.GetByExternalSub(r.Context(), userSub)
	if err != nil || user == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get user",
			"",
			http.StatusInternalServerError,
		))
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	walletID := query.Get("wallet_id")
	action := query.Get("action")
	limitStr := query.Get("limit")
	cursorStr := query.Get("cursor")

	limit := 100
	if limitStr != "" {
		if parsedLimit, err := strconv.Atoi(limitStr); err == nil && parsedLimit > 0 && parsedLimit <= 100 {
			limit = parsedLimit
		}
	}

	var cursor int64
	if cursorStr != "" {
		if parsedCursor, err := strconv.ParseInt(cursorStr, 10, 64); err == nil {
			cursor = parsedCursor
		}
	}

	// Build query to get audit logs (transactions) for this user
	sqlQuery := `
		SELECT id, actor, action, resource_type, resource_id,
		       policy_result, signer_id, tx_hash, request_digest,
		       client_ip, user_agent, created_at
		FROM audit_logs
		WHERE actor = $1
	`
	args := []interface{}{userSub}
	argIndex := 2

	if walletID != "" {
		sqlQuery += ` AND resource_id = $` + strconv.Itoa(argIndex)
		args = append(args, walletID)
		argIndex++
	}

	if action != "" {
		sqlQuery += ` AND action = $` + strconv.Itoa(argIndex)
		args = append(args, action)
		argIndex++
	}

	if cursor > 0 {
		sqlQuery += ` AND id < $` + strconv.Itoa(argIndex)
		args = append(args, cursor)
		argIndex++
	}

	sqlQuery += ` ORDER BY id DESC LIMIT $` + strconv.Itoa(argIndex)
	args = append(args, limit+1) // Fetch one extra to determine if there are more results

	rows, err := s.store.DB().Query(r.Context(), sqlQuery, args...)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list transactions",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	defer rows.Close()

	var transactions []TransactionResponse
	for rows.Next() {
		var log types.AuditLog

		err := rows.Scan(
			&log.ID,
			&log.Actor,
			&log.Action,
			&log.ResourceType,
			&log.ResourceID,
			&log.PolicyResult,
			&log.SignerID,
			&log.TxHash,
			&log.RequestDigest,
			&log.ClientIP,
			&log.UserAgent,
			&log.CreatedAt,
		)
		if err != nil {
			continue
		}

		transactions = append(transactions, convertAuditLogToTransactionResponse(&log))
	}

	// Prepare response with pagination
	var nextCursor *string
	if len(transactions) > limit {
		// Remove the extra item
		transactions = transactions[:limit]
		// Set next cursor to the ID of the last item
		lastID := strconv.FormatInt(transactions[len(transactions)-1].ID, 10)
		nextCursor = &lastID
	}

	response := ListTransactionsResponse{
		Data:       transactions,
		NextCursor: nextCursor,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// convertAuditLogToTransactionResponse converts an audit log to transaction response format
func convertAuditLogToTransactionResponse(log *types.AuditLog) TransactionResponse {
	return TransactionResponse{
		ID:            log.ID,
		Actor:         log.Actor,
		Action:        log.Action,
		ResourceType:  log.ResourceType,
		ResourceID:    log.ResourceID,
		PolicyResult:  log.PolicyResult,
		SignerID:      log.SignerID,
		TxHash:        log.TxHash,
		RequestDigest: log.RequestDigest,
		ClientIP:      log.ClientIP,
		UserAgent:     log.UserAgent,
		CreatedAt:     log.CreatedAt.UnixMilli(),
	}
}
