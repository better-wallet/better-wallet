package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// KeyQuorumResponse represents a key quorum in API responses
type KeyQuorumResponse struct {
	ID        uuid.UUID   `json:"id"`
	Threshold int         `json:"threshold"`
	KeyIDs    []uuid.UUID `json:"key_ids"`
	Status    string      `json:"status"`
	CreatedAt int64       `json:"created_at"` // Unix timestamp in milliseconds
}

// CreateKeyQuorumRequest represents the request to create a key quorum
type CreateKeyQuorumRequest struct {
	Threshold int         `json:"threshold"`
	KeyIDs    []uuid.UUID `json:"key_ids"`
}

// UpdateKeyQuorumRequest represents the request to update a key quorum
type UpdateKeyQuorumRequest struct {
	Threshold *int         `json:"threshold,omitempty"`
	KeyIDs    *[]uuid.UUID `json:"key_ids,omitempty"`
	Status    *string      `json:"status,omitempty"`
}

// ListKeyQuorumsResponse for paginated key quorum listing
type ListKeyQuorumsResponse struct {
	Data       []KeyQuorumResponse `json:"data"`
	NextCursor *string             `json:"next_cursor,omitempty"`
}

// handleKeyQuorums handles key quorum list and creation
func (s *Server) handleKeyQuorums(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListKeyQuorums(w, r)
	case http.MethodPost:
		s.handleCreateKeyQuorum(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleKeyQuorumOperations routes key quorum operations
func (s *Server) handleKeyQuorumOperations(w http.ResponseWriter, r *http.Request) {
	// Extract key quorum ID from path: /v1/key-quorums/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/key-quorums/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	keyQuorumID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid key quorum ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetKeyQuorum(w, r, keyQuorumID)
	case http.MethodPatch:
		s.handleUpdateKeyQuorum(w, r, keyQuorumID)
	case http.MethodDelete:
		s.handleDeleteKeyQuorum(w, r, keyQuorumID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetKeyQuorum retrieves a single key quorum by ID
func (s *Server) handleGetKeyQuorum(w http.ResponseWriter, r *http.Request, keyQuorumID uuid.UUID) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	repo := storage.NewKeyQuorumRepository(s.store)
	kq, err := repo.GetByID(r.Context(), keyQuorumID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if kq == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Key quorum not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	response := convertKeyQuorumToResponse(kq)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListKeyQuorums lists all key quorums
func (s *Server) handleListKeyQuorums(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get all key quorums
	query := `
		SELECT id, threshold, key_ids, status, created_at
		FROM key_quorums
		WHERE status = 'active'
		ORDER BY created_at DESC
	`

	rows, err := s.store.DB().Query(r.Context(), query)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list key quorums",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	defer rows.Close()

	var keyQuorums []KeyQuorumResponse
	for rows.Next() {
		var kq types.KeyQuorum

		err := rows.Scan(
			&kq.ID,
			&kq.Threshold,
			&kq.KeyIDs,
			&kq.Status,
			&kq.CreatedAt,
		)
		if err != nil {
			continue
		}

		keyQuorums = append(keyQuorums, convertKeyQuorumToResponse(&kq))
	}

	response := ListKeyQuorumsResponse{
		Data: keyQuorums,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleCreateKeyQuorum creates a new key quorum
func (s *Server) handleCreateKeyQuorum(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req CreateKeyQuorumRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Validate
	if req.Threshold <= 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Threshold must be greater than 0",
			"",
			http.StatusBadRequest,
		))
		return
	}

	if len(req.KeyIDs) == 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"At least one key ID is required",
			"",
			http.StatusBadRequest,
		))
		return
	}

	if req.Threshold > len(req.KeyIDs) {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Threshold cannot exceed number of keys",
			"",
			http.StatusBadRequest,
		))
		return
	}

	// Create key quorum
	kq := &types.KeyQuorum{
		ID:        uuid.New(),
		Threshold: req.Threshold,
		KeyIDs:    req.KeyIDs,
		Status:    types.StatusActive,
		CreatedAt: time.Now(),
	}

	repo := storage.NewKeyQuorumRepository(s.store)
	if err := repo.Create(r.Context(), kq); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertKeyQuorumToResponse(kq)
	s.writeJSON(w, http.StatusCreated, response)
}

// handleUpdateKeyQuorum updates a key quorum
func (s *Server) handleUpdateKeyQuorum(w http.ResponseWriter, r *http.Request, keyQuorumID uuid.UUID) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

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

	var req UpdateKeyQuorumRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Get key quorum
	repo := storage.NewKeyQuorumRepository(s.store)
	kq, err := repo.GetByID(r.Context(), keyQuorumID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if kq == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Key quorum not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Update fields
	if req.Threshold != nil {
		if *req.Threshold <= 0 {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Threshold must be greater than 0",
				"",
				http.StatusBadRequest,
			))
			return
		}
		kq.Threshold = *req.Threshold
	}

	if req.KeyIDs != nil {
		if len(*req.KeyIDs) == 0 {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"At least one key ID is required",
				"",
				http.StatusBadRequest,
			))
			return
		}
		kq.KeyIDs = *req.KeyIDs
	}

	if req.Status != nil {
		if *req.Status != types.StatusActive && *req.Status != types.StatusInactive {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid status",
				"",
				http.StatusBadRequest,
			))
			return
		}
		kq.Status = *req.Status
	}

	// Validate threshold vs key count
	if kq.Threshold > len(kq.KeyIDs) {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Threshold cannot exceed number of keys",
			"",
			http.StatusBadRequest,
		))
		return
	}

	// Update in database
	if err := repo.Update(r.Context(), kq); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to update key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertKeyQuorumToResponse(kq)
	s.writeJSON(w, http.StatusOK, response)
}

// handleDeleteKeyQuorum deletes a key quorum
func (s *Server) handleDeleteKeyQuorum(w http.ResponseWriter, r *http.Request, keyQuorumID uuid.UUID) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get key quorum to verify it exists
	repo := storage.NewKeyQuorumRepository(s.store)
	kq, err := repo.GetByID(r.Context(), keyQuorumID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if kq == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Key quorum not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Delete key quorum
	if err := repo.Delete(r.Context(), keyQuorumID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to delete key quorum",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertKeyQuorumToResponse converts a key quorum to API response format
func convertKeyQuorumToResponse(kq *types.KeyQuorum) KeyQuorumResponse {
	return KeyQuorumResponse{
		ID:        kq.ID,
		Threshold: kq.Threshold,
		KeyIDs:    kq.KeyIDs,
		Status:    kq.Status,
		CreatedAt: kq.CreatedAt.UnixMilli(),
	}
}
