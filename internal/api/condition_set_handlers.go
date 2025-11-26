package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// ConditionSetResponse represents a condition set in API responses
type ConditionSetResponse struct {
	ID          uuid.UUID     `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Values      []interface{} `json:"values"`
	OwnerID     uuid.UUID     `json:"owner_id"`
	CreatedAt   int64         `json:"created_at"` // Unix timestamp in milliseconds
	UpdatedAt   int64         `json:"updated_at"` // Unix timestamp in milliseconds
}

// CreateConditionSetRequest represents the request to create a condition set
type CreateConditionSetRequest struct {
	Name        string        `json:"name"`
	Description string        `json:"description,omitempty"`
	Values      []interface{} `json:"values"`
	OwnerID     *uuid.UUID    `json:"owner_id,omitempty"` // Authorization key ID that owns this set
}

// UpdateConditionSetRequest represents the request to update a condition set
type UpdateConditionSetRequest struct {
	Name        *string        `json:"name,omitempty"`
	Description *string        `json:"description,omitempty"`
	Values      *[]interface{} `json:"values,omitempty"`
}

// ListConditionSetsResponse for paginated condition set listing
type ListConditionSetsResponse struct {
	Data       []ConditionSetResponse `json:"data"`
	NextCursor *string                `json:"next_cursor,omitempty"`
}

// handleConditionSets handles condition set list and creation
func (s *Server) handleConditionSets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListConditionSets(w, r)
	case http.MethodPost:
		s.handleCreateConditionSet(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleConditionSetOperations routes condition set operations
func (s *Server) handleConditionSetOperations(w http.ResponseWriter, r *http.Request) {
	// Extract condition set ID from path: /v1/condition_sets/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/condition_sets/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	csID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid condition set ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetConditionSet(w, r, csID)
	case http.MethodPatch:
		s.handleUpdateConditionSet(w, r, csID)
	case http.MethodDelete:
		s.handleDeleteConditionSet(w, r, csID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetConditionSet retrieves a single condition set by ID
func (s *Server) handleGetConditionSet(w http.ResponseWriter, r *http.Request, csID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	csRepo := storage.NewConditionSetRepository(s.store)
	cs, err := csRepo.GetByID(r.Context(), csID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if cs == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Condition set not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership - check if the condition set's owner key belongs to the authenticated user
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	ownerKey, err := authKeyRepo.GetByID(r.Context(), cs.OwnerID)
	if err != nil || ownerKey == nil || ownerKey.OwnerEntity != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertConditionSetToResponse(cs)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListConditionSets lists all condition sets for the authenticated user
func (s *Server) handleListConditionSets(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get user's authorization keys
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	userKeys, err := authKeyRepo.GetActiveByOwnerEntity(r.Context(), userSub)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get authorization keys",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Build list of key IDs
	keyIDs := make([]uuid.UUID, len(userKeys))
	for i, key := range userKeys {
		keyIDs[i] = key.ID
	}

	// If user has no keys, return empty list
	if len(keyIDs) == 0 {
		response := ListConditionSetsResponse{
			Data: []ConditionSetResponse{},
		}
		s.writeJSON(w, http.StatusOK, response)
		return
	}

	// Get all condition sets owned by user's authorization keys
	csRepo := storage.NewConditionSetRepository(s.store)
	sets, err := csRepo.GetByOwnerIDs(r.Context(), keyIDs)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list condition sets",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	data := make([]ConditionSetResponse, len(sets))
	for i, cs := range sets {
		data[i] = convertConditionSetToResponse(cs)
	}

	response := ListConditionSetsResponse{
		Data: data,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleCreateConditionSet creates a new condition set
func (s *Server) handleCreateConditionSet(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req CreateConditionSetRequest
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
	if req.Name == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Name is required",
			"",
			http.StatusBadRequest,
		))
		return
	}

	if req.Values == nil {
		req.Values = []interface{}{}
	}

	// Determine owner ID
	var ownerID uuid.UUID
	if req.OwnerID != nil {
		// Use provided authorization key ID
		ownerID = *req.OwnerID

		// Verify the auth key exists and is active
		authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
		authKey, err := authKeyRepo.GetByID(r.Context(), ownerID)
		if err != nil || authKey == nil || authKey.Status != types.StatusActive {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid owner_id",
				"Owner must be an active authorization key",
				http.StatusBadRequest,
			))
			return
		}

		// Verify the auth key belongs to the authenticated user
		if authKey.OwnerEntity != userSub {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"Cannot create condition set with another user's authorization key",
				"",
				http.StatusForbidden,
			))
			return
		}
	} else {
		// Use user's default (first active) authorization key
		authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
		keys, err := authKeyRepo.GetActiveByOwnerEntity(r.Context(), userSub)
		if err != nil || len(keys) == 0 {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"No active authorization key found",
				"Create an authorization key first",
				http.StatusBadRequest,
			))
			return
		}
		ownerID = keys[0].ID
	}

	// Verify authorization signature against the owner key
	if err := s.verifySignatureAgainstAuthKey(r, ownerID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"Invalid authorization signature",
			err.Error(),
			http.StatusForbidden,
		))
		return
	}

	// Create condition set
	cs := &types.ConditionSet{
		ID:          uuid.New(),
		Name:        req.Name,
		Description: req.Description,
		Values:      req.Values,
		OwnerID:     ownerID,
	}

	csRepo := storage.NewConditionSetRepository(s.store)
	if err := csRepo.Create(r.Context(), cs); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertConditionSetToResponse(cs)
	s.writeJSON(w, http.StatusCreated, response)
}

// handleUpdateConditionSet updates a condition set
func (s *Server) handleUpdateConditionSet(w http.ResponseWriter, r *http.Request, csID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Verify authorization signature
	if err := s.verifyConditionSetAuthorizationSignature(r, csID, userSub); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
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

	var req UpdateConditionSetRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Get condition set
	csRepo := storage.NewConditionSetRepository(s.store)
	cs, err := csRepo.GetByID(r.Context(), csID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if cs == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Condition set not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Update fields
	if req.Name != nil {
		cs.Name = *req.Name
	}
	if req.Description != nil {
		cs.Description = *req.Description
	}
	if req.Values != nil {
		cs.Values = *req.Values
	}

	// Update in database
	if err := csRepo.Update(r.Context(), cs); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to update condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertConditionSetToResponse(cs)
	s.writeJSON(w, http.StatusOK, response)
}

// handleDeleteConditionSet deletes a condition set
func (s *Server) handleDeleteConditionSet(w http.ResponseWriter, r *http.Request, csID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Verify authorization signature
	if err := s.verifyConditionSetAuthorizationSignature(r, csID, userSub); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
		return
	}

	// Get condition set
	csRepo := storage.NewConditionSetRepository(s.store)
	cs, err := csRepo.GetByID(r.Context(), csID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if cs == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Condition set not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Delete condition set
	if err := csRepo.Delete(r.Context(), csID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to delete condition set",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertConditionSetToResponse converts a condition set to API response format
func convertConditionSetToResponse(cs *types.ConditionSet) ConditionSetResponse {
	return ConditionSetResponse{
		ID:          cs.ID,
		Name:        cs.Name,
		Description: cs.Description,
		Values:      cs.Values,
		OwnerID:     cs.OwnerID,
		CreatedAt:   cs.CreatedAt.UnixMilli(),
		UpdatedAt:   cs.UpdatedAt.UnixMilli(),
	}
}

// verifyConditionSetAuthorizationSignature verifies the authorization signature for condition set operations
func (s *Server) verifyConditionSetAuthorizationSignature(r *http.Request, csID uuid.UUID, userSub string) error {
	// Build canonical payload
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		return err
	}

	// Extract signatures from x-authorization-signature header
	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		return apperrors.New(
			apperrors.ErrCodeUnauthorized,
			"No authorization signatures provided",
			401,
		)
	}

	// Get condition set
	csRepo := storage.NewConditionSetRepository(s.store)
	cs, err := csRepo.GetByID(r.Context(), csID)
	if err != nil || cs == nil {
		return apperrors.New(
			apperrors.ErrCodeNotFound,
			"Condition set not found",
			404,
		)
	}

	// Get the owner authorization key
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	ownerKey, err := authKeyRepo.GetByID(r.Context(), cs.OwnerID)
	if err != nil || ownerKey == nil {
		return apperrors.New(
			apperrors.ErrCodeInternalError,
			"Condition set owner key not found",
			500,
		)
	}

	// Verify the owner key belongs to the authenticated user
	if ownerKey.OwnerEntity != userSub {
		return apperrors.New(
			apperrors.ErrCodeForbidden,
			"You do not own this condition set",
			403,
		)
	}

	// Verify the owner key is active
	if ownerKey.Status != types.StatusActive {
		return apperrors.New(
			apperrors.ErrCodeForbidden,
			"Condition set owner key is not active",
			403,
		)
	}

	// Verify signature with the owner key
	publicKeyPEM, err := auth.PublicKeyToPEM(ownerKey.PublicKey)
	if err != nil {
		return apperrors.New(
			apperrors.ErrCodeInternalError,
			"Failed to parse owner public key",
			500,
		)
	}

	verifier := auth.NewSignatureVerifier()
	for _, sig := range signatures {
		if verified, err := verifier.VerifySignature(sig, canonicalBytes, publicKeyPEM); err == nil && verified {
			return nil
		}
	}

	return apperrors.New(
		apperrors.ErrCodeForbidden,
		"Authorization signature verification failed",
		403,
	)
}
