package api

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// PolicyResponse represents a policy in API responses
type PolicyResponse struct {
	ID        uuid.UUID              `json:"id"`
	Name      string                 `json:"name"`
	ChainType string                 `json:"chain_type"`
	Version   string                 `json:"version"`
	Rules     map[string]interface{} `json:"rules"`
	OwnerID   uuid.UUID              `json:"owner_id"`
	CreatedAt int64                  `json:"created_at"` // Unix timestamp in milliseconds
}

// CreatePolicyRequest represents the request to create a policy
type CreatePolicyRequest struct {
	Name      string                 `json:"name"`
	ChainType string                 `json:"chain_type"`
	Rules     map[string]interface{} `json:"rules"`
}

// UpdatePolicyRequest represents the request to update a policy
type UpdatePolicyRequest struct {
	Name  *string                 `json:"name,omitempty"`
	Rules *map[string]interface{} `json:"rules,omitempty"`
}

// ListPoliciesResponse for paginated policy listing
type ListPoliciesResponse struct {
	Data       []PolicyResponse `json:"data"`
	NextCursor *string          `json:"next_cursor,omitempty"`
}

// handlePolicies handles policy list and creation
func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListPolicies(w, r)
	case http.MethodPost:
		s.handleCreatePolicy(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handlePolicyOperations routes policy operations
func (s *Server) handlePolicyOperations(w http.ResponseWriter, r *http.Request) {
	// Extract policy ID from path: /v1/policies/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/policies/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	policyID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid policy ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetPolicy(w, r, policyID)
	case http.MethodPatch:
		s.handleUpdatePolicy(w, r, policyID)
	case http.MethodDelete:
		s.handleDeletePolicy(w, r, policyID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetPolicy retrieves a single policy by ID
func (s *Server) handleGetPolicy(w http.ResponseWriter, r *http.Request, policyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	policyRepo := storage.NewPolicyRepository(s.store)
	policy, err := policyRepo.GetByID(r.Context(), policyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if policy == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Policy not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership
	userRepo := storage.NewUserRepository(s.store)
	user, err := userRepo.GetByExternalSub(r.Context(), userSub)
	if err != nil || user == nil || user.ID != policy.OwnerID {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertPolicyToResponse(policy)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListPolicies lists all policies for the authenticated user
func (s *Server) handleListPolicies(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

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

	// Get all policies owned by this user
	query := `
		SELECT id, name, chain_type, version, rules, owner_id, created_at
		FROM policies
		WHERE owner_id = $1
		ORDER BY created_at DESC
	`

	rows, err := s.store.DB().Query(r.Context(), query, user.ID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list policies",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	defer rows.Close()

	var policies []PolicyResponse
	for rows.Next() {
		var p types.Policy
		var rulesJSON []byte

		err := rows.Scan(
			&p.ID,
			&p.Name,
			&p.ChainType,
			&p.Version,
			&rulesJSON,
			&p.OwnerID,
			&p.CreatedAt,
		)
		if err != nil {
			continue
		}

		if err := json.Unmarshal(rulesJSON, &p.Rules); err != nil {
			continue
		}

		policies = append(policies, convertPolicyToResponse(&p))
	}

	response := ListPoliciesResponse{
		Data: policies,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleCreatePolicy creates a new policy
func (s *Server) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req CreatePolicyRequest
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

	if req.ChainType == "" {
		req.ChainType = types.ChainTypeEthereum
	}

	if req.Rules == nil {
		req.Rules = make(map[string]interface{})
	}

	// Get user
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

	// Create policy
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      req.Name,
		ChainType: req.ChainType,
		Version:   "v1",
		Rules:     req.Rules,
		OwnerID:   user.ID,
	}

	policyRepo := storage.NewPolicyRepository(s.store)
	if err := policyRepo.Create(r.Context(), policy); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertPolicyToResponse(policy)
	s.writeJSON(w, http.StatusCreated, response)
}

// handleUpdatePolicy updates a policy
func (s *Server) handleUpdatePolicy(w http.ResponseWriter, r *http.Request, policyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
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

	var req UpdatePolicyRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Get policy
	policyRepo := storage.NewPolicyRepository(s.store)
	policy, err := policyRepo.GetByID(r.Context(), policyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if policy == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Policy not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership
	userRepo := storage.NewUserRepository(s.store)
	user, err := userRepo.GetByExternalSub(r.Context(), userSub)
	if err != nil || user == nil || user.ID != policy.OwnerID {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	// Update fields
	if req.Name != nil {
		policy.Name = *req.Name
	}
	if req.Rules != nil {
		policy.Rules = *req.Rules
	}

	// Update in database
	rulesJSON, err := json.Marshal(policy.Rules)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to marshal rules",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	query := `
		UPDATE policies
		SET name = $1, rules = $2
		WHERE id = $3
	`
	_, err = s.store.DB().Exec(r.Context(), query, policy.Name, rulesJSON, policyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to update policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertPolicyToResponse(policy)
	s.writeJSON(w, http.StatusOK, response)
}

// handleDeletePolicy deletes a policy
func (s *Server) handleDeletePolicy(w http.ResponseWriter, r *http.Request, policyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get policy
	policyRepo := storage.NewPolicyRepository(s.store)
	policy, err := policyRepo.GetByID(r.Context(), policyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if policy == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Policy not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership
	userRepo := storage.NewUserRepository(s.store)
	user, err := userRepo.GetByExternalSub(r.Context(), userSub)
	if err != nil || user == nil || user.ID != policy.OwnerID {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	// Delete policy
	query := `DELETE FROM policies WHERE id = $1`
	_, err = s.store.DB().Exec(r.Context(), query, policyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to delete policy",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertPolicyToResponse converts a policy to API response format
func convertPolicyToResponse(p *types.Policy) PolicyResponse {
	return PolicyResponse{
		ID:        p.ID,
		Name:      p.Name,
		ChainType: p.ChainType,
		Version:   p.Version,
		Rules:     p.Rules,
		OwnerID:   p.OwnerID,
		CreatedAt: p.CreatedAt.UnixMilli(),
	}
}
