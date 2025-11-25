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
	OwnerID   *uuid.UUID             `json:"owner_id,omitempty"` // Authorization key ID that will own this policy
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

	// Verify ownership - check if the policy's owner key belongs to the authenticated user
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	ownerKey, err := authKeyRepo.GetByID(r.Context(), policy.OwnerID)
	if err != nil || ownerKey == nil || ownerKey.OwnerEntity != userSub {
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
		response := ListPoliciesResponse{
			Data: []PolicyResponse{},
		}
		s.writeJSON(w, http.StatusOK, response)
		return
	}

	// Get all policies owned by user's authorization keys
	query := `
		SELECT id, name, chain_type, version, rules, owner_id, created_at
		FROM policies
		WHERE owner_id = ANY($1)
		ORDER BY created_at DESC
	`

	rows, err := s.store.DB().Query(r.Context(), query, keyIDs)
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
				"Cannot create policy with another user's authorization key",
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

	// Create policy
	policy := &types.Policy{
		ID:        uuid.New(),
		Name:      req.Name,
		ChainType: req.ChainType,
		Version:   "v1",
		Rules:     req.Rules,
		OwnerID:   ownerID,
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

	// Verify authorization signature
	if err := s.verifyPolicyAuthorizationSignature(r, policyID, userSub); err != nil {
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

	// Verify authorization signature
	if err := s.verifyPolicyAuthorizationSignature(r, policyID, userSub); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
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

// verifyPolicyAuthorizationSignature verifies the authorization signature for policy operations
// Validates signature against the policy's owner authorization key
func (s *Server) verifyPolicyAuthorizationSignature(r *http.Request, policyID uuid.UUID, userSub string) error {
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

	// Get policy
	policyRepo := storage.NewPolicyRepository(s.store)
	policy, err := policyRepo.GetByID(r.Context(), policyID)
	if err != nil || policy == nil {
		return apperrors.New(
			apperrors.ErrCodeNotFound,
			"Policy not found",
			404,
		)
	}

	// Get the owner authorization key
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	ownerKey, err := authKeyRepo.GetByID(r.Context(), policy.OwnerID)
	if err != nil || ownerKey == nil {
		return apperrors.New(
			apperrors.ErrCodeInternalError,
			"Policy owner key not found",
			500,
		)
	}

	// Verify the owner key belongs to the authenticated user
	if ownerKey.OwnerEntity != userSub {
		return apperrors.New(
			apperrors.ErrCodeForbidden,
			"You do not own this policy",
			403,
		)
	}

	// Verify the owner key is active
	if ownerKey.Status != types.StatusActive {
		return apperrors.New(
			apperrors.ErrCodeForbidden,
			"Policy owner key is not active",
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

// verifySignatureAgainstAuthKey verifies authorization signature against an auth key
func (s *Server) verifySignatureAgainstAuthKey(r *http.Request, authKeyID uuid.UUID) error {
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

	// Get the authorization key
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	authKey, err := authKeyRepo.GetByID(r.Context(), authKeyID)
	if err != nil || authKey == nil {
		return apperrors.New(
			apperrors.ErrCodeNotFound,
			"Authorization key not found",
			404,
		)
	}

	// Verify signature with the auth key
	publicKeyPEM, err := auth.PublicKeyToPEM(authKey.PublicKey)
	if err != nil {
		return apperrors.New(
			apperrors.ErrCodeInternalError,
			"Failed to parse public key",
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
