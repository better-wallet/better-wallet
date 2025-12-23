package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AuthorizationKeyResponse represents an authorization key in API responses
type AuthorizationKeyResponse struct {
	ID          uuid.UUID `json:"id"`
	PublicKey   string    `json:"public_key"` // hex-encoded
	Algorithm   string    `json:"algorithm"`
	OwnerEntity string    `json:"owner_entity"`
	Status      string    `json:"status"`
	CreatedAt   int64     `json:"created_at"` // Unix timestamp in milliseconds
	RotatedAt   *int64    `json:"rotated_at,omitempty"`
}

// CreateAuthorizationKeyRequest represents the request to create an authorization key
type CreateAuthorizationKeyRequest struct {
	PublicKey   string `json:"public_key"` // hex-encoded P-256 public key
	OwnerEntity string `json:"owner_entity"`
}

// ListAuthorizationKeysResponse for paginated key listing
type ListAuthorizationKeysResponse struct {
	Data       []AuthorizationKeyResponse `json:"data"`
	NextCursor *string                    `json:"next_cursor,omitempty"`
}

// handleAuthorizationKeys handles authorization key list and creation
func (s *Server) handleAuthorizationKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListAuthorizationKeys(w, r)
	case http.MethodPost:
		s.handleCreateAuthorizationKey(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleAuthorizationKeyOperations routes authorization key operations
func (s *Server) handleAuthorizationKeyOperations(w http.ResponseWriter, r *http.Request) {
	// Extract key ID from path: /v1/authorization-keys/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/authorization-keys/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	keyID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid key ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Check for sub-resources
	if len(pathParts) >= 2 {
		switch pathParts[1] {
		case "rotate":
			if r.Method == http.MethodPost {
				s.handleRotateAuthorizationKey(w, r, keyID)
				return
			}
		case "revoke":
			if r.Method == http.MethodPost {
				s.handleRevokeAuthorizationKey(w, r, keyID)
				return
			}
		}
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetAuthorizationKey(w, r, keyID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetAuthorizationKey retrieves a single authorization key by ID
func (s *Server) handleGetAuthorizationKey(w http.ResponseWriter, r *http.Request, keyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
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

	repo := storage.NewAuthorizationKeyRepository(s.store)
	key, err := repo.GetByID(r.Context(), keyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get authorization key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if key == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Authorization key not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership - owner_entity should match user's external_sub
	if key.OwnerEntity != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertAuthorizationKeyToResponse(key)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListAuthorizationKeys lists all authorization keys for the authenticated user
func (s *Server) handleListAuthorizationKeys(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	appID, err := storage.RequireAppID(r.Context())
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing app context",
			err.Error(),
			http.StatusUnauthorized,
		))
		return
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

	// Parse query parameters
	query := r.URL.Query()
	status := query.Get("status")

	// Build query
	sqlQuery := `
		SELECT id, public_key, algorithm, owner_entity, status, created_at, rotated_at
		FROM authorization_keys
		WHERE owner_entity = $1 AND app_id = $2
	`
	args := []interface{}{userSub, appID}

	if status != "" {
		sqlQuery += ` AND status = $3`
		args = append(args, status)
	}

	sqlQuery += ` ORDER BY created_at DESC`

	rows, err := s.store.DB().Query(r.Context(), sqlQuery, args...)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list authorization keys",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	defer rows.Close()

	var keys []AuthorizationKeyResponse
	for rows.Next() {
		var key types.AuthorizationKey
		var publicKeyHex string

		err := rows.Scan(
			&key.ID,
			&publicKeyHex,
			&key.Algorithm,
			&key.OwnerEntity,
			&key.Status,
			&key.CreatedAt,
			&key.RotatedAt,
		)
		if err != nil {
			continue
		}

		publicKeyBytes, err := decodeHexPublicKey(publicKeyHex)
		if err != nil {
			continue
		}
		key.PublicKey = publicKeyBytes

		keys = append(keys, convertAuthorizationKeyToResponse(&key))
	}

	response := ListAuthorizationKeysResponse{
		Data: keys,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleCreateAuthorizationKey creates a new authorization key
func (s *Server) handleCreateAuthorizationKey(w http.ResponseWriter, r *http.Request) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	var req CreateAuthorizationKeyRequest
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
	if req.PublicKey == "" {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Public key is required",
			"",
			http.StatusBadRequest,
		))
		return
	}

	// Default owner_entity to current user if not specified
	if req.OwnerEntity == "" {
		req.OwnerEntity = userSub
	}

	// Only allow users to create keys for themselves
	if req.OwnerEntity != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	// Decode hex public key
	publicKeyBytes, err := decodeHexPublicKey(req.PublicKey)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid public key format",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	appID, err := storage.RequireAppID(r.Context())
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing app context",
			err.Error(),
			http.StatusUnauthorized,
		))
		return
	}

	// Create authorization key
	key := &types.AuthorizationKey{
		ID:          uuid.New(),
		PublicKey:   publicKeyBytes,
		Algorithm:   types.AlgorithmP256,
		OwnerEntity: req.OwnerEntity,
		Status:      types.StatusActive,
		AppID:       &appID,
	}

	repo := storage.NewAuthorizationKeyRepository(s.store)
	if err := repo.Create(r.Context(), key); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to create authorization key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := convertAuthorizationKeyToResponse(key)
	s.writeJSON(w, http.StatusCreated, response)
}

// handleRotateAuthorizationKey rotates an authorization key
func (s *Server) handleRotateAuthorizationKey(w http.ResponseWriter, r *http.Request, keyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get key
	repo := storage.NewAuthorizationKeyRepository(s.store)
	key, err := repo.GetByID(r.Context(), keyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get authorization key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if key == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Authorization key not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership
	if key.OwnerEntity != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	// Rotate key
	if err := repo.RotateKey(r.Context(), keyID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to rotate key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Get updated key
	key, err = repo.GetByID(r.Context(), keyID)
	if err != nil || key == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get rotated key",
			"",
			http.StatusInternalServerError,
		))
		return
	}

	response := convertAuthorizationKeyToResponse(key)
	s.writeJSON(w, http.StatusOK, response)
}

// handleRevokeAuthorizationKey revokes an authorization key
func (s *Server) handleRevokeAuthorizationKey(w http.ResponseWriter, r *http.Request, keyID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get key
	repo := storage.NewAuthorizationKeyRepository(s.store)
	key, err := repo.GetByID(r.Context(), keyID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get authorization key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if key == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"Authorization key not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Verify ownership
	if key.OwnerEntity != userSub {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	// Revoke key
	if err := repo.RevokeKey(r.Context(), keyID); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to revoke key",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// convertAuthorizationKeyToResponse converts an authorization key to API response format
func convertAuthorizationKeyToResponse(key *types.AuthorizationKey) AuthorizationKeyResponse {
	response := AuthorizationKeyResponse{
		ID:          key.ID,
		PublicKey:   encodeHexPublicKey(key.PublicKey),
		Algorithm:   key.Algorithm,
		OwnerEntity: key.OwnerEntity,
		Status:      key.Status,
		CreatedAt:   key.CreatedAt.UnixMilli(),
	}

	if key.RotatedAt != nil {
		rotatedAtMilli := key.RotatedAt.UnixMilli()
		response.RotatedAt = &rotatedAtMilli
	}

	return response
}

// Helper functions for hex encoding/decoding public keys
func encodeHexPublicKey(publicKey []byte) string {
	return "0x" + hex.EncodeToString(publicKey)
}

func decodeHexPublicKey(hexKey string) ([]byte, error) {
	hexKey = strings.TrimSpace(hexKey)
	hexKey = strings.TrimPrefix(hexKey, "0x")
	if hexKey == "" {
		return nil, fmt.Errorf("public key cannot be empty")
	}
	if len(hexKey)%2 != 0 {
		return nil, fmt.Errorf("public key hex must have even length")
	}

	publicKeyBytes, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("public key must be hex-encoded: %w", err)
	}

	// Validate P-256 public key.
	switch len(publicKeyBytes) {
	case 33:
		x, y := elliptic.UnmarshalCompressed(elliptic.P256(), publicKeyBytes)
		if x == nil {
			return nil, fmt.Errorf("invalid P-256 compressed public key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		ecdhPub, err := pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("invalid P-256 compressed public key: %w", err)
		}
		return ecdhPub.Bytes(), nil
	case 65:
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), publicKeyBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid P-256 uncompressed public key: %w", err)
		}
		ecdhPub, err := pub.ECDH()
		if err != nil {
			return nil, fmt.Errorf("invalid P-256 public key: %w", err)
		}
		return ecdhPub.Bytes(), nil
	default:
		return nil, fmt.Errorf("invalid public key length: expected 33 (compressed) or 65 (uncompressed) bytes, got %d", len(publicKeyBytes))
	}
}
