package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/better-wallet/better-wallet/internal/storage"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// UserResponse represents a user in API responses
type UserResponse struct {
	ID          uuid.UUID `json:"id"`
	ExternalSub string    `json:"external_sub"`
	CreatedAt   int64     `json:"created_at"` // Unix timestamp in milliseconds
}

// ListUsersResponse for paginated user listing
type ListUsersResponse struct {
	Data       []UserResponse `json:"data"`
	NextCursor *string        `json:"next_cursor,omitempty"`
}

// handleUsers handles user list operations
func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListUsers(w, r)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleUserOperations routes user operations
func (s *Server) handleUserOperations(w http.ResponseWriter, r *http.Request) {
	// Extract user ID from path: /v1/users/{id}
	pathParts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/users/"), "/")
	if len(pathParts) < 1 || pathParts[0] == "" {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	userID, err := uuid.Parse(pathParts[0])
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid user ID",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	switch r.Method {
	case http.MethodGet:
		s.handleGetUser(w, r, userID)
	default:
		s.writeError(w, apperrors.New(
			apperrors.ErrCodeBadRequest,
			"Method not allowed",
			http.StatusMethodNotAllowed,
		))
	}
}

// handleGetUser retrieves a single user by ID
func (s *Server) handleGetUser(w http.ResponseWriter, r *http.Request, userID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	repo := storage.NewUserRepository(s.store)
	user, err := repo.GetByID(r.Context(), userID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get user",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if user == nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotFound,
			"User not found",
			"",
			http.StatusNotFound,
		))
		return
	}

	// Only allow users to access their own information
	currentUser, err := repo.GetByExternalSub(r.Context(), userSub)
	if err != nil || currentUser == nil || currentUser.ID != user.ID {
		s.writeError(w, apperrors.ErrForbidden)
		return
	}

	response := convertUserToResponse(user)
	s.writeJSON(w, http.StatusOK, response)
}

// handleListUsers lists users who have wallets in the current app
// Only returns users who have at least one wallet belonging to the current app
func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	_, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	// Get app_id from context (set by app auth middleware)
	appID, err := storage.RequireAppID(r.Context())
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"App authentication required",
			err.Error(),
			http.StatusUnauthorized,
		))
		return
	}

	// Parse query parameters
	query := r.URL.Query()
	cursor := query.Get("cursor")
	limitStr := query.Get("limit")
	limit := 20
	if limitStr != "" {
		if l, err := strconv.Atoi(limitStr); err == nil && l > 0 && l <= 100 {
			limit = l
		}
	}

	// Query users who have wallets in this app
	// This ensures multi-tenant isolation: only users with wallets in the current app are visible
	sqlQuery := `
		SELECT DISTINCT u.id, u.external_sub, u.created_at
		FROM users u
		INNER JOIN wallets w ON u.id = w.user_id
		WHERE w.app_id = $1
	`
	args := []interface{}{appID}
	argIdx := 2

	if cursor != "" {
		// Parse cursor as Unix milliseconds and convert to time.Time
		cursorMillis, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid cursor",
				"Cursor must be a valid Unix timestamp in milliseconds",
				http.StatusBadRequest,
			))
			return
		}
		cursorTime := time.UnixMilli(cursorMillis)
		sqlQuery += ` AND u.created_at < $` + strconv.Itoa(argIdx)
		args = append(args, cursorTime)
		argIdx++
	}

	sqlQuery += ` ORDER BY u.created_at DESC LIMIT $` + strconv.Itoa(argIdx)
	args = append(args, limit+1) // Fetch one extra to determine if there's a next page

	rows, err := s.store.DB().Query(r.Context(), sqlQuery, args...)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to list users",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	defer rows.Close()

	var users []UserResponse
	for rows.Next() {
		var u types.User
		err := rows.Scan(
			&u.ID,
			&u.ExternalSub,
			&u.CreatedAt,
		)
		if err != nil {
			continue
		}
		users = append(users, convertUserToResponse(&u))
	}

	// Determine next cursor
	var nextCursor *string
	if len(users) > limit {
		users = users[:limit]
		cursorVal := users[len(users)-1].CreatedAt
		cursorStr := strconv.FormatInt(cursorVal, 10)
		nextCursor = &cursorStr
	}

	response := ListUsersResponse{
		Data:       users,
		NextCursor: nextCursor,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// convertUserToResponse converts a user to API response format
func convertUserToResponse(u *types.User) UserResponse {
	return UserResponse{
		ID:          u.ID,
		ExternalSub: u.ExternalSub,
		CreatedAt:   u.CreatedAt.UnixMilli(),
	}
}
