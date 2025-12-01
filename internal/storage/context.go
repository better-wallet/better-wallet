package storage

import (
	"context"
	"fmt"

	"github.com/google/uuid"
)

// ContextKey is a type for context keys used in storage layer
type ContextKey string

const (
	// AppIDContextKey is the key for app ID in context
	AppIDContextKey ContextKey = "storage_app_id"
)

// ErrMissingAppID is returned when app_id is required but not found in context
var ErrMissingAppID = fmt.Errorf("app_id not found in context - this operation requires app-scoped access")

// WithAppID creates a new context with the given app ID
// This should be called by middleware to set the app scope for all subsequent operations
func WithAppID(ctx context.Context, appID uuid.UUID) context.Context {
	return context.WithValue(ctx, AppIDContextKey, appID)
}

// GetAppID retrieves the app ID from context
// Returns the app ID and true if found, zero UUID and false otherwise
func GetAppID(ctx context.Context) (uuid.UUID, bool) {
	if appID, ok := ctx.Value(AppIDContextKey).(uuid.UUID); ok {
		return appID, true
	}
	return uuid.Nil, false
}

// MustGetAppID retrieves the app ID from context or panics
// Use this only when you're certain the app ID must be present
func MustGetAppID(ctx context.Context) uuid.UUID {
	appID, ok := GetAppID(ctx)
	if !ok {
		panic(ErrMissingAppID)
	}
	return appID
}

// RequireAppID retrieves the app ID from context or returns an error
// This is the preferred way to get app ID in repository methods
func RequireAppID(ctx context.Context) (uuid.UUID, error) {
	appID, ok := GetAppID(ctx)
	if !ok {
		return uuid.Nil, ErrMissingAppID
	}
	return appID, nil
}
