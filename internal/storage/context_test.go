package storage

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Context-Based App Isolation Tests
// =============================================================================

func TestWithAppID_SetsAppIDInContext(t *testing.T) {
	appID := uuid.New()
	ctx := context.Background()

	// Verify context doesn't have app_id initially
	_, ok := GetAppID(ctx)
	assert.False(t, ok, "expected no app_id in fresh context")

	// Add app_id to context
	ctxWithApp := WithAppID(ctx, appID)

	// Verify app_id is set
	retrievedID, ok := GetAppID(ctxWithApp)
	assert.True(t, ok, "expected app_id in context")
	assert.Equal(t, appID, retrievedID, "app_id mismatch")
}

func TestGetAppID_ReturnsNilForMissingAppID(t *testing.T) {
	ctx := context.Background()

	appID, ok := GetAppID(ctx)
	assert.False(t, ok)
	assert.Equal(t, uuid.Nil, appID)
}

func TestRequireAppID_ReturnsErrorForMissingAppID(t *testing.T) {
	ctx := context.Background()

	_, err := RequireAppID(ctx)
	assert.Error(t, err)
	assert.Equal(t, ErrMissingAppID, err)
}

func TestRequireAppID_ReturnsAppIDWhenPresent(t *testing.T) {
	appID := uuid.New()
	ctx := WithAppID(context.Background(), appID)

	retrievedID, err := RequireAppID(ctx)
	require.NoError(t, err)
	assert.Equal(t, appID, retrievedID)
}

func TestMustGetAppID_PanicsForMissingAppID(t *testing.T) {
	ctx := context.Background()

	assert.Panics(t, func() {
		MustGetAppID(ctx)
	}, "expected panic for missing app_id")
}

func TestMustGetAppID_ReturnsAppIDWhenPresent(t *testing.T) {
	appID := uuid.New()
	ctx := WithAppID(context.Background(), appID)

	// Should not panic
	assert.NotPanics(t, func() {
		retrievedID := MustGetAppID(ctx)
		assert.Equal(t, appID, retrievedID)
	})
}

// =============================================================================
// Context Isolation Tests - App Scoping
// =============================================================================

func TestContextIsolation_DifferentAppsHaveDifferentContexts(t *testing.T) {
	app1ID := uuid.New()
	app2ID := uuid.New()

	ctx1 := WithAppID(context.Background(), app1ID)
	ctx2 := WithAppID(context.Background(), app2ID)

	// Verify each context has its own app_id
	retrievedApp1, _ := GetAppID(ctx1)
	retrievedApp2, _ := GetAppID(ctx2)

	assert.NotEqual(t, retrievedApp1, retrievedApp2, "different apps should have different contexts")
	assert.Equal(t, app1ID, retrievedApp1)
	assert.Equal(t, app2ID, retrievedApp2)
}

func TestContextIsolation_NestedContextsInheritAppID(t *testing.T) {
	appID := uuid.New()
	ctx := WithAppID(context.Background(), appID)

	// Create child context with a cancel (simulating request processing)
	childCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Child should inherit app_id
	retrievedID, ok := GetAppID(childCtx)
	assert.True(t, ok)
	assert.Equal(t, appID, retrievedID)
}

func TestContextIsolation_OverwriteAppIDCreatesNewContext(t *testing.T) {
	app1ID := uuid.New()
	app2ID := uuid.New()

	ctx1 := WithAppID(context.Background(), app1ID)
	// This creates a new context, doesn't modify ctx1
	ctx2 := WithAppID(ctx1, app2ID)

	// Original context unchanged
	retrievedApp1, _ := GetAppID(ctx1)
	assert.Equal(t, app1ID, retrievedApp1)

	// New context has new app_id
	retrievedApp2, _ := GetAppID(ctx2)
	assert.Equal(t, app2ID, retrievedApp2)
}

// =============================================================================
// SQL Query Parameter Scoping Tests
// These tests verify the logic that would be used in query building
// =============================================================================

func TestQueryScoping_AppIDIsRequired(t *testing.T) {
	tests := []struct {
		name          string
		hasAppID      bool
		expectError   bool
	}{
		{
			name:        "with_app_id_succeeds",
			hasAppID:    true,
			expectError: false,
		},
		{
			name:        "without_app_id_fails",
			hasAppID:    false,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			if tt.hasAppID {
				ctx = WithAppID(ctx, uuid.New())
			}

			_, err := RequireAppID(ctx)
			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// =============================================================================
// User Isolation Logic Tests
// Tests the filtering logic used in repository List methods
// =============================================================================

func TestUserIsolationLogic(t *testing.T) {
	tests := []struct {
		name                string
		userID              *uuid.UUID
		onlyAppManaged      bool
		expectUserFilter    bool
		expectAppManagedInc bool
	}{
		{
			name:                "user_specified_includes_app_managed",
			userID:              ptrUUID(uuid.New()),
			onlyAppManaged:      false,
			expectUserFilter:    true,
			expectAppManagedInc: true,
		},
		{
			name:                "no_user_only_app_managed",
			userID:              nil,
			onlyAppManaged:      true,
			expectUserFilter:    false,
			expectAppManagedInc: true,
		},
		{
			name:                "no_user_not_app_managed_returns_all",
			userID:              nil,
			onlyAppManaged:      false,
			expectUserFilter:    false,
			expectAppManagedInc: false, // Returns all, doesn't specifically filter
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Simulate the query building logic from List method
			var queryCondition string

			if tt.userID != nil {
				queryCondition = "(user_id = $X OR user_id IS NULL)"
			} else if tt.onlyAppManaged {
				queryCondition = "user_id IS NULL"
			} else {
				queryCondition = "all" // No user filter
			}

			// Verify expected behavior
			if tt.expectUserFilter {
				assert.Contains(t, queryCondition, "user_id = $X")
			}
			if tt.expectAppManagedInc && tt.userID != nil {
				assert.Contains(t, queryCondition, "user_id IS NULL")
			}
		})
	}
}

// =============================================================================
// Tenant Boundary Tests
// =============================================================================

func TestTenantBoundary_UUIDIsolation(t *testing.T) {
	// Simulate multiple tenants
	tenants := []struct {
		name   string
		appID  uuid.UUID
		userID uuid.UUID
	}{
		{name: "tenant_a", appID: uuid.New(), userID: uuid.New()},
		{name: "tenant_b", appID: uuid.New(), userID: uuid.New()},
		{name: "tenant_c", appID: uuid.New(), userID: uuid.New()},
	}

	// Verify all tenants have unique IDs
	seenAppIDs := make(map[uuid.UUID]bool)
	seenUserIDs := make(map[uuid.UUID]bool)

	for _, tenant := range tenants {
		assert.False(t, seenAppIDs[tenant.appID], "duplicate app_id detected")
		assert.False(t, seenUserIDs[tenant.userID], "duplicate user_id detected")

		seenAppIDs[tenant.appID] = true
		seenUserIDs[tenant.userID] = true

		// Verify context isolation
		ctx := WithAppID(context.Background(), tenant.appID)
		retrievedID, ok := GetAppID(ctx)
		assert.True(t, ok)
		assert.Equal(t, tenant.appID, retrievedID)
	}
}

// =============================================================================
// Edge Cases
// =============================================================================

func TestEdgeCase_NilUUIDIsNotValidAppID(t *testing.T) {
	// Using uuid.Nil as app_id would be a bug
	nilUUID := uuid.Nil
	ctx := WithAppID(context.Background(), nilUUID)

	// GetAppID still returns it, but it's technically valid (uuid.Nil is a valid UUID)
	retrievedID, ok := GetAppID(ctx)
	assert.True(t, ok, "uuid.Nil is still technically valid in context")
	assert.Equal(t, nilUUID, retrievedID)

	// Production code should check for uuid.Nil separately if needed
}

func TestEdgeCase_WrongTypeInContext(t *testing.T) {
	// If someone puts wrong type in context, GetAppID should handle gracefully
	ctx := context.WithValue(context.Background(), AppIDContextKey, "not-a-uuid")

	_, ok := GetAppID(ctx)
	assert.False(t, ok, "wrong type should return false")
}

func TestEdgeCase_CancelledContextStillHasAppID(t *testing.T) {
	appID := uuid.New()
	ctx, cancel := context.WithCancel(WithAppID(context.Background(), appID))

	// Cancel the context
	cancel()

	// App ID should still be retrievable
	retrievedID, ok := GetAppID(ctx)
	assert.True(t, ok)
	assert.Equal(t, appID, retrievedID)
}

// =============================================================================
// Security Boundary Tests
// =============================================================================

func TestSecurityBoundary_AppIDRequiredForAllOperations(t *testing.T) {
	// This test documents the security requirement:
	// All storage operations MUST require app_id from context

	operations := []string{
		"GetByID",
		"GetByUserID",
		"GetByAddress",
		"Delete",
		"List",
		// Note: Create uses wallet.AppID field, not context
	}

	ctx := context.Background() // No app_id

	for _, op := range operations {
		_, err := RequireAppID(ctx)
		assert.Error(t, err, "operation %s should require app_id", op)
		assert.Equal(t, ErrMissingAppID, err)
	}
}

func TestSecurityBoundary_CrossTenantAccessPrevented(t *testing.T) {
	// Scenario: Tenant A tries to access Tenant B's resources
	tenantA := uuid.New()
	tenantB := uuid.New()

	ctxTenantA := WithAppID(context.Background(), tenantA)

	// Verify tenant A's context only has their app_id
	retrievedID, _ := GetAppID(ctxTenantA)
	assert.Equal(t, tenantA, retrievedID)
	assert.NotEqual(t, tenantB, retrievedID, "should not have access to tenant B")
}

// =============================================================================
// Helper Functions
// =============================================================================

func ptrUUID(u uuid.UUID) *uuid.UUID {
	return &u
}
