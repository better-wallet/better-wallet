package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	// UserSubKey is the context key for the user's subject claim
	UserSubKey ContextKey = "user_sub"
)

// JWKSCache represents a cached JWKS per issuer
type JWKSCache struct {
	// Map of issuer -> (kid -> public key)
	Keys      map[string]map[string]interface{}
	ExpiresAt map[string]time.Time
	mu        sync.RWMutex
}

// AuthMiddleware handles JWT/OIDC authentication using per-app settings
type AuthMiddleware struct {
	jwksCache  *JWKSCache
	httpClient *http.Client
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware() *AuthMiddleware {
	return &AuthMiddleware{
		jwksCache: &JWKSCache{
			Keys:      make(map[string]map[string]interface{}),
			ExpiresAt: make(map[string]time.Time),
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Authenticate is the middleware function that validates JWT tokens
// It reads auth configuration from App.Settings (set by AppAuthMiddleware)
// For app-managed operations (no Bearer token), this middleware passes through
// without setting user_sub, indicating an app-only authenticated request.
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get app from context (set by AppAuthMiddleware)
		app := GetApp(r.Context())
		if app == nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"App context not found",
				"AppAuthMiddleware must run before AuthMiddleware",
				http.StatusUnauthorized,
			))
			return
		}

		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")

		// Check for Bearer token - if no Bearer token present, this is an app-only request
		// App authentication was already done by AppAuthMiddleware
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			// No Bearer token - pass through for app-managed operations
			// The handler should check for user_sub to determine if user context is required
			next.ServeHTTP(w, r)
			return
		}

		// Get auth settings from app for JWT validation
		authSettings := app.Settings.Auth
		if authSettings == nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Auth not configured",
				"App does not have auth settings configured for user authentication",
				http.StatusUnauthorized,
			))
			return
		}

		tokenString := parts[1]

		// Parse and validate the token
		token, err := m.parseToken(tokenString, authSettings)
		if err != nil {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid token",
				err.Error(),
				http.StatusUnauthorized,
			))
			return
		}

		// Extract claims
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok || !token.Valid {
			m.writeError(w, apperrors.ErrUnauthorized)
			return
		}

		// Validate issuer
		if iss, ok := claims["iss"].(string); !ok || iss != authSettings.Issuer {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid issuer",
				fmt.Sprintf("expected %s, got %s", authSettings.Issuer, iss),
				http.StatusUnauthorized,
			))
			return
		}

		// Validate audience
		if !m.validateAudience(claims, authSettings.Audience) {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid audience",
				fmt.Sprintf("expected %s", authSettings.Audience),
				http.StatusUnauthorized,
			))
			return
		}

		// Extract subject
		sub, ok := claims["sub"].(string)
		if !ok || sub == "" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Missing subject claim",
				"",
				http.StatusUnauthorized,
			))
			return
		}

		// Add subject to context
		ctx := context.WithValue(r.Context(), UserSubKey, sub)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// parseToken parses and validates a JWT token using app-specific settings
func (m *AuthMiddleware) parseToken(tokenString string, authSettings *types.AppAuthSettings) (*jwt.Token, error) {
	return jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
		}

		// Get the key ID from the token header
		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Get the public key from JWKS
		key, err := m.getPublicKey(kid, authSettings.JWKSURI)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}

		return key, nil
	})
}

// getPublicKey retrieves a public key from JWKS (with caching per issuer)
func (m *AuthMiddleware) getPublicKey(kid, jwksURI string) (interface{}, error) {
	// Check cache first
	m.jwksCache.mu.RLock()
	if keys, ok := m.jwksCache.Keys[jwksURI]; ok {
		if key, found := keys[kid]; found && time.Now().Before(m.jwksCache.ExpiresAt[jwksURI]) {
			m.jwksCache.mu.RUnlock()
			return key, nil
		}
	}
	m.jwksCache.mu.RUnlock()

	// Fetch JWKS
	resp, err := m.httpClient.Get(jwksURI)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned status %d", resp.StatusCode)
	}

	var jwks struct {
		Keys []map[string]interface{} `json:"keys"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}

	// Parse and cache keys
	m.jwksCache.mu.Lock()
	defer m.jwksCache.mu.Unlock()

	if m.jwksCache.Keys[jwksURI] == nil {
		m.jwksCache.Keys[jwksURI] = make(map[string]interface{})
	}

	for _, jwk := range jwks.Keys {
		keyID, ok := jwk["kid"].(string)
		if !ok {
			continue
		}

		// Parse the key based on key type
		kty, ok := jwk["kty"].(string)
		if !ok {
			continue
		}

		var publicKey interface{}
		var parseErr error

		switch kty {
		case "RSA":
			publicKey, parseErr = m.parseRSAKey(jwk)
		case "EC":
			publicKey, parseErr = m.parseECKey(jwk)
		default:
			continue
		}

		if parseErr != nil {
			continue
		}

		m.jwksCache.Keys[jwksURI][keyID] = publicKey
	}

	// Set cache expiration (1 hour)
	m.jwksCache.ExpiresAt[jwksURI] = time.Now().Add(1 * time.Hour)

	key, ok := m.jwksCache.Keys[jwksURI][kid]
	if !ok {
		return nil, fmt.Errorf("key %s not found in JWKS", kid)
	}

	return key, nil
}

// parseRSAKey parses an RSA public key from JWK format
func (m *AuthMiddleware) parseRSAKey(jwk map[string]interface{}) (*rsa.PublicKey, error) {
	nStr, ok := jwk["n"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'n' parameter")
	}

	eStr, ok := jwk["e"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'e' parameter")
	}

	// Decode base64url-encoded values
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode n: %w", err)
	}

	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode e: %w", err)
	}

	// Convert to big integers
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}

// parseECKey parses an EC public key from JWK format
func (m *AuthMiddleware) parseECKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, ok := jwk["crv"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'crv' parameter")
	}

	xStr, ok := jwk["x"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'x' parameter")
	}

	yStr, ok := jwk["y"].(string)
	if !ok {
		return nil, fmt.Errorf("missing 'y' parameter")
	}

	// Decode coordinates
	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode x: %w", err)
	}

	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("failed to decode y: %w", err)
	}

	x := new(big.Int).SetBytes(xBytes)
	y := new(big.Int).SetBytes(yBytes)

	// Determine curve
	var c elliptic.Curve
	switch crv {
	case "P-256":
		c = elliptic.P256()
	case "P-384":
		c = elliptic.P384()
	case "P-521":
		c = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported curve: %s", crv)
	}

	return &ecdsa.PublicKey{
		Curve: c,
		X:     x,
		Y:     y,
	}, nil
}

// validateAudience checks if the token's audience matches the expected audience
func (m *AuthMiddleware) validateAudience(claims jwt.MapClaims, expectedAudience string) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}

	// Audience can be a string or array of strings
	switch v := aud.(type) {
	case string:
		return v == expectedAudience
	case []interface{}:
		for _, a := range v {
			if str, ok := a.(string); ok && str == expectedAudience {
				return true
			}
		}
	}

	return false
}

// writeError writes an error response
func (m *AuthMiddleware) writeError(w http.ResponseWriter, err *apperrors.AppError) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(err.StatusCode)
	json.NewEncoder(w).Encode(err)
}

// GetUserSub extracts the user subject from the request context
func GetUserSub(ctx context.Context) (string, bool) {
	sub, ok := ctx.Value(UserSubKey).(string)
	return sub, ok
}

// ValidateJWT validates a JWT token and returns the subject claim
// This method requires auth settings from the app
func (m *AuthMiddleware) ValidateJWT(tokenString string, authSettings *types.AppAuthSettings) (string, error) {
	if authSettings == nil {
		return "", fmt.Errorf("auth settings not configured")
	}

	// Parse and validate the token
	token, err := m.parseToken(tokenString, authSettings)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	// Extract claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return "", fmt.Errorf("invalid token claims")
	}

	// Validate issuer
	iss, ok := claims["iss"].(string)
	if !ok || iss != authSettings.Issuer {
		return "", fmt.Errorf("invalid issuer: expected %s, got %s", authSettings.Issuer, iss)
	}

	// Validate audience
	if !m.validateAudience(claims, authSettings.Audience) {
		return "", fmt.Errorf("invalid audience: expected %s", authSettings.Audience)
	}

	// Extract subject
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("missing or invalid subject claim")
	}

	return sub, nil
}
