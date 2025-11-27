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

	"github.com/better-wallet/better-wallet/internal/config"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/golang-jwt/jwt/v5"
)

// ContextKey is a type for context keys
type ContextKey string

const (
	// UserSubKey is the context key for the user's subject claim
	UserSubKey ContextKey = "user_sub"
)

// JWKSCache represents a cached JWKS
type JWKSCache struct {
	Keys      map[string]interface{}
	ExpiresAt time.Time
	mu        sync.RWMutex
}

// AuthMiddleware handles JWT/OIDC authentication
type AuthMiddleware struct {
	config     *config.Config
	jwksCache  *JWKSCache
	httpClient *http.Client
}

// NewAuthMiddleware creates a new authentication middleware
func NewAuthMiddleware(cfg *config.Config) *AuthMiddleware {
	return &AuthMiddleware{
		config: cfg,
		jwksCache: &JWKSCache{
			Keys: make(map[string]interface{}),
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// Authenticate is the middleware function that validates JWT tokens
func (m *AuthMiddleware) Authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeError(w, apperrors.ErrUnauthorized)
			return
		}

		// Check for Bearer token
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid authorization header format",
				"Expected 'Bearer <token>'",
				http.StatusUnauthorized,
			))
			return
		}

		tokenString := parts[1]

		// Parse and validate the token
		token, err := m.parseToken(tokenString)
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
		if iss, ok := claims["iss"].(string); !ok || iss != m.config.AuthIssuer {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid issuer",
				fmt.Sprintf("expected %s, got %s", m.config.AuthIssuer, iss),
				http.StatusUnauthorized,
			))
			return
		}

		// Validate audience
		if !m.validateAudience(claims) {
			m.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid audience",
				fmt.Sprintf("expected %s", m.config.AuthAudience),
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

// parseToken parses and validates a JWT token
func (m *AuthMiddleware) parseToken(tokenString string) (*jwt.Token, error) {
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
		key, err := m.getPublicKey(kid)
		if err != nil {
			return nil, fmt.Errorf("failed to get public key: %w", err)
		}

		return key, nil
	})
}

// getPublicKey retrieves a public key from JWKS (with caching)
func (m *AuthMiddleware) getPublicKey(kid string) (interface{}, error) {
	// Check cache first
	m.jwksCache.mu.RLock()
	if key, ok := m.jwksCache.Keys[kid]; ok && time.Now().Before(m.jwksCache.ExpiresAt) {
		m.jwksCache.mu.RUnlock()
		return key, nil
	}
	m.jwksCache.mu.RUnlock()

	// Fetch JWKS
	resp, err := m.httpClient.Get(m.config.AuthJWKSURI)
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

		m.jwksCache.Keys[keyID] = publicKey
	}

	// Set cache expiration (1 hour)
	m.jwksCache.ExpiresAt = time.Now().Add(1 * time.Hour)

	key, ok := m.jwksCache.Keys[kid]
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
func (m *AuthMiddleware) validateAudience(claims jwt.MapClaims) bool {
	aud, ok := claims["aud"]
	if !ok {
		return false
	}

	// Audience can be a string or array of strings
	switch v := aud.(type) {
	case string:
		return v == m.config.AuthAudience
	case []interface{}:
		for _, a := range v {
			if str, ok := a.(string); ok && str == m.config.AuthAudience {
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
// This method can be called directly for validating JWTs outside of middleware
func (m *AuthMiddleware) ValidateJWT(tokenString string) (string, error) {
	// Parse and validate the token
	token, err := m.parseToken(tokenString)
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
	if !ok || iss != m.config.AuthIssuer {
		return "", fmt.Errorf("invalid issuer: expected %s, got %s", m.config.AuthIssuer, iss)
	}

	// Validate audience
	if !m.validateAudience(claims) {
		return "", fmt.Errorf("invalid audience: expected %s", m.config.AuthAudience)
	}

	// Extract subject
	sub, ok := claims["sub"].(string)
	if !ok || sub == "" {
		return "", fmt.Errorf("missing or invalid subject claim")
	}

	return sub, nil
}
