// Package mocks provides mock implementations for testing.
package mocks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MockJWKSServer provides a test JWKS server for JWT validation testing.
type MockJWKSServer struct {
	server *httptest.Server
	mu     sync.RWMutex

	// Key storage
	rsaKeys  map[string]*rsa.PrivateKey
	ecKeys   map[string]*ecdsa.PrivateKey
	keyOrder []string // Order of keys added

	// Configuration
	issuer   string
	audience string

	// Behavior controls
	shouldFail    bool
	delayResponse time.Duration
	statusCode    int
}

// NewMockJWKSServer creates a new mock JWKS server.
func NewMockJWKSServer(issuer, audience string) *MockJWKSServer {
	m := &MockJWKSServer{
		rsaKeys:    make(map[string]*rsa.PrivateKey),
		ecKeys:     make(map[string]*ecdsa.PrivateKey),
		issuer:     issuer,
		audience:   audience,
		statusCode: http.StatusOK,
	}

	m.server = httptest.NewServer(http.HandlerFunc(m.handleJWKS))
	return m
}

// handleJWKS serves the JWKS endpoint.
func (m *MockJWKSServer) handleJWKS(w http.ResponseWriter, r *http.Request) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.delayResponse > 0 {
		time.Sleep(m.delayResponse)
	}

	if m.shouldFail {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error": "mock server failure"}`))
		return
	}

	w.WriteHeader(m.statusCode)
	if m.statusCode != http.StatusOK {
		w.Write([]byte(`{"error": "configured failure"}`))
		return
	}

	jwks := m.buildJWKS()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jwks)
}

// buildJWKS constructs the JWKS response.
func (m *MockJWKSServer) buildJWKS() map[string]interface{} {
	keys := make([]map[string]interface{}, 0)

	// Add RSA keys
	for kid, key := range m.rsaKeys {
		jwk := map[string]interface{}{
			"kty": "RSA",
			"kid": kid,
			"use": "sig",
			"alg": "RS256",
			"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
		}
		keys = append(keys, jwk)
	}

	// Add EC keys
	for kid, key := range m.ecKeys {
		jwk := map[string]interface{}{
			"kty": "EC",
			"kid": kid,
			"use": "sig",
			"alg": "ES256",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(key.PublicKey.X.Bytes()),
			"y":   base64.RawURLEncoding.EncodeToString(key.PublicKey.Y.Bytes()),
		}
		keys = append(keys, jwk)
	}

	return map[string]interface{}{"keys": keys}
}

// AddRSAKey adds an RSA key pair to the JWKS.
func (m *MockJWKSServer) AddRSAKey(kid string) (*rsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	m.rsaKeys[kid] = key
	m.keyOrder = append(m.keyOrder, kid)
	return key, nil
}

// AddECKey adds an ECDSA P-256 key pair to the JWKS.
func (m *MockJWKSServer) AddECKey(kid string) (*ecdsa.PrivateKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EC key: %w", err)
	}

	m.ecKeys[kid] = key
	m.keyOrder = append(m.keyOrder, kid)
	return key, nil
}

// GetRSAKey returns an RSA private key by kid.
func (m *MockJWKSServer) GetRSAKey(kid string) *rsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.rsaKeys[kid]
}

// GetECKey returns an ECDSA private key by kid.
func (m *MockJWKSServer) GetECKey(kid string) *ecdsa.PrivateKey {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ecKeys[kid]
}

// URL returns the JWKS server URL.
func (m *MockJWKSServer) URL() string {
	return m.server.URL
}

// JWKSURI returns the full JWKS URI.
func (m *MockJWKSServer) JWKSURI() string {
	return m.server.URL + "/.well-known/jwks.json"
}

// Issuer returns the configured issuer.
func (m *MockJWKSServer) Issuer() string {
	return m.issuer
}

// Audience returns the configured audience.
func (m *MockJWKSServer) Audience() string {
	return m.audience
}

// SetShouldFail configures the server to fail all requests.
func (m *MockJWKSServer) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

// SetStatusCode sets the HTTP status code to return.
func (m *MockJWKSServer) SetStatusCode(code int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statusCode = code
}

// SetDelayResponse sets a delay before responding.
func (m *MockJWKSServer) SetDelayResponse(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.delayResponse = delay
}

// Close shuts down the test server.
func (m *MockJWKSServer) Close() {
	m.server.Close()
}

// CreateValidJWT creates a valid JWT signed with the first available key.
func (m *MockJWKSServer) CreateValidJWT(subject string, extraClaims map[string]interface{}) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	claims := jwt.MapClaims{
		"iss": m.issuer,
		"aud": m.audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	for k, v := range extraClaims {
		claims[k] = v
	}

	// Use first available key
	for kid, key := range m.rsaKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		return token.SignedString(key)
	}

	for kid, key := range m.ecKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = kid
		return token.SignedString(key)
	}

	return "", fmt.Errorf("no signing keys available")
}

// CreateJWTWithRSAKey creates a JWT signed with a specific RSA key.
func (m *MockJWKSServer) CreateJWTWithRSAKey(kid, subject string, claims jwt.MapClaims) (string, error) {
	m.mu.RLock()
	key, ok := m.rsaKeys[kid]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("RSA key %s not found", kid)
	}

	if claims == nil {
		claims = jwt.MapClaims{}
	}

	claims["iss"] = m.issuer
	claims["aud"] = m.audience
	claims["sub"] = subject
	if claims["iat"] == nil {
		claims["iat"] = time.Now().Unix()
	}
	if claims["exp"] == nil {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

// CreateJWTWithECKey creates a JWT signed with a specific EC key.
func (m *MockJWKSServer) CreateJWTWithECKey(kid, subject string, claims jwt.MapClaims) (string, error) {
	m.mu.RLock()
	key, ok := m.ecKeys[kid]
	m.mu.RUnlock()

	if !ok {
		return "", fmt.Errorf("EC key %s not found", kid)
	}

	if claims == nil {
		claims = jwt.MapClaims{}
	}

	claims["iss"] = m.issuer
	claims["aud"] = m.audience
	claims["sub"] = subject
	if claims["iat"] == nil {
		claims["iat"] = time.Now().Unix()
	}
	if claims["exp"] == nil {
		claims["exp"] = time.Now().Add(1 * time.Hour).Unix()
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

// CreateExpiredJWT creates an expired JWT.
func (m *MockJWKSServer) CreateExpiredJWT(subject string) (string, error) {
	return m.CreateValidJWT(subject, map[string]interface{}{
		"exp": time.Now().Add(-1 * time.Hour).Unix(),
		"iat": time.Now().Add(-2 * time.Hour).Unix(),
	})
}

// CreateJWTWithWrongIssuer creates a JWT with a different issuer.
func (m *MockJWKSServer) CreateJWTWithWrongIssuer(subject string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	claims := jwt.MapClaims{
		"iss": "https://wrong-issuer.example.com",
		"aud": m.audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	for kid, key := range m.rsaKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		token.Header["kid"] = kid
		return token.SignedString(key)
	}

	for kid, key := range m.ecKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		token.Header["kid"] = kid
		return token.SignedString(key)
	}

	return "", fmt.Errorf("no signing keys available")
}

// CreateJWTWithWrongAudience creates a JWT with a different audience.
func (m *MockJWKSServer) CreateJWTWithWrongAudience(subject string) (string, error) {
	return m.CreateValidJWT(subject, map[string]interface{}{
		"aud": "wrong-audience",
	})
}

// CreateJWTWithNoKid creates a JWT without a key ID.
func (m *MockJWKSServer) CreateJWTWithNoKid(subject string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	claims := jwt.MapClaims{
		"iss": m.issuer,
		"aud": m.audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	for _, key := range m.rsaKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		// Don't set kid in header
		return token.SignedString(key)
	}

	for _, key := range m.ecKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
		return token.SignedString(key)
	}

	return "", fmt.Errorf("no signing keys available")
}

// CreateJWTSignedWithWrongKey creates a JWT signed with a key not in JWKS.
func (m *MockJWKSServer) CreateJWTSignedWithWrongKey(subject string) (string, error) {
	// Generate a new key not in the JWKS
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", err
	}

	claims := jwt.MapClaims{
		"iss": m.issuer,
		"aud": m.audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "unknown-kid"
	return token.SignedString(key)
}

// CreateNoneAlgorithmJWT creates a JWT with "alg": "none" (security attack vector).
func (m *MockJWKSServer) CreateNoneAlgorithmJWT(subject string) string {
	// Manually construct a "none" algorithm JWT
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"iss":"%s","aud":"%s","sub":"%s","iat":%d,"exp":%d}`,
		m.issuer, m.audience, subject,
		time.Now().Unix(), time.Now().Add(1*time.Hour).Unix(),
	)))
	return header + "." + payload + "."
}

// CreateHS256WithPublicKeyJWT creates a JWT using HS256 with public key as secret.
// This is a security attack vector (algorithm confusion).
func (m *MockJWKSServer) CreateHS256WithPublicKeyJWT(subject string) (string, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	claims := jwt.MapClaims{
		"iss": m.issuer,
		"aud": m.audience,
		"sub": subject,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(1 * time.Hour).Unix(),
	}

	// Use RSA public key as HMAC secret (attack vector)
	for kid, key := range m.rsaKeys {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		token.Header["kid"] = kid
		// Use the public key bytes as the HMAC secret
		pubKeyBytes := key.PublicKey.N.Bytes()
		return token.SignedString(pubKeyBytes)
	}

	return "", fmt.Errorf("no RSA keys available")
}
