// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
)

// MockKMSProvider is a mock implementation of the KMS provider for testing.
type MockKMSProvider struct {
	mu             sync.RWMutex
	masterKey      []byte
	encryptCalls   int
	decryptCalls   int
	shouldFail     bool
	failOnNthCall  int
	callCount      int
	encryptedData  map[string][]byte // Track encrypted data for verification
}

// NewMockKMSProvider creates a new mock KMS provider.
func NewMockKMSProvider() *MockKMSProvider {
	key := make([]byte, 32)
	rand.Read(key)
	return &MockKMSProvider{
		masterKey:     key,
		encryptedData: make(map[string][]byte),
	}
}

// Encrypt encrypts data using AES-GCM (real encryption for realistic testing).
func (m *MockKMSProvider) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.encryptCalls++
	m.callCount++

	if m.shouldFail || (m.failOnNthCall > 0 && m.callCount == m.failOnNthCall) {
		return nil, fmt.Errorf("mock KMS encrypt failure")
	}

	block, err := aes.NewCipher(m.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts data using AES-GCM.
func (m *MockKMSProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.decryptCalls++
	m.callCount++

	if m.shouldFail || (m.failOnNthCall > 0 && m.callCount == m.failOnNthCall) {
		return nil, fmt.Errorf("mock KMS decrypt failure")
	}

	block, err := aes.NewCipher(m.masterKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// Provider returns the provider name.
func (m *MockKMSProvider) Provider() string {
	return "mock"
}

// SetShouldFail configures the mock to fail on all calls.
func (m *MockKMSProvider) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

// SetFailOnNthCall configures the mock to fail on the nth call.
func (m *MockKMSProvider) SetFailOnNthCall(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failOnNthCall = n
	m.callCount = 0
}

// GetEncryptCalls returns the number of encrypt calls.
func (m *MockKMSProvider) GetEncryptCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.encryptCalls
}

// GetDecryptCalls returns the number of decrypt calls.
func (m *MockKMSProvider) GetDecryptCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.decryptCalls
}

// Reset resets the mock state.
func (m *MockKMSProvider) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.encryptCalls = 0
	m.decryptCalls = 0
	m.shouldFail = false
	m.failOnNthCall = 0
	m.callCount = 0
}

// CorruptedKMSProvider returns corrupted data to test error handling.
type CorruptedKMSProvider struct {
	*MockKMSProvider
	corruptDecrypt bool
}

// NewCorruptedKMSProvider creates a provider that returns corrupted data.
func NewCorruptedKMSProvider() *CorruptedKMSProvider {
	return &CorruptedKMSProvider{
		MockKMSProvider: NewMockKMSProvider(),
		corruptDecrypt:  true,
	}
}

// Decrypt returns corrupted data.
func (c *CorruptedKMSProvider) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	if c.corruptDecrypt {
		// Return garbage data
		corrupted := make([]byte, 32)
		rand.Read(corrupted)
		return corrupted, nil
	}
	return c.MockKMSProvider.Decrypt(ctx, ciphertext)
}
