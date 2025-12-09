// Package mocks provides mock implementations for testing.
package mocks

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// MockTEEDialer implements TEEDialer interface for testing.
type MockTEEDialer struct {
	mu sync.RWMutex

	// Connection tracking
	dialCalls    int
	connections  []*MockTEEConnection
	shouldFail   bool
	failOnNthCall int
	callCount    int

	// Behavior controls
	connectDelay time.Duration
	platform     string
}

// NewMockTEEDialer creates a new mock TEE dialer.
func NewMockTEEDialer() *MockTEEDialer {
	return &MockTEEDialer{
		platform: "mock-tee",
	}
}

// Dial creates a mock connection to the TEE enclave.
func (m *MockTEEDialer) Dial(ctx context.Context) (net.Conn, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.dialCalls++
	m.callCount++

	if m.shouldFail || (m.failOnNthCall > 0 && m.callCount == m.failOnNthCall) {
		return nil, fmt.Errorf("mock TEE dial failure")
	}

	if m.connectDelay > 0 {
		time.Sleep(m.connectDelay)
	}

	conn := NewMockTEEConnection()
	m.connections = append(m.connections, conn)
	return conn, nil
}

// Platform returns the TEE platform name.
func (m *MockTEEDialer) Platform() string {
	return m.platform
}

// SetShouldFail configures the mock to fail all dial attempts.
func (m *MockTEEDialer) SetShouldFail(fail bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.shouldFail = fail
}

// SetFailOnNthCall configures the mock to fail on the nth call.
func (m *MockTEEDialer) SetFailOnNthCall(n int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failOnNthCall = n
	m.callCount = 0
}

// SetConnectDelay sets a delay before returning connections.
func (m *MockTEEDialer) SetConnectDelay(delay time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connectDelay = delay
}

// GetDialCalls returns the number of dial calls.
func (m *MockTEEDialer) GetDialCalls() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.dialCalls
}

// GetLastConnection returns the most recent connection.
func (m *MockTEEDialer) GetLastConnection() *MockTEEConnection {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if len(m.connections) == 0 {
		return nil
	}
	return m.connections[len(m.connections)-1]
}

// Reset resets the mock state.
func (m *MockTEEDialer) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialCalls = 0
	m.callCount = 0
	m.shouldFail = false
	m.failOnNthCall = 0
	m.connections = nil
}

// MockTEEConnection implements net.Conn for testing TEE communication.
type MockTEEConnection struct {
	mu sync.Mutex

	// Data buffers
	readBuffer  []byte
	writeBuffer []byte
	responses   [][]byte // Pre-configured responses

	// State tracking
	closed        bool
	readDeadline  time.Time
	writeDeadline time.Time

	// Behavior controls
	shouldFailRead  bool
	shouldFailWrite bool
	readDelay       time.Duration
	writeDelay      time.Duration
}

// NewMockTEEConnection creates a new mock TEE connection.
func NewMockTEEConnection() *MockTEEConnection {
	return &MockTEEConnection{
		responses: make([][]byte, 0),
	}
}

// Read reads data from the mock connection.
func (c *MockTEEConnection) Read(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, io.EOF
	}

	if c.shouldFailRead {
		return 0, fmt.Errorf("mock read failure")
	}

	if c.readDelay > 0 {
		time.Sleep(c.readDelay)
	}

	// Check deadline
	if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
		return 0, fmt.Errorf("read deadline exceeded")
	}

	// Return pre-configured responses first
	if len(c.responses) > 0 {
		resp := c.responses[0]
		c.responses = c.responses[1:]
		n := copy(b, resp)
		return n, nil
	}

	// Otherwise return from read buffer
	if len(c.readBuffer) == 0 {
		return 0, io.EOF
	}

	n := copy(b, c.readBuffer)
	c.readBuffer = c.readBuffer[n:]
	return n, nil
}

// Write writes data to the mock connection.
func (c *MockTEEConnection) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.closed {
		return 0, fmt.Errorf("connection closed")
	}

	if c.shouldFailWrite {
		return 0, fmt.Errorf("mock write failure")
	}

	if c.writeDelay > 0 {
		time.Sleep(c.writeDelay)
	}

	// Check deadline
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, fmt.Errorf("write deadline exceeded")
	}

	c.writeBuffer = append(c.writeBuffer, b...)
	return len(b), nil
}

// Close closes the mock connection.
func (c *MockTEEConnection) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}

// LocalAddr returns the local network address.
func (c *MockTEEConnection) LocalAddr() net.Addr {
	return &mockAddr{network: "mock-tee", address: "local"}
}

// RemoteAddr returns the remote network address.
func (c *MockTEEConnection) RemoteAddr() net.Addr {
	return &mockAddr{network: "mock-tee", address: "enclave"}
}

// SetDeadline sets the read and write deadlines.
func (c *MockTEEConnection) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline sets the read deadline.
func (c *MockTEEConnection) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline sets the write deadline.
func (c *MockTEEConnection) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// AddResponse adds a pre-configured response to return on Read.
func (c *MockTEEConnection) AddResponse(data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.responses = append(c.responses, data)
}

// AddJSONResponse adds a JSON-encoded response.
func (c *MockTEEConnection) AddJSONResponse(v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	c.AddResponse(data)
	return nil
}

// GetWrittenData returns all data written to the connection.
func (c *MockTEEConnection) GetWrittenData() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writeBuffer
}

// SetShouldFailRead configures read operations to fail.
func (c *MockTEEConnection) SetShouldFailRead(fail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shouldFailRead = fail
}

// SetShouldFailWrite configures write operations to fail.
func (c *MockTEEConnection) SetShouldFailWrite(fail bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.shouldFailWrite = fail
}

// SetReadDelay sets a delay before read operations complete.
func (c *MockTEEConnection) SetReadDelay(delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDelay = delay
}

// SetWriteDelay sets a delay before write operations complete.
func (c *MockTEEConnection) SetWriteDelay(delay time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDelay = delay
}

// IsClosed returns whether the connection is closed.
func (c *MockTEEConnection) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

// mockAddr implements net.Addr for mock connections.
type mockAddr struct {
	network string
	address string
}

func (a *mockAddr) Network() string {
	return a.network
}

func (a *mockAddr) String() string {
	return a.address
}

// TEEEnclaveResponse represents a mock enclave response.
type TEEEnclaveResponse struct {
	Success   bool   `json:"success"`
	Data      []byte `json:"data,omitempty"`
	Error     string `json:"error,omitempty"`
	Signature []byte `json:"signature,omitempty"`
}

// MockTEEEnclaveServer simulates a TEE enclave server for testing.
type MockTEEEnclaveServer struct {
	mu sync.RWMutex

	// Key storage (simulates sealed keys in enclave)
	sealedKeys map[string][]byte

	// Behavior controls
	shouldFail          bool
	attestationRequired bool
	attestationValid    bool
}

// NewMockTEEEnclaveServer creates a new mock enclave server.
func NewMockTEEEnclaveServer() *MockTEEEnclaveServer {
	return &MockTEEEnclaveServer{
		sealedKeys:       make(map[string][]byte),
		attestationValid: true,
	}
}

// SealKey simulates sealing a key in the enclave.
func (s *MockTEEEnclaveServer) SealKey(keyID string, keyData []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.shouldFail {
		return fmt.Errorf("mock seal failure")
	}

	s.sealedKeys[keyID] = keyData
	return nil
}

// UnsealKey simulates unsealing a key from the enclave.
func (s *MockTEEEnclaveServer) UnsealKey(keyID string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.shouldFail {
		return nil, fmt.Errorf("mock unseal failure")
	}

	if s.attestationRequired && !s.attestationValid {
		return nil, fmt.Errorf("attestation failed")
	}

	key, ok := s.sealedKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return key, nil
}

// SetShouldFail configures the mock to fail all operations.
func (s *MockTEEEnclaveServer) SetShouldFail(fail bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shouldFail = fail
}

// SetAttestationRequired configures whether attestation is required.
func (s *MockTEEEnclaveServer) SetAttestationRequired(required bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestationRequired = required
}

// SetAttestationValid configures whether attestation should pass.
func (s *MockTEEEnclaveServer) SetAttestationValid(valid bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attestationValid = valid
}

// HasKey returns whether a key exists in the enclave.
func (s *MockTEEEnclaveServer) HasKey(keyID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sealedKeys[keyID]
	return ok
}

// DeleteKey removes a key from the enclave.
func (s *MockTEEEnclaveServer) DeleteKey(keyID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sealedKeys, keyID)
}

// Reset clears all state.
func (s *MockTEEEnclaveServer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sealedKeys = make(map[string][]byte)
	s.shouldFail = false
	s.attestationRequired = false
	s.attestationValid = true
}
