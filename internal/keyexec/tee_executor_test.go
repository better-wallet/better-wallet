package keyexec

import (
	"context"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTEEExecutor(t *testing.T) {
	t.Run("creates executor with dev platform", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:     "dev",
			VsockPort:    5000,
			MasterKeyHex: "test-master-key-32-bytes-long!!",
		}

		executor, err := NewTEEExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
		assert.Equal(t, "dev", executor.Platform())
	})

	t.Run("creates executor with aws-nitro platform", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:     "aws-nitro",
			VsockCID:     3,
			VsockPort:    5000,
			MasterKeyHex: "test-master-key-32-bytes-long!!",
		}

		executor, err := NewTEEExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
		assert.Equal(t, "aws-nitro", executor.Platform())
	})

	t.Run("uses default port when not specified", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:     "dev",
			MasterKeyHex: "test-key",
		}

		executor, err := NewTEEExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
	})

	t.Run("uses default timeout when not specified", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:     "dev",
			MasterKeyHex: "test-key",
		}

		executor, err := NewTEEExecutor(cfg)
		require.NoError(t, err)
		require.NotNil(t, executor)
		assert.Equal(t, 30*time.Second, executor.connectionTimeout)
	})

	t.Run("returns error for unsupported platform", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform: "invalid",
		}

		executor, err := NewTEEExecutor(cfg)
		assert.Error(t, err)
		assert.Nil(t, executor)
		assert.Contains(t, err.Error(), "failed to create TEE dialer")
	})

	t.Run("returns error for aws-nitro without CID", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:  "aws-nitro",
			VsockPort: 5000,
			// VsockCID not set
		}

		executor, err := NewTEEExecutor(cfg)
		assert.Error(t, err)
		assert.Nil(t, executor)
	})
}

func TestTEEExecutor_Platform(t *testing.T) {
	cfg := &TEEConfig{
		Platform:     "dev",
		MasterKeyHex: "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	assert.Equal(t, "dev", executor.Platform())
}

func TestTEEExecutor_EncryptDecrypt(t *testing.T) {
	cfg := &TEEConfig{
		Platform:     "dev",
		MasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("encrypts and decrypts data", func(t *testing.T) {
		plaintext := []byte("Hello, TEE world!")

		ciphertext, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)
		assert.NotEmpty(t, ciphertext)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := executor.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})

	t.Run("encrypts and decrypts empty data", func(t *testing.T) {
		plaintext := []byte{}

		ciphertext, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		decrypted, err := executor.Decrypt(ctx, ciphertext)
		require.NoError(t, err)
		assert.Len(t, decrypted, 0)
	})

	t.Run("different encryptions produce different ciphertexts", func(t *testing.T) {
		plaintext := []byte("Same data")

		cipher1, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		cipher2, err := executor.Encrypt(ctx, plaintext)
		require.NoError(t, err)

		// Due to random nonce, ciphertexts should differ
		assert.NotEqual(t, cipher1, cipher2)
	})
}

// MockEnclaveServer creates a mock TEE enclave server for testing
type MockEnclaveServer struct {
	listener net.Listener
	handler  func(req *EnclaveRequest) *EnclaveResponse
}

func NewMockEnclaveServer(t *testing.T, handler func(req *EnclaveRequest) *EnclaveResponse) (*MockEnclaveServer, int) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &MockEnclaveServer{
		listener: listener,
		handler:  handler,
	}

	go server.serve()

	return server, listener.Addr().(*net.TCPAddr).Port
}

func (s *MockEnclaveServer) serve() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go s.handleConnection(conn)
	}
}

func (s *MockEnclaveServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read request length
	lenBuf := make([]byte, 4)
	if _, err := conn.Read(lenBuf); err != nil {
		return
	}
	reqLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])

	// Read request data
	reqData := make([]byte, reqLen)
	if _, err := conn.Read(reqData); err != nil {
		return
	}

	// Parse request
	var req EnclaveRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		return
	}

	// Handle request
	resp := s.handler(&req)

	// Send response
	respData, _ := json.Marshal(resp)

	// Send length
	respLen := len(respData)
	lenBuf[0] = byte(respLen >> 24)
	lenBuf[1] = byte(respLen >> 16)
	lenBuf[2] = byte(respLen >> 8)
	lenBuf[3] = byte(respLen)
	conn.Write(lenBuf)
	conn.Write(respData)
}

func (s *MockEnclaveServer) Close() {
	s.listener.Close()
}

func TestTEEExecutor_GenerateAndSplitKey(t *testing.T) {
	handler := func(req *EnclaveRequest) *EnclaveResponse {
		if req.Operation == "generate_key" {
			return &EnclaveResponse{
				Success:   true,
				Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
				AuthShare: []byte("mock-auth-share-data-for-testing-purposes"),
			}
		}
		return &EnclaveResponse{Success: false, Error: "unknown operation"}
	}

	server, port := NewMockEnclaveServer(t, handler)
	defer server.Close()

	cfg := &TEEConfig{
		Platform:     "dev",
		VsockPort:    uint32(port),
		MasterKeyHex: "test-master-key-32-bytes-long!!",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("generates key material from enclave", func(t *testing.T) {
		keyMaterial, err := executor.GenerateAndSplitKey(ctx)
		require.NoError(t, err)
		require.NotNil(t, keyMaterial)

		assert.Equal(t, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", keyMaterial.Address)
		assert.NotEmpty(t, keyMaterial.AuthShare)
		assert.Nil(t, keyMaterial.ExecShare) // TEE doesn't return exec share
		assert.Equal(t, 2, keyMaterial.Threshold)
		assert.Equal(t, 2, keyMaterial.TotalShares)
	})
}

func TestTEEExecutor_GenerateAndSplitKey_Error(t *testing.T) {
	handler := func(req *EnclaveRequest) *EnclaveResponse {
		return &EnclaveResponse{
			Success: false,
			Error:   "key generation failed in enclave",
		}
	}

	server, port := NewMockEnclaveServer(t, handler)
	defer server.Close()

	cfg := &TEEConfig{
		Platform:     "dev",
		VsockPort:    uint32(port),
		MasterKeyHex: "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	_, err = executor.GenerateAndSplitKey(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "enclave error")
}

func TestTEEExecutor_SignHash(t *testing.T) {
	// Signature is 65 bytes (r, s, v)
	mockSignature := make([]byte, 65)
	for i := range mockSignature {
		mockSignature[i] = byte(i)
	}

	handler := func(req *EnclaveRequest) *EnclaveResponse {
		if req.Operation == "sign_hash" {
			if len(req.Hash) != 32 {
				return &EnclaveResponse{Success: false, Error: "invalid hash length"}
			}
			if req.Address == "" {
				return &EnclaveResponse{Success: false, Error: "wallet address required"}
			}
			return &EnclaveResponse{
				Success:   true,
				Signature: mockSignature,
			}
		}
		return &EnclaveResponse{Success: false, Error: "unknown operation"}
	}

	server, port := NewMockEnclaveServer(t, handler)
	defer server.Close()

	cfg := &TEEConfig{
		Platform:     "dev",
		VsockPort:    uint32(port),
		MasterKeyHex: "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs hash successfully", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}

		hash := make([]byte, 32)
		signature, err := executor.SignHash(ctx, keyMaterial, hash)
		require.NoError(t, err)
		assert.Equal(t, mockSignature, signature)
	})

	t.Run("returns error for non-32-byte hash", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}

		shortHash := make([]byte, 16)
		_, err := executor.SignHash(ctx, keyMaterial, shortHash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "hash must be exactly 32 bytes")
	})

	t.Run("returns error when address is missing", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			AuthShare: []byte("auth-share"),
			// Address is empty
		}

		hash := make([]byte, 32)
		_, err := executor.SignHash(ctx, keyMaterial, hash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wallet address is required")
	})
}

func TestTEEExecutor_SignMessage(t *testing.T) {
	mockSignature := make([]byte, 65)

	handler := func(req *EnclaveRequest) *EnclaveResponse {
		if req.Operation == "sign_hash" {
			return &EnclaveResponse{
				Success:   true,
				Signature: mockSignature,
			}
		}
		return &EnclaveResponse{Success: false, Error: "unknown operation"}
	}

	server, port := NewMockEnclaveServer(t, handler)
	defer server.Close()

	cfg := &TEEConfig{
		Platform:     "dev",
		VsockPort:    uint32(port),
		MasterKeyHex: "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs message", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}

		message := []byte("Hello, World!")
		signature, err := executor.SignMessage(ctx, keyMaterial, message)
		require.NoError(t, err)
		assert.Equal(t, mockSignature, signature)
	})
}

func TestTEEExecutor_SignTransaction(t *testing.T) {
	// Create a properly signed transaction for mock response
	to := common.HexToAddress("0x742d35Cc6634C0532925a3b844Bc454e4438f44e")
	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(1),
		Nonce:     0,
		GasTipCap: big.NewInt(1000000000),
		GasFeeCap: big.NewInt(2000000000),
		Gas:       21000,
		To:        &to,
		Value:     big.NewInt(1000000000000000000),
	})

	// Get the RLP-encoded transaction (unsigned)
	signedTxBytes, _ := tx.MarshalBinary()

	handler := func(req *EnclaveRequest) *EnclaveResponse {
		if req.Operation == "sign_transaction" {
			if req.Address == "" {
				return &EnclaveResponse{Success: false, Error: "wallet address required"}
			}
			// Return the transaction (in real enclave it would be signed)
			return &EnclaveResponse{
				Success:  true,
				SignedTx: signedTxBytes,
			}
		}
		return &EnclaveResponse{Success: false, Error: "unknown operation"}
	}

	server, port := NewMockEnclaveServer(t, handler)
	defer server.Close()

	cfg := &TEEConfig{
		Platform:     "dev",
		VsockPort:    uint32(port),
		MasterKeyHex: "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("signs transaction", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}

		signedTx, err := executor.SignTransaction(ctx, keyMaterial, tx, 1)
		require.NoError(t, err)
		require.NotNil(t, signedTx)
	})

	t.Run("returns error when address is missing", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			AuthShare: []byte("auth-share"),
		}

		_, err := executor.SignTransaction(ctx, keyMaterial, tx, 1)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "wallet address is required")
	})
}

func TestTEEExecutor_ConnectionFailure(t *testing.T) {
	// Use a port that's not listening
	cfg := &TEEConfig{
		Platform:          "dev",
		VsockPort:         59998,
		ConnectionTimeout: 1 * time.Second,
		MasterKeyHex:      "test-key",
	}

	executor, err := NewTEEExecutor(cfg)
	require.NoError(t, err)

	ctx := context.Background()

	t.Run("generate key fails with connection error", func(t *testing.T) {
		_, err := executor.GenerateAndSplitKey(ctx)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enclave call failed")
	})

	t.Run("sign hash fails with connection error", func(t *testing.T) {
		keyMaterial := &KeyMaterial{
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}
		hash := make([]byte, 32)

		_, err := executor.SignHash(ctx, keyMaterial, hash)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "enclave call failed")
	})
}

func TestTEEConfig(t *testing.T) {
	t.Run("struct initialization", func(t *testing.T) {
		cfg := &TEEConfig{
			Platform:          "aws-nitro",
			VsockCID:          3,
			VsockPort:         5000,
			ConnectionTimeout: 30 * time.Second,
			MasterKeyHex:      "test-master-key",
		}

		assert.Equal(t, "aws-nitro", cfg.Platform)
		assert.Equal(t, uint32(3), cfg.VsockCID)
		assert.Equal(t, uint32(5000), cfg.VsockPort)
		assert.Equal(t, 30*time.Second, cfg.ConnectionTimeout)
		assert.Equal(t, "test-master-key", cfg.MasterKeyHex)
	})
}

func TestEnclaveRequest(t *testing.T) {
	t.Run("JSON marshaling for generate_key", func(t *testing.T) {
		req := EnclaveRequest{
			Operation: "generate_key",
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"operation":"generate_key"`)
	})

	t.Run("JSON marshaling for sign_hash", func(t *testing.T) {
		hash := make([]byte, 32)
		req := EnclaveRequest{
			Operation: "sign_hash",
			AuthShare: []byte("auth-share"),
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			Hash:      hash,
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)

		var decoded EnclaveRequest
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.Equal(t, req.Operation, decoded.Operation)
		assert.Equal(t, req.Address, decoded.Address)
	})

	t.Run("JSON marshaling for sign_transaction", func(t *testing.T) {
		req := EnclaveRequest{
			Operation: "sign_transaction",
			AuthShare: []byte("auth-share"),
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			ChainID:   1,
			TxData: &EnclaveTransactionData{
				Nonce:     0,
				To:        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
				Value:     "1000000000000000000",
				Gas:       21000,
				GasFeeCap: "2000000000",
				GasTipCap: "1000000000",
				Data:      nil,
				ChainID:   1,
			},
		}

		data, err := json.Marshal(req)
		require.NoError(t, err)
		assert.Contains(t, string(data), `"sign_transaction"`)
	})
}

func TestEnclaveResponse(t *testing.T) {
	t.Run("JSON marshaling for success response", func(t *testing.T) {
		resp := EnclaveResponse{
			Success:   true,
			Address:   "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
			AuthShare: []byte("auth-share"),
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded EnclaveResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.True(t, decoded.Success)
		assert.Equal(t, resp.Address, decoded.Address)
	})

	t.Run("JSON marshaling for error response", func(t *testing.T) {
		resp := EnclaveResponse{
			Success: false,
			Error:   "operation failed",
		}

		data, err := json.Marshal(resp)
		require.NoError(t, err)

		var decoded EnclaveResponse
		err = json.Unmarshal(data, &decoded)
		require.NoError(t, err)
		assert.False(t, decoded.Success)
		assert.Equal(t, "operation failed", decoded.Error)
	})
}

func TestTEEKeyMaterial(t *testing.T) {
	t.Run("struct initialization", func(t *testing.T) {
		km := TEEKeyMaterial{
			KeyMaterial: KeyMaterial{
				Address:     "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
				AuthShare:   []byte("auth-share"),
				ExecShare:   nil,
				Threshold:   2,
				TotalShares: 2,
			},
			EnclaveID:       "enclave-123",
			SealedExecShare: []byte("sealed-exec-share"),
		}

		assert.Equal(t, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e", km.Address)
		assert.Equal(t, "enclave-123", km.EnclaveID)
		assert.NotEmpty(t, km.SealedExecShare)
	})
}

func TestAESGCMHelpers(t *testing.T) {
	// AES-256 requires exactly 32 bytes
	key := []byte("test-master-key-32-bytes-long!!!")

	t.Run("encryptAESGCM and decryptAESGCM", func(t *testing.T) {
		plaintext := []byte("Secret data")

		ciphertext, err := encryptAESGCM(key, plaintext)
		require.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)

		decrypted, err := decryptAESGCM(key, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	})
}

// fakeDialer returns a pre-created connection for deterministic tests.
type fakeDialer struct {
	conn     net.Conn
	platform string
}

func (d *fakeDialer) Dial(ctx context.Context) (net.Conn, error) {
	return d.conn, nil
}

func (d *fakeDialer) Platform() string {
	if d.platform == "" {
		return "fake"
	}
	return d.platform
}

func TestTEEExecutor_CallEnclave_ResponseTooLarge(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
			return
		}
		reqLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if reqLen > 0 {
			reqData := make([]byte, reqLen)
			_, _ = io.ReadFull(serverConn, reqData)
		}

		respLen := 10*1024*1024 + 1
		lenBuf[0] = byte(respLen >> 24)
		lenBuf[1] = byte(respLen >> 16)
		lenBuf[2] = byte(respLen >> 8)
		lenBuf[3] = byte(respLen)
		_, _ = serverConn.Write(lenBuf)
	}()

	exec := &TEEExecutor{
		dialer:            &fakeDialer{conn: clientConn, platform: "fake"},
		connectionTimeout: 2 * time.Second,
		masterKey:         make([]byte, 32),
	}

	_, err := exec.callEnclave(context.Background(), &EnclaveRequest{Operation: "generate_key"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "response too large")
}

func TestTEEExecutor_CallEnclave_InvalidJSON(t *testing.T) {
	clientConn, serverConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		lenBuf := make([]byte, 4)
		if _, err := io.ReadFull(serverConn, lenBuf); err != nil {
			return
		}
		reqLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
		if reqLen > 0 {
			reqData := make([]byte, reqLen)
			_, _ = io.ReadFull(serverConn, reqData)
		}

		payload := []byte("not-json")
		lenBuf[0] = byte(len(payload) >> 24)
		lenBuf[1] = byte(len(payload) >> 16)
		lenBuf[2] = byte(len(payload) >> 8)
		lenBuf[3] = byte(len(payload))
		_, _ = serverConn.Write(lenBuf)
		_, _ = serverConn.Write(payload)
	}()

	exec := &TEEExecutor{
		dialer:            &fakeDialer{conn: clientConn, platform: "fake"},
		connectionTimeout: 2 * time.Second,
		masterKey:         make([]byte, 32),
	}

	_, err := exec.callEnclave(context.Background(), &EnclaveRequest{Operation: "generate_key"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to unmarshal response")
}
