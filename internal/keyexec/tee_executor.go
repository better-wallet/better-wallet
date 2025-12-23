package keyexec

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
)

// TEEExecutor implements KeyExecutor using a Trusted Execution Environment (AWS Nitro Enclave)
//
// Architecture:
// ┌─────────────────────────────────────────────────────────────────┐
// │                     Parent Instance                              │
// │  ┌─────────────────────────────────────────────────────────┐    │
// │  │  TEEExecutor                                             │    │
// │  │  - Sends encrypted shares to enclave via vsock           │    │
// │  │  - Receives signed results                               │    │
// │  └─────────────────────────────────────────────────────────┘    │
// │                          │ vsock                                 │
// └──────────────────────────┼──────────────────────────────────────┘
//
//	↓
//
// ┌─────────────────────────────────────────────────────────────────┐
// │                     Nitro Enclave                                │
// │  ┌─────────────────────────────────────────────────────────┐    │
// │  │  Enclave Application                                     │    │
// │  │  - Receives auth_share from parent                       │    │
// │  │  - Has exec_share sealed in enclave memory               │    │
// │  │  - Combines shares in isolated memory                    │    │
// │  │  - Signs transactions/messages                           │    │
// │  │  - Returns only signature (never the private key)        │    │
// │  └─────────────────────────────────────────────────────────┘    │
// └─────────────────────────────────────────────────────────────────┘
//
// Security Properties:
// - Private key is reconstructed only inside the enclave
// - Parent instance never sees the reconstructed private key
// - Enclave memory is encrypted and isolated from the host
// - exec_share is sealed with enclave's attestation key
type TEEExecutor struct {
	// dialer handles platform-specific connection to the TEE enclave
	dialer TEEDialer

	// connectionTimeout for enclave operations
	connectionTimeout time.Duration

	// masterKey for encrypting shares stored in database
	masterKey []byte
}

// TEEConfig contains configuration for the TEE executor
type TEEConfig struct {
	// Platform specifies which TEE platform to use
	// Supported: "dev" (TCP for development), "aws-nitro" (vsock for Nitro Enclaves)
	// Future: "azure-sgx", "gcp-confidential"
	Platform string

	// VsockCID is the Context ID for AWS Nitro Enclave vsock connection
	// Required when Platform is "aws-nitro"
	VsockCID uint32

	// VsockPort is the port number for the enclave service (default: 5000)
	VsockPort uint32

	// ConnectionTimeout for enclave operations (default: 30s)
	ConnectionTimeout time.Duration

	// MasterKeyHex is the master key for encrypting auth shares in database
	MasterKeyHex string
}

// EnclaveRequest represents a request sent to the enclave
type EnclaveRequest struct {
	Operation string `json:"operation"` // "generate_key", "sign_transaction", "sign_hash"

	// For key generation
	// (no additional fields needed)

	// For signing operations
	AuthShare []byte `json:"auth_share,omitempty"`
	Address   string `json:"address,omitempty"` // Wallet address to look up sealed exec_share
	Hash      []byte `json:"hash,omitempty"`
	ChainID   int64  `json:"chain_id,omitempty"`

	// Transaction data (for sign_transaction)
	TxData *EnclaveTransactionData `json:"tx_data,omitempty"`
}

// EnclaveTransactionData contains transaction fields for signing
type EnclaveTransactionData struct {
	Nonce     uint64 `json:"nonce"`
	To        string `json:"to"`
	Value     string `json:"value"`
	Gas       uint64 `json:"gas"`
	GasFeeCap string `json:"gas_fee_cap"`
	GasTipCap string `json:"gas_tip_cap"`
	Data      []byte `json:"data"`
	ChainID   int64  `json:"chain_id"`
}

// EnclaveResponse represents a response from the enclave
type EnclaveResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`

	// For key generation (2-of-2: only auth_share returned, exec_share sealed in enclave)
	Address   string `json:"address,omitempty"`
	AuthShare []byte `json:"auth_share,omitempty"`

	// For signing operations
	Signature []byte `json:"signature,omitempty"`

	// Signed transaction (RLP-encoded)
	SignedTx []byte `json:"signed_tx,omitempty"`
}

// NewTEEExecutor creates a new TEE executor
func NewTEEExecutor(cfg *TEEConfig) (*TEEExecutor, error) {
	// Set defaults
	if cfg.VsockPort == 0 {
		cfg.VsockPort = 5000
	}
	if cfg.ConnectionTimeout == 0 {
		cfg.ConnectionTimeout = 30 * time.Second
	}

	// Create platform-specific dialer
	dialer, err := NewTEEDialer(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TEE dialer: %w", err)
	}

	// Master key for encrypting auth shares in database
	masterKey := make([]byte, 32)
	copy(masterKey, []byte(cfg.MasterKeyHex))

	return &TEEExecutor{
		dialer:            dialer,
		connectionTimeout: cfg.ConnectionTimeout,
		masterKey:         masterKey,
	}, nil
}

// GenerateAndSplitKey generates a new key inside the enclave
// The enclave:
// 1. Generates private key in isolated memory
// 2. Splits using Shamir's Secret Sharing (2-of-2)
// 3. Seals exec_share with enclave attestation key
// 4. Returns only auth_share to parent (exec_share stays in enclave)
func (t *TEEExecutor) GenerateAndSplitKey(ctx context.Context) (*KeyMaterial, error) {
	req := &EnclaveRequest{
		Operation: "generate_key",
	}

	resp, err := t.callEnclave(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("enclave call failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("enclave error: %s", resp.Error)
	}

	return &KeyMaterial{
		Address:     resp.Address,
		AuthShare:   resp.AuthShare,
		ExecShare:   nil, // Sealed inside enclave, we don't have access
		Threshold:   2,
		TotalShares: 2,
	}, nil
}

// SignTransaction signs a transaction using shares combined inside the enclave
func (t *TEEExecutor) SignTransaction(ctx context.Context, keyMaterial *KeyMaterial, tx *types.Transaction, chainID int64) (*types.Transaction, error) {
	if keyMaterial.Address == "" {
		return nil, fmt.Errorf("wallet address is required for TEE signing")
	}

	to := ""
	if tx.To() != nil {
		to = tx.To().Hex()
	}

	req := &EnclaveRequest{
		Operation: "sign_transaction",
		AuthShare: keyMaterial.AuthShare,
		Address:   keyMaterial.Address,
		ChainID:   chainID,
		TxData: &EnclaveTransactionData{
			Nonce:     tx.Nonce(),
			To:        to,
			Value:     tx.Value().String(),
			Gas:       tx.Gas(),
			GasFeeCap: tx.GasFeeCap().String(),
			GasTipCap: tx.GasTipCap().String(),
			Data:      tx.Data(),
			ChainID:   chainID,
		},
	}

	resp, err := t.callEnclave(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("enclave call failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("enclave error: %s", resp.Error)
	}

	// Decode signed transaction from RLP
	signedTx := new(types.Transaction)
	if err := signedTx.UnmarshalBinary(resp.SignedTx); err != nil {
		return nil, fmt.Errorf("failed to unmarshal signed transaction: %w", err)
	}

	return signedTx, nil
}

// SignMessage signs a raw message (hashes internally)
func (t *TEEExecutor) SignMessage(ctx context.Context, keyMaterial *KeyMaterial, message []byte) ([]byte, error) {
	hash := ethcrypto.Keccak256Hash(message)
	return t.SignHash(ctx, keyMaterial, hash.Bytes())
}

// SignHash signs a pre-hashed 32-byte value
func (t *TEEExecutor) SignHash(ctx context.Context, keyMaterial *KeyMaterial, hash []byte) ([]byte, error) {
	if keyMaterial.Address == "" {
		return nil, fmt.Errorf("wallet address is required for TEE signing")
	}
	if len(hash) != 32 {
		return nil, fmt.Errorf("hash must be exactly 32 bytes, got %d", len(hash))
	}

	req := &EnclaveRequest{
		Operation: "sign_hash",
		AuthShare: keyMaterial.AuthShare,
		Address:   keyMaterial.Address,
		Hash:      hash,
	}

	resp, err := t.callEnclave(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("enclave call failed: %w", err)
	}

	if !resp.Success {
		return nil, fmt.Errorf("enclave error: %s", resp.Error)
	}

	return resp.Signature, nil
}

// Encrypt encrypts data for storage (shares in database)
func (t *TEEExecutor) Encrypt(ctx context.Context, data []byte) ([]byte, error) {
	// Use same AES-GCM encryption as KMS executor for auth shares
	// The exec_share is sealed by the enclave itself
	return encryptAESGCM(t.masterKey, data)
}

// Decrypt decrypts data from storage
func (t *TEEExecutor) Decrypt(ctx context.Context, encryptedData []byte) ([]byte, error) {
	return decryptAESGCM(t.masterKey, encryptedData)
}

// callEnclave sends a request to the enclave and returns the response
func (t *TEEExecutor) callEnclave(ctx context.Context, req *EnclaveRequest) (*EnclaveResponse, error) {
	// Create connection to enclave using platform-specific dialer
	conn, err := t.dialer.Dial(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to enclave (%s): %w", t.dialer.Platform(), err)
	}
	defer conn.Close()

	// Set deadline from context
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(t.connectionTimeout))
	}

	// Encode and send request
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Send length-prefixed message
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(reqData) >> 24)
	lenBuf[1] = byte(len(reqData) >> 16)
	lenBuf[2] = byte(len(reqData) >> 8)
	lenBuf[3] = byte(len(reqData))

	if _, err := conn.Write(lenBuf); err != nil {
		return nil, fmt.Errorf("failed to send request length: %w", err)
	}
	if _, err := conn.Write(reqData); err != nil {
		return nil, fmt.Errorf("failed to send request data: %w", err)
	}

	// Read response length (use io.ReadFull to handle short reads)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read response length: %w", err)
	}
	respLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])

	if respLen > 10*1024*1024 { // 10MB max response
		return nil, fmt.Errorf("response too large: %d bytes", respLen)
	}

	// Read response data (use io.ReadFull to handle short reads)
	respData := make([]byte, respLen)
	if _, err := io.ReadFull(conn, respData); err != nil {
		return nil, fmt.Errorf("failed to read response data: %w", err)
	}

	// Parse response
	var resp EnclaveResponse
	if err := json.Unmarshal(respData, &resp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return &resp, nil
}

// Platform returns the TEE platform being used
func (t *TEEExecutor) Platform() string {
	return t.dialer.Platform()
}

// Helper functions for AES-GCM encryption (uses LocalKMSProvider)
func encryptAESGCM(key, plaintext []byte) ([]byte, error) {
	provider := &LocalKMSProvider{masterKey: key}
	return provider.Encrypt(context.Background(), plaintext)
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	provider := &LocalKMSProvider{masterKey: key}
	return provider.Decrypt(context.Background(), ciphertext)
}

// TEEKeyMaterial extends KeyMaterial with TEE-specific fields
type TEEKeyMaterial struct {
	KeyMaterial

	// EnclaveID identifies which enclave has the sealed exec_share
	EnclaveID string

	// SealedExecShare is the exec_share sealed by the enclave's attestation key
	// This can only be unsealed by the same enclave
	SealedExecShare []byte
}

// Ensure TEEExecutor implements KeyExecutor
var _ KeyExecutor = (*TEEExecutor)(nil)
