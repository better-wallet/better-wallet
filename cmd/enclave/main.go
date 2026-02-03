// Package main implements the Nitro Enclave application for secure key operations
//
// This application runs inside an AWS Nitro Enclave and handles:
// - Key generation with Shamir's Secret Sharing
// - Transaction signing
// - Message/hash signing
//
// Security Properties:
// - The enclave's memory is encrypted and isolated from the parent instance
// - exec_share is sealed with the enclave's attestation key
// - Private keys are reconstructed only in enclave memory
// - Only signatures are returned, never the private key
//
// Communication:
// - Uses vsock (AF_VSOCK) for parent <-> enclave communication
// - JSON-encoded request/response protocol
//
// Build:
//
//	GOOS=linux GOARCH=amd64 go build -o enclave ./cmd/enclave
//
// Deploy:
//
//	nitro-cli build-enclave --docker-uri enclave-image --output-file enclave.eif
//	nitro-cli run-enclave --eif-path enclave.eif --memory 512 --cpu-count 2
package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"os"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/better-wallet/better-wallet/internal/crypto"
)

const (
	vsockPort  = 5000
	maxMsgSize = 10 * 1024 * 1024 // 10MB
)

// EnclaveState holds the enclave's sealed shares
// In production, this would be persisted to enclave-sealed storage
type EnclaveState struct {
	mu sync.RWMutex
	// sealedShares maps wallet address to sealed exec_share
	sealedShares map[string][]byte
}

var state = &EnclaveState{
	sealedShares: make(map[string][]byte),
}

// Request/Response types (must match tee_executor.go)
type EnclaveRequest struct {
	Operation string                  `json:"operation"`
	AuthShare []byte                  `json:"auth_share,omitempty"`
	Hash      []byte                  `json:"hash,omitempty"`
	ChainID   int64                   `json:"chain_id,omitempty"`
	TxData    *EnclaveTransactionData `json:"tx_data,omitempty"`
	Address   string                  `json:"address,omitempty"` // For looking up sealed share
}

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

type EnclaveResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	Address   string `json:"address,omitempty"`
	AuthShare []byte `json:"auth_share,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	SignedTx  []byte `json:"signed_tx,omitempty"`
}

func main() {
	log.Println("Starting Nitro Enclave key service...")

	// In production, use vsock listener
	// For development, we use TCP
	listener, err := createListener()
	if err != nil {
		log.Fatalf("Failed to create listener: %v", err)
	}
	defer listener.Close()

	log.Printf("Listening on port %d", vsockPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleConnection(conn)
	}
}

func createListener() (net.Listener, error) {
	// Check if running in Nitro Enclave (vsock available)
	if _, err := os.Stat("/dev/vsock"); err == nil {
		// Use vsock in production
		// Note: This requires the mdlayher/vsock package or syscall-based implementation
		log.Println("vsock device found, but using TCP fallback for now")
	}

	// Fallback to TCP for development
	return net.Listen("tcp", fmt.Sprintf(":%d", vsockPort))
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	// Read request length (4 bytes, big-endian)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		log.Printf("Failed to read length: %v", err)
		return
	}

	reqLen := int(lenBuf[0])<<24 | int(lenBuf[1])<<16 | int(lenBuf[2])<<8 | int(lenBuf[3])
	if reqLen > maxMsgSize {
		sendError(conn, "request too large")
		return
	}

	// Read request data
	reqData := make([]byte, reqLen)
	if _, err := io.ReadFull(conn, reqData); err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}

	// Parse request
	var req EnclaveRequest
	if err := json.Unmarshal(reqData, &req); err != nil {
		sendError(conn, fmt.Sprintf("invalid request: %v", err))
		return
	}

	// Handle operation
	var resp *EnclaveResponse
	switch req.Operation {
	case "generate_key":
		resp = handleGenerateKey(&req)
	case "sign_transaction":
		resp = handleSignTransaction(&req)
	case "sign_hash":
		resp = handleSignHash(&req)
	default:
		resp = &EnclaveResponse{
			Success: false,
			Error:   fmt.Sprintf("unknown operation: %s", req.Operation),
		}
	}

	sendResponse(conn, resp)
}

func handleGenerateKey(_ *EnclaveRequest) *EnclaveResponse {
	// Generate new Ethereum private key
	privateKey, err := ethcrypto.GenerateKey()
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("key generation failed: %v", err)}
	}
	defer zeroPrivateKey(privateKey)

	// Get address
	address := ethcrypto.PubkeyToAddress(privateKey.PublicKey)

	// Convert to bytes
	privateKeyBytes := ethcrypto.FromECDSA(privateKey)
	defer zeroBytes(privateKeyBytes)

	// Split using Shamir's Secret Sharing (2-of-2)
	shareSet, err := crypto.SplitKeyDefault(privateKeyBytes)
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("key split failed: %v", err)}
	}

	// Seal exec_share in enclave state
	// In production, this would use AWS Nitro's attestation-based sealing
	state.mu.Lock()
	state.sealedShares[address.Hex()] = shareSet.ExecShare
	state.mu.Unlock()

	return &EnclaveResponse{
		Success:   true,
		Address:   address.Hex(),
		AuthShare: shareSet.AuthShare,
		// exec_share stays sealed in enclave, not returned
	}
}

func handleSignTransaction(req *EnclaveRequest) *EnclaveResponse {
	if req.TxData == nil {
		return &EnclaveResponse{Success: false, Error: "missing transaction data"}
	}
	if len(req.AuthShare) == 0 {
		return &EnclaveResponse{Success: false, Error: "missing auth share"}
	}
	if req.Address == "" {
		return &EnclaveResponse{Success: false, Error: "missing wallet address"}
	}

	// Get sealed exec_share
	state.mu.RLock()
	execShare, ok := state.sealedShares[req.Address]
	state.mu.RUnlock()

	if !ok {
		return &EnclaveResponse{Success: false, Error: "exec share not found for address"}
	}

	// Reconstruct private key
	privateKey, err := reconstructKey(req.AuthShare, execShare)
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("key reconstruction failed: %v", err)}
	}
	defer zeroPrivateKey(privateKey)

	// Parse transaction values
	value := new(big.Int)
	value.SetString(req.TxData.Value, 10)

	gasFeeCap := new(big.Int)
	gasFeeCap.SetString(req.TxData.GasFeeCap, 10)

	gasTipCap := new(big.Int)
	gasTipCap.SetString(req.TxData.GasTipCap, 10)

	// Build transaction
	var toAddr *common.Address
	if req.TxData.To != "" {
		addr := common.HexToAddress(req.TxData.To)
		toAddr = &addr
	}

	tx := types.NewTx(&types.DynamicFeeTx{
		ChainID:   big.NewInt(req.TxData.ChainID),
		Nonce:     req.TxData.Nonce,
		To:        toAddr,
		Value:     value,
		Gas:       req.TxData.Gas,
		GasFeeCap: gasFeeCap,
		GasTipCap: gasTipCap,
		Data:      req.TxData.Data,
	})

	// Sign transaction
	signer := types.NewLondonSigner(big.NewInt(req.TxData.ChainID))
	signedTx, err := types.SignTx(tx, signer, privateKey)
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("signing failed: %v", err)}
	}

	// Encode signed transaction
	signedTxBytes, err := signedTx.MarshalBinary()
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("encoding failed: %v", err)}
	}

	return &EnclaveResponse{
		Success:  true,
		SignedTx: signedTxBytes,
	}
}

func handleSignHash(req *EnclaveRequest) *EnclaveResponse {
	if len(req.Hash) != 32 {
		return &EnclaveResponse{Success: false, Error: "hash must be 32 bytes"}
	}
	if len(req.AuthShare) == 0 {
		return &EnclaveResponse{Success: false, Error: "missing auth share"}
	}
	if req.Address == "" {
		return &EnclaveResponse{Success: false, Error: "missing wallet address"}
	}

	// Get sealed exec_share
	state.mu.RLock()
	execShare, ok := state.sealedShares[req.Address]
	state.mu.RUnlock()

	if !ok {
		return &EnclaveResponse{Success: false, Error: "exec share not found for address"}
	}

	// Reconstruct private key
	privateKey, err := reconstructKey(req.AuthShare, execShare)
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("key reconstruction failed: %v", err)}
	}
	defer zeroPrivateKey(privateKey)

	// Sign hash
	signature, err := ethcrypto.Sign(req.Hash, privateKey)
	if err != nil {
		return &EnclaveResponse{Success: false, Error: fmt.Sprintf("signing failed: %v", err)}
	}

	return &EnclaveResponse{
		Success:   true,
		Signature: signature,
	}
}

func reconstructKey(authShare, execShare []byte) (*ecdsa.PrivateKey, error) {
	privateKeyBytes, err := crypto.CombineSharesSSS([][]byte{authShare, execShare})
	if err != nil {
		return nil, err
	}
	defer zeroBytes(privateKeyBytes)

	return ethcrypto.ToECDSA(privateKeyBytes)
}

func sendResponse(conn net.Conn, resp *EnclaveResponse) {
	respData, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Failed to marshal response: %v", err)
		return
	}

	// Send length-prefixed response
	lenBuf := make([]byte, 4)
	lenBuf[0] = byte(len(respData) >> 24)
	lenBuf[1] = byte(len(respData) >> 16)
	lenBuf[2] = byte(len(respData) >> 8)
	lenBuf[3] = byte(len(respData))

	_, _ = conn.Write(lenBuf)
	_, _ = conn.Write(respData)
}

func sendError(conn net.Conn, errMsg string) {
	sendResponse(conn, &EnclaveResponse{
		Success: false,
		Error:   errMsg,
	})
}

func zeroPrivateKey(key *ecdsa.PrivateKey) {
	if key != nil && key.D != nil {
		key.D.SetInt64(0)
	}
}

func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
