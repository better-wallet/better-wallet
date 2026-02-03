package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/ethereum/go-ethereum/common"
)

// AgentSigningHandlers handles signing requests from agents
type AgentSigningHandlers struct {
	agentService *app.AgentService
}

// NewAgentSigningHandlers creates new signing handlers
func NewAgentSigningHandlers(agentService *app.AgentService) *AgentSigningHandlers {
	return &AgentSigningHandlers{agentService: agentService}
}

// JSONRPCRequest represents a JSON-RPC 2.0 request for agent signing
type JSONRPCRequest struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  []any  `json:"params"`
	ID      any    `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response for agent signing
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      any           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// HandleRPC handles JSON-RPC signing requests from agents
func (h *AgentSigningHandlers) HandleRPC(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		h.writeRPCError(w, -32600, "Invalid Request", nil, nil)
		return
	}

	// Get agent credential and wallet from context (set by agent auth middleware)
	credential := middleware.GetAgentCredential(r.Context())
	wallet := middleware.GetAgentWallet(r.Context())
	if credential == nil || wallet == nil {
		h.writeRPCError(w, -32603, "Internal error: missing auth context", nil, nil)
		return
	}

	// Parse JSON-RPC request
	var rpcReq JSONRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&rpcReq); err != nil {
		h.writeRPCError(w, -32700, "Parse error", nil, nil)
		return
	}

	// Validate JSON-RPC version
	if rpcReq.JSONRPC != "2.0" {
		h.writeRPCError(w, -32600, "Invalid Request: jsonrpc must be 2.0", nil, rpcReq.ID)
		return
	}

	slog.Info("agent rpc request",
		"method", rpcReq.Method,
		"credential_id", credential.ID,
		"wallet_address", wallet.Address)

	// Route by method
	switch rpcReq.Method {
	case "eth_sendTransaction":
		h.handleSendTransaction(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_signTransaction":
		h.handleSignTransaction(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "personal_sign":
		h.handlePersonalSign(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_signTypedData_v4":
		h.handleSignTypedData(w, r, credential, wallet, rpcReq.Params, rpcReq.ID)
	case "eth_accounts":
		h.handleAccounts(w, wallet, rpcReq.ID)
	case "eth_chainId":
		h.handleChainID(w, rpcReq.ID)
	case "eth_getBalance":
		h.handleGetBalance(w, r, wallet, rpcReq.ID)
	default:
		h.writeRPCError(w, -32601, "Method not found", nil, rpcReq.ID)
	}
}

func (h *AgentSigningHandlers) handleSendTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []any, id any) {
	if len(params) < 1 {
		h.writeRPCError(w, -32602, "Invalid params: transaction object required", nil, id)
		return
	}

	txParams, ok := params[0].(map[string]any)
	if !ok {
		h.writeRPCError(w, -32602, "Invalid params: transaction must be an object", nil, id)
		return
	}

	// Validate 'to' address - empty means contract deployment
	to := getString(txParams, "to")
	isContractDeploy := to == ""

	if isContractDeploy {
		// Contract deployment requires data
		if getString(txParams, "data") == "" {
			h.writeRPCError(w, -32602, "Invalid params: 'data' is required for contract deployment", nil, id)
			return
		}
		// Check contract_deploy capability
		if !h.hasOperation(credential, types.OperationContractDeploy) {
			h.writeRPCError(w, -32000, "Operation not allowed: contract_deploy not in credential capabilities", nil, id)
			return
		}
	} else {
		// Validate address format
		if !common.IsHexAddress(to) {
			h.writeRPCError(w, -32602, "Invalid params: 'to' must be a valid hex address", nil, id)
			return
		}
		// Check for zero address (likely a mistake for non-deploy tx)
		if common.HexToAddress(to) == (common.Address{}) {
			h.writeRPCError(w, -32602, "Invalid params: 'to' cannot be zero address (use empty for contract deployment)", nil, id)
			return
		}
	}

	// Extract value for rate limit check
	value := big.NewInt(0)
	if v, ok := txParams["value"].(string); ok && v != "" {
		parsedValue, ok := new(big.Int).SetString(v, 0)
		if !ok {
			h.writeRPCError(w, -32602, "Invalid params: value must be a valid number", nil, id)
			return
		}
		value = parsedValue
	}

	// Check capability constraints (transfer for regular tx, contract_deploy already checked above)
	if !isContractDeploy && !h.hasOperation(credential, types.OperationTransfer) {
		h.writeRPCError(w, -32000, "Operation not allowed: transfer not in credential capabilities", nil, id)
		return
	}

	// Check contract allowlist if specified (only for non-deploy transactions)
	if !isContractDeploy && len(credential.Capabilities.AllowedContracts) > 0 {
		if !h.isContractAllowed(credential, to) {
			h.writeRPCError(w, -32000, "Contract not in allowlist", nil, id)
			return
		}
	}

	// Check rate limits
	if err := h.agentService.CheckRateLimits(r.Context(), credential, value); err != nil {
		h.writeRPCError(w, -32000, err.Error(), map[string]string{"code": "RATE_LIMIT_EXCEEDED"}, id)
		return
	}

	// Determine chain ID: from params, validate against RPC
	chainID, err := h.getChainID(txParams)
	if err != nil {
		h.writeRPCError(w, -32602, fmt.Sprintf("Invalid params: %s", err.Error()), nil, id)
		return
	}

	// Build transaction params
	txReq := app.SendTransactionRequest{
		WalletID: wallet.ID,
		ChainID:  chainID,
		Params: app.TransactionParams{
			From:     wallet.Address,
			To:       to,
			Value:    getString(txParams, "value"),
			Data:     getString(txParams, "data"),
			Gas:      getString(txParams, "gas"),
			GasPrice: getString(txParams, "gasPrice"),
			Nonce:    getString(txParams, "nonce"),
		},
	}

	// Sign and broadcast the transaction
	resp, err := h.agentService.SendTransaction(r.Context(), txReq)
	if err != nil {
		slog.Error("failed to send transaction", "error", err, "wallet_id", wallet.ID)
		h.writeRPCError(w, -32000, "Failed to send transaction", nil, id)
		return
	}

	// Record the transaction for rate limiting
	if err := h.agentService.RecordTransaction(r.Context(), credential.ID, value); err != nil {
		slog.Error("failed to record transaction", "error", err, "credential_id", credential.ID)
		// Don't fail the request, just log the error
	}

	// Return tx hash if available, otherwise return signed tx
	if resp.TxHash != "" {
		h.writeRPCResult(w, resp.TxHash, id)
	} else {
		h.writeRPCResult(w, resp.SignedTx, id)
	}
}

func (h *AgentSigningHandlers) handleSignTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []any, id any) {
	// Similar to sendTransaction but returns signed tx instead of broadcasting
	if len(params) < 1 {
		h.writeRPCError(w, -32602, "Invalid params: transaction object required", nil, id)
		return
	}

	txParams, ok := params[0].(map[string]any)
	if !ok {
		h.writeRPCError(w, -32602, "Invalid params: transaction must be an object", nil, id)
		return
	}

	// Validate 'to' address - empty means contract deployment
	to := getString(txParams, "to")
	isContractDeploy := to == ""

	if isContractDeploy {
		// Contract deployment requires data
		if getString(txParams, "data") == "" {
			h.writeRPCError(w, -32602, "Invalid params: 'data' is required for contract deployment", nil, id)
			return
		}
		// Check contract_deploy capability
		if !h.hasOperation(credential, types.OperationContractDeploy) {
			h.writeRPCError(w, -32000, "Operation not allowed: contract_deploy not in credential capabilities", nil, id)
			return
		}
	} else {
		// Validate address format
		if !common.IsHexAddress(to) {
			h.writeRPCError(w, -32602, "Invalid params: 'to' must be a valid hex address", nil, id)
			return
		}
		// Check for zero address (likely a mistake for non-deploy tx)
		if common.HexToAddress(to) == (common.Address{}) {
			h.writeRPCError(w, -32602, "Invalid params: 'to' cannot be zero address (use empty for contract deployment)", nil, id)
			return
		}
	}

	// Extract value for rate limit check
	value := big.NewInt(0)
	if v, ok := txParams["value"].(string); ok && v != "" {
		parsedValue, ok := new(big.Int).SetString(v, 0)
		if !ok {
			h.writeRPCError(w, -32602, "Invalid params: value must be a valid number", nil, id)
			return
		}
		value = parsedValue
	}

	// Check capability constraints (transfer for regular tx, contract_deploy already checked above)
	if !isContractDeploy && !h.hasOperation(credential, types.OperationTransfer) {
		h.writeRPCError(w, -32000, "Operation not allowed: transfer not in credential capabilities", nil, id)
		return
	}

	// Check contract allowlist if specified (only for non-deploy transactions)
	if !isContractDeploy && len(credential.Capabilities.AllowedContracts) > 0 {
		if !h.isContractAllowed(credential, to) {
			h.writeRPCError(w, -32000, "Contract not in allowlist", nil, id)
			return
		}
	}

	// Check rate limits
	if err := h.agentService.CheckRateLimits(r.Context(), credential, value); err != nil {
		h.writeRPCError(w, -32000, err.Error(), map[string]string{"code": "RATE_LIMIT_EXCEEDED"}, id)
		return
	}

	// Determine chain ID: from params, validate against RPC
	chainID, err := h.getChainID(txParams)
	if err != nil {
		h.writeRPCError(w, -32602, fmt.Sprintf("Invalid params: %s", err.Error()), nil, id)
		return
	}

	// Build transaction params
	txReq := app.SignTransactionRequest{
		WalletID: wallet.ID,
		ChainID:  chainID,
		Params: app.TransactionParams{
			From:     wallet.Address,
			To:       to,
			Value:    getString(txParams, "value"),
			Data:     getString(txParams, "data"),
			Gas:      getString(txParams, "gas"),
			GasPrice: getString(txParams, "gasPrice"),
			Nonce:    getString(txParams, "nonce"),
		},
	}

	// Sign the transaction
	signedTx, err := h.agentService.SignTransaction(r.Context(), txReq)
	if err != nil {
		slog.Error("failed to sign transaction", "error", err, "wallet_id", wallet.ID)
		h.writeRPCError(w, -32000, "Failed to sign transaction", nil, id)
		return
	}

	// Record the transaction for rate limiting (even though not broadcast, it could be broadcast elsewhere)
	if err := h.agentService.RecordTransaction(r.Context(), credential.ID, value); err != nil {
		slog.Error("failed to record transaction", "error", err, "credential_id", credential.ID)
	}

	h.writeRPCResult(w, signedTx, id)
}

func (h *AgentSigningHandlers) handlePersonalSign(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []any, id any) {
	if len(params) < 2 {
		h.writeRPCError(w, -32602, "Invalid params: message and address required", nil, id)
		return
	}

	// Check capability
	if !h.hasOperation(credential, types.OperationSignMessage) {
		h.writeRPCError(w, -32000, "Operation not allowed: sign_message not in credential capabilities", nil, id)
		return
	}

	// Get message (first param is the message hex, second is the address)
	messageHex, ok := params[0].(string)
	if !ok {
		h.writeRPCError(w, -32602, "Invalid params: message must be a hex string", nil, id)
		return
	}

	// Decode message from hex
	message, err := hex.DecodeString(stripHexPrefix(messageHex))
	if err != nil {
		h.writeRPCError(w, -32602, "Invalid params: message must be valid hex", nil, id)
		return
	}

	// Sign the message
	signature, err := h.agentService.SignPersonalMessage(r.Context(), app.SignPersonalMessageRequest{
		WalletID: wallet.ID,
		Message:  message,
	})
	if err != nil {
		slog.Error("failed to sign message", "error", err, "wallet_id", wallet.ID)
		h.writeRPCError(w, -32000, "Failed to sign message", nil, id)
		return
	}

	h.writeRPCResult(w, signature, id)
}

func (h *AgentSigningHandlers) handleSignTypedData(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []any, id any) {
	if len(params) < 2 {
		h.writeRPCError(w, -32602, "Invalid params: address and typed data required", nil, id)
		return
	}

	// Check capability
	if !h.hasOperation(credential, types.OperationSignTypedData) {
		h.writeRPCError(w, -32000, "Operation not allowed: sign_typed_data not in credential capabilities", nil, id)
		return
	}

	// Get typed data (second param)
	typedDataRaw, err := json.Marshal(params[1])
	if err != nil {
		h.writeRPCError(w, -32602, "Invalid params: typed data must be valid JSON", nil, id)
		return
	}

	// Sign the typed data
	signature, err := h.agentService.SignTypedData(r.Context(), app.SignTypedDataRequest{
		WalletID:  wallet.ID,
		TypedData: typedDataRaw,
	})
	if err != nil {
		slog.Error("failed to sign typed data", "error", err, "wallet_id", wallet.ID)
		h.writeRPCError(w, -32000, "Failed to sign typed data", nil, id)
		return
	}

	h.writeRPCResult(w, signature, id)
}

func (h *AgentSigningHandlers) handleAccounts(w http.ResponseWriter, wallet *types.AgentWallet, id any) {
	h.writeRPCResult(w, []string{wallet.Address}, id)
}

func (h *AgentSigningHandlers) handleChainID(w http.ResponseWriter, id any) {
	chainID := h.agentService.GetChainID()
	if chainID == 0 {
		h.writeRPCError(w, -32000, "Chain ID not available: RPC not configured", nil, id)
		return
	}
	h.writeRPCResult(w, fmt.Sprintf("0x%x", chainID), id)
}

func (h *AgentSigningHandlers) handleGetBalance(w http.ResponseWriter, r *http.Request, wallet *types.AgentWallet, id any) {
	balance, err := h.agentService.GetBalance(r.Context(), wallet.ID)
	if err != nil {
		slog.Error("failed to get balance", "error", err, "wallet_id", wallet.ID)
		h.writeRPCError(w, -32000, "Failed to get balance", nil, id)
		return
	}
	h.writeRPCResult(w, balance, id)
}

// hasOperation checks if the credential allows the given operation
func (h *AgentSigningHandlers) hasOperation(credential *types.AgentCredential, operation string) bool {
	// Empty operations list means all operations allowed
	if len(credential.Capabilities.Operations) == 0 {
		return true
	}
	for _, op := range credential.Capabilities.Operations {
		if op == operation || op == "*" {
			return true
		}
	}
	return false
}

// isContractAllowed checks if the target contract is in the allowlist
func (h *AgentSigningHandlers) isContractAllowed(credential *types.AgentCredential, to string) bool {
	if to == "" {
		return false
	}
	for _, contract := range credential.Capabilities.AllowedContracts {
		// Case-insensitive comparison for Ethereum addresses
		if strings.EqualFold(contract, to) {
			return true
		}
	}
	return false
}

func (h *AgentSigningHandlers) writeRPCResult(w http.ResponseWriter, result, id any) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func (h *AgentSigningHandlers) writeRPCError(w http.ResponseWriter, code int, message string, data, id any) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID: id,
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// getString safely extracts a string from a map
func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// getChainID extracts chain ID from params, validates against RPC if configured
// Returns (chainID, error) - error if chainId is invalid or mismatches RPC
func (h *AgentSigningHandlers) getChainID(txParams map[string]any) (int64, error) {
	rpcChainID := h.agentService.GetChainID()
	chainIDStr := getString(txParams, "chainId")

	// If chainId is provided in params, validate it
	if chainIDStr != "" {
		chainID, ok := new(big.Int).SetString(chainIDStr, 0)
		if !ok || chainID.Int64() <= 0 {
			return 0, fmt.Errorf("invalid chainId: must be a valid positive number")
		}

		providedChainID := chainID.Int64()

		// If RPC is configured, reject chainId override to prevent chain mismatch
		// (nonce/gas/gasPrice come from RPC, so chainId must match)
		if rpcChainID != 0 && providedChainID != rpcChainID {
			return 0, fmt.Errorf("chainId mismatch: provided %d but RPC is connected to chain %d", providedChainID, rpcChainID)
		}

		return providedChainID, nil
	}

	// No chainId provided - use RPC chain ID if available
	if rpcChainID == 0 {
		return 0, fmt.Errorf("chainId is required when RPC is not configured")
	}

	return rpcChainID, nil
}

// stripHexPrefix removes 0x prefix from hex string
func stripHexPrefix(s string) string {
	if len(s) >= 2 && s[0:2] == "0x" {
		return s[2:]
	}
	return s
}
