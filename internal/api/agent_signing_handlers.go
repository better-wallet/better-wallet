package api

import (
	"encoding/json"
	"log/slog"
	"math/big"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
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
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      interface{}   `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response for agent signing
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	Result  interface{}   `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
	ID      interface{}   `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
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
		h.handleChainId(w, rpcReq.ID)
	case "eth_getBalance":
		h.handleGetBalance(w, wallet, rpcReq.ID)
	default:
		h.writeRPCError(w, -32601, "Method not found", nil, rpcReq.ID)
	}
}

func (h *AgentSigningHandlers) handleSendTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	if len(params) < 1 {
		h.writeRPCError(w, -32602, "Invalid params: transaction object required", nil, id)
		return
	}

	txParams, ok := params[0].(map[string]interface{})
	if !ok {
		h.writeRPCError(w, -32602, "Invalid params: transaction must be an object", nil, id)
		return
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

	// Check capability constraints
	if !h.hasOperation(credential, types.OperationTransfer) {
		h.writeRPCError(w, -32000, "Operation not allowed: transfer not in credential capabilities", nil, id)
		return
	}

	// Check contract allowlist if specified
	if len(credential.Capabilities.AllowedContracts) > 0 {
		to, _ := txParams["to"].(string)
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

	// TODO: Actually sign and broadcast the transaction
	// For now, return a placeholder indicating the feature is not yet implemented
	h.writeRPCError(w, -32000, "Transaction signing not yet implemented", nil, id)
}

func (h *AgentSigningHandlers) handleSignTransaction(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	// Similar to sendTransaction but returns signed tx instead of broadcasting
	h.writeRPCError(w, -32000, "Transaction signing not yet implemented", nil, id)
}

func (h *AgentSigningHandlers) handlePersonalSign(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	if len(params) < 2 {
		h.writeRPCError(w, -32602, "Invalid params: message and address required", nil, id)
		return
	}

	// Check capability
	if !h.hasOperation(credential, types.OperationSignMessage) {
		h.writeRPCError(w, -32000, "Operation not allowed: sign_message not in credential capabilities", nil, id)
		return
	}

	// TODO: Actually sign the message
	h.writeRPCError(w, -32000, "Message signing not yet implemented", nil, id)
}

func (h *AgentSigningHandlers) handleSignTypedData(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential, wallet *types.AgentWallet, params []interface{}, id interface{}) {
	if len(params) < 2 {
		h.writeRPCError(w, -32602, "Invalid params: address and typed data required", nil, id)
		return
	}

	// Check capability
	if !h.hasOperation(credential, types.OperationSignTypedData) {
		h.writeRPCError(w, -32000, "Operation not allowed: sign_typed_data not in credential capabilities", nil, id)
		return
	}

	// TODO: Actually sign the typed data
	h.writeRPCError(w, -32000, "Typed data signing not yet implemented", nil, id)
}

func (h *AgentSigningHandlers) handleAccounts(w http.ResponseWriter, wallet *types.AgentWallet, id interface{}) {
	h.writeRPCResult(w, []string{wallet.Address}, id)
}

func (h *AgentSigningHandlers) handleChainId(w http.ResponseWriter, id interface{}) {
	// Default to Ethereum mainnet - in production this would come from config
	h.writeRPCResult(w, "0x1", id)
}

func (h *AgentSigningHandlers) handleGetBalance(w http.ResponseWriter, wallet *types.AgentWallet, id interface{}) {
	// TODO: Actually query balance from RPC
	// For now return placeholder
	h.writeRPCError(w, -32000, "Balance query not yet implemented", nil, id)
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

func (h *AgentSigningHandlers) writeRPCResult(w http.ResponseWriter, result interface{}, id interface{}) {
	resp := JSONRPCResponse{
		JSONRPC: "2.0",
		Result:  result,
		ID:      id,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (h *AgentSigningHandlers) writeRPCError(w http.ResponseWriter, code int, message string, data interface{}, id interface{}) {
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
	json.NewEncoder(w).Encode(resp)
}
