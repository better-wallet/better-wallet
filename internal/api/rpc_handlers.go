package api

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/google/uuid"
)

// RPCRequest represents a unified RPC request
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// RPCResponse represents a unified RPC response
type RPCResponse struct {
	Method string      `json:"method"`
	Data   interface{} `json:"data"`
}

// eth_sendTransaction params
type EthSendTransactionParams struct {
	Transaction EthTransaction `json:"transaction"`
	Sponsor     bool           `json:"sponsor,omitempty"`
}

type EthTransaction struct {
	To                   string `json:"to"`
	Value                string `json:"value"`
	ChainID              int64  `json:"chain_id"`
	Data                 string `json:"data,omitempty"`
	GasLimit             string `json:"gas_limit,omitempty"`
	Nonce                string `json:"nonce,omitempty"`
	MaxFeePerGas         string `json:"max_fee_per_gas,omitempty"`
	MaxPriorityFeePerGas string `json:"max_priority_fee_per_gas,omitempty"`
	GasPrice             string `json:"gas_price,omitempty"` // Legacy
}

// eth_signTransaction params
type EthSignTransactionParams struct {
	Transaction EthTransaction `json:"transaction"`
}

// eth_signTypedData_v4 params
type EthSignTypedDataParams struct {
	TypedData TypedData `json:"typed_data"`
}

type TypedData struct {
	Types       map[string][]TypeField `json:"types"`
	Message     map[string]interface{} `json:"message"`
	PrimaryType string                 `json:"primary_type"`
	Domain      map[string]interface{} `json:"domain"`
}

type TypeField struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// handleRPC handles the unified RPC endpoint
func (s *Server) handleRPC(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	userSub, ok := getUserSub(r.Context())
	if !ok {
		s.writeError(w, apperrors.ErrUnauthorized)
		return
	}

	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Failed to read request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	var rpcReq RPCRequest
	if err := json.Unmarshal(bodyBytes, &rpcReq); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid request body",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Verify authorization signature
	_, canonicalBytes, err := auth.BuildCanonicalPayload(r)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Failed to build canonical payload",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	signatures := auth.ExtractSignatures(r)
	if len(signatures) == 0 {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing authorization signature",
			"x-authorization-signature header required",
			http.StatusUnauthorized,
		))
		return
	}

	// Route to appropriate handler based on method
	switch rpcReq.Method {
	case "eth_sendTransaction":
		s.handleEthSendTransaction(w, r, walletID, userSub, rpcReq.Params, signatures, canonicalBytes)
	case "eth_signTransaction":
		s.handleEthSignTransaction(w, r, walletID, userSub, rpcReq.Params, signatures, canonicalBytes)
	case "eth_signTypedData_v4":
		s.handleEthSignTypedData(w, r, walletID, userSub, rpcReq.Params, signatures, canonicalBytes)
	default:
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Unsupported RPC method",
			"method: "+rpcReq.Method,
			http.StatusBadRequest,
		))
	}
}

// handleEthSendTransaction handles eth_sendTransaction
func (s *Server) handleEthSendTransaction(
	w http.ResponseWriter,
	r *http.Request,
	walletID uuid.UUID,
	userSub string,
	params json.RawMessage,
	signatures []string,
	canonicalBytes []byte,
) {
	var p EthSendTransactionParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid params",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Parse transaction parameters
	value, ok := new(big.Int).SetString(p.Transaction.Value, 0)
	if !ok {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid value",
			"Value must be a valid integer",
			http.StatusBadRequest,
		))
		return
	}

	// Parse nonce
	var nonce uint64
	if p.Transaction.Nonce != "" {
		n, ok := new(big.Int).SetString(p.Transaction.Nonce, 0)
		if !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid nonce",
				"",
				http.StatusBadRequest,
			))
			return
		}
		nonce = n.Uint64()
	}

	// Parse gas limit
	var gasLimit uint64 = 21000 // Default
	if p.Transaction.GasLimit != "" {
		gl, ok := new(big.Int).SetString(p.Transaction.GasLimit, 0)
		if !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_limit",
				"",
				http.StatusBadRequest,
			))
			return
		}
		gasLimit = gl.Uint64()
	}

	// Parse gas parameters
	gasFeeCap := new(big.Int)
	if p.Transaction.MaxFeePerGas != "" {
		if _, ok := gasFeeCap.SetString(p.Transaction.MaxFeePerGas, 0); !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_fee_per_gas",
				"",
				http.StatusBadRequest,
			))
			return
		}
	} else if p.Transaction.GasPrice != "" {
		if _, ok := gasFeeCap.SetString(p.Transaction.GasPrice, 0); !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_price",
				"",
				http.StatusBadRequest,
			))
			return
		}
	}

	gasTipCap := new(big.Int)
	if p.Transaction.MaxPriorityFeePerGas != "" {
		if _, ok := gasTipCap.SetString(p.Transaction.MaxPriorityFeePerGas, 0); !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_priority_fee_per_gas",
				"",
				http.StatusBadRequest,
			))
			return
		}
	}

	// Parse data
	var data []byte
	if p.Transaction.Data != "" {
		dataStr := strings.TrimPrefix(p.Transaction.Data, "0x")
		var err error
		data, err = hex.DecodeString(dataStr)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid data",
				"Data must be a valid hex string",
				http.StatusBadRequest,
			))
			return
		}
	}

	// Sign transaction
	signedTx, err := s.walletService.SignTransaction(r.Context(), userSub, &app.SignTransactionRequest{
		WalletID:         walletID,
		To:               p.Transaction.To,
		Value:            value,
		Data:             data,
		ChainID:          p.Transaction.ChainID,
		Nonce:            nonce,
		GasLimit:         gasLimit,
		GasFeeCap:        gasFeeCap,
		GasTipCap:        gasTipCap,
		Signatures:       signatures,
		CanonicalPayload: canonicalBytes,
		IdempotencyKey:   r.Header.Get("x-idempotency-key"),
		AppID:            r.Header.Get("x-app-id"),
		HTTPMethod:       r.Method,
		URLPath:          r.URL.Path,
		RequestDigest:    "",
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// TODO: If sponsor=true, submit transaction to network
	// For now, just return the signed transaction

	response := RPCResponse{
		Method: "eth_sendTransaction",
		Data: map[string]interface{}{
			"hash":           signedTx.Hash().Hex(),
			"caip2":          fmt.Sprintf("eip155:%d", p.Transaction.ChainID),
			"transaction_id": uuid.New().String(), // TODO: Generate proper transaction ID
		},
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleEthSignTransaction handles eth_signTransaction (sign without sending)
func (s *Server) handleEthSignTransaction(
	w http.ResponseWriter,
	r *http.Request,
	walletID uuid.UUID,
	userSub string,
	params json.RawMessage,
	signatures []string,
	canonicalBytes []byte,
) {
	var p EthSignTransactionParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid params",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Parse transaction parameters (similar to eth_sendTransaction)
	value, ok := new(big.Int).SetString(p.Transaction.Value, 0)
	if !ok {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid value",
			"",
			http.StatusBadRequest,
		))
		return
	}

	var nonce uint64
	if p.Transaction.Nonce != "" {
		n, ok := new(big.Int).SetString(p.Transaction.Nonce, 0)
		if !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid nonce",
				"",
				http.StatusBadRequest,
			))
			return
		}
		nonce = n.Uint64()
	}

	var gasLimit uint64 = 21000
	if p.Transaction.GasLimit != "" {
		gl, ok := new(big.Int).SetString(p.Transaction.GasLimit, 0)
		if !ok {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_limit",
				"",
				http.StatusBadRequest,
			))
			return
		}
		gasLimit = gl.Uint64()
	}

	gasFeeCap, _ := new(big.Int).SetString(p.Transaction.MaxFeePerGas, 0)
	gasTipCap, _ := new(big.Int).SetString(p.Transaction.MaxPriorityFeePerGas, 0)

	var data []byte
	if p.Transaction.Data != "" {
		dataStr := strings.TrimPrefix(p.Transaction.Data, "0x")
		var err error
		data, err = hex.DecodeString(dataStr)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid data",
				"",
				http.StatusBadRequest,
			))
			return
		}
	}

	// Sign transaction
	signedTx, err := s.walletService.SignTransaction(r.Context(), userSub, &app.SignTransactionRequest{
		WalletID:         walletID,
		To:               p.Transaction.To,
		Value:            value,
		Data:             data,
		ChainID:          p.Transaction.ChainID,
		Nonce:            nonce,
		GasLimit:         gasLimit,
		GasFeeCap:        gasFeeCap,
		GasTipCap:        gasTipCap,
		Signatures:       signatures,
		CanonicalPayload: canonicalBytes,
		IdempotencyKey:   r.Header.Get("x-idempotency-key"),
		AppID:            r.Header.Get("x-app-id"),
		HTTPMethod:       r.Method,
		URLPath:          r.URL.Path,
		RequestDigest:    "",
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Serialize to RLP
	txBytes, err := signedTx.MarshalBinary()
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to serialize transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := RPCResponse{
		Method: "eth_signTransaction",
		Data: map[string]interface{}{
			"signed_transaction": hex.EncodeToString(txBytes),
			"encoding":           "rlp",
		},
	}

	s.writeJSON(w, http.StatusOK, response)
}

// handleEthSignTypedData handles eth_signTypedData_v4
func (s *Server) handleEthSignTypedData(
	w http.ResponseWriter,
	r *http.Request,
	walletID uuid.UUID,
	userSub string,
	params json.RawMessage,
	signatures []string,
	canonicalBytes []byte,
) {
	var p EthSignTypedDataParams
	if err := json.Unmarshal(params, &p); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid params",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Verify wallet ownership
	wallet, err := s.walletService.GetWallet(r.Context(), walletID, userSub)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get wallet",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}
	if wallet == nil {
		s.writeError(w, apperrors.ErrNotFound)
		return
	}

	// Verify authorization signatures
	owner, err := s.walletService.GetOwner(r.Context(), wallet.OwnerID)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to get owner",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	verifier := auth.NewSignatureVerifier()
	if err := verifier.VerifyOwnerSignature(signatures, canonicalBytes, owner); err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"Invalid authorization signature",
			err.Error(),
			http.StatusForbidden,
		))
		return
	}

	// Convert TypedData to app.TypedData
	typedData := app.TypedData{
		Types:       convertTypes(p.TypedData.Types),
		PrimaryType: p.TypedData.PrimaryType,
		Domain:      p.TypedData.Domain,
		Message:     p.TypedData.Message,
	}

	// Sign the typed data
	signature, err := s.walletService.SignTypedData(r.Context(), walletID, typedData)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to sign typed data",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	response := map[string]interface{}{
		"signature": signature,
	}

	s.writeJSON(w, http.StatusOK, response)
}

// convertTypes converts the API TypeField structure to app TypedData format
func convertTypes(types map[string][]TypeField) map[string]interface{} {
	result := make(map[string]interface{})
	for typeName, fields := range types {
		fieldList := make([]map[string]interface{}, len(fields))
		for i, field := range fields {
			fieldList[i] = map[string]interface{}{
				"name": field.Name,
				"type": field.Type,
			}
		}
		result[typeName] = fieldList
	}
	return result
}
