package api

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/google/uuid"
)

// RPCRequest represents a unified RPC request
type RPCRequest struct {
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// parseHexBigInt parses a hex string (with or without 0x prefix) into a big.Int
// Also accepts decimal strings for backward compatibility
// Returns error with clear message if parsing fails
func parseHexBigInt(s string) (*big.Int, error) {
	if s == "" {
		return new(big.Int), nil
	}

	// Try 0x hex first (preferred format per Ethereum JSON-RPC spec)
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v := new(big.Int)
		if _, ok := v.SetString(s[2:], 16); ok {
			return v, nil
		}
		return nil, fmt.Errorf("invalid hex value: %s", s)
	}

	// Fallback: try decimal (for backward compatibility)
	v := new(big.Int)
	if _, ok := v.SetString(s, 10); ok {
		return v, nil
	}

	return nil, fmt.Errorf("invalid value (expected 0x hex or decimal): %s", s)
}

// parseHexUint64 parses a hex string into uint64
func parseHexUint64(s string) (uint64, error) {
	v, err := parseHexBigInt(s)
	if err != nil {
		return 0, err
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("value too large for uint64: %s", s)
	}
	return v.Uint64(), nil
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
	GasPrice             string `json:"gas_price,omitempty"` // For EIP-1559 fallback
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
	// userSub is optional for app-managed wallets (which don't have a user owner)
	// The wallet service layer will validate ownership for user-owned wallets
	userSub, _ := getUserSub(r.Context())

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

	// Restore the body so canonical payload/signature verification sees the original request.
	r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

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

	// Wallet operations via /rpc always require an authorization signature.
	if err := s.verifyAuthorizationSignature(r, walletID); err != nil {
		s.writeError(w, apperrors.InvalidSignature(err.Error()))
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

	// Signatures are optional for app-managed wallets (which don't require user authorization)
	// The wallet service layer will validate signatures for user-owned wallets
	signatures := auth.ExtractSignatures(r)

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

	// Parse transaction parameters using hex parsing (0x preferred, decimal accepted)
	value, err := parseHexBigInt(p.Transaction.Value)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid value",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	// Parse nonce
	var nonce uint64
	if p.Transaction.Nonce != "" {
		nonce, err = parseHexUint64(p.Transaction.Nonce)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid nonce",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	// Parse gas limit
	var gasLimit uint64 = 21000 // Default
	if p.Transaction.GasLimit != "" {
		gasLimit, err = parseHexUint64(p.Transaction.GasLimit)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_limit",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	// Parse gas parameters
	gasFeeCap := new(big.Int)
	if p.Transaction.MaxFeePerGas != "" {
		gasFeeCap, err = parseHexBigInt(p.Transaction.MaxFeePerGas)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_fee_per_gas",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	} else if p.Transaction.GasPrice != "" {
		gasFeeCap, err = parseHexBigInt(p.Transaction.GasPrice)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_price",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	gasTipCap := new(big.Int)
	if p.Transaction.MaxPriorityFeePerGas != "" {
		gasTipCap, err = parseHexBigInt(p.Transaction.MaxPriorityFeePerGas)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_priority_fee_per_gas",
				err.Error(),
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
		Method:           "eth_sendTransaction",
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

	// TODO: Gas sponsorship is not yet implemented.
	// True gas sponsorship requires either:
	// - Meta-transactions (EIP-2771) with a relayer that pays gas
	// - Account Abstraction (EIP-4337) with a Paymaster contract
	// - A server-side sponsored account that wraps user intents
	// For now, reject sponsor=true requests explicitly.
	if p.Sponsor {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeNotImplemented,
			"Gas sponsorship not implemented",
			"The sponsor=true option is not yet supported. Please submit the signed transaction yourself.",
			http.StatusNotImplemented,
		))
		return
	}

	txHash := signedTx.Hash().Hex()

	// Encode signed transaction
	txBytes, err := signedTx.MarshalBinary()
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeInternalError,
			"Failed to encode transaction",
			err.Error(),
			http.StatusInternalServerError,
		))
		return
	}

	// Create transaction record
	txID := uuid.New()
	txRepo := storage.NewTransactionRepository(s.store)
	toAddr := p.Transaction.To
	valueStr := p.Transaction.Value
	dataStr := p.Transaction.Data
	nonceVal := int64(nonce)
	gasLimitVal := int64(gasLimit)
	maxFeeStr := gasFeeCap.String()
	maxPriorityStr := gasTipCap.String()

	txRecord := &storage.Transaction{
		ID:                   txID,
		WalletID:             walletID,
		ChainID:              p.Transaction.ChainID,
		TxHash:               &txHash,
		Status:               "submitted", // For now, mark as submitted since we signed it
		Method:               "eth_sendTransaction",
		ToAddress:            &toAddr,
		Value:                &valueStr,
		Data:                 &dataStr,
		Nonce:                &nonceVal,
		GasLimit:             &gasLimitVal,
		MaxFeePerGas:         &maxFeeStr,
		MaxPriorityFeePerGas: &maxPriorityStr,
		SignedTx:             txBytes,
	}

	if err := txRepo.Create(r.Context(), txRecord); err != nil {
		// Log error but don't fail the request
		log.Printf("Failed to create transaction record: wallet_id=%s tx_hash=%s error=%v",
			walletID.String(), txHash, err)
	}

	response := RPCResponse{
		Method: "eth_sendTransaction",
		Data: map[string]interface{}{
			"hash":           txHash,
			"caip2":          fmt.Sprintf("eip155:%d", p.Transaction.ChainID),
			"transaction_id": txID.String(),
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

	// Parse transaction parameters using hex parsing (0x preferred, decimal accepted)
	value, err := parseHexBigInt(p.Transaction.Value)
	if err != nil {
		s.writeError(w, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid value",
			err.Error(),
			http.StatusBadRequest,
		))
		return
	}

	var nonce uint64
	if p.Transaction.Nonce != "" {
		nonce, err = parseHexUint64(p.Transaction.Nonce)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid nonce",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	var gasLimit uint64 = 21000
	if p.Transaction.GasLimit != "" {
		gasLimit, err = parseHexUint64(p.Transaction.GasLimit)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid gas_limit",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	gasFeeCap := new(big.Int)
	if p.Transaction.MaxFeePerGas != "" {
		gasFeeCap, err = parseHexBigInt(p.Transaction.MaxFeePerGas)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_fee_per_gas",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

	gasTipCap := new(big.Int)
	if p.Transaction.MaxPriorityFeePerGas != "" {
		gasTipCap, err = parseHexBigInt(p.Transaction.MaxPriorityFeePerGas)
		if err != nil {
			s.writeError(w, apperrors.NewWithDetail(
				apperrors.ErrCodeBadRequest,
				"Invalid max_priority_fee_per_gas",
				err.Error(),
				http.StatusBadRequest,
			))
			return
		}
	}

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
		Method:           "eth_signTransaction",
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

	// Convert TypedData to app.TypedData
	typedData := app.TypedData{
		Types:       convertTypes(p.TypedData.Types),
		PrimaryType: p.TypedData.PrimaryType,
		Domain:      p.TypedData.Domain,
		Message:     p.TypedData.Message,
	}

	// Sign the typed data (ownership/authz/policy enforced in service layer)
	signature, err := s.walletService.SignTypedData(r.Context(), userSub, &app.SignTypedDataRequest{
		WalletID:         walletID,
		TypedData:        typedData,
		Signatures:       signatures,
		CanonicalPayload: canonicalBytes,
	})
	if err != nil {
		if appErr, ok := apperrors.IsAppError(err); ok {
			s.writeError(w, appErr)
			return
		}
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

