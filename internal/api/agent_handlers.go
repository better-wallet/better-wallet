package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/google/uuid"
)

// AgentHandlers handles agent-related API requests
type AgentHandlers struct {
	agentService *app.AgentService
}

// NewAgentHandlers creates new agent handlers
func NewAgentHandlers(agentService *app.AgentService) *AgentHandlers {
	return &AgentHandlers{agentService: agentService}
}

// HandlePrincipals handles principal collection operations (no auth required for creation)
func (h *AgentHandlers) HandlePrincipals(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createPrincipal(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *AgentHandlers) createPrincipal(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := h.agentService.CreatePrincipal(r.Context(), app.CreatePrincipalRequest{
		Name:  req.Name,
		Email: req.Email,
	})
	if err != nil {
		slog.Error("failed to create principal", "error", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to create principal"})
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

// HandleWallets handles wallet collection operations
func (h *AgentHandlers) HandleWallets(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		h.createWallet(w, r)
	case http.MethodGet:
		h.listWallets(w, r)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *AgentHandlers) createWallet(w http.ResponseWriter, r *http.Request) {
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	var req struct {
		Name      string `json:"name"`
		ChainType string `json:"chain_type"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := h.agentService.CreateWallet(r.Context(), app.CreateAgentWalletRequest{
		PrincipalID: principal.ID,
		Name:        req.Name,
		ChainType:   req.ChainType,
	})
	if err != nil {
		slog.Error("failed to create wallet", "error", err, "principal_id", principal.ID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to create wallet"})
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (h *AgentHandlers) listWallets(w http.ResponseWriter, r *http.Request) {
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	wallets, err := h.agentService.ListWallets(r.Context(), principal.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list wallets"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"wallets": wallets})
}

// HandleWalletOperations handles single wallet operations
func (h *AgentHandlers) HandleWalletOperations(w http.ResponseWriter, r *http.Request) {
	// Extract wallet ID from path: /v1/wallets/{id}/...
	path := strings.TrimPrefix(r.URL.Path, "/v1/wallets/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "wallet id required"})
		return
	}

	walletID, err := uuid.Parse(parts[0])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid wallet id"})
		return
	}

	// Verify ownership
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	wallet, err := h.agentService.GetWallet(r.Context(), walletID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get wallet"})
		return
	}
	if wallet == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet not found"})
		return
	}
	if wallet.PrincipalID != principal.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
		return
	}

	// Determine sub-resource
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}

	switch subPath {
	case "":
		h.getWallet(w, r, wallet)
	case "credentials":
		h.handleCredentials(w, r, walletID)
	case "pause":
		h.pauseWallet(w, r, walletID)
	case "resume":
		h.resumeWallet(w, r, walletID)
	case "kill":
		h.killWallet(w, r, walletID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *AgentHandlers) getWallet(w http.ResponseWriter, r *http.Request, wallet *types.AgentWallet) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"wallet": wallet})
}

func (h *AgentHandlers) pauseWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.PauseWallet(r.Context(), walletID); err != nil {
		slog.Error("failed to pause wallet", "error", err, "wallet_id", walletID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to pause wallet"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (h *AgentHandlers) resumeWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.ResumeWallet(r.Context(), walletID); err != nil {
		slog.Error("failed to resume wallet", "error", err, "wallet_id", walletID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to resume wallet"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
}

func (h *AgentHandlers) killWallet(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.KillWallet(r.Context(), walletID); err != nil {
		slog.Error("failed to kill wallet", "error", err, "wallet_id", walletID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to kill wallet"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "killed"})
}

func (h *AgentHandlers) handleCredentials(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	switch r.Method {
	case http.MethodPost:
		h.createCredential(w, r, walletID)
	case http.MethodGet:
		h.listCredentials(w, r, walletID)
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
	}
}

func (h *AgentHandlers) createCredential(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	var req struct {
		Name         string                  `json:"name"`
		Capabilities types.AgentCapabilities `json:"capabilities"`
		Limits       types.AgentLimits       `json:"limits"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}

	resp, err := h.agentService.CreateCredential(r.Context(), app.CreateAgentCredentialRequest{
		WalletID:     walletID,
		Name:         req.Name,
		Capabilities: req.Capabilities,
		Limits:       req.Limits,
	})
	if err != nil {
		slog.Error("failed to create credential", "error", err, "wallet_id", walletID)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to create credential"})
		return
	}

	writeJSON(w, http.StatusCreated, resp)
}

func (h *AgentHandlers) listCredentials(w http.ResponseWriter, r *http.Request, walletID uuid.UUID) {
	credentials, err := h.agentService.ListCredentials(r.Context(), walletID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to list credentials"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"credentials": credentials})
}

// HandleCredentialOperations handles single credential operations
func (h *AgentHandlers) HandleCredentialOperations(w http.ResponseWriter, r *http.Request) {
	// Extract credential ID from path: /v1/credentials/{id}/...
	path := strings.TrimPrefix(r.URL.Path, "/v1/credentials/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "credential id required"})
		return
	}

	credentialID, err := uuid.Parse(parts[0])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid credential id"})
		return
	}

	// Verify ownership through wallet
	principal := middleware.GetPrincipal(r.Context())
	if principal == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	credential, err := h.agentService.GetCredential(r.Context(), credentialID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to get credential"})
		return
	}
	if credential == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "credential not found"})
		return
	}

	// Verify wallet ownership
	wallet, err := h.agentService.GetWallet(r.Context(), credential.WalletID)
	if err != nil || wallet == nil || wallet.PrincipalID != principal.ID {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "access denied"})
		return
	}

	// Determine sub-resource
	subPath := ""
	if len(parts) > 1 {
		subPath = parts[1]
	}

	switch subPath {
	case "":
		h.getCredential(w, r, credential)
	case "pause":
		h.pauseCredential(w, r, credentialID)
	case "resume":
		h.resumeCredential(w, r, credentialID)
	case "revoke":
		h.revokeCredential(w, r, credentialID)
	default:
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	}
}

func (h *AgentHandlers) getCredential(w http.ResponseWriter, r *http.Request, credential *types.AgentCredential) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"credential": credential})
}

func (h *AgentHandlers) pauseCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.PauseCredential(r.Context(), credentialID); err != nil {
		slog.Error("failed to pause credential", "error", err, "credential_id", credentialID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to pause credential"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "paused"})
}

func (h *AgentHandlers) resumeCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.ResumeCredential(r.Context(), credentialID); err != nil {
		slog.Error("failed to resume credential", "error", err, "credential_id", credentialID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to resume credential"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "active"})
}

func (h *AgentHandlers) revokeCredential(w http.ResponseWriter, r *http.Request, credentialID uuid.UUID) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	if err := h.agentService.RevokeCredential(r.Context(), credentialID); err != nil {
		slog.Error("failed to revoke credential", "error", err, "credential_id", credentialID)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "failed to revoke credential"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"status": "revoked"})
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
