package app

import (
	"context"
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"time"

	internalcrypto "github.com/better-wallet/better-wallet/internal/crypto"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/internal/validation"
	"github.com/better-wallet/better-wallet/pkg/auth"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/google/uuid"
)

// WalletService handles wallet operations
type WalletService struct {
	walletRepo  *storage.WalletRepository
	userRepo    *storage.UserRepository
	policyRepo  *storage.PolicyRepository
	auditRepo   *storage.AuditRepository
	sessionRepo *storage.SessionSignerRepository
	authKeyRepo *storage.AuthorizationKeyRepository
	keyExec     keyexec.KeyExecutor
	policyEng   *policy.Engine
	store       *storage.Store
}

// NewWalletService creates a new wallet service
func NewWalletService(
	store *storage.Store,
	keyExec keyexec.KeyExecutor,
	policyEng *policy.Engine,
) *WalletService {
	return &WalletService{
		walletRepo:  storage.NewWalletRepository(store),
		userRepo:    storage.NewUserRepository(store),
		policyRepo:  storage.NewPolicyRepository(store),
		auditRepo:   storage.NewAuditRepository(store),
		sessionRepo: storage.NewSessionSignerRepository(store),
		authKeyRepo: storage.NewAuthorizationKeyRepository(store),
		keyExec:     keyExec,
		policyEng:   policyEng,
		store:       store,
	}
}

// IsAppManagedWallet returns true if the wallet has no owner (app-managed)
func IsAppManagedWallet(wallet *types.Wallet) bool {
	return wallet.OwnerID == nil
}

// CreateWalletRequest represents a request to create a wallet
type CreateWalletRequest struct {
	UserSub           string
	ChainType         string
	OwnerPublicKey    string            // Hex-encoded public key (if creating new owner)
	OwnerAlgorithm    string            // "p256" (if creating new owner)
	OwnerID           *uuid.UUID        // Existing authorization key or quorum ID
	ExecBackend       string
	PolicyIDs         []uuid.UUID       // Policy IDs to attach
	AdditionalSigners []AdditionalSigner // Session signers to create
	RecoveryMethod    string            // "password", "cloud_backup", or "passkey"
	RecoveryHint      string            // Optional hint for password recovery
}

// CreateWalletResponse includes wallet info
type CreateWalletResponse struct {
	Wallet *types.Wallet `json:"wallet"`
	// Note: RecoveryShare removed - using 2-of-2 scheme
	// Recovery share will be added with on-device mode (2-of-3 scheme)
}

// ListWalletsRequest represents a request to list wallets
type ListWalletsRequest struct {
	UserSub      string
	Cursor       string
	Limit        int
	ChainType    string
	FilterUserID *uuid.UUID
}

// UpdateWalletRequest represents a request to update a wallet
type UpdateWalletRequest struct {
	UserSub           string
	WalletID          uuid.UUID
	PolicyIDs         *[]uuid.UUID
	OwnerID           *uuid.UUID
	Owner             *OwnerInput
	AdditionalSigners *[]AdditionalSigner
}

// OwnerInput for creating a new owner
type OwnerInput struct {
	PublicKey string
	UserID    *uuid.UUID
}

// AdditionalSigner represents a session signer on a wallet
type AdditionalSigner struct {
	SignerID          uuid.UUID
	OverridePolicyIDs []uuid.UUID
}

// CreateWallet creates a new wallet for a user or app-managed wallet
// Returns the wallet and recovery share (recovery share must be stored securely by the client)
// If no owner is provided, creates an app-managed wallet that can be controlled via app secret
func (s *WalletService) CreateWallet(ctx context.Context, req *CreateWalletRequest) (*CreateWalletResponse, error) {
	// Get AppID from context for multi-tenant isolation
	appID, _ := storage.GetAppID(ctx)

	// Get or create user (optional for app-managed wallets)
	var userID *uuid.UUID
	if req.UserSub != "" {
		user, err := s.userRepo.GetOrCreate(ctx, req.UserSub)
		if err != nil {
			return nil, fmt.Errorf("failed to get or create user: %w", err)
		}
		userID = &user.ID
	}

	// Determine owner ID - either use existing, create new, or leave nil for app-managed wallets
	var ownerID *uuid.UUID
	var authKey *types.AuthorizationKey

	if req.OwnerID != nil {
		// Use existing authorization key or quorum
		oid := *req.OwnerID

		// Verify owner exists (either authorization key or key quorum)
		existingKey, err := s.authKeyRepo.GetByID(ctx, oid)
		if err == nil && existingKey != nil {
			// Owner is an authorization key
			ownerID = &existingKey.ID
		} else {
			// Check if it's a key quorum
			quorumRepo := storage.NewKeyQuorumRepository(s.store)
			quorum, err := quorumRepo.GetByID(ctx, oid)
			if err != nil || quorum == nil {
				return nil, fmt.Errorf("owner_id does not reference a valid authorization key or key quorum")
			}

			// Validate quorum membership and threshold
			if quorum.Status != types.StatusActive {
				return nil, fmt.Errorf("key quorum is not active")
			}
			if quorum.Threshold <= 0 || quorum.Threshold > len(quorum.KeyIDs) {
				return nil, fmt.Errorf("key quorum has invalid threshold")
			}

			// Verify all member keys exist and are active
			for _, keyID := range quorum.KeyIDs {
				memberKey, err := s.authKeyRepo.GetByID(ctx, keyID)
				if err != nil || memberKey == nil {
					return nil, fmt.Errorf("key quorum member %s not found", keyID)
				}
				if memberKey.Status != types.StatusActive {
					return nil, fmt.Errorf("key quorum member %s is not active", keyID)
				}
			}

			ownerID = &quorum.ID
		}
	} else if req.OwnerPublicKey != "" {
		// Create new authorization key
		publicKeyBytes := common.FromHex(req.OwnerPublicKey)
		if len(publicKeyBytes) == 0 {
			return nil, fmt.Errorf("invalid owner public key hex")
		}

		// Validate public key format based on algorithm
		if req.OwnerAlgorithm != types.AlgorithmP256 {
			return nil, fmt.Errorf("unsupported algorithm: %s (only 'p256' is supported)", req.OwnerAlgorithm)
		}

		// P-256: Validate format and ensure point is on curve
		if len(publicKeyBytes) != 65 && len(publicKeyBytes) != 33 {
			return nil, fmt.Errorf("invalid P-256 public key length: expected 65 (uncompressed) or 33 (compressed) bytes, got %d", len(publicKeyBytes))
		}

		x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
		if x == nil {
			return nil, fmt.Errorf("invalid P-256 public key format: failed to parse")
		}
		if !elliptic.P256().IsOnCurve(x, y) {
			return nil, fmt.Errorf("invalid P-256 public key: point not on curve")
		}

		ownerEntity := req.UserSub
		if ownerEntity == "" {
			ownerEntity = "app-managed"
		}

		authKey = &types.AuthorizationKey{
			ID:          uuid.New(),
			PublicKey:   publicKeyBytes,
			Algorithm:   req.OwnerAlgorithm,
			OwnerEntity: ownerEntity,
			Status:      types.StatusActive,
			AppID:       &appID,
		}
		ownerID = &authKey.ID
	}
	// If neither owner_id nor owner_public_key is provided, ownerID remains nil (app-managed wallet)

	// Generate and split key
	keyMaterial, err := s.keyExec.GenerateAndSplitKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt shares
	encryptedAuthShare, err := s.keyExec.Encrypt(ctx, keyMaterial.AuthShare)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth share: %w", err)
	}

	encryptedExecShare, err := s.keyExec.Encrypt(ctx, keyMaterial.ExecShare)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt exec share: %w", err)
	}

	// Create wallet record
	wallet := &types.Wallet{
		ID:          uuid.New(),
		UserID:      userID, // nil for app-managed wallets
		ChainType:   req.ChainType,
		OwnerID:     ownerID, // nil for app-managed wallets
		ExecBackend: req.ExecBackend,
		Address:     keyMaterial.Address,
		AppID:       &appID,
	}

	// Begin transaction
	tx, err := s.store.DB().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Create authorization key if new
	if authKey != nil {
		if err := s.authKeyRepo.CreateTx(ctx, tx, authKey); err != nil {
			return nil, fmt.Errorf("failed to create authorization key: %w", err)
		}
	}

	// Create wallet
	if err := s.walletRepo.CreateTx(ctx, tx, wallet); err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	// Store wallet shares
	shareRepo := storage.NewWalletShareRepository(s.store)
	if err := shareRepo.CreateTx(ctx, tx, &types.WalletShare{
		WalletID:      wallet.ID,
		ShareType:     types.ShareTypeAuth,
		BlobEncrypted: encryptedAuthShare,
		Threshold:     keyMaterial.Threshold,
		TotalShares:   keyMaterial.TotalShares,
	}); err != nil {
		return nil, fmt.Errorf("failed to store auth share: %w", err)
	}

	if err := shareRepo.CreateTx(ctx, tx, &types.WalletShare{
		WalletID:      wallet.ID,
		ShareType:     types.ShareTypeExec,
		BlobEncrypted: encryptedExecShare,
		Threshold:     keyMaterial.Threshold,
		TotalShares:   keyMaterial.TotalShares,
	}); err != nil {
		return nil, fmt.Errorf("failed to store exec share: %w", err)
	}

	// Note: 2-of-2 scheme - no recovery share
	// Recovery share support will be added with on-device mode (2-of-3 scheme)

	// Attach policies
	if len(req.PolicyIDs) > 0 {
		for _, policyID := range req.PolicyIDs {
			if err := s.policyRepo.AttachToWalletTx(ctx, tx, wallet.ID, policyID); err != nil {
				return nil, fmt.Errorf("failed to attach policy %s: %w", policyID, err)
			}
		}
	}

	// Create additional signers (session signers)
	if len(req.AdditionalSigners) > 0 {
		for _, signer := range req.AdditionalSigners {
			sessionSigner := &types.SessionSigner{
				ID:           uuid.New(),
				WalletID:     wallet.ID,
				SignerID:     signer.SignerID.String(),
				TTLExpiresAt: time.Now().Add(24 * time.Hour), // Default 24h
				AppID:        &appID,
			}

			if len(signer.OverridePolicyIDs) > 0 {
				// Store first override policy ID
				policyID := signer.OverridePolicyIDs[0]
				sessionSigner.PolicyOverrideID = &policyID
			}

			if err := s.sessionRepo.CreateTx(ctx, tx, sessionSigner); err != nil {
				return nil, fmt.Errorf("failed to create session signer: %w", err)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Audit log
	s.auditRepo.Create(ctx, &types.AuditLog{
		Actor:        req.UserSub,
		Action:       "wallet.create",
		ResourceType: "wallet",
		ResourceID:   wallet.ID.String(),
		ClientIP:     middleware.GetClientIP(ctx),
		UserAgent:    middleware.GetUserAgent(ctx),
	})

	return &CreateWalletResponse{
		Wallet: wallet,
	}, nil
}

// SignTransactionRequest represents a request to sign a transaction
type SignTransactionRequest struct {
	WalletID         uuid.UUID
	To               string
	Value            *big.Int
	Data             []byte
	ChainID          int64
	Nonce            uint64
	GasLimit         uint64
	GasFeeCap        *big.Int
	GasTipCap        *big.Int
	Signatures       []string
	CanonicalPayload []byte
	IdempotencyKey   string
	AppID            string
	HTTPMethod       string
	URLPath          string
	RequestDigest    string
}

// SessionSignerWithKey wraps a session signer with its authorization public key
type SessionSignerWithKey struct {
	Signer    *types.SessionSigner
	PublicKey []byte
}

// CreateSessionSignerRequest represents a request to add a session signer to a wallet
type CreateSessionSignerRequest struct {
	UserSub          string
	WalletID         uuid.UUID
	SignerPublicKey  string
	PolicyOverrideID *uuid.UUID
	AllowedMethods   []string
	MaxValue         *big.Int
	MaxTxs           *int
	TTL              time.Duration
}

// SignTransaction signs a transaction
func (s *WalletService) SignTransaction(ctx context.Context, userSub string, req *SignTransactionRequest) (*ethtypes.Transaction, error) {
	// Input validation
	validationConfig := &validation.TransactionValidationConfig{
		MaxValue:        nil,         // No global limit, policy engine will handle this
		MaxDataSize:     1024 * 1024, // 1MB max calldata
		AllowedChainIDs: nil,         // Allow all chains
	}

	if err := validation.ValidateTransaction(
		req.To,
		req.Value,
		req.Data,
		req.ChainID,
		req.Nonce,
		req.GasLimit,
		req.GasFeeCap,
		req.GasTipCap,
		validationConfig,
	); err != nil {
		return nil, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid transaction parameters",
			err.Error(),
			400,
		)
	}

	// Get wallet (app_id scope is automatically enforced by repository)
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, apperrors.WalletNotFound(req.WalletID.String())
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets (no owner), skip user verification - app secret auth is sufficient
	var matchedSignerID string
	if !IsAppManagedWallet(wallet) {
		// Verify ownership
		user, err := s.userRepo.GetByExternalSub(ctx, userSub)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		if wallet.UserID != nil && (user == nil || user.ID != *wallet.UserID) {
			return nil, apperrors.ErrForbidden
		}

		// Verify authorization signature (owner or active session signer)
		matchedSignerID, err = s.verifyAuthorizationSignature(ctx, wallet, req.Signatures, req.CanonicalPayload, types.SignMethodTransaction)
		if err != nil {
			return nil, err
		}
	}
	// For app-managed wallets, no authorization signature required - app secret auth is sufficient

	// Check if signed by session signer and enforce limits
	var sessionSigner *types.SessionSigner
	ownerIDStr := ""
	if wallet.OwnerID != nil {
		ownerIDStr = wallet.OwnerID.String()
	}
	if matchedSignerID != "" && matchedSignerID != ownerIDStr {
		// Matched a session signer - load it and check limits
		signerUUID, err := uuid.Parse(matchedSignerID)
		if err == nil {
			sessionSigner, err = s.sessionRepo.GetByID(ctx, signerUUID)
			if err != nil {
				return nil, fmt.Errorf("failed to load session signer: %w", err)
			}

			if sessionSigner != nil {
				// Enforce max_value limit
				if sessionSigner.MaxValue != nil {
					maxValue := new(big.Int)
					if _, ok := maxValue.SetString(*sessionSigner.MaxValue, 10); ok {
						if req.Value.Cmp(maxValue) > 0 {
							return nil, apperrors.NewWithDetail(
								apperrors.ErrCodeForbidden,
								"Transaction value exceeds session signer limit",
								fmt.Sprintf("max_value: %s, requested: %s", *sessionSigner.MaxValue, req.Value.String()),
								http.StatusForbidden,
							)
						}
					}
				}

				// Enforce max_txs limit
				if sessionSigner.MaxTxs != nil {
					// Count transactions signed by this signer
					txCount, err := s.auditRepo.CountBySessionSigner(ctx, sessionSigner.ID.String())
					if err != nil {
						return nil, fmt.Errorf("failed to count session signer transactions: %w", err)
					}

					if txCount >= *sessionSigner.MaxTxs {
						return nil, apperrors.NewWithDetail(
							apperrors.ErrCodeForbidden,
							"Session signer has reached transaction limit",
							fmt.Sprintf("max_txs: %d, current: %d", *sessionSigner.MaxTxs, txCount),
							http.StatusForbidden,
						)
					}
				}
			}
		}
	}

	// Load policies - use session signer override if present
	var policies []*types.Policy
	if sessionSigner != nil && sessionSigner.PolicyOverrideID != nil {
		// Session signer has policy override - use only that policy
		policy, err := s.policyRepo.GetByID(ctx, *sessionSigner.PolicyOverrideID)
		if err != nil {
			return nil, fmt.Errorf("failed to load override policy: %w", err)
		}
		if policy != nil {
			policies = []*types.Policy{policy}
		}
	} else {
		// Use wallet's policies
		var err error
		policies, err = s.policyRepo.GetByWalletID(ctx, wallet.ID)
		if err != nil {
			return nil, fmt.Errorf("failed to load policies: %w", err)
		}
	}

	// Load condition sets referenced by policies for in_condition_set operator
	conditionSets, err := s.loadConditionSetsForPolicies(ctx, policies)
	if err != nil {
		return nil, fmt.Errorf("failed to load condition sets: %w", err)
	}

	// Evaluate policies
	evalCtx := &policy.EvaluationContext{
		WalletID:      wallet.ID.String(),
		ChainType:     wallet.ChainType,
		Address:       wallet.Address,
		To:            &req.To,
		Value:         req.Value,
		Data:          req.Data,
		Actor:         userSub,
		SessionSigner: sessionSigner,
		Timestamp:     time.Now(),
		ConditionSets: conditionSets,
	}

	result, err := s.policyEng.Evaluate(ctx, policies, evalCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if result.Decision == policy.DecisionDeny {
		// Audit the denial
		policyResultStr := result.Reason
		log := &types.AuditLog{
			Actor:         userSub,
			Action:        "wallet.sign_transaction",
			ResourceType:  "wallet",
			ResourceID:    wallet.ID.String(),
			PolicyResult:  &policyResultStr,
			RequestDigest: &req.RequestDigest,
			ClientIP:      middleware.GetClientIP(ctx),
			UserAgent:     middleware.GetUserAgent(ctx),
		}
		if matchedSignerID != "" && matchedSignerID != ownerIDStr {
			log.SignerID = &matchedSignerID
		}
		s.auditRepo.Create(ctx, log)

		return nil, apperrors.PolicyDenied(result.Reason)
	}

	// Load key material
	shareRepo := storage.NewWalletShareRepository(s.store)
	shares, err := shareRepo.GetByWalletID(ctx, wallet.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load key shares: %w", err)
	}

	var authShare, execShare []byte
	for _, share := range shares {
		decrypted, err := s.keyExec.Decrypt(ctx, share.BlobEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt share: %w", err)
		}

		if share.ShareType == types.ShareTypeAuth {
			authShare = decrypted
		} else if share.ShareType == types.ShareTypeExec {
			execShare = decrypted
		}
	}

	keyMaterial := &keyexec.KeyMaterial{
		Address:   wallet.Address,
		AuthShare: authShare,
		ExecShare: execShare,
	}

	// Parse recipient address
	toAddr := common.HexToAddress(req.To)

	// Create the transaction
	tx := ethtypes.NewTx(&ethtypes.DynamicFeeTx{
		ChainID:   big.NewInt(req.ChainID),
		Nonce:     req.Nonce,
		To:        &toAddr,
		Value:     req.Value,
		Gas:       req.GasLimit,
		GasFeeCap: req.GasFeeCap,
		GasTipCap: req.GasTipCap,
		Data:      req.Data,
	})

	// Sign the transaction
	signedTx, err := s.keyExec.SignTransaction(ctx, keyMaterial, tx, req.ChainID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign transaction: %w", err)
	}

	// Audit the successful signing
	txHashStr := signedTx.Hash().Hex()
	policyResultStr := "allow"
	log := &types.AuditLog{
		Actor:         userSub,
		Action:        "wallet.sign_transaction",
		ResourceType:  "wallet",
		ResourceID:    wallet.ID.String(),
		PolicyResult:  &policyResultStr,
		TxHash:        &txHashStr,
		RequestDigest: &req.RequestDigest,
		ClientIP:      middleware.GetClientIP(ctx),
		UserAgent:     middleware.GetUserAgent(ctx),
	}
	if matchedSignerID != "" && matchedSignerID != ownerIDStr {
		log.SignerID = &matchedSignerID
	}
	s.auditRepo.Create(ctx, log)

	return signedTx, nil
}

// GetWallets retrieves all wallets for a user
func (s *WalletService) GetWallets(ctx context.Context, userSub string) ([]*types.Wallet, error) {
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return []*types.Wallet{}, nil
	}

	wallets, err := s.walletRepo.GetByUserID(ctx, user.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallets: %w", err)
	}

	return wallets, nil
}

// CreateSessionSigner adds a session signer (authorization key) to a wallet
func (s *WalletService) CreateSessionSigner(ctx context.Context, req *CreateSessionSignerRequest) (*types.SessionSigner, *types.AuthorizationKey, error) {
	// Verify wallet ownership (app_id scope is automatically enforced by repository)
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, nil, apperrors.WalletNotFound(req.WalletID.String())
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return nil, nil, apperrors.ErrForbidden
		}
	}

	// Validate public key (P-256 only)
	pubKeyBytes := common.FromHex(req.SignerPublicKey)
	if len(pubKeyBytes) == 0 {
		return nil, nil, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid signer public key",
			"Must be hex-encoded",
			400,
		)
	}
	if len(pubKeyBytes) != 65 && len(pubKeyBytes) != 33 {
		return nil, nil, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid signer public key length",
			"Expected 65 (uncompressed) or 33 (compressed) bytes",
			400,
		)
	}
	if x, y := elliptic.Unmarshal(elliptic.P256(), pubKeyBytes); x == nil || !elliptic.P256().IsOnCurve(x, y) {
		return nil, nil, apperrors.NewWithDetail(
			apperrors.ErrCodeBadRequest,
			"Invalid signer public key",
			"Point not on P-256 curve",
			400,
		)
	}

	// Normalize allowed methods
	allowedMethods := req.AllowedMethods
	if len(allowedMethods) == 0 {
		allowedMethods = []string{"sign_transaction"}
	}

	// MaxValue store as string pointer
	var maxValueStr *string
	if req.MaxValue != nil {
		mv := req.MaxValue.String()
		maxValueStr = &mv
	}

	// Get AppID from context for multi-tenant isolation
	appID, _ := storage.GetAppID(ctx)

	// Transactional creation of auth key + session signer
	tx, err := s.store.DB().Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	authKey := &types.AuthorizationKey{
		ID:          uuid.New(),
		PublicKey:   pubKeyBytes,
		Algorithm:   types.AlgorithmP256,
		OwnerEntity: req.UserSub,
		Status:      types.StatusActive,
		AppID:       &appID,
	}
	if err := s.authKeyRepo.CreateTx(ctx, tx, authKey); err != nil {
		return nil, nil, err
	}

	ss := &types.SessionSigner{
		ID:              uuid.New(),
		WalletID:        wallet.ID,
		SignerID:        authKey.ID.String(),
		PolicyOverrideID: req.PolicyOverrideID,
		AllowedMethods:  allowedMethods,
		MaxValue:        maxValueStr,
		MaxTxs:          req.MaxTxs,
		TTLExpiresAt:    time.Now().Add(req.TTL),
		AppID:           &appID,
	}
	if err := s.sessionRepo.CreateTx(ctx, tx, ss); err != nil {
		return nil, nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to commit session signer creation: %w", err)
	}

	return ss, authKey, nil
}

// ListSessionSigners lists session signers for a wallet (including revoked/expired)
func (s *WalletService) ListSessionSigners(ctx context.Context, userSub string, walletID uuid.UUID) ([]SessionSignerWithKey, error) {
	// App-scoped access is automatically enforced by repository
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, apperrors.WalletNotFound(walletID.String())
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, userSub)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return nil, apperrors.ErrForbidden
		}
	}

	signers, err := s.sessionRepo.ListByWallet(ctx, walletID)
	if err != nil {
		return nil, err
	}

	result := make([]SessionSignerWithKey, 0, len(signers))
	for _, ss := range signers {
		keyID, err := uuid.Parse(ss.SignerID)
		if err != nil {
			continue
		}
		authKey, err := s.authKeyRepo.GetByID(ctx, keyID)
		if err != nil || authKey == nil {
			continue
		}
		result = append(result, SessionSignerWithKey{Signer: ss, PublicKey: authKey.PublicKey})
	}

	return result, nil
}

// DeleteSessionSigner revokes a session signer and its authorization key
func (s *WalletService) DeleteSessionSigner(ctx context.Context, userSub string, walletID, signerID uuid.UUID) error {
	// App-scoped access is automatically enforced by repository
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return apperrors.WalletNotFound(walletID.String())
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, userSub)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return apperrors.ErrForbidden
		}
	}

	ss, err := s.sessionRepo.GetByID(ctx, signerID)
	if err != nil {
		return err
	}
	if ss == nil || ss.WalletID != walletID {
		return apperrors.ErrForbidden
	}

	// Revoke session signer and auth key
	if err := s.sessionRepo.Revoke(ctx, signerID); err != nil {
		return err
	}
	keyID, err := uuid.Parse(ss.SignerID)
	if err == nil {
		_ = s.authKeyRepo.UpdateStatus(ctx, keyID, types.StatusRevoked)
	}

	return nil
}

// verifyAuthorizationSignature checks that at least one provided signature is valid for the wallet owner
// or an active session signer. It returns the authorization key ID that validated (empty string means owner).
// The requiredMethod parameter specifies which signing method is being requested (e.g., sign_transaction, personal_sign).
func (s *WalletService) verifyAuthorizationSignature(ctx context.Context, wallet *types.Wallet, signatures []string, canonicalPayload []byte, requiredMethod types.SigningMethod) (string, error) {
	if len(signatures) == 0 {
		return "", apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing authorization signature",
			"X-Authorization-Signature header required",
			http.StatusUnauthorized,
		)
	}

	// Check if owner is a key quorum
	quorumRepo := storage.NewKeyQuorumRepository(s.store)
	quorum, err := quorumRepo.GetByID(ctx, *wallet.OwnerID)

	if err == nil && quorum != nil {
		// Owner is a key quorum - verify M-of-N signatures
		return s.verifyQuorumSignatures(ctx, quorum, signatures, canonicalPayload)
	}

	// Owner is a single authorization key - verify single signature or session signer
	return s.verifySingleOwnerSignature(ctx, wallet, signatures, canonicalPayload, requiredMethod)
}

// verifyQuorumSignatures verifies M-of-N threshold signatures for a key quorum
func (s *WalletService) verifyQuorumSignatures(ctx context.Context, quorum *types.KeyQuorum, signatures []string, canonicalPayload []byte) (string, error) {
	if quorum.Status != types.StatusActive {
		return "", apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"Quorum is not active",
			fmt.Sprintf("quorum %s has status %s", quorum.ID, quorum.Status),
			http.StatusForbidden,
		)
	}

	// Track which quorum keys have been verified
	verifiedKeys := make(map[uuid.UUID]bool)
	verifier := auth.NewSignatureVerifier()

	// Try to match each signature against each quorum key
	for _, sig := range signatures {
		for _, keyID := range quorum.KeyIDs {
			// Skip if already verified this key
			if verifiedKeys[keyID] {
				continue
			}

			authKey, err := s.authKeyRepo.GetByID(ctx, keyID)
			if err != nil || authKey == nil || authKey.Status != types.StatusActive {
				continue
			}

			if authKey.Algorithm != types.AlgorithmP256 {
				continue
			}

			publicKeyPEM, err := auth.PublicKeyToPEM(authKey.PublicKey)
			if err != nil {
				continue
			}

			if verified, err := verifier.VerifySignature(sig, canonicalPayload, publicKeyPEM); err == nil && verified {
				verifiedKeys[keyID] = true
				break // This signature matched, move to next signature
			}
		}
	}

	// Check if threshold is met
	if len(verifiedKeys) < quorum.Threshold {
		return "", apperrors.NewWithDetail(
			apperrors.ErrCodeForbidden,
			"Insufficient signatures for quorum",
			fmt.Sprintf("required %d signatures, got %d valid signatures", quorum.Threshold, len(verifiedKeys)),
			http.StatusForbidden,
		)
	}

	// Return quorum ID as matched signer
	return quorum.ID.String(), nil
}

// verifySingleOwnerSignature verifies signature for a single owner key or session signer
// The requiredMethod parameter specifies which signing method is being requested.
// Note: This function should only be called for user-owned wallets (wallet.OwnerID != nil)
func (s *WalletService) verifySingleOwnerSignature(ctx context.Context, wallet *types.Wallet, signatures []string, canonicalPayload []byte, requiredMethod types.SigningMethod) (string, error) {
	// Build list of allowed authorization keys
	allowed := make(map[uuid.UUID]*types.SessionSigner)
	if wallet.OwnerID != nil {
		allowed[*wallet.OwnerID] = nil // nil indicates primary owner (has all permissions)
	}

	// Active session signers
	sessionSigners, err := s.sessionRepo.GetActiveByWallet(ctx, wallet.ID, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to load session signers: %w", err)
	}

	for _, ss := range sessionSigners {
		// Check if this session signer is allowed to perform the required method
		if !s.sessionSignerAllowsMethod(ss, requiredMethod) {
			continue
		}

		keyID, err := uuid.Parse(ss.SignerID)
		if err != nil {
			continue
		}
		allowed[keyID] = ss
	}

	// Iterate signatures and try to verify against allowed keys
	verifier := auth.NewSignatureVerifier()
	for _, sig := range signatures {
		for keyID, ss := range allowed {
			authKey, err := s.authKeyRepo.GetByID(ctx, keyID)
			if err != nil {
				continue
			}
			if authKey == nil || authKey.Status != types.StatusActive {
				continue
			}
			if authKey.Algorithm != types.AlgorithmP256 {
				continue
			}

			// Convert public key to PEM format for verification
			publicKeyPEM, err := auth.PublicKeyToPEM(authKey.PublicKey)
			if err != nil {
				continue
			}

			// Verify signature using auth package
			if verified, err := verifier.VerifySignature(sig, canonicalPayload, publicKeyPEM); err == nil && verified {
				// Additional session signer checks (TTL/revoked already filtered in query)
				if ss != nil && ss.TTLExpiresAt.Before(time.Now()) {
					continue
				}
				return keyID.String(), nil
			}
		}
	}

	return "", apperrors.NewWithDetail(
		apperrors.ErrCodeUnauthorized,
		"Invalid authorization signature",
		"no signature matched an active owner or session signer key",
		http.StatusUnauthorized,
	)
}

// sessionSignerAllowsMethod checks if a session signer is allowed to perform a signing method
func (s *WalletService) sessionSignerAllowsMethod(ss *types.SessionSigner, method types.SigningMethod) bool {
	// If no allowed_methods specified, allow all methods (backwards compatibility)
	if len(ss.AllowedMethods) == 0 {
		return true
	}

	// Check if the required method is in the allowed list
	for _, allowedMethod := range ss.AllowedMethods {
		if types.SigningMethod(allowedMethod) == method {
			return true
		}
	}

	return false
}

// GetWallet retrieves a single wallet by ID
func (s *WalletService) GetWallet(ctx context.Context, walletID uuid.UUID, userSub string) (*types.Wallet, error) {
	// App-scoped access is automatically enforced by repository
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet not found")
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, userSub)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return nil, apperrors.ErrForbidden
		}
	}

	return wallet, nil
}

// ListWallets lists wallets with pagination and filtering
// App-scoped access is automatically enforced by repository
// Maintains per-user isolation: users can only see their own wallets + app-managed wallets
func (s *WalletService) ListWallets(ctx context.Context, req *ListWalletsRequest) ([]*types.Wallet, *string, error) {
	// Determine user ID for filtering to maintain per-user isolation
	// Users can see: their own wallets + app-managed wallets (user_id IS NULL)
	var userID *uuid.UUID
	onlyAppManaged := false

	// SECURITY: If caller has a user sub, they can only see their own wallets
	// FilterUserID is only honored when there's no user sub (backend/admin calls)
	if req.UserSub != "" {
		// User-authenticated request: always use caller's own user ID
		// FilterUserID is IGNORED to prevent enumeration attacks
		user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user != nil {
			userID = &user.ID
		} else {
			// Caller has no user record - only return app-managed wallets
			// This maintains isolation: new/unknown users can't see other users' wallets
			onlyAppManaged = true
		}
	} else if req.FilterUserID != nil {
		// Backend/admin call with explicit user filter (no user JWT)
		// This is for app-to-app calls where the app wants to list a specific user's wallets
		userID = req.FilterUserID
	} else {
		// No user context and no filter - only return app-managed wallets for safety
		onlyAppManaged = true
	}

	// Use repository's List method (app_id scope is automatically enforced)
	var cursor *string
	if req.Cursor != "" {
		cursor = &req.Cursor
	}

	wallets, err := s.walletRepo.List(ctx, userID, onlyAppManaged, req.ChainType, cursor, req.Limit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list wallets: %w", err)
	}

	// Determine next cursor (repository fetches limit+1 to check for next page)
	var nextCursor *string
	if len(wallets) > req.Limit {
		wallets = wallets[:req.Limit]
		cursorVal := wallets[len(wallets)-1].CreatedAt.Format(time.RFC3339)
		nextCursor = &cursorVal
	}

	return wallets, nextCursor, nil
}

// UpdateWallet updates a wallet's configuration
func (s *WalletService) UpdateWallet(ctx context.Context, req *UpdateWalletRequest) (*types.Wallet, error) {
	// Get wallet (automatically scoped to app_id from context)
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet not found")
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
		if err != nil {
			return nil, fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return nil, apperrors.ErrForbidden
		}
	}

	// Begin transaction
	tx, err := s.store.DB().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Update owner if provided
	if req.OwnerID != nil {
		// Verify owner exists
		owner, err := s.authKeyRepo.GetByID(ctx, *req.OwnerID)
		if err != nil || owner == nil {
			return nil, fmt.Errorf("owner not found")
		}

		query := `UPDATE wallets SET owner_id = $1 WHERE id = $2`
		_, err = tx.Exec(ctx, query, *req.OwnerID, req.WalletID)
		if err != nil {
			return nil, fmt.Errorf("failed to update owner: %w", err)
		}
		wallet.OwnerID = req.OwnerID
	} else if req.Owner != nil {
		// Create new owner
		publicKeyBytes := common.FromHex(req.Owner.PublicKey)
		if len(publicKeyBytes) == 0 {
			return nil, fmt.Errorf("invalid owner public key hex")
		}

		// Get AppID from context for the new authorization key
		appID, _ := storage.GetAppID(ctx)

		authKey := &types.AuthorizationKey{
			ID:          uuid.New(),
			PublicKey:   publicKeyBytes,
			Algorithm:   types.AlgorithmP256,
			OwnerEntity: req.UserSub,
			Status:      types.StatusActive,
			AppID:       &appID,
		}

		if err := s.authKeyRepo.CreateTx(ctx, tx, authKey); err != nil {
			return nil, fmt.Errorf("failed to create owner: %w", err)
		}

		query := `UPDATE wallets SET owner_id = $1 WHERE id = $2`
		_, err = tx.Exec(ctx, query, authKey.ID, req.WalletID)
		if err != nil {
			return nil, fmt.Errorf("failed to update owner: %w", err)
		}
		wallet.OwnerID = &authKey.ID
	}

	// Update policy IDs if provided
	if req.PolicyIDs != nil {
		// Delete existing policy associations
		_, err = tx.Exec(ctx, `DELETE FROM wallet_policies WHERE wallet_id = $1`, req.WalletID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete existing policies: %w", err)
		}

		// Insert new policy associations
		for _, policyID := range *req.PolicyIDs {
			_, err = tx.Exec(ctx,
				`INSERT INTO wallet_policies (wallet_id, policy_id) VALUES ($1, $2)`,
				req.WalletID, policyID,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to associate policy: %w", err)
			}
		}
	}

	// Update additional signers if provided
	if req.AdditionalSigners != nil {
		// Delete existing session signers
		_, err = tx.Exec(ctx, `DELETE FROM session_signers WHERE wallet_id = $1`, req.WalletID)
		if err != nil {
			return nil, fmt.Errorf("failed to delete existing signers: %w", err)
		}

		// Get AppID from context for new session signers
		signerAppID, _ := storage.GetAppID(ctx)

		// Insert new session signers
		for _, signer := range *req.AdditionalSigners {
			ss := &types.SessionSigner{
				ID:            uuid.New(),
				WalletID:      req.WalletID,
				SignerID:      signer.SignerID.String(),
				TTLExpiresAt:  time.Now().Add(365 * 24 * time.Hour), // Default 1 year
				AllowedMethods: []string{"sign_transaction"},
				AppID:         &signerAppID,
			}

			// Store override policy IDs if provided
			if len(signer.OverridePolicyIDs) > 0 {
				// Store first policy as override (simplified)
				ss.PolicyOverrideID = &signer.OverridePolicyIDs[0]
			}

			if err := s.sessionRepo.CreateTx(ctx, tx, ss); err != nil {
				return nil, fmt.Errorf("failed to create session signer: %w", err)
			}
		}
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Reload wallet (AppID already verified above, so using GetByIDAndAppID for consistency)
	wallet, err = s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload wallet: %w", err)
	}

	return wallet, nil
}

// DeleteWallet deletes a wallet
func (s *WalletService) DeleteWallet(ctx context.Context, walletID uuid.UUID, userSub string) error {
	// Get wallet (automatically scoped to app_id from context)
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return fmt.Errorf("wallet not found")
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	if !IsAppManagedWallet(wallet) && wallet.UserID != nil {
		user, err := s.userRepo.GetByExternalSub(ctx, userSub)
		if err != nil {
			return fmt.Errorf("failed to get user: %w", err)
		}
		if user == nil || user.ID != *wallet.UserID {
			return apperrors.ErrForbidden
		}
	}

	// Delete wallet (cascading deletes handled by DB)
	if err := s.walletRepo.Delete(ctx, walletID); err != nil {
		return fmt.Errorf("failed to delete wallet: %w", err)
	}

	// Audit log
	s.auditRepo.Create(ctx, &types.AuditLog{
		Actor:        userSub,
		Action:       "wallet.delete",
		ResourceType: "wallet",
		ResourceID:   walletID.String(),
		ClientIP:     middleware.GetClientIP(ctx),
		UserAgent:    middleware.GetUserAgent(ctx),
	})

	return nil
}

// GetOwner retrieves owner information for authorization signature verification
func (s *WalletService) GetOwner(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error) {
	// Try to get as authorization key
	authKey, err := s.authKeyRepo.GetByID(ctx, ownerID)
	if err != nil {
		return nil, fmt.Errorf("failed to get owner: %w", err)
	}
	if authKey != nil {
		// Convert to PEM format for signature verification
		publicKeyPEM, err := auth.PublicKeyToPEM(authKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert public key: %w", err)
		}

		return &auth.Owner{
			Type:      auth.OwnerTypeSingleKey,
			PublicKey: publicKeyPEM,
		}, nil
	}

	// TODO: Check if it's a key quorum
	// For now, return error
	return nil, fmt.Errorf("owner not found")
}

// ExportWalletRequest represents a request to export a wallet's private key
type ExportWalletRequest struct {
	WalletID         uuid.UUID
	Signatures       []string
	CanonicalPayload []byte
}

// ExportWallet exports the private key for a wallet
// SECURITY: This operation is highly sensitive and requires:
// 1. Authorization signature from wallet owner (for user-owned wallets)
// 2. Full audit logging
// 3. Rate limiting (should be implemented at API layer)
// For app-managed wallets, only app secret auth is required
func (s *WalletService) ExportWallet(ctx context.Context, userSub string, req *ExportWalletRequest) ([]byte, error) {
	// Get wallet (automatically scoped to app_id from context)
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, apperrors.WalletNotFound(req.WalletID.String())
	}

	// For app-managed wallets, skip user and signature verification - app secret auth is sufficient
	if IsAppManagedWallet(wallet) {
		// App-managed wallet - no owner signature required
		// Just proceed to key export with app secret auth
	} else {
		// User-owned wallet - verify ownership and authorization signature
		if wallet.UserID != nil {
			user, err := s.userRepo.GetByExternalSub(ctx, userSub)
			if err != nil {
				return nil, fmt.Errorf("failed to get user: %w", err)
			}
			if user == nil || user.ID != *wallet.UserID {
				return nil, apperrors.ErrForbidden
			}
		}

		// Verify authorization signature (owner only - session signers cannot export)
		// For export, we only accept the wallet owner's signature, not session signers
		if wallet.OwnerID == nil {
			return nil, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"Owner not found",
				"",
				http.StatusForbidden,
			)
		}

		ownerKey, err := s.authKeyRepo.GetByID(ctx, *wallet.OwnerID)
		if err != nil {
			return nil, fmt.Errorf("failed to get owner key: %w", err)
		}
		if ownerKey == nil || ownerKey.Status != types.StatusActive {
			return nil, apperrors.NewWithDetail(
				apperrors.ErrCodeForbidden,
				"Owner key not found or inactive",
				"",
				http.StatusForbidden,
			)
		}

		// Verify the signature is from the owner
		publicKeyPEM, err := auth.PublicKeyToPEM(ownerKey.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to convert public key: %w", err)
		}

		verifier := auth.NewSignatureVerifier()
		verified := false
		for _, sig := range req.Signatures {
			if ok, err := verifier.VerifySignature(sig, req.CanonicalPayload, publicKeyPEM); err == nil && ok {
				verified = true
				break
			}
		}
		if !verified {
			return nil, apperrors.NewWithDetail(
				apperrors.ErrCodeUnauthorized,
				"Invalid authorization signature",
				"Only wallet owner can export private key",
				http.StatusUnauthorized,
			)
		}
	}

	// Get wallet shares (encrypted private key material)
	shareRepo := storage.NewWalletShareRepository(s.store)
	shares, err := shareRepo.GetByWalletID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet shares: %w", err)
	}
	if len(shares) < 2 {
		return nil, fmt.Errorf("insufficient shares to reconstruct key")
	}

	// Decrypt shares and reconstruct private key
	var authShare, execShare []byte
	for _, share := range shares {
		decrypted, err := s.keyExec.Decrypt(ctx, share.BlobEncrypted)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt share: %w", err)
		}

		if share.ShareType == types.ShareTypeAuth {
			authShare = decrypted
		} else if share.ShareType == types.ShareTypeExec {
			execShare = decrypted
		}
	}

	if authShare == nil || execShare == nil {
		return nil, fmt.Errorf("missing required shares")
	}

	// Reconstruct private key using Shamir's Secret Sharing
	privateKeyBytes, err := internalcrypto.CombineAuthAndExec(authShare, execShare)
	if err != nil {
		return nil, fmt.Errorf("failed to combine shares: %w", err)
	}

	// Audit log the export (this is a sensitive operation)
	s.auditRepo.Create(ctx, &types.AuditLog{
		Actor:        userSub,
		Action:       "wallet.export",
		ResourceType: "wallet",
		ResourceID:   wallet.ID.String(),
		ClientIP:     middleware.GetClientIP(ctx),
		UserAgent:    middleware.GetUserAgent(ctx),
	})

	return privateKeyBytes, nil
}

// SignMessageRequest represents a request to sign a personal message
type SignMessageRequest struct {
	WalletID         uuid.UUID
	Message          string   // The message to sign (can be raw string or hex-encoded)
	Encoding         string   // "utf8" or "hex" - default "utf8"
	Signatures       []string // Authorization signatures
	CanonicalPayload []byte
}

// SignMessage signs an arbitrary message with the wallet's private key using EIP-191 personal_sign
func (s *WalletService) SignMessage(ctx context.Context, userSub string, req *SignMessageRequest) (string, error) {
	// Get wallet (automatically scoped to app_id from context)
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return "", apperrors.WalletNotFound(req.WalletID.String())
	}

	// For user-owned wallets, verify ownership
	// For app-managed wallets, skip user verification - app secret auth is sufficient
	var matchedSignerID string
	if !IsAppManagedWallet(wallet) {
		if wallet.UserID != nil {
			user, err := s.userRepo.GetByExternalSub(ctx, userSub)
			if err != nil {
				return "", fmt.Errorf("failed to get user: %w", err)
			}
			if user == nil || user.ID != *wallet.UserID {
				return "", apperrors.ErrForbidden
			}
		}

		// Verify authorization signature (owner or session signer with personal_sign permission)
		var err error
		matchedSignerID, err = s.verifyAuthorizationSignature(ctx, wallet, req.Signatures, req.CanonicalPayload, types.SignMethodPersonal)
		if err != nil {
			return "", err
		}
	}

	// Load policies and evaluate
	var sessionSigner *types.SessionSigner
	if matchedSignerID != "" && wallet.OwnerID != nil && matchedSignerID != wallet.OwnerID.String() {
		signerUUID, err := uuid.Parse(matchedSignerID)
		if err == nil {
			sessionSigner, _ = s.sessionRepo.GetByID(ctx, signerUUID)
		}
	}

	// Load policies
	var policies []*types.Policy
	if sessionSigner != nil && sessionSigner.PolicyOverrideID != nil {
		policy, err := s.policyRepo.GetByID(ctx, *sessionSigner.PolicyOverrideID)
		if err != nil {
			return "", fmt.Errorf("failed to load override policy: %w", err)
		}
		if policy != nil {
			policies = []*types.Policy{policy}
		}
	} else {
		policies, err = s.policyRepo.GetByWalletID(ctx, wallet.ID)
		if err != nil {
			return "", fmt.Errorf("failed to load policies: %w", err)
		}
	}

	// Evaluate policies
	evalCtx := &policy.EvaluationContext{
		WalletID:        wallet.ID.String(),
		ChainType:       wallet.ChainType,
		Address:         wallet.Address,
		Method:          "personal_sign",
		PersonalMessage: req.Message,
		Actor:           userSub,
		SessionSigner:   sessionSigner,
		Timestamp:       time.Now(),
	}

	result, err := s.policyEng.Evaluate(ctx, policies, evalCtx)
	if err != nil {
		return "", fmt.Errorf("failed to evaluate policy: %w", err)
	}

	if result.Decision == policy.DecisionDeny {
		s.auditRepo.Create(ctx, &types.AuditLog{
			Actor:        userSub,
			Action:       "wallet.sign_message",
			ResourceType: "wallet",
			ResourceID:   wallet.ID.String(),
			PolicyResult: &result.Reason,
			ClientIP:     middleware.GetClientIP(ctx),
			UserAgent:    middleware.GetUserAgent(ctx),
		})
		return "", apperrors.PolicyDenied(result.Reason)
	}

	// Decode message based on encoding
	var messageBytes []byte
	if req.Encoding == "hex" {
		messageBytes = common.FromHex(req.Message)
	} else {
		messageBytes = []byte(req.Message)
	}

	// Format message according to EIP-191 (personal_sign)
	// The prefix is: "\x19Ethereum Signed Message:\n" + len(message) + message
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d", len(messageBytes))
	prefixedMessage := append([]byte(prefix), messageBytes...)

	// Hash the prefixed message
	hash := crypto.Keccak256(prefixedMessage)

	// Load key material
	shareRepo := storage.NewWalletShareRepository(s.store)
	shares, err := shareRepo.GetByWalletID(ctx, wallet.ID)
	if err != nil {
		return "", fmt.Errorf("failed to load key shares: %w", err)
	}

	var authShare, execShare []byte
	for _, share := range shares {
		decrypted, err := s.keyExec.Decrypt(ctx, share.BlobEncrypted)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt share: %w", err)
		}

		if share.ShareType == types.ShareTypeAuth {
			authShare = decrypted
		} else if share.ShareType == types.ShareTypeExec {
			execShare = decrypted
		}
	}

	keyMaterial := &keyexec.KeyMaterial{
		Address:   wallet.Address,
		AuthShare: authShare,
		ExecShare: execShare,
	}

	// Sign the pre-computed hash (use SignHash to avoid double-hashing)
	signature, err := s.keyExec.SignHash(ctx, keyMaterial, hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign message: %w", err)
	}

	// Adjust v value for Ethereum compatibility (27 or 28 instead of 0 or 1)
	if len(signature) == 65 && (signature[64] == 0 || signature[64] == 1) {
		signature[64] += 27
	}

	// Audit log
	sigStr := formatSignature(signature)
	s.auditRepo.Create(ctx, &types.AuditLog{
		Actor:        userSub,
		Action:       "wallet.sign_message",
		ResourceType: "wallet",
		ResourceID:   wallet.ID.String(),
		ClientIP:     middleware.GetClientIP(ctx),
		UserAgent:    middleware.GetUserAgent(ctx),
	})

	return sigStr, nil
}

// TypedData represents EIP-712 typed data structure
type TypedData struct {
	Types       map[string]interface{} `json:"types"`
	PrimaryType string                 `json:"primaryType"`
	Domain      map[string]interface{} `json:"domain"`
	Message     map[string]interface{} `json:"message"`
}

// SignTypedData signs EIP-712 typed data
func (s *WalletService) SignTypedData(ctx context.Context, walletID uuid.UUID, typedData TypedData) (string, error) {
	// Get wallet (automatically scoped to app_id from context)
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return "", fmt.Errorf("wallet not found")
	}

	// Encode typed data according to EIP-712
	hash, err := encodeTypedData(typedData)
	if err != nil {
		return "", fmt.Errorf("failed to encode typed data: %w", err)
	}

	// Load key material
	shareRepo := storage.NewWalletShareRepository(s.store)
	shares, err := shareRepo.GetByWalletID(ctx, wallet.ID)
	if err != nil {
		return "", fmt.Errorf("failed to load key shares: %w", err)
	}

	var authShare, execShare []byte
	for _, share := range shares {
		decrypted, err := s.keyExec.Decrypt(ctx, share.BlobEncrypted)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt share: %w", err)
		}

		if share.ShareType == types.ShareTypeAuth {
			authShare = decrypted
		} else if share.ShareType == types.ShareTypeExec {
			execShare = decrypted
		}
	}

	keyMaterial := &keyexec.KeyMaterial{
		Address:   wallet.Address,
		AuthShare: authShare,
		ExecShare: execShare,
	}

	// Use key executor to sign the pre-computed hash (use SignHash to avoid double-hashing)
	signature, err := s.keyExec.SignHash(ctx, keyMaterial, hash)
	if err != nil {
		return "", fmt.Errorf("failed to sign typed data: %w", err)
	}

	// Format signature as hex string (0x-prefixed)
	return formatSignature(signature), nil
}

// encodeTypedData encodes EIP-712 typed data and returns its hash
func encodeTypedData(typedData TypedData) ([]byte, error) {
	// Convert our TypedData to go-ethereum's apitypes.TypedData
	eip712Data := make(map[string]interface{})
	eip712Data["types"] = typedData.Types
	eip712Data["primaryType"] = typedData.PrimaryType
	eip712Data["domain"] = typedData.Domain
	eip712Data["message"] = typedData.Message

	// Marshal to JSON
	jsonData, err := json.Marshal(eip712Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal typed data: %w", err)
	}

	// Use go-ethereum's EIP-712 encoding
	var td apitypes.TypedData
	if err := json.Unmarshal(jsonData, &td); err != nil {
		return nil, fmt.Errorf("failed to unmarshal into apitypes.TypedData: %w", err)
	}

	// Compute the EIP-712 hash
	domainSeparator, err := td.HashStruct("EIP712Domain", td.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}

	typedDataHash, err := td.HashStruct(td.PrimaryType, td.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash message: %w", err)
	}

	// EIP-712 final hash: keccak256("\x19\x01" ‖ domainSeparator ‖ hashStruct(message))
	rawData := []byte(fmt.Sprintf("\x19\x01%s%s", domainSeparator, typedDataHash))
	hash := crypto.Keccak256(rawData)

	return hash, nil
}

// formatSignature formats a signature as a hex-encoded string with 0x prefix
func formatSignature(signature []byte) string {
	return "0x" + hex.EncodeToString(signature)
}

// loadConditionSetsForPolicies extracts condition set IDs from policies and loads them from the database
// Returns a map of condition set ID -> values for use in policy evaluation
func (s *WalletService) loadConditionSetsForPolicies(ctx context.Context, policies []*types.Policy) (map[string][]interface{}, error) {
	result := make(map[string][]interface{})

	// Extract condition set IDs from all policies
	conditionSetIDs := make(map[string]bool)
	for _, p := range policies {
		if p == nil || p.Rules == nil {
			continue
		}

		// Parse rules to find in_condition_set operators
		rules, ok := p.Rules["rules"].([]interface{})
		if !ok {
			continue
		}

		for _, ruleInterface := range rules {
			rule, ok := ruleInterface.(map[string]interface{})
			if !ok {
				continue
			}

			conditions, ok := rule["conditions"].([]interface{})
			if !ok {
				continue
			}

			for _, condInterface := range conditions {
				cond, ok := condInterface.(map[string]interface{})
				if !ok {
					continue
				}

				operator, _ := cond["operator"].(string)
				if operator == "in_condition_set" {
					if value, ok := cond["value"].(string); ok && value != "" {
						conditionSetIDs[value] = true
					}
				}
			}
		}
	}

	// If no condition sets referenced, return empty map
	if len(conditionSetIDs) == 0 {
		return result, nil
	}

	// Load each condition set from the database
	csRepo := storage.NewConditionSetRepository(s.store)
	for csID := range conditionSetIDs {
		// Try to parse as UUID
		csUUID, err := uuid.Parse(csID)
		if err != nil {
			// Not a valid UUID, skip
			continue
		}

		cs, err := csRepo.GetByID(ctx, csUUID)
		if err != nil {
			// Log error but continue with other sets
			continue
		}
		if cs != nil {
			result[csID] = cs.Values
		}
	}

	return result, nil
}
