package app

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/authsig"
	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/internal/validation"
	apperrors "github.com/better-wallet/better-wallet/pkg/errors"
	"github.com/better-wallet/better-wallet/pkg/types"
	"github.com/ethereum/go-ethereum/common"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

// WalletService handles wallet operations
type WalletService struct {
	walletRepo  *storage.WalletRepository
	userRepo    *storage.UserRepository
	policyRepo  *storage.PolicyRepository
	auditRepo   *storage.AuditRepository
	sessionRepo *storage.SessionSignerRepository
	idemRepo    *storage.IdempotencyRepository
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
		idemRepo:    storage.NewIdempotencyRepository(store),
		authKeyRepo: storage.NewAuthorizationKeyRepository(store),
		keyExec:     keyExec,
		policyEng:   policyEng,
		store:       store,
	}
}

// CreateWalletRequest represents a request to create a wallet
type CreateWalletRequest struct {
	UserSub        string
	ChainType      string
	OwnerPublicKey string // Hex-encoded public key
	OwnerAlgorithm string // "p256"
	ExecBackend    string
}

// CreateWallet creates a new wallet for a user
func (s *WalletService) CreateWallet(ctx context.Context, req *CreateWalletRequest) (*types.Wallet, error) {
	// Get or create user
	user, err := s.userRepo.GetOrCreate(ctx, req.UserSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get or create user: %w", err)
	}

	// Decode and validate owner public key
	publicKeyBytes := common.FromHex(req.OwnerPublicKey)
	if len(publicKeyBytes) == 0 {
		return nil, fmt.Errorf("invalid owner public key hex")
	}

	// Validate public key format based on algorithm
	// Only P-256 is supported for production use
	if req.OwnerAlgorithm != types.AlgorithmP256 {
		return nil, fmt.Errorf("unsupported algorithm: %s (only 'p256' is supported)", req.OwnerAlgorithm)
	}

	// P-256: Validate format and ensure point is on curve
	if len(publicKeyBytes) != 65 && len(publicKeyBytes) != 33 {
		return nil, fmt.Errorf("invalid P-256 public key length: expected 65 (uncompressed) or 33 (compressed) bytes, got %d", len(publicKeyBytes))
	}

	// Parse and validate the public key
	x, y := elliptic.Unmarshal(elliptic.P256(), publicKeyBytes)
	if x == nil {
		return nil, fmt.Errorf("invalid P-256 public key format: failed to parse")
	}
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("invalid P-256 public key: point not on curve")
	}

	// Generate and split key
	keyMaterial, err := s.keyExec.GenerateAndSplitKey(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Encrypt the auth share before storing
	encryptedAuthShare, err := s.keyExec.Encrypt(ctx, keyMaterial.AuthShare)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt auth share: %w", err)
	}

	// Create authorization key
	authKey := &types.AuthorizationKey{
		ID:          uuid.New(),
		PublicKey:   publicKeyBytes,
		Algorithm:   req.OwnerAlgorithm,
		OwnerEntity: req.UserSub,
		Status:      types.StatusActive,
	}

	// Create wallet record
	wallet := &types.Wallet{
		ID:          uuid.New(),
		UserID:      user.ID,
		ChainType:   req.ChainType,
		OwnerID:     authKey.ID, // Reference the authorization key
		ExecBackend: req.ExecBackend,
		Address:     keyMaterial.Address,
	}

	// Begin transaction
	tx, err := s.store.DB().Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to begin transaction: %w", err)
	}
	defer tx.Rollback(ctx)

	// Create authorization key first
	authKeyRepo := storage.NewAuthorizationKeyRepository(s.store)
	if err := authKeyRepo.CreateTx(ctx, tx, authKey); err != nil {
		return nil, fmt.Errorf("failed to create authorization key: %w", err)
	}

	// Create wallet using transaction
	if err := s.walletRepo.CreateTx(ctx, tx, wallet); err != nil {
		return nil, fmt.Errorf("failed to create wallet: %w", err)
	}

	// Store wallet shares
	shareRepo := storage.NewWalletShareRepository(s.store)
	authShare := &types.WalletShare{
		WalletID:      wallet.ID,
		ShareType:     types.ShareTypeAuth,
		BlobEncrypted: encryptedAuthShare,
		Version:       1,
	}

	if err := shareRepo.CreateTx(ctx, tx, authShare); err != nil {
		return nil, fmt.Errorf("failed to store auth share: %w", err)
	}

	// For KMS mode, store exec share in database as well (encrypted)
	// In production, this might be stored differently based on backend
	encryptedExecShare, err := s.keyExec.Encrypt(ctx, keyMaterial.ExecShare)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt exec share: %w", err)
	}

	execShare := &types.WalletShare{
		WalletID:      wallet.ID,
		ShareType:     types.ShareTypeExec,
		BlobEncrypted: encryptedExecShare,
		Version:       1,
	}

	if err := shareRepo.CreateTx(ctx, tx, execShare); err != nil {
		return nil, fmt.Errorf("failed to store exec share: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("failed to commit transaction: %w", err)
	}

	// Audit log with client context
	s.auditRepo.Create(ctx, &types.AuditLog{
		Actor:        req.UserSub,
		Action:       "wallet.create",
		ResourceType: "wallet",
		ResourceID:   wallet.ID.String(),
		ClientIP:     middleware.GetClientIP(ctx),
		UserAgent:    middleware.GetUserAgent(ctx),
	})

	return wallet, nil
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

	// Get wallet
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, apperrors.WalletNotFound(req.WalletID.String())
	}

	// Verify ownership
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return nil, apperrors.ErrForbidden
	}

	// Verify authorization signature (owner or active session signer)
	matchedSignerID, err := s.verifyAuthorizationSignature(ctx, wallet, req.Signatures, req.CanonicalPayload)
	if err != nil {
		return nil, err
	}

	// Idempotency enforcement (if provided)
	if req.IdempotencyKey != "" {
		if err := s.idemRepo.CheckAndRecord(ctx, req.AppID, req.IdempotencyKey, req.HTTPMethod, req.URLPath, req.RequestDigest); err != nil {
			return nil, apperrors.NewWithDetail(
				apperrors.ErrCodeConflict,
				"Idempotency key conflict",
				err.Error(),
				409,
			)
		}
	}

	// Load policies associated with this wallet
	policies, err := s.policyRepo.GetByWalletID(ctx, wallet.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to load policies: %w", err)
	}

	// Evaluate policies
	evalCtx := &policy.EvaluationContext{
		WalletID:  wallet.ID.String(),
		ChainType: wallet.ChainType,
		Address:   wallet.Address,
		To:        &req.To,
		Value:     req.Value,
		Data:      req.Data,
		Actor:     userSub,
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
		if matchedSignerID != "" && matchedSignerID != wallet.OwnerID.String() {
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
		Version:   1,
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
	if matchedSignerID != "" && matchedSignerID != wallet.OwnerID.String() {
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

// verifyAuthorizationSignature checks that at least one provided signature is valid for the wallet owner
// or an active session signer. It returns the authorization key ID that validated (empty string means owner).
func (s *WalletService) verifyAuthorizationSignature(ctx context.Context, wallet *types.Wallet, signatures []string, canonicalPayload []byte) (string, error) {
	if len(signatures) == 0 {
		return "", apperrors.NewWithDetail(
			apperrors.ErrCodeUnauthorized,
			"Missing authorization signature",
			"X-Authorization-Signature header required",
			http.StatusUnauthorized,
		)
	}

	// Build list of allowed authorization keys
	allowed := make(map[uuid.UUID]*types.SessionSigner)
	allowed[wallet.OwnerID] = nil // nil indicates primary owner

	// Active session signers
	sessionSigners, err := s.sessionRepo.GetActiveByWallet(ctx, wallet.ID, time.Now())
	if err != nil {
		return "", fmt.Errorf("failed to load session signers: %w", err)
	}

	for _, ss := range sessionSigners {
		// If allowed_methods is set, require sign_transaction to be allowed
		if len(ss.AllowedMethods) > 0 {
			allowedMethod := false
			for _, m := range ss.AllowedMethods {
				if m == "sign_transaction" {
					allowedMethod = true
					break
				}
			}
			if !allowedMethod {
				continue
			}
		}

		keyID, err := uuid.Parse(ss.SignerID)
		if err != nil {
			continue
		}
		allowed[keyID] = ss
	}

	// Iterate signatures and try to verify against allowed keys
	for _, sig := range signatures {
		for keyID, ss := range allowed {
			authKey, err := s.authKeyRepo.GetByID(ctx, keyID)
			if err != nil {
				return "", fmt.Errorf("failed to load authorization key: %w", err)
			}
			if authKey == nil || authKey.Status != types.StatusActive {
				continue
			}
			if authKey.Algorithm != types.AlgorithmP256 {
				return "", fmt.Errorf("unsupported algorithm for authorization key %s: %s", keyID, authKey.Algorithm)
			}

			if err := authsig.VerifyP256Signature(authKey.PublicKey, canonicalPayload, sig); err == nil {
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
