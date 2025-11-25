package app

import (
	"context"
	"crypto/elliptic"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/better-wallet/better-wallet/internal/keyexec"
	"github.com/better-wallet/better-wallet/internal/middleware"
	"github.com/better-wallet/better-wallet/internal/policy"
	"github.com/better-wallet/better-wallet/internal/storage"
	"github.com/better-wallet/better-wallet/internal/validation"
	"github.com/better-wallet/better-wallet/pkg/auth"
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

// CreateSessionSigner adds a session signer (authorization key) to a wallet
func (s *WalletService) CreateSessionSigner(ctx context.Context, req *CreateSessionSignerRequest) (*types.SessionSigner, *types.AuthorizationKey, error) {
	// Verify wallet ownership
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, nil, apperrors.WalletNotFound(req.WalletID.String())
	}

	user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return nil, nil, apperrors.ErrForbidden
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
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, apperrors.WalletNotFound(walletID.String())
	}
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return nil, apperrors.ErrForbidden
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
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return apperrors.WalletNotFound(walletID.String())
	}
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return apperrors.ErrForbidden
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

			// Convert public key to PEM format for verification
			publicKeyPEM, err := auth.PublicKeyToPEM(authKey.PublicKey)
			if err != nil {
				continue
			}

			// Verify signature using auth package
			verifier := auth.NewSignatureVerifier()
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

// GetWallet retrieves a single wallet by ID
func (s *WalletService) GetWallet(ctx context.Context, walletID uuid.UUID, userSub string) (*types.Wallet, error) {
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet not found")
	}

	// Verify ownership
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return nil, apperrors.ErrForbidden
	}

	return wallet, nil
}

// ListWallets lists wallets with pagination and filtering
func (s *WalletService) ListWallets(ctx context.Context, req *ListWalletsRequest) ([]*types.Wallet, *string, error) {
	// Get user
	user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil {
		return []*types.Wallet{}, nil, nil
	}

	// Build query
	query := `
		SELECT id, user_id, chain_type, owner_id, exec_backend, address, created_at
		FROM wallets
		WHERE user_id = $1
	`
	args := []interface{}{user.ID}
	argPos := 2

	// Apply filters
	if req.ChainType != "" {
		query += fmt.Sprintf(" AND chain_type = $%d", argPos)
		args = append(args, req.ChainType)
		argPos++
	}

	// Cursor-based pagination
	if req.Cursor != "" {
		cursorTime, err := time.Parse(time.RFC3339, req.Cursor)
		if err == nil {
			query += fmt.Sprintf(" AND created_at < $%d", argPos)
			args = append(args, cursorTime)
			argPos++
		}
	}

	query += " ORDER BY created_at DESC"

	// Fetch limit + 1 to determine if there's a next page
	fetchLimit := req.Limit + 1
	query += fmt.Sprintf(" LIMIT $%d", argPos)
	args = append(args, fetchLimit)

	rows, err := s.store.DB().Query(ctx, query, args...)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list wallets: %w", err)
	}
	defer rows.Close()

	wallets := []*types.Wallet{}
	for rows.Next() {
		var wallet types.Wallet
		err := rows.Scan(
			&wallet.ID,
			&wallet.UserID,
			&wallet.ChainType,
			&wallet.OwnerID,
			&wallet.ExecBackend,
			&wallet.Address,
			&wallet.CreatedAt,
		)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to scan wallet: %w", err)
		}
		wallets = append(wallets, &wallet)
	}

	// Determine next cursor
	var nextCursor *string
	if len(wallets) > req.Limit {
		wallets = wallets[:req.Limit]
		cursor := wallets[len(wallets)-1].CreatedAt.Format(time.RFC3339)
		nextCursor = &cursor
	}

	return wallets, nextCursor, nil
}

// UpdateWallet updates a wallet's configuration
func (s *WalletService) UpdateWallet(ctx context.Context, req *UpdateWalletRequest) (*types.Wallet, error) {
	// Get wallet
	wallet, err := s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return nil, fmt.Errorf("wallet not found")
	}

	// Verify ownership
	user, err := s.userRepo.GetByExternalSub(ctx, req.UserSub)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return nil, apperrors.ErrForbidden
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
		wallet.OwnerID = *req.OwnerID
	} else if req.Owner != nil {
		// Create new owner
		publicKeyBytes := common.FromHex(req.Owner.PublicKey)
		if len(publicKeyBytes) == 0 {
			return nil, fmt.Errorf("invalid owner public key hex")
		}

		authKey := &types.AuthorizationKey{
			ID:          uuid.New(),
			PublicKey:   publicKeyBytes,
			Algorithm:   types.AlgorithmP256,
			OwnerEntity: req.UserSub,
			Status:      types.StatusActive,
		}

		if err := s.authKeyRepo.CreateTx(ctx, tx, authKey); err != nil {
			return nil, fmt.Errorf("failed to create owner: %w", err)
		}

		query := `UPDATE wallets SET owner_id = $1 WHERE id = $2`
		_, err = tx.Exec(ctx, query, authKey.ID, req.WalletID)
		if err != nil {
			return nil, fmt.Errorf("failed to update owner: %w", err)
		}
		wallet.OwnerID = authKey.ID
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

		// Insert new session signers
		for _, signer := range *req.AdditionalSigners {
			ss := &types.SessionSigner{
				ID:            uuid.New(),
				WalletID:      req.WalletID,
				SignerID:      signer.SignerID.String(),
				TTLExpiresAt:  time.Now().Add(365 * 24 * time.Hour), // Default 1 year
				AllowedMethods: []string{"sign_transaction"},
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

	// Reload wallet
	wallet, err = s.walletRepo.GetByID(ctx, req.WalletID)
	if err != nil {
		return nil, fmt.Errorf("failed to reload wallet: %w", err)
	}

	return wallet, nil
}

// DeleteWallet deletes a wallet
func (s *WalletService) DeleteWallet(ctx context.Context, walletID uuid.UUID, userSub string) error {
	// Get wallet
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return fmt.Errorf("wallet not found")
	}

	// Verify ownership
	user, err := s.userRepo.GetByExternalSub(ctx, userSub)
	if err != nil {
		return fmt.Errorf("failed to get user: %w", err)
	}
	if user == nil || user.ID != wallet.UserID {
		return apperrors.ErrForbidden
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

// ExportWallet exports the private key for a wallet
// NOTE: This is a placeholder implementation. Full implementation requires:
// 1. Multi-party computation to reconstruct private key from shares
// 2. Proper authorization and audit logging
// 3. Rate limiting and security controls
func (s *WalletService) ExportWallet(ctx context.Context, walletID uuid.UUID) (string, error) {
	// Get wallet
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return "", fmt.Errorf("wallet not found")
	}

	// Get wallet shares (encrypted private key material)
	shareRepo := storage.NewWalletShareRepository(s.store)
	shares, err := shareRepo.GetByWalletID(ctx, walletID)
	if err != nil || len(shares) == 0 {
		return "", fmt.Errorf("failed to get wallet shares: %w", err)
	}

	// TODO: Implement actual key reconstruction from shares
	// This would involve:
	// 1. Decrypting each share using KMS
	// 2. Combining shares using threshold cryptography
	// 3. Reconstructing the private key

	// For now, return placeholder indicating feature needs implementation
	return "", fmt.Errorf("wallet export not yet fully implemented")
}

// SignMessage signs an arbitrary message with the wallet's private key
// NOTE: This is a placeholder implementation. Full implementation requires:
// 1. Proper message formatting (EIP-191 or EIP-712)
// 2. Integration with key executor for signing
// 3. Support for different chain types
func (s *WalletService) SignMessage(ctx context.Context, walletID uuid.UUID, message string) (string, error) {
	// Get wallet
	wallet, err := s.walletRepo.GetByID(ctx, walletID)
	if err != nil {
		return "", fmt.Errorf("failed to get wallet: %w", err)
	}
	if wallet == nil {
		return "", fmt.Errorf("wallet not found")
	}

	// TODO: Implement actual message signing
	// This would involve:
	// 1. Formatting message according to EIP-191 (personal_sign)
	// 2. Hashing the formatted message
	// 3. Using key executor to sign the hash
	// 4. Formatting signature properly (v, r, s)

	// For now, return placeholder indicating feature needs implementation
	return "", fmt.Errorf("message signing not yet fully implemented")
}
