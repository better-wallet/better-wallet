package api

import (
	"context"

	"github.com/better-wallet/better-wallet/internal/app"
	"github.com/better-wallet/better-wallet/pkg/auth"
	"github.com/better-wallet/better-wallet/pkg/types"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/google/uuid"
)

// WalletService is the subset of app.WalletService used by the API layer.
// It is an interface to allow handler-level unit tests without a database.
type WalletService interface {
	CreateWallet(ctx context.Context, req *app.CreateWalletRequest) (*app.CreateWalletResponse, error)
	GetWallet(ctx context.Context, walletID uuid.UUID, userSub string) (*types.Wallet, error)
	ListWallets(ctx context.Context, req *app.ListWalletsRequest) ([]*types.Wallet, *string, error)
	UpdateWallet(ctx context.Context, req *app.UpdateWalletRequest) (*types.Wallet, error)
	DeleteWallet(ctx context.Context, walletID uuid.UUID, userSub string) error

	SignTransaction(ctx context.Context, userSub string, req *app.SignTransactionRequest) (*ethtypes.Transaction, error)
	SignMessage(ctx context.Context, userSub string, req *app.SignMessageRequest) (string, error)
	SignTypedData(ctx context.Context, userSub string, req *app.SignTypedDataRequest) (string, error)

	GetOwner(ctx context.Context, ownerID uuid.UUID) (*auth.Owner, error)
	ExportWallet(ctx context.Context, userSub string, req *app.ExportWalletRequest) ([]byte, error)

	CreateSessionSigner(ctx context.Context, req *app.CreateSessionSignerRequest) (*types.SessionSigner, *types.AuthorizationKey, error)
	ListSessionSigners(ctx context.Context, userSub string, walletID uuid.UUID) ([]app.SessionSignerWithKey, error)
	DeleteSessionSigner(ctx context.Context, userSub string, walletID, signerID uuid.UUID) error
}

