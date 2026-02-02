package eth

import (
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/ethclient"
)

// Client wraps an Ethereum RPC client
type Client struct {
	client  *ethclient.Client
	chainID *big.Int
}

// NewClient creates a new EVM client and auto-detects chain ID
func NewClient(rpcURL string) (*Client, error) {
	if rpcURL == "" {
		return nil, fmt.Errorf("RPC URL is required")
	}

	client, err := ethclient.Dial(rpcURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to RPC: %w", err)
	}

	// Auto-detect chain ID from RPC
	chainID, err := client.ChainID(context.Background())
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("failed to get chain ID: %w", err)
	}

	return &Client{
		client:  client,
		chainID: chainID,
	}, nil
}

// ChainID returns the chain ID
func (c *Client) ChainID() int64 {
	return c.chainID.Int64()
}

// ChainIDBig returns the chain ID as big.Int
func (c *Client) ChainIDBig() *big.Int {
	return c.chainID
}

// GetBalance returns the balance of an address in wei
func (c *Client) GetBalance(ctx context.Context, address string) (*big.Int, error) {
	addr := common.HexToAddress(address)
	balance, err := c.client.BalanceAt(ctx, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get balance: %w", err)
	}
	return balance, nil
}

// GetNonce returns the next nonce for an address
func (c *Client) GetNonce(ctx context.Context, address string) (uint64, error) {
	addr := common.HexToAddress(address)
	nonce, err := c.client.PendingNonceAt(ctx, addr)
	if err != nil {
		return 0, fmt.Errorf("failed to get nonce: %w", err)
	}
	return nonce, nil
}

// EstimateGas estimates the gas needed for a transaction
// If 'to' is empty, it's treated as a contract deployment (To = nil)
func (c *Client) EstimateGas(ctx context.Context, from, to string, value *big.Int, data []byte) (uint64, error) {
	fromAddr := common.HexToAddress(from)

	msg := ethereum.CallMsg{
		From:  fromAddr,
		Value: value,
		Data:  data,
	}

	// For contract deployment, To should be nil
	if to != "" {
		toAddr := common.HexToAddress(to)
		msg.To = &toAddr
	}

	gas, err := c.client.EstimateGas(ctx, msg)
	if err != nil {
		return 0, fmt.Errorf("failed to estimate gas: %w", err)
	}

	// Add 20% buffer for safety
	return gas * 120 / 100, nil
}

// SuggestGasPrice returns the suggested gas price
func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	gasPrice, err := c.client.SuggestGasPrice(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas price: %w", err)
	}
	return gasPrice, nil
}

// SuggestGasTipCap returns the suggested gas tip cap for EIP-1559 transactions
func (c *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	tipCap, err := c.client.SuggestGasTipCap(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get gas tip cap: %w", err)
	}
	return tipCap, nil
}

// SendRawTransaction broadcasts a signed transaction to the network
func (c *Client) SendRawTransaction(ctx context.Context, signedTx *types.Transaction) (string, error) {
	err := c.client.SendTransaction(ctx, signedTx)
	if err != nil {
		return "", fmt.Errorf("failed to send transaction: %w", err)
	}
	return signedTx.Hash().Hex(), nil
}

// Close closes the client connection
func (c *Client) Close() {
	c.client.Close()
}
