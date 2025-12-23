# Signing Overview

Better Wallet supports multiple signing operations for Ethereum transactions, messages, and structured data. All signing uses the unified `/rpc` endpoint with JSON-RPC 2.0 format.

## Signing Methods

| JSON-RPC Method | Use Case | Standard |
|-----------------|----------|----------|
| `eth_sendTransaction` | Send ETH, interact with contracts | EIP-1559, Legacy |
| `eth_signTransaction` | Sign transaction (no broadcast) | EIP-1559, Legacy |
| `personal_sign` | Authentication, off-chain signatures | EIP-191 |
| `eth_signTypedData_v4` | Permits, orders, structured data | EIP-712 |

## Transaction Signing

Sign Ethereum transactions for on-chain execution.

### EIP-1559 Transaction

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "value": "0xde0b6b3a7640000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x5208",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400"
    }],
    "id": 1
  }'
```

### Parameters

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `to` | string | Recipient address (hex) | Yes |
| `value` | string | Wei amount (decimal string) | Yes |
| `chain_id` | integer | Network chain ID | Yes |
| `nonce` | integer | Transaction nonce | Yes |
| `gas_limit` | integer | Gas limit | Yes |
| `gas_fee_cap` | string | Max fee per gas (EIP-1559) | Yes* |
| `gas_tip_cap` | string | Priority fee (EIP-1559) | Yes* |
| `gas_price` | string | Gas price (legacy) | Yes* |
| `data` | string | Call data (hex) | No |

*Either `gas_fee_cap`+`gas_tip_cap` (EIP-1559) or `gas_price` (legacy)

### Response

```json
{
  "signed_transaction": "0x02f87001808477359400850708d7c00082520894742d35cc6634c0532925a3b844bc9e7595f0beb88de0b6b3a764000080c001a0...",
  "tx_hash": "0xabc123def456789..."
}
```

### Contract Interaction

```bash
# ERC-20 transfer
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "value": "0x0",
      "chain_id": 1,
      "nonce": "0x1",
      "gas_limit": "0xfde8",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400",
      "data": "0xa9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000003b9aca00"
    }],
    "id": 1
  }'
```

## Personal Message Signing

Sign arbitrary messages for authentication or off-chain verification.

### Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "personal_sign",
    "params": [{
      "message": "Welcome to MyApp!\n\nPlease sign this message to verify your wallet ownership.\n\nNonce: abc123xyz"
    }],
    "id": 1
  }'
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b"
  },
  "id": 1
}
```

### Message Format

The message is prefixed according to EIP-191:
```
"\x19Ethereum Signed Message:\n" + len(message) + message
```

### Use Cases

| Use Case | Example Message |
|----------|-----------------|
| Authentication | "Sign in to MyApp\nNonce: xyz123" |
| Terms acceptance | "I agree to the Terms of Service v2.0" |
| Ownership proof | "I own this wallet\nTimestamp: 1705312800" |

## Typed Data Signing (EIP-712)

Sign structured data with type information for better security and UX.

### Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_signTypedData_v4",
    "params": [{
      "typed_data": {
        "types": {
          "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
          ],
          "Permit": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "deadline", "type": "uint256"}
          ]
        },
        "primaryType": "Permit",
        "domain": {
          "name": "USD Coin",
          "version": "2",
          "chainId": 1,
          "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        },
        "message": {
          "owner": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
          "spender": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
          "value": "1000000000",
          "nonce": 0,
          "deadline": 1735689600
        }
      }
    }],
    "id": 1
  }'
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "0x..."
  },
  "id": 1
}
```

### Common Use Cases

| Protocol | Use Case | Primary Type |
|----------|----------|--------------|
| ERC-2612 | Token approvals without gas | Permit |
| Uniswap | Gasless swaps | Permit2 |
| OpenSea | NFT listings | Order |
| Gnosis Safe | Multi-sig transactions | SafeTx |

### EIP-2612 Permit Example

```json
{
  "types": {
    "EIP712Domain": [...],
    "Permit": [
      {"name": "owner", "type": "address"},
      {"name": "spender", "type": "address"},
      {"name": "value", "type": "uint256"},
      {"name": "nonce", "type": "uint256"},
      {"name": "deadline", "type": "uint256"}
    ]
  },
  "primaryType": "Permit",
  "domain": {
    "name": "Token Name",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0xTokenAddress..."
  },
  "message": {
    "owner": "0xWalletAddress...",
    "spender": "0xSpenderAddress...",
    "value": "1000000000000000000",
    "nonce": 0,
    "deadline": 1735689600
  }
}
```

## Policy Evaluation

All signing operations pass through the policy engine:

```
┌─────────────────────────────────────────────────────────────┐
│                    Signing Request                           │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Authentication Check                        │
│  • App credentials (X-App-Id, X-App-Secret)                 │
│  • User JWT                                                  │
│  • Wallet ownership or session signer                        │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                  Policy Evaluation                           │
│  • Load wallet policies                                      │
│  • Load session signer override (if applicable)              │
│  • Evaluate rules against request                            │
│  • Return ALLOW or DENY                                      │
└─────────────────────────────┬───────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              │                               │
              ▼                               ▼
      ┌──────────────┐                ┌──────────────┐
      │    ALLOW     │                │    DENY      │
      │              │                │              │
      │  Proceed to  │                │  Return 403  │
      │   signing    │                │  with reason │
      └──────────────┘                └──────────────┘
```

### Policy Fields by Signing Method

| Signing Method | Available Field Sources |
|----------------|------------------------|
| Transaction | `ethereum_transaction`, `ethereum_calldata` |
| Personal Message | `ethereum_message` |
| Typed Data | `ethereum_typed_data_domain`, `ethereum_typed_data_message` |
| All | `system` |

## Using Session Signers

For delegated signing (bots, automated systems), session signers use the same authorization signature mechanism. Sign with the session signer's private key:

```bash
# Sign using a session signer's authorization key
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SESSION_SIGNER_SIGNATURE" \
  -H "X-Authorization-Key-Id: $SESSION_SIGNER_AUTH_KEY_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0x...",
      "value": "0x16345785d8a0000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x5208",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400"
    }],
    "id": 1
  }'
```

The server automatically identifies whether the signing key belongs to the wallet owner or a session signer and applies the appropriate limits.

Session signers can have:
- **TTL**: Automatic expiration
- **max_value**: Maximum transaction value
- **max_txs**: Maximum transaction count
- **policy_override_id**: Different policy than wallet default

See [Session Signers](../session-signers/overview.md) for details.

## Error Handling

### Common Errors

| Error Code | Meaning | Resolution |
|------------|---------|------------|
| `policy_denied` | Policy rejected transaction | Check policy rules |
| `wallet_not_found` | Wallet doesn't exist | Verify wallet ID |
| `insufficient_funds` | Not enough ETH for gas | Fund the wallet |
| `invalid_nonce` | Nonce already used | Get current nonce |
| `session_expired` | Session signer TTL passed | Create new session |

### Error Response Example

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied by policy",
    "details": {
      "policy_id": "550e8400-...",
      "policy_name": "Max 0.1 ETH",
      "rule_name": "Value limit",
      "reason": "value 1000000000000000000 exceeds limit 100000000000000000"
    }
  }
}
```

## Best Practices

### 1. Always Specify Chain ID

```json
{
  "chain_id": 1,  // Mainnet
  "chain_id": 11155111  // Sepolia testnet
}
```

### 2. Use Appropriate Gas Settings

```javascript
// For EIP-1559
const baseFee = await getBaseFee();
const gasSettings = {
  gas_fee_cap: (baseFee * 2n + priorityFee).toString(),
  gas_tip_cap: priorityFee.toString(),
};
```

### 3. Handle Nonce Management

```javascript
// Get current nonce before signing
const nonce = await provider.getTransactionCount(walletAddress);
```

### 4. Validate Before Signing

```javascript
// Simulate transaction before signing
const simulation = await provider.call({
  to: txParams.to,
  data: txParams.data,
  value: txParams.value,
});
```

## Next Steps

- [Transaction Signing](./transaction-signing.md) - Detailed transaction guide
- [Message Signing](./message-signing.md) - Personal message signing
- [Typed Data Signing](./typed-data-signing.md) - EIP-712 guide
- [Session Signers](../session-signers/overview.md) - Delegated signing
- [Policy Engine](../policies/overview.md) - Access control
