# Session Signers Overview

Session signers enable delegated, time-limited signing capabilities for wallets. They're ideal for automated systems, bots, and scenarios where you need to sign transactions without the wallet owner's direct involvement.

## What are Session Signers?

A session signer is a temporary authorization that allows a specific identifier to sign transactions on behalf of a wallet, subject to:

- **Time limits (TTL)**: Automatic expiration
- **Value limits**: Maximum transaction value
- **Transaction count limits**: Maximum number of transactions
- **Method restrictions**: Only specific signing methods
- **Policy overrides**: Different policies than the wallet default

```
┌─────────────────────────────────────────────────────────────┐
│                      Wallet Owner                            │
│                  (Authorization Key)                         │
└─────────────────────────────┬───────────────────────────────┘
                              │
                    Creates session signer
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Session Signer                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  signer_id: "trading-bot-001"                       │   │
│  │  ttl: 24 hours                                       │   │
│  │  max_value: 0.5 ETH                                  │   │
│  │  max_txs: 100                                        │   │
│  │  allowed_methods: ["sign_transaction"]               │   │
│  │  policy_override: "bot-trading-policy"               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
              Can sign within limits
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Signing Request                           │
│  Headers: X-Authorization-Signature + X-Authorization-Key-Id │
│  (signed with session signer's private key)                 │
└─────────────────────────────────────────────────────────────┘
```

## Use Cases

| Scenario | Configuration |
|----------|---------------|
| **Trading bot** | 24h TTL, specific DEX contracts only |
| **Telegram bot** | 1h TTL, small value limit, revocable |
| **Game session** | 2h TTL, game contract only, limited txs |
| **Batch minting** | 1h TTL, mint function only, 1000 tx limit |
| **Payment processor** | 12h TTL, payment contract, value limit |
| **Automated DCA** | 7d TTL, swap function, daily tx limit |

## Creating a Session Signer

### Prerequisites

1. Wallet with an owner (authorization key)
2. Authorization signature from the owner

### Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID" \
  -H "X-Idempotency-Key: create-session-$(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "signer_id": "trading-bot-001",
    "ttl": 86400,
    "max_value": "500000000000000000",
    "max_txs": 100,
    "allowed_methods": ["sign_transaction"],
    "policy_override_id": "bot-policy-uuid"
  }'
```

### Parameters

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `signer_id` | string | Unique identifier for this session | Yes |
| `ttl` | integer | Time-to-live in seconds | Yes |
| `max_value` | string | Max value per transaction (wei) | No |
| `max_txs` | integer | Max number of transactions | No |
| `allowed_methods` | array | Restricted signing methods | No |
| `policy_override_id` | UUID | Policy to use instead of wallet policy | No |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "wallet_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "signer_id": "trading-bot-001",
  "ttl_expires_at": "2025-01-16T10:00:00Z",
  "max_value": "500000000000000000",
  "max_txs": 100,
  "allowed_methods": ["sign_transaction"],
  "policy_override_id": "bot-policy-uuid",
  "created_at": "2025-01-15T10:00:00Z"
}
```

## Using a Session Signer

### Signing with Session Signer

Session signers use the same authorization signature mechanism as wallet owners. Sign the request with the session signer's private key and include the session signer's authorization key ID. All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format:

```bash
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
      "to": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "value": "0x16345785d8a0000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x30d40",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400",
      "data": "0x38ed1739..."
    }],
    "id": 1
  }'
```

> **Note:** The server automatically identifies whether the signing key belongs to the wallet owner or a session signer, and applies the appropriate limits and policy overrides.

### Validation Flow

```
1. Verify session signer exists and not revoked
2. Check TTL hasn't expired
3. Verify wallet_id matches
4. Check transaction count limit
5. Check value limit (if set)
6. Check method is allowed (if restricted)
7. Evaluate policy_override (if set) or wallet policies
8. If all pass, proceed to signing
```

## Session Signer Limits

### Value Limit

```json
{
  "max_value": "500000000000000000"  // 0.5 ETH in wei
}
```

Each transaction's `value` is checked against this limit. Contract calls with value are also checked.

### Transaction Count Limit

```json
{
  "max_txs": 100
}
```

Counter increments with each successful signing. Once reached, all subsequent requests are denied.

### Method Restrictions

```json
{
  "allowed_methods": ["eth_sendTransaction", "personal_sign"]
}
```

Available methods:
- `eth_sendTransaction` - Transaction signing
- `personal_sign` - Personal message signing
- `eth_signTypedData_v4` - EIP-712 typed data signing

If not specified, all methods are allowed.

## Policy Overrides

Session signers can use a different policy than the wallet's default:

### Create Override Policy

```bash
# Create a restrictive policy for the bot
curl -X POST "http://localhost:8080/v1/policies" \
  -H "..." \
  -d '{
    "name": "Trading bot policy",
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [
        {
          "name": "Only Uniswap V2",
          "method": "*",
          "conditions": [
            {
              "field_source": "ethereum_transaction",
              "field": "to",
              "operator": "eq",
              "value": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            }
          ],
          "action": "ALLOW"
        }
      ]
    }
  }'
```

### Use in Session Signer

```json
{
  "signer_id": "trading-bot-001",
  "ttl": 86400,
  "policy_override_id": "trading-bot-policy-uuid"
}
```

When this session signer is used:
1. The override policy is evaluated INSTEAD of wallet policies
2. The override policy must explicitly ALLOW the operation
3. Session limits (value, txs) are still enforced

## Listing Session Signers

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID/session-signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

Response:
```json
{
  "session_signers": [
    {
      "id": "uuid-1",
      "signer_id": "trading-bot-001",
      "ttl_expires_at": "2025-01-16T10:00:00Z",
      "max_value": "500000000000000000",
      "max_txs": 100,
      "created_at": "2025-01-15T10:00:00Z",
      "revoked_at": null
    },
    {
      "id": "uuid-2",
      "signer_id": "telegram-bot",
      "ttl_expires_at": "2025-01-15T11:00:00Z",
      "max_value": "100000000000000000",
      "max_txs": 10,
      "created_at": "2025-01-15T10:00:00Z",
      "revoked_at": null
    }
  ]
}
```

## Revoking Session Signers

Immediately invalidate a session signer:

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/session-signers/trading-bot-001" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID"
```

After revocation:
- Existing sessions are immediately invalid
- `revoked_at` timestamp is set
- Audit log records the revocation

## Example: Telegram Bot Integration

### Setup

```javascript
// 1. User requests to enable Telegram bot for their wallet
const sessionSigner = await createSessionSigner(walletId, ownerSignature, {
  signer_id: `telegram-${telegramUserId}`,
  ttl: 3600, // 1 hour
  max_value: '100000000000000000', // 0.1 ETH
  max_txs: 10,
  allowed_methods: ['eth_sendTransaction'],
  policy_override_id: telegramBotPolicyId,
});
```

### Bot Signing

```javascript
// 2. Bot signs transactions using session signer's authorization key
async function signWithBot(walletId, sessionSignerKeyId, signatureForRequest, txParams) {
  const rpcBody = {
    jsonrpc: '2.0',
    method: 'eth_sendTransaction',
    params: [txParams],
    id: 1,
  };

  const response = await fetch(`${API}/v1/wallets/${walletId}/rpc`, {
    method: 'POST',
    headers: {
      'X-App-Id': APP_ID,
      'X-App-Secret': APP_SECRET,
      'Authorization': `Bearer ${userJwt}`,
      'X-Authorization-Signature': signatureForRequest,
      'X-Authorization-Key-Id': sessionSignerKeyId,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(rpcBody),
  });

  return response.json();
}
```

### Revocation

```javascript
// 3. User revokes bot access
await revokeSessionSigner(walletId, `telegram-${telegramUserId}`, ownerSignature);
```

## Example: Trading Bot

### Create Session with Tight Limits

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session-signers" \
  -H "..." \
  -d '{
    "signer_id": "dca-bot-eth",
    "ttl": 604800,
    "max_value": "1000000000000000000",
    "max_txs": 7,
    "policy_override_id": "dca-swap-only-policy"
  }'
```

### DCA Policy

```json
{
  "name": "DCA swap only",
  "rules": [
    {
      "name": "Allow swapExactETHForTokens on Uniswap",
      "method": "*",
      "conditions": [
        {
          "field_source": "ethereum_transaction",
          "field": "to",
          "operator": "eq",
          "value": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        },
        {
          "field_source": "ethereum_calldata",
          "field": "function_selector",
          "operator": "eq",
          "value": "0x7ff36ab5"
        }
      ],
      "action": "ALLOW"
    }
  ]
}
```

## Security Considerations

### 1. Use Minimal Permissions

```json
{
  "max_value": "100000000000000000",  // Only what's needed
  "max_txs": 10,                       // Reasonable limit
  "allowed_methods": ["eth_sendTransaction"]  // Specific methods
}
```

### 2. Short TTL for Sensitive Operations

```json
{
  "ttl": 3600  // 1 hour for interactive sessions
}
```

### 3. Always Use Policy Overrides

```json
{
  "policy_override_id": "restrictive-bot-policy"
}
```

### 4. Monitor and Revoke

- Track session signer usage in audit logs
- Revoke immediately on suspicious activity
- Set up alerts for high-frequency usage

## Error Handling

| Error Code | Meaning | Resolution |
|------------|---------|------------|
| `session_not_found` | Session signer doesn't exist | Check signer_id |
| `session_expired` | TTL has passed | Create new session |
| `session_revoked` | Session was revoked | Create new session |
| `session_limit_exceeded` | max_txs reached | Create new session |
| `session_value_exceeded` | Transaction exceeds max_value | Reduce value |
| `session_method_not_allowed` | Method not in allowed_methods | Use allowed method |

## Audit Trail

All session signer operations are logged:

```json
{
  "action": "session_signer_created",
  "resource_type": "session_signer",
  "resource_id": "trading-bot-001",
  "actor": "user-sub",
  "details": {
    "wallet_id": "wallet-uuid",
    "ttl": 86400,
    "max_value": "500000000000000000"
  }
}
```

```json
{
  "action": "sign_transaction",
  "resource_type": "wallet",
  "resource_id": "wallet-uuid",
  "signer_id": "trading-bot-001",
  "details": {
    "to": "0x7a250d5630...",
    "value": "100000000000000000",
    "tx_hash": "0xabc..."
  }
}
```

## Next Steps

- [Creating Sessions](./creating-sessions.md) - Detailed creation guide
- [Session Limits](./session-limits.md) - Limit configuration
- [Policy Overrides](./policy-overrides.md) - Override policies
- [Using Sessions](./using-sessions.md) - Integration patterns
- [Revoking Sessions](./revoking-sessions.md) - Revocation guide
