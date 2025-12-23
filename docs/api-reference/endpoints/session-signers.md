# Session Signers API

Complete reference for session signer management endpoints. Session signers are managed as sub-resources of wallets.

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/wallets/{wallet_id}/session_signers` | Create a session signer |
| GET | `/v1/wallets/{wallet_id}/session_signers` | List session signers for wallet |
| DELETE | `/v1/wallets/{wallet_id}/session_signers/{id}` | Revoke a session signer |

---

## Create Session Signer

Create a temporary delegated signer for a wallet.

### Request

```
POST /v1/wallets/{wallet_id}/session_signers
```

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-App-Id` | Yes | Application ID |
| `X-App-Secret` | Yes | Application secret |
| `Authorization` | Yes | Bearer JWT token |
| `X-Authorization-Signature` | Yes | Owner's P-256 signature |
| `X-Authorization-Key-Id` | Yes | Owner's authorization key ID |
| `X-Idempotency-Key` | Recommended | Unique request identifier |

### Body

```json
{
  "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
  "signer_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100,
  "policy_override_id": "policy-uuid"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `signer_id` | UUID | Yes | Authorization key ID of the signer |
| `expires_at` | timestamp | Yes | When the session expires |
| `max_value` | string | No | Maximum total value in wei |
| `max_txs` | integer | No | Maximum number of transactions |
| `policy_override_id` | UUID | No | Policy to use instead of wallet policies |

### Session Limits

Session signers support multiple limiting mechanisms:

| Limit | Description | Enforcement |
|-------|-------------|-------------|
| `expires_at` | Hard expiration time | Session invalid after this time |
| `max_value` | Cumulative value limit | Sum of all transaction values |
| `max_txs` | Transaction count limit | Total number of signing operations |
| `policy_override_id` | Policy override | Uses this policy instead of wallet policies |

### Response

```json
{
  "id": "770e9400-f29b-41d4-b716-557766550000",
  "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
  "signer_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100,
  "used_value": "0",
  "used_txs": 0,
  "policy_override_id": "policy-uuid",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
# Build canonical payload for authorization signature
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/session_signers{\"expires_at\":\"2025-01-22T10:00:00Z\",\"signer_id\":\"$SIGNER_KEY_ID\"}$APP_ID$IDEMPOTENCY_KEY"

# Sign with owner's private key
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign owner_private_key.pem | base64)

# Create session signer
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "signer_id": "'$SIGNER_KEY_ID'",
    "expires_at": "2025-01-22T10:00:00Z",
    "max_value": "10000000000000000000",
    "max_txs": 100
  }'
```

---

## List Session Signers

List all session signers for a wallet.

### Request

```
GET /v1/wallets/{wallet_id}/session_signers
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status (`active`, `expired`, `revoked`, `exhausted`) |
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "session_signers": [
    {
      "id": "770e9400-f29b-41d4-b716-557766550000",
      "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
      "signer_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
      "expires_at": "2025-01-22T10:00:00Z",
      "max_value": "10000000000000000000",
      "max_txs": 100,
      "used_value": "5000000000000000000",
      "used_txs": 25,
      "status": "active",
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Session Status Values

| Status | Description |
|--------|-------------|
| `active` | Valid and usable |
| `expired` | Past `expires_at` timestamp |
| `revoked` | Manually revoked by owner |
| `exhausted` | Reached `max_value` or `max_txs` limit |

### Example

```bash
# List active session signers for a wallet
curl "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers?status=active" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Revoke Session Signer

Revoke a session signer before expiration. Requires owner authorization.

### Request

```
DELETE /v1/wallets/{wallet_id}/session_signers/{id}
```

### Headers (Additional)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signature` | Yes | Owner's signature |
| `X-Authorization-Key-Id` | Yes | Owner's key ID |

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers/$SESSION_SIGNER_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID"
```

---

## Using Session Signers

Once created, session signers can sign transactions without owner involvement.

### Signing with Session Signer

All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format:

```bash
# Sign a transaction using session signer
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SESSION_SIGNATURE" \
  -H "X-Authorization-Key-Id: $SESSION_SIGNER_KEY_ID" \
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

### Policy Override Behavior

When a session signer has `policy_override_id`:

1. Wallet's attached policies are **ignored**
2. Only the override policy is evaluated
3. Session limits (`max_value`, `max_txs`) still apply on top of policy

```json
{
  "signer_id": "session-key-uuid",
  "policy_override_id": "restrictive-policy-uuid",
  "max_value": "10000000000000000000",
  "max_txs": 100
}
```

This allows creating sessions with more restrictive policies than the wallet normally has.

---

## Common Use Cases

### Gaming Session

Allow a game to sign transactions up to 0.1 ETH each, max 10 ETH total:

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "game-server-key-uuid",
  "expires_at": "2025-01-16T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 1000,
  "policy_override_id": "max-0.1-eth-per-tx-policy"
}
```

### DeFi Trading Session

Allow a trading bot to interact with specific DEX contracts:

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "trading-bot-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "policy_override_id": "allowed-dex-contracts-policy"
}
```

### NFT Minting Session

Allow minting during a specific window:

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "minting-service-key-uuid",
  "expires_at": "2025-01-15T12:00:00Z",
  "max_txs": 10,
  "policy_override_id": "nft-contract-only-policy"
}
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 400 | `invalid_expires_at` | Expiration in the past |
| 401 | `invalid_token` | JWT validation failed |
| 403 | `not_authorized` | Not wallet owner |
| 403 | `invalid_signature` | Authorization signature invalid |
| 404 | `wallet_not_found` | Wallet doesn't exist |
| 404 | `signer_not_found` | Signer key doesn't exist |
| 404 | `session_not_found` | Session signer doesn't exist |
| 409 | `session_exists` | Active session for this signer exists |

### Example Error

```json
{
  "error": {
    "code": "session_exhausted",
    "message": "Session signer has reached its limits",
    "details": {
      "session_id": "session-uuid",
      "limit_type": "max_txs",
      "limit_value": 100,
      "current_value": 100
    }
  }
}
```
