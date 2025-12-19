# Wallets API

Complete reference for wallet management endpoints.

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/wallets` | Create a wallet |
| GET | `/v1/wallets` | List wallets |
| GET | `/v1/wallets/{id}` | Get wallet details |
| DELETE | `/v1/wallets/{id}` | Delete a wallet |
| POST | `/v1/wallets/{id}/sign` | Sign a transaction |
| POST | `/v1/wallets/{id}/sign-message` | Sign a personal message |
| POST | `/v1/wallets/{id}/sign-typed-data` | Sign EIP-712 typed data |
| POST | `/v1/wallets/{id}/policies` | Attach a policy |
| DELETE | `/v1/wallets/{id}/policies/{policy_id}` | Detach a policy |

---

## Create Wallet

Create a new blockchain wallet.

### Request

```
POST /v1/wallets
```

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-App-Id` | Yes | Application ID |
| `X-App-Secret` | Yes | Application secret |
| `Authorization` | Optional | Bearer JWT token (required for user-owned wallets, optional for app-managed wallets) |
| `X-Idempotency-Key` | Recommended | Unique request identifier |

> **Note:** When creating app-managed wallets (without a user JWT), the wallet is owned by the application. When a user JWT is provided, the wallet is associated with that user.

### Body

```json
{
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "owner_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `chain_type` | string | Yes | Blockchain type (`ethereum`) |
| `exec_backend` | string | Yes | Execution backend (`kms`, `tee`) |
| `owner_id` | UUID | No | Authorization key or quorum ID |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": null,
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Idempotency-Key: create-wallet-$(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'
```

---

## List Wallets

List all wallets for the authenticated user.

### Request

```
GET /v1/wallets
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `chain_type` | string | - | Filter by chain type |
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "chain_type": "ethereum",
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "exec_backend": "kms",
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

### Example

```bash
curl "http://localhost:8080/v1/wallets?chain_type=ethereum&limit=10" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Get Wallet

Get details of a specific wallet.

### Request

```
GET /v1/wallets/{id}
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": "auth-key-uuid",
  "policies": [
    {
      "id": "policy-uuid",
      "name": "Default policy"
    }
  ],
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Delete Wallet

Permanently delete a wallet and its key material.

**Warning**: This operation is irreversible.

### Request

```
DELETE /v1/wallets/{id}
```

### Headers (Additional)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signature` | If owned | Owner's signature |
| `X-Authorization-Key-Id` | If owned | Owner's key ID |

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID"
```

---

## Sign Transaction

Sign an Ethereum transaction.

### Request

```
POST /v1/wallets/{id}/sign
```

### Body

```json
{
  "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "value": "1000000000000000000",
  "chain_id": 1,
  "nonce": 0,
  "gas_limit": 21000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": ""
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | Yes | Recipient address |
| `value` | string | Yes | Amount in wei |
| `chain_id` | integer | Yes | Network chain ID |
| `nonce` | integer | Yes | Transaction nonce |
| `gas_limit` | integer | Yes | Gas limit |
| `gas_fee_cap` | string | Yes* | Max fee per gas (EIP-1559) |
| `gas_tip_cap` | string | Yes* | Priority fee (EIP-1559) |
| `gas_price` | string | Yes* | Gas price (legacy) |
| `data` | string | No | Contract call data |

*Either `gas_fee_cap`+`gas_tip_cap` or `gas_price`

### Response

```json
{
  "signed_transaction": "0x02f87001808477359400850708d7c00082520894...",
  "tx_hash": "0xabc123def456789..."
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/sign" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "value": "1000000000000000000",
    "chain_id": 1,
    "nonce": 0,
    "gas_limit": 21000,
    "gas_fee_cap": "30000000000",
    "gas_tip_cap": "2000000000"
  }'
```

---

## Sign Personal Message

Sign a personal message (EIP-191).

### Request

```
POST /v1/wallets/{id}/sign-message
```

### Body

```json
{
  "message": "Hello, World!"
}
```

### Response

```json
{
  "signature": "0x..."
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/sign-message" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"message": "Sign in to MyApp"}'
```

---

## Sign Typed Data

Sign EIP-712 structured data.

### Request

```
POST /v1/wallets/{id}/sign-typed-data
```

### Body

```json
{
  "typed_data": {
    "types": {
      "EIP712Domain": [...],
      "Permit": [...]
    },
    "primaryType": "Permit",
    "domain": {...},
    "message": {...}
  }
}
```

### Response

```json
{
  "signature": "0x..."
}
```

---

## Attach Policy

Attach a policy to control wallet operations.

### Request

```
POST /v1/wallets/{id}/policies
```

### Body

```json
{
  "policy_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Response

```
201 Created
```

---

## Detach Policy

Remove a policy from a wallet.

### Request

```
DELETE /v1/wallets/{id}/policies/{policy_id}
```

### Response

```
204 No Content
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 401 | `invalid_token` | JWT validation failed |
| 403 | `policy_denied` | Policy rejected operation |
| 403 | `not_authorized` | User doesn't own wallet |
| 404 | `wallet_not_found` | Wallet doesn't exist |
| 409 | `duplicate_key` | Idempotency key reused |

### Example Error

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied by policy",
    "details": {
      "policy_id": "policy-uuid",
      "rule_name": "Value limit",
      "reason": "value exceeds maximum"
    }
  }
}
```
