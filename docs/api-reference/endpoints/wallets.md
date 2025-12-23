# Wallets API

Complete reference for wallet management endpoints.

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/wallets` | Create a wallet |
| GET | `/v1/wallets` | List wallets |
| GET | `/v1/wallets/{id}` | Get wallet details |
| DELETE | `/v1/wallets/{id}` | Delete a wallet |
| POST | `/v1/wallets/{id}/rpc` | JSON-RPC endpoint for signing |
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

## JSON-RPC Endpoint

All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format.

### Request

```
POST /v1/wallets/{id}/rpc
```

### Supported Methods

| Method | Description |
|--------|-------------|
| `eth_sendTransaction` | Sign and optionally broadcast transaction |
| `eth_signTransaction` | Sign transaction (returns signed tx only) |
| `eth_signTypedData_v4` | Sign EIP-712 typed data |
| `personal_sign` | Sign personal message (EIP-191) |

---

## eth_sendTransaction

Sign an Ethereum transaction.

### Body

```json
{
  "jsonrpc": "2.0",
  "method": "eth_sendTransaction",
  "params": [{
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "value": "0xde0b6b3a7640000",
    "chain_id": 1,
    "nonce": "0x0",
    "gas_limit": "0x5208",
    "max_fee_per_gas": "0x6fc23ac00",
    "max_priority_fee_per_gas": "0x77359400",
    "data": "0x"
  }],
  "id": 1
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `to` | string | Yes | Recipient address |
| `value` | string | Yes | Amount in wei (0x hex or decimal) |
| `chain_id` | integer | Yes | Network chain ID |
| `nonce` | string | Yes | Transaction nonce (0x hex or decimal) |
| `gas_limit` | string | Yes | Gas limit (0x hex or decimal) |
| `max_fee_per_gas` | string | Yes* | Max fee per gas (EIP-1559) |
| `max_priority_fee_per_gas` | string | Yes* | Priority fee (EIP-1559) |
| `gas_price` | string | Yes* | Gas price (legacy) |
| `data` | string | No | Contract call data |

*Either `max_fee_per_gas`+`max_priority_fee_per_gas` or `gas_price`

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "signed_transaction": "0x02f87001808477359400850708d7c00082520894...",
    "tx_hash": "0xabc123def456789..."
  },
  "id": 1
}
```

### Example

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

---

## eth_signTypedData_v4

Sign EIP-712 structured data.

### Body

```json
{
  "jsonrpc": "2.0",
  "method": "eth_signTypedData_v4",
  "params": [{
    "typed_data": {
      "types": {
        "EIP712Domain": [...],
        "Permit": [...]
      },
      "primaryType": "Permit",
      "domain": {...},
      "message": {...}
    }
  }],
  "id": 1
}
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
