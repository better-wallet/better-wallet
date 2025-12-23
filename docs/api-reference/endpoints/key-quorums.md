# Key Quorums API

Complete reference for M-of-N key quorum management endpoints.

## Overview

Key quorums enable multi-signature authorization where M out of N authorization keys must sign for operations to proceed. This provides enhanced security through distributed control.

### Use Cases

- **Treasury wallets**: Require 2-of-3 executives to approve large transfers
- **Operational wallets**: Allow any 2-of-5 operators to sign transactions
- **Recovery scenarios**: Enable 3-of-5 recovery keys for emergency access

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/key-quorums` | Create a key quorum |
| GET | `/v1/key-quorums` | List key quorums |
| GET | `/v1/key-quorums/{id}` | Get quorum details |
| PATCH | `/v1/key-quorums/{id}` | Update quorum members |
| DELETE | `/v1/key-quorums/{id}` | Delete a key quorum |

---

## Create Key Quorum

Create a new M-of-N key quorum.

### Request

```
POST /v1/key-quorums
```

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-App-Id` | Yes | Application ID |
| `X-App-Secret` | Yes | Application secret |
| `Authorization` | Yes | Bearer JWT token |
| `X-Idempotency-Key` | Recommended | Unique request identifier |

### Body

```json
{
  "name": "Treasury Quorum",
  "threshold": 2,
  "member_ids": [
    "auth-key-uuid-1",
    "auth-key-uuid-2",
    "auth-key-uuid-3"
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable quorum name |
| `threshold` | integer | Yes | Minimum signatures required (M) |
| `member_ids` | array | Yes | Authorization key IDs (N keys) |

### Validation Rules

- `threshold` must be >= 1
- `threshold` must be <= length of `member_ids`
- `member_ids` must contain at least 2 keys
- All member IDs must be valid, active authorization keys
- No duplicate member IDs allowed

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Treasury Quorum",
  "threshold": 2,
  "members": [
    {
      "id": "auth-key-uuid-1",
      "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
      "owner_entity": "cfo@company.com"
    },
    {
      "id": "auth-key-uuid-2",
      "public_key": "BGHiJ9876KLmnOP...",
      "owner_entity": "cto@company.com"
    },
    {
      "id": "auth-key-uuid-3",
      "public_key": "BCDeFgHiJkLmNoP...",
      "owner_entity": "ceo@company.com"
    }
  ],
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/key-quorums" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Treasury Quorum",
    "threshold": 2,
    "member_ids": [
      "'$AUTH_KEY_1'",
      "'$AUTH_KEY_2'",
      "'$AUTH_KEY_3'"
    ]
  }'
```

---

## List Key Quorums

List all key quorums for the application.

### Request

```
GET /v1/key-quorums
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "key_quorums": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Treasury Quorum",
      "threshold": 2,
      "member_count": 3,
      "created_at": "2025-01-15T10:00:00Z"
    },
    {
      "id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
      "name": "Operations Quorum",
      "threshold": 2,
      "member_count": 5,
      "created_at": "2025-01-10T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 2,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Example

```bash
curl "http://localhost:8080/v1/key-quorums" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Get Key Quorum

Get details of a specific key quorum including all members.

### Request

```
GET /v1/key-quorums/{id}
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Treasury Quorum",
  "threshold": 2,
  "members": [
    {
      "id": "auth-key-uuid-1",
      "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
      "owner_entity": "cfo@company.com",
      "status": "active"
    },
    {
      "id": "auth-key-uuid-2",
      "public_key": "BGHiJ9876KLmnOP...",
      "owner_entity": "cto@company.com",
      "status": "active"
    },
    {
      "id": "auth-key-uuid-3",
      "public_key": "BCDeFgHiJkLmNoP...",
      "owner_entity": "ceo@company.com",
      "status": "active"
    }
  ],
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": null
}
```

### Example

```bash
curl "http://localhost:8080/v1/key-quorums/$QUORUM_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Update Key Quorum

Update quorum name, threshold, or members. Requires signatures from M members.

### Request

```
PATCH /v1/key-quorums/{id}
```

### Headers (Additional)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signatures` | Yes | JSON array of member signatures |
| `X-Authorization-Key-Ids` | Yes | JSON array of signing key IDs |

### Body

```json
{
  "name": "Updated Treasury Quorum",
  "threshold": 3,
  "member_ids": [
    "auth-key-uuid-1",
    "auth-key-uuid-2",
    "auth-key-uuid-3",
    "auth-key-uuid-4"
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Updated name |
| `threshold` | integer | No | Updated threshold |
| `member_ids` | array | No | Updated member list |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Updated Treasury Quorum",
  "threshold": 3,
  "members": [...],
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2025-01-15T14:00:00Z"
}
```

### Example

```bash
# Each member signs the canonical payload
PAYLOAD="1.0PATCH/v1/key-quorums/$QUORUM_ID{\"threshold\":3}$APP_ID$IDEMPOTENCY_KEY"

# Collect signatures from M members
SIG1=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member1_key.pem | base64)
SIG2=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member2_key.pem | base64)

curl -X PATCH "http://localhost:8080/v1/key-quorums/$QUORUM_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signatures: [\"$SIG1\",\"$SIG2\"]" \
  -H "X-Authorization-Key-Ids: [\"$KEY_ID_1\",\"$KEY_ID_2\"]" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"threshold": 3}'
```

---

## Delete Key Quorum

Delete a key quorum. Requires signatures from M members.

### Request

```
DELETE /v1/key-quorums/{id}
```

### Headers (Additional)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signatures` | Yes | JSON array of member signatures |
| `X-Authorization-Key-Ids` | Yes | JSON array of signing key IDs |

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/key-quorums/$QUORUM_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signatures: [\"$SIG1\",\"$SIG2\"]" \
  -H "X-Authorization-Key-Ids: [\"$KEY_ID_1\",\"$KEY_ID_2\"]"
```

**Note**: Cannot delete a quorum that owns wallets or policies.

---

## Using Quorums as Wallet Owners

Assign a quorum as the owner when creating a wallet:

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "'$QUORUM_ID'"
  }'
```

### Signing with Quorum-Owned Wallets

When a wallet is owned by a quorum, high-risk operations require M signatures. All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format:

```bash
# Build canonical payload for the RPC request
RPC_BODY='{"jsonrpc":"2.0","method":"eth_sendTransaction","params":[{"to":"0x...","value":"0xde0b6b3a7640000","chain_id":1,"nonce":"0x0","gas_limit":"0x5208","max_fee_per_gas":"0x6fc23ac00","max_priority_fee_per_gas":"0x77359400"}],"id":1}'
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/rpc${RPC_BODY}$APP_ID$IDEMPOTENCY_KEY"

# Collect M signatures from quorum members
SIG1=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member1_key.pem | base64)
SIG2=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member2_key.pem | base64)

# Sign transaction with quorum authorization
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signatures: [\"$SIG1\",\"$SIG2\"]" \
  -H "X-Authorization-Key-Ids: [\"$KEY_ID_1\",\"$KEY_ID_2\"]" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
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

## Quorum Signature Verification

The system verifies quorum signatures by:

1. Extracting key IDs from `X-Authorization-Key-Ids` header
2. Verifying each key is a member of the quorum
3. Verifying each signature against the canonical payload
4. Confirming at least `threshold` valid signatures

### Canonical Payload Format

```
version + method + path + canonical_json_body + app_id + idempotency_key
```

All members must sign the same canonical payload.

---

## Common Patterns

### Corporate Treasury (2-of-3)

```json
{
  "name": "Corporate Treasury",
  "threshold": 2,
  "member_ids": ["cfo-key", "cto-key", "ceo-key"]
}
```

### Operations Team (2-of-5)

```json
{
  "name": "Operations",
  "threshold": 2,
  "member_ids": ["op1-key", "op2-key", "op3-key", "op4-key", "op5-key"]
}
```

### Emergency Recovery (3-of-5)

```json
{
  "name": "Recovery Quorum",
  "threshold": 3,
  "member_ids": ["recovery1", "recovery2", "recovery3", "recovery4", "recovery5"]
}
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 400 | `invalid_threshold` | Threshold > member count or < 1 |
| 400 | `insufficient_members` | Less than 2 members |
| 400 | `duplicate_members` | Duplicate member IDs |
| 401 | `invalid_token` | JWT validation failed |
| 403 | `insufficient_signatures` | Not enough valid signatures |
| 403 | `invalid_signature` | Signature verification failed |
| 404 | `quorum_not_found` | Key quorum doesn't exist |
| 404 | `member_not_found` | Member key doesn't exist |
| 409 | `quorum_in_use` | Quorum owns wallets or policies |

### Example Error

```json
{
  "error": {
    "code": "insufficient_signatures",
    "message": "Quorum requires 2 signatures, received 1",
    "details": {
      "required": 2,
      "received": 1,
      "valid_signers": ["auth-key-uuid-1"]
    }
  }
}
```
