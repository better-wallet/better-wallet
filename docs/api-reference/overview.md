# API Reference Overview

Better Wallet provides a REST API for all wallet operations. This document covers API conventions, authentication, error handling, and common patterns.

## Base URL

| Environment | URL |
|-------------|-----|
| Local Development | `http://localhost:8080` |
| Production | `https://api.your-domain.com` |

## API Versioning

All endpoints are prefixed with `/v1/`:

```
GET /v1/wallets
POST /v1/wallets
GET /v1/wallets/{wallet_id}
```

## Authentication

Every request requires app authentication headers (`X-App-Id`, `X-App-Secret`).

Most `/v1/*` endpoints also require a user JWT via `Authorization: Bearer <JWT>`.

The server allows **app-only** (no user JWT) calls only for:

- `POST /v1/wallets`
- `POST /v1/policies`
- `POST /v1/wallets/{wallet_id}/rpc` (authorization signature required)

### Required Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-App-Id` | Application UUID | `550e8400-e29b-...` |
| `X-App-Secret` | Application secret | `bw_secret_xyz...` |
| `Authorization` | User JWT bearer token (required for all `/v1/*` endpoints except the app-only calls above) | `Bearer eyJhbGc...` |
| `Content-Type` | Request content type (required for JSON bodies) | `application/json` |

### Example Request

```bash
curl -X GET "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-App-Secret: bw_secret_xyz123abc456" \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json"
```

### Optional Headers

| Header | Description | When to Use |
|--------|-------------|-------------|
| `X-Idempotency-Key` | Unique request ID | Write operations |
| `X-Authorization-Signature` | P-256 signature | High-risk operations and delegated signing |
| `X-Authorization-Key-Id` | Auth key UUID (owner or session signer) | With signature |

## Request Format

### JSON Body

Request bodies must be valid JSON:

```json
{
  "chain_type": "ethereum",
  "exec_backend": "kms"
}
```

### Path Parameters

Parameters in the URL path:

```
GET /v1/wallets/{wallet_id}
DELETE /v1/policies/{policy_id}
```

### Query Parameters

Filtering and pagination:

```
GET /v1/wallets?chain_type=ethereum&limit=10&offset=0
```

## Response Format

### Success Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "chain_type": "ethereum",
  "created_at": "2025-01-15T10:00:00Z"
}
```

### List Response

```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-...",
      "address": "0x742d35Cc..."
    },
    {
      "id": "660f9511-f39c-...",
      "address": "0x851e46Dd..."
    }
  ],
  "pagination": {
    "total": 42,
    "limit": 10,
    "offset": 0,
    "has_more": true
  }
}
```

### Error Response

```json
{
  "error": {
    "code": "invalid_request",
    "message": "chain_type is required",
    "details": {
      "field": "chain_type",
      "reason": "missing required field"
    }
  }
}
```

## HTTP Status Codes

| Code | Meaning | Description |
|------|---------|-------------|
| 200 | OK | Request succeeded |
| 201 | Created | Resource created successfully |
| 204 | No Content | Success with no response body |
| 400 | Bad Request | Invalid request format or parameters |
| 401 | Unauthorized | Missing or invalid authentication |
| 403 | Forbidden | Not authorized for this operation |
| 404 | Not Found | Resource does not exist |
| 409 | Conflict | Resource conflict (duplicate key) |
| 422 | Unprocessable | Valid format but semantic error |
| 429 | Too Many Requests | Rate limit exceeded |
| 500 | Internal Error | Server error |

## Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `invalid_request` | 400 | Malformed request |
| `missing_field` | 400 | Required field missing |
| `invalid_field` | 400 | Field value invalid |
| `invalid_app_credentials` | 401 | Bad app ID or secret |
| `invalid_token` | 401 | JWT validation failed |
| `token_expired` | 401 | JWT has expired |
| `not_authorized` | 403 | User lacks permission |
| `policy_denied` | 403 | Policy rejected operation |
| `invalid_signature` | 403 | Authorization signature invalid |
| `not_found` | 404 | Resource not found |
| `wallet_not_found` | 404 | Wallet doesn't exist |
| `policy_not_found` | 404 | Policy doesn't exist |
| `duplicate_key` | 409 | Idempotency key reused |
| `validation_failed` | 422 | Semantic validation error |
| `rate_limited` | 429 | Too many requests |
| `internal_error` | 500 | Unexpected server error |
| `kms_error` | 500 | KMS operation failed |
| `tee_error` | 500 | TEE operation failed |

## Pagination

List endpoints support pagination:

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Example

```bash
# Get first page
curl "http://localhost:8080/v1/wallets?limit=10&offset=0"

# Get second page
curl "http://localhost:8080/v1/wallets?limit=10&offset=10"
```

### Response

```json
{
  "wallets": [...],
  "pagination": {
    "total": 42,
    "limit": 10,
    "offset": 10,
    "has_more": true
  }
}
```

## Idempotency

For write operations, use idempotency keys to prevent duplicates:

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-Idempotency-Key: create-wallet-user123-$(date +%s)" \
  -H "..." \
  -d '{"chain_type": "ethereum"}'
```

### Idempotency Behavior

| Scenario | Result |
|----------|--------|
| First request | Processes normally |
| Duplicate (same key) within 24h | Returns cached response |
| Duplicate with different body | Returns 409 Conflict |
| After 24h expiry | Processes as new request |

### Recommended Key Format

```
{operation}-{resource}-{unique-identifier}-{timestamp}
```

Examples:
- `create-wallet-user123-1705312800`
- `sign-tx-wallet456-nonce42`
- `update-policy-policy789-v2`

## Rate Limiting

API endpoints are rate-limited per app:

| Tier | Limit |
|------|-------|
| Default | 100 requests/second |
| Configured | Per-app setting |

### Rate Limit Headers

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1705312860
```

### Handling Rate Limits

```javascript
async function fetchWithRetry(url, options, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    const response = await fetch(url, options);

    if (response.status === 429) {
      const resetTime = response.headers.get('X-RateLimit-Reset');
      const waitMs = (parseInt(resetTime) - Date.now() / 1000) * 1000;
      await new Promise(resolve => setTimeout(resolve, Math.max(waitMs, 1000)));
      continue;
    }

    return response;
  }
  throw new Error('Rate limit exceeded after retries');
}
```

## Endpoint Categories

### Wallets

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/wallets` | Create wallet |
| GET | `/v1/wallets` | List wallets |
| GET | `/v1/wallets/{id}` | Get wallet |
| DELETE | `/v1/wallets/{id}` | Delete wallet |
| POST | `/v1/wallets/{id}/rpc` | JSON-RPC signing (eth_sendTransaction, eth_signTypedData_v4, personal_sign) |

### Policies

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/policies` | Create policy |
| GET | `/v1/policies` | List policies |
| GET | `/v1/policies/{id}` | Get policy |
| PATCH | `/v1/policies/{id}` | Update policy |
| DELETE | `/v1/policies/{id}` | Delete policy |

### Authorization Keys

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/authorization-keys` | Register key |
| GET | `/v1/authorization-keys` | List keys |
| GET | `/v1/authorization-keys/{id}` | Get key |
| DELETE | `/v1/authorization-keys/{id}` | Revoke key |

### Key Quorums

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/key-quorums` | Create quorum |
| GET | `/v1/key-quorums` | List quorums |
| GET | `/v1/key-quorums/{id}` | Get quorum |
| PATCH | `/v1/key-quorums/{id}` | Update quorum |
| DELETE | `/v1/key-quorums/{id}` | Delete quorum |

### Session Signers

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/wallets/{id}/session-signers` | Create session |
| GET | `/v1/wallets/{id}/session-signers` | List sessions |
| DELETE | `/v1/wallets/{id}/session-signers/{signer_id}` | Revoke session |

### Condition Sets

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/condition_sets` | Create set |
| GET | `/v1/condition_sets` | List sets |
| GET | `/v1/condition_sets/{id}` | Get set |
| PATCH | `/v1/condition_sets/{id}` | Update set |
| DELETE | `/v1/condition_sets/{id}` | Delete set |

### Users

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/users` | List users |
| GET | `/v1/users/{id}` | Get user |
| GET | `/v1/users/me` | Get current user |

### Transactions

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/transactions` | List transactions |
| GET | `/v1/transactions/{hash}` | Get transaction |

### Health

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/health` | Health check (no auth) |

## Common Patterns

### Create and Use

```bash
# 1. Create wallet
WALLET=$(curl -X POST "$API/v1/wallets" \
  -H "..." \
  -d '{"chain_type": "ethereum"}')

WALLET_ID=$(echo $WALLET | jq -r '.id')

# 2. Sign transaction
curl -X POST "$API/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{"to": "0x...", "value": "0xde0b6b3a7640000", "chain_id": 1, "nonce": "0x0", "gas_limit": "0x5208", "max_fee_per_gas": "0x6fc23ac00", "max_priority_fee_per_gas": "0x77359400"}],
    "id": 1
  }'
```

### Filtered Listing

```bash
# List Ethereum wallets only
curl "$API/v1/wallets?chain_type=ethereum"

# List active authorization keys
curl "$API/v1/authorization-keys?status=active"
```

### Batch Operations

Better Wallet doesn't support batch endpoints. For multiple operations, use concurrent requests with unique idempotency keys:

```javascript
const walletIds = ['uuid1', 'uuid2', 'uuid3'];

const results = await Promise.all(
  walletIds.map((id, index) =>
    fetch(`${API}/v1/wallets/${id}/rpc`, {
      method: 'POST',
      headers: {
        'X-Idempotency-Key': `batch-sign-${Date.now()}-${index}`,
        ...commonHeaders,
      },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [txParams],
        id: 1
      }),
    })
  )
);
```

## SDK Examples

### Node.js / TypeScript

```typescript
class BetterWalletClient {
  constructor(
    private baseUrl: string,
    private appId: string,
    private appSecret: string,
  ) {}

  async request<T>(
    method: string,
    path: string,
    token: string,
    body?: object,
  ): Promise<T> {
    const response = await fetch(`${this.baseUrl}${path}`, {
      method,
      headers: {
        'X-App-Id': this.appId,
        'X-App-Secret': this.appSecret,
        Authorization: `Bearer ${token}`,
        'Content-Type': 'application/json',
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error.message);
    }

    return response.json();
  }

  createWallet(token: string, chainType: string) {
    return this.request('POST', '/v1/wallets', token, {
      chain_type: chainType,
      exec_backend: 'kms',
    });
  }

  signTransaction(token: string, walletId: string, tx: object) {
    return this.request('POST', `/v1/wallets/${walletId}/rpc`, token, {
      jsonrpc: '2.0',
      method: 'eth_sendTransaction',
      params: [tx],
      id: 1
    });
  }
}
```

### Python

```python
import requests

class BetterWalletClient:
    def __init__(self, base_url: str, app_id: str, app_secret: str):
        self.base_url = base_url
        self.app_id = app_id
        self.app_secret = app_secret

    def request(self, method: str, path: str, token: str, body: dict = None):
        response = requests.request(
            method,
            f"{self.base_url}{path}",
            headers={
                "X-App-Id": self.app_id,
                "X-App-Secret": self.app_secret,
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json=body,
        )
        response.raise_for_status()
        return response.json()

    def create_wallet(self, token: str, chain_type: str):
        return self.request("POST", "/v1/wallets", token, {
            "chain_type": chain_type,
            "exec_backend": "kms",
        })

    def sign_transaction(self, token: str, wallet_id: str, tx: dict):
        return self.request("POST", f"/v1/wallets/{wallet_id}/rpc", token, {
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [tx],
            "id": 1
        })
```

## Next Steps

- [Wallets API](./endpoints/wallets.md) - Wallet endpoints
- [Policies API](./endpoints/policies.md) - Policy endpoints
- [Authorization Keys](./endpoints/authorization-keys.md) - Key management
- [Session Signers](./endpoints/session-signers.md) - Delegated signing
- [Authentication](../authentication/overview.md) - Auth configuration
