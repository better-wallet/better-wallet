# API Reference

Complete API documentation for Better Wallet Agent Wallet system.

## Authentication

Better Wallet uses two types of authentication:

### Principal Authentication

For wallet management and credential operations:

```
Authorization: Bearer aw_pk_<prefix>.<secret>
```

### Agent Authentication

For signing operations:

```
Authorization: Bearer aw_ag_<prefix>.<secret>
```

## Principal API

Base URL: `/v1`

### Wallets

#### Create Wallet

```http
POST /v1/wallets
Authorization: Bearer aw_pk_xxx.secret
Content-Type: application/json
```

Request:
```json
{
  "name": "Trading Bot Wallet",
  "chain_type": "evm"
}
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "principal_id": "440e8400-e29b-41d4-a716-446655440000",
  "name": "Trading Bot Wallet",
  "chain_type": "evm",
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "status": "active",
  "created_at": "2026-02-02T10:00:00Z",
  "updated_at": "2026-02-02T10:00:00Z"
}
```

#### List Wallets

```http
GET /v1/wallets
Authorization: Bearer aw_pk_xxx.secret
```

Response:
```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Trading Bot Wallet",
      "chain_type": "evm",
      "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      "status": "active",
      "created_at": "2026-02-02T10:00:00Z"
    }
  ]
}
```

#### Get Wallet

```http
GET /v1/wallets/{wallet_id}
Authorization: Bearer aw_pk_xxx.secret
```

#### Pause Wallet

```http
POST /v1/wallets/{wallet_id}/pause
Authorization: Bearer aw_pk_xxx.secret
```

#### Resume Wallet

```http
POST /v1/wallets/{wallet_id}/resume
Authorization: Bearer aw_pk_xxx.secret
```

#### Kill Wallet (Emergency)

Permanently blocks ALL credentials for this wallet.

```http
POST /v1/wallets/{wallet_id}/kill
Authorization: Bearer aw_pk_xxx.secret
```

**Warning**: This action cannot be undone.

---

### Credentials

#### Create Credential

```http
POST /v1/wallets/{wallet_id}/credentials
Authorization: Bearer aw_pk_xxx.secret
Content-Type: application/json
```

Request:
```json
{
  "name": "DeFi Trading Agent",
  "capabilities": {
    "operations": ["transfer", "sign_message", "sign_typed_data"],
    "allowed_contracts": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
    ]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_value_per_hour": "5000000000000000000",
    "max_value_per_day": "10000000000000000000",
    "max_tx_per_hour": 100,
    "max_tx_per_day": 1000
  }
}
```

Response:
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
  "credential": "aw_ag_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy",
  "name": "DeFi Trading Agent",
  "capabilities": {
    "operations": ["transfer", "sign_message", "sign_typed_data"],
    "allowed_contracts": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
    ]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_value_per_hour": "5000000000000000000",
    "max_value_per_day": "10000000000000000000",
    "max_tx_per_hour": 100,
    "max_tx_per_day": 1000
  },
  "status": "active",
  "created_at": "2026-02-02T10:00:00Z"
}
```

**Important**: The `credential` field contains the full credential token. The secret part is only returned once at creation time.

#### List Credentials

```http
GET /v1/wallets/{wallet_id}/credentials
Authorization: Bearer aw_pk_xxx.secret
```

Response:
```json
{
  "credentials": [
    {
      "id": "660e8400-e29b-41d4-a716-446655440001",
      "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
      "key_prefix": "aw_ag_xxxxxxxxxxxx",
      "name": "DeFi Trading Agent",
      "capabilities": {...},
      "limits": {...},
      "status": "active",
      "last_used_at": "2026-02-02T12:00:00Z",
      "created_at": "2026-02-02T10:00:00Z"
    }
  ]
}
```

#### Get Credential

```http
GET /v1/credentials/{credential_id}
Authorization: Bearer aw_pk_xxx.secret
```

#### Pause Credential

Temporarily disable a credential. Can be resumed later.

```http
POST /v1/credentials/{credential_id}/pause
Authorization: Bearer aw_pk_xxx.secret
```

#### Resume Credential

Re-enable a paused credential.

```http
POST /v1/credentials/{credential_id}/resume
Authorization: Bearer aw_pk_xxx.secret
```

#### Revoke Credential

Permanently disable a credential. Cannot be undone.

```http
POST /v1/credentials/{credential_id}/revoke
Authorization: Bearer aw_pk_xxx.secret
```

---

## Agent Signing API

Base URL: `/v1/agent/rpc`

All agent signing operations use JSON-RPC 2.0 format.

```http
POST /v1/agent/rpc
Authorization: Bearer aw_ag_xxx.secret
Content-Type: application/json
```

### eth_sendTransaction

Sign and broadcast a transaction to the network.

**Required capability**: `transfer` (or `contract_deploy` for contract deployment)

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_sendTransaction",
  "params": [{
    "to": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "value": "0xde0b6b3a7640000",
    "data": "0x",
    "chainId": "0x1",
    "gas": "0x5208",
    "gasPrice": "0x4a817c800",
    "nonce": "0x0"
  }],
  "id": 1
}
```

Parameters (all optional except `chainId` when RPC not configured):
- `to`: Recipient address (empty for contract deployment)
- `value`: Amount in wei (hex string)
- `data`: Transaction data (hex string)
- `chainId`: Chain ID (hex string) - must match RPC if configured
- `gas`: Gas limit (hex string) - auto-estimated if omitted
- `gasPrice`: Gas price (hex string) - auto-fetched if omitted
- `nonce`: Transaction nonce (hex string) - auto-fetched if omitted

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x...(transaction hash)",
  "id": 1
}
```

### eth_signTransaction

Sign a transaction without broadcasting.

**Required capability**: `transfer` (or `contract_deploy` for contract deployment)

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_signTransaction",
  "params": [{
    "to": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "value": "0xde0b6b3a7640000",
    "chainId": "0x1"
  }],
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x...(signed transaction hex)",
  "id": 1
}
```

### personal_sign

Sign an arbitrary message (EIP-191).

**Required capability**: `sign_message`

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "personal_sign",
  "params": [
    "0x48656c6c6f20576f726c64",
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  ],
  "id": 1
}
```

Parameters:
- `params[0]`: Message to sign (hex-encoded)
- `params[1]`: Signer address (must match wallet address)

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x...(signature)",
  "id": 1
}
```

### eth_signTypedData_v4

Sign EIP-712 typed data.

**Required capability**: `sign_typed_data`

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_signTypedData_v4",
  "params": [
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    {
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
        "name": "MyToken",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x..."
      },
      "message": {
        "owner": "0x...",
        "spender": "0x...",
        "value": "1000000000000000000",
        "nonce": 0,
        "deadline": 1893456000
      }
    }
  ],
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x...(signature)",
  "id": 1
}
```

### eth_accounts

Get the wallet address.

**Required capability**: None

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_accounts",
  "params": [],
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
  "id": 1
}
```

### eth_chainId

Get the chain ID (requires RPC to be configured).

**Required capability**: None

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_chainId",
  "params": [],
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x1",
  "id": 1
}
```

### eth_getBalance

Get the wallet balance (requires RPC to be configured).

**Required capability**: None

Request:
```json
{
  "jsonrpc": "2.0",
  "method": "eth_getBalance",
  "params": [],
  "id": 1
}
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0xde0b6b3a7640000",
  "id": 1
}
```

---

## Error Responses

### HTTP Errors

| Status | Description |
|--------|-------------|
| 401 | Invalid or missing authentication |
| 403 | Credential/wallet paused, revoked, or killed |
| 404 | Resource not found |
| 500 | Internal server error |

### JSON-RPC Errors

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Error description",
    "data": {"code": "ERROR_CODE"}
  },
  "id": 1
}
```

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid Request | Invalid JSON-RPC request |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid method parameters |
| -32000 | Operation not allowed | Capability check failed |
| -32000 | Rate limit exceeded | Rate limit check failed |
| -32000 | Contract not in allowlist | Contract allowlist check failed |
| -32000 | Chain ID mismatch | Provided chainId doesn't match RPC |

### Error Codes in Data

| Code | Description |
|------|-------------|
| `RATE_LIMIT_EXCEEDED` | Transaction or value limit exceeded |
| `CREDENTIAL_PAUSED` | Agent credential is paused |
| `CREDENTIAL_REVOKED` | Agent credential is revoked |
| `WALLET_PAUSED` | Wallet is paused |
| `WALLET_KILLED` | Wallet kill switch activated |

---

## Capabilities Reference

### Operations

| Operation | Description | Methods |
|-----------|-------------|---------|
| `transfer` | Send transactions | `eth_sendTransaction`, `eth_signTransaction` |
| `sign_message` | Sign messages | `personal_sign` |
| `sign_typed_data` | Sign typed data | `eth_signTypedData_v4` |
| `contract_deploy` | Deploy contracts | `eth_sendTransaction` (empty `to`) |
| `swap` | DEX operations | Reserved |
| `*` | All operations | All methods |

### Limits

| Limit | Type | Description |
|-------|------|-------------|
| `max_value_per_tx` | string (wei) | Maximum value per transaction |
| `max_value_per_hour` | string (wei) | Maximum value per rolling hour |
| `max_value_per_day` | string (wei) | Maximum value per rolling day |
| `max_tx_per_hour` | integer | Maximum transactions per hour |
| `max_tx_per_day` | integer | Maximum transactions per day |

All limits are optional. If not specified or set to `0`/empty, the limit is not enforced.
