# Better Wallet Documentation

Welcome to the Better Wallet documentation. Better Wallet is a self-hosted wallet infrastructure designed specifically for **AI Agents**.

## What is Better Wallet?

Better Wallet provides secure, controlled on-chain execution for AI Agents:

- **Agent-First Design**: Built specifically for AI agent scenarios, not end-user wallets
- **Principal Control**: Humans/organizations maintain ultimate control over agent wallets
- **Capability-Based Security**: Fine-grained permissions with operations, contract allowlists, and rate limits
- **Kill Switch**: Instantly revoke agent access when needed
- **Self-Hosted**: Complete control over your infrastructure and data
- **EVM Compatible**: Supports all EVM-compatible chains

## Quick Navigation

### Getting Started

| Document | Description |
|----------|-------------|
| [Agent Wallet Overview](./agent-wallet/overview.md) | Core concepts and architecture |
| [Quick Start](./agent-wallet/quickstart.md) | Get running in under 5 minutes |
| [API Reference](./agent-wallet/api-reference.md) | Complete API documentation |

### Core Concepts

| Concept | Description |
|---------|-------------|
| **Principal** | Human or organization that owns wallets. Authenticates with API Key (`aw_pk_xxx.secret`). |
| **Agent Wallet** | Blockchain wallet owned by a Principal. Private key protected by KMS/TEE. |
| **Agent Credential** | Capability token granted to an AI agent (`aw_ag_xxx.secret`) with specific permissions and limits. |

### Security Model

1. **Separation** — Agent runtime and signing service are completely isolated
2. **Least Privilege** — Agent Credential grants only necessary capabilities
3. **Default Deny** — Any operation not explicitly allowed is denied
4. **Auditable** — All operations recorded with full context
5. **Revocable** — Principal can revoke agent permissions instantly

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Principal (Human/Org)                      │
│               - Creates Agent Wallets                        │
│               - Grants Agent Credentials                     │
│               - Monitors & Kill Switch                       │
└─────────────────────┬───────────────────────────────────────┘
                      │ API Key (aw_pk_xxx.secret)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                  Agent Wallet Service                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Rate Limit  │  │ Capability  │  │ Signing Service     │  │
│  │ Enforcement │  │ Checking    │  │ (KMS/TEE)           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │ Agent Credential (aw_ag_xxx.secret)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                       AI Agent                               │
│               - Holds Agent Credential                       │
│               - Calls JSON-RPC signing API                   │
│               - Never has access to private keys             │
└─────────────────────────────────────────────────────────────┘
```

## API Overview

### Two Authentication Contexts

| Context | Header | Use Case |
|---------|--------|----------|
| **Principal API** | `Bearer aw_pk_xxx.secret` | Wallet management, credential creation, monitoring |
| **Agent API** | `Bearer aw_ag_xxx.secret` | Signing operations (JSON-RPC) |

### Principal Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/wallets` | POST | Create new agent wallet |
| `/api/wallets` | GET | List wallets |
| `/api/wallets/{id}` | GET | Get wallet details |
| `/api/wallets/{id}/credentials` | POST | Create agent credential |
| `/api/wallets/{id}/credentials` | GET | List credentials |
| `/api/credentials/{id}/pause` | POST | Pause credential |
| `/api/credentials/{id}/resume` | POST | Resume credential |
| `/api/credentials/{id}/revoke` | POST | Revoke credential (permanent) |
| `/api/wallets/{id}/kill` | POST | Kill switch - block all credentials |

### Agent Signing API (JSON-RPC)

| Method | Description |
|--------|-------------|
| `eth_sendTransaction` | Sign and broadcast transaction |
| `eth_signTransaction` | Sign transaction (return raw) |
| `personal_sign` | Sign message (EIP-191) |
| `eth_signTypedData_v4` | Sign typed data (EIP-712) |
| `eth_accounts` | Get wallet address |
| `eth_chainId` | Get chain ID |
| `eth_getBalance` | Get wallet balance |

### Capability Operations

| Operation | Description |
|-----------|-------------|
| `transfer` | Send ETH/tokens via eth_sendTransaction |
| `sign_message` | Sign messages via personal_sign |
| `sign_typed_data` | Sign EIP-712 typed data |
| `contract_deploy` | Deploy contracts (empty `to` address) |
| `swap` | Reserved for DEX operations |
| `*` | Wildcard - all operations allowed |

### Rate Limits

| Limit | Description |
|-------|-------------|
| `max_value_per_tx` | Maximum wei per transaction |
| `max_value_per_hour` | Maximum wei per rolling hour |
| `max_value_per_day` | Maximum wei per rolling day |
| `max_tx_per_hour` | Maximum transactions per hour |
| `max_tx_per_day` | Maximum transactions per day |

## Quick Start Example

### 1. Principal creates a wallet

```bash
curl -X POST http://localhost:8080/api/wallets \
  -H "Authorization: Bearer aw_pk_xxx.secret" \
  -H "Content-Type: application/json" \
  -d '{"name": "Trading Bot", "chain_type": "evm"}'
```

### 2. Principal creates an agent credential

```bash
curl -X POST http://localhost:8080/api/wallets/{wallet_id}/credentials \
  -H "Authorization: Bearer aw_pk_xxx.secret" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DeFi Agent",
    "capabilities": {
      "operations": ["transfer", "sign_typed_data"],
      "allowed_contracts": ["0x...uniswap"]
    },
    "limits": {
      "max_value_per_tx": "1000000000000000000",
      "max_tx_per_hour": 100
    }
  }'
```

### 3. Agent uses credential to sign

```bash
curl -X POST http://localhost:8080/agent/rpc \
  -H "Authorization: Bearer aw_ag_xxx.secret" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{"to": "0x...", "value": "0x...", "chainId": "0x1"}],
    "id": 1
  }'
```

### 4. Principal revokes access if needed

```bash
curl -X POST http://localhost:8080/api/credentials/{credential_id}/revoke \
  -H "Authorization: Bearer aw_pk_xxx.secret"
```

## Deployment

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `EXECUTION_BACKEND` | Yes | `kms` or `tee` |
| `KMS_PROVIDER` | If kms | `local`, `aws`, or `vault` |
| `KMS_MASTER_KEY` | If local | 32-byte hex master key |
| `RPC_URL` | No | EVM RPC URL for chain operations |
| `PORT` | No | Server port (default: 8080) |

### Docker

```bash
docker-compose up -d
```

### From Source

```bash
go build -o bin/server ./cmd/server
./bin/server
```

## Support

- **GitHub Issues**: [Bug reports and feature requests](https://github.com/better-wallet/better-wallet/issues)
- **GitHub Discussions**: [Questions and community support](https://github.com/better-wallet/better-wallet/discussions)

## License

Better Wallet is open source under the [MIT License](https://github.com/better-wallet/better-wallet/blob/main/LICENSE).
