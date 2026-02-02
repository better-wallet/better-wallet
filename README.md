# Better Wallet - Agent Wallet

**Better Wallet** is an open-source, self-hosted wallet infrastructure for **AI Agents**. It provides secure, controlled on-chain execution where agents can only request signing, never control private keys.

> Secure, controlled on-chain execution for AI Agents. Agents can only request, never control.

## Key Features

- **Agent-First Design**: Built specifically for AI agent scenarios, not end-user wallets
- **Principal Control**: Humans/organizations maintain ultimate control over agent wallets
- **Capability-Based Security**: Fine-grained permissions with operations, contract allowlists, and rate limits
- **Kill Switch**: Instantly revoke agent access when needed
- **Self-Hosted**: Complete control over your infrastructure and data
- **EVM Compatible**: Supports all EVM-compatible chains (Ethereum, Polygon, Arbitrum, Base, etc.)

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

## Core Concepts

### Three Core Entities

| Entity | Description |
|--------|-------------|
| **Principal** | Human or organization that owns wallets. Authenticates with API Key. |
| **Agent Wallet** | Blockchain wallet owned by a Principal. Private key protected by KMS/TEE. |
| **Agent Credential** | Capability token granted to an AI agent with specific permissions and limits. |

### Security Model

1. **Separation** — Agent runtime and signing service are completely isolated
2. **Least Privilege** — Agent Credential grants only necessary capabilities
3. **Default Deny** — Any operation not explicitly allowed is denied
4. **Auditable** — All operations recorded with full context
5. **Revocable** — Principal can revoke agent permissions instantly

## Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 15+

### Installation

```bash
# Clone the repository
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Set up the database
createdb better_wallet
cd dashboard && bun install && bun run db:push && cd ..

# Configure environment
cat > .env << EOF
POSTGRES_DSN=postgres://user:pass@localhost:5432/better_wallet?sslmode=disable
EXECUTION_BACKEND=kms
KMS_PROVIDER=local
KMS_MASTER_KEY=$(openssl rand -hex 32)
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
EOF

# Build and run
go build -o bin/server ./cmd/server
./bin/server
```

## API Reference

### Authentication

**Principal API** (wallet management):
```
Authorization: Bearer aw_pk_<prefix>.<secret>
```

**Agent API** (signing operations):
```
Authorization: Bearer aw_ag_<prefix>.<secret>
```

### Principal Endpoints

#### Create Agent Wallet
```http
POST /api/wallets
Authorization: Bearer aw_pk_xxx.secret
Content-Type: application/json

{
  "name": "Trading Bot Wallet",
  "chain_type": "evm"
}

Response:
{
  "id": "uuid",
  "address": "0x...",
  "name": "Trading Bot Wallet",
  "chain_type": "evm",
  "status": "active"
}
```

#### Create Agent Credential
```http
POST /api/wallets/{wallet_id}/credentials
Authorization: Bearer aw_pk_xxx.secret
Content-Type: application/json

{
  "name": "DeFi Trading Agent",
  "capabilities": {
    "operations": ["transfer", "sign_message", "sign_typed_data"],
    "allowed_contracts": ["0x...uniswap", "0x...aave"]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_value_per_hour": "5000000000000000000",
    "max_value_per_day": "10000000000000000000",
    "max_tx_per_hour": 100,
    "max_tx_per_day": 1000
  }
}

Response:
{
  "id": "uuid",
  "credential": "aw_ag_xxxxxxxxxxxx.yyyyyyyyyyyyyyyy",
  "name": "DeFi Trading Agent",
  "capabilities": {...},
  "limits": {...},
  "status": "active"
}
```

#### Control Agent
```http
POST /api/credentials/{credential_id}/pause    # Pause (can resume)
POST /api/credentials/{credential_id}/resume   # Resume
POST /api/credentials/{credential_id}/revoke   # Permanent revocation

POST /api/wallets/{wallet_id}/kill             # Kill switch - blocks ALL credentials
```

### Agent Signing API (JSON-RPC)

```http
POST /agent/rpc
Authorization: Bearer aw_ag_xxx.secret
Content-Type: application/json
```

#### eth_sendTransaction
```json
{
  "jsonrpc": "2.0",
  "method": "eth_sendTransaction",
  "params": [{
    "to": "0x...",
    "value": "0xde0b6b3a7640000",
    "data": "0x...",
    "chainId": "0x1"
  }],
  "id": 1
}
```

#### eth_signTransaction
```json
{
  "jsonrpc": "2.0",
  "method": "eth_signTransaction",
  "params": [{
    "to": "0x...",
    "value": "0xde0b6b3a7640000",
    "data": "0x...",
    "chainId": "0x1"
  }],
  "id": 1
}
```

#### personal_sign
```json
{
  "jsonrpc": "2.0",
  "method": "personal_sign",
  "params": ["0x48656c6c6f", "0x...address"],
  "id": 1
}
```

#### eth_signTypedData_v4
```json
{
  "jsonrpc": "2.0",
  "method": "eth_signTypedData_v4",
  "params": ["0x...address", {
    "types": {...},
    "primaryType": "...",
    "domain": {...},
    "message": {...}
  }],
  "id": 1
}
```

#### eth_accounts
```json
{
  "jsonrpc": "2.0",
  "method": "eth_accounts",
  "params": [],
  "id": 1
}
```

#### eth_chainId
```json
{
  "jsonrpc": "2.0",
  "method": "eth_chainId",
  "params": [],
  "id": 1
}
```

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

### Error Responses

```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32000,
    "message": "Rate limit exceeded: daily transaction limit",
    "data": {"code": "RATE_LIMIT_EXCEEDED"}
  },
  "id": 1
}
```

| Code | Message |
|------|---------|
| -32600 | Invalid Request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32000 | Operation not allowed / Rate limit exceeded |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `POSTGRES_DSN` | Yes | PostgreSQL connection string |
| `EXECUTION_BACKEND` | Yes | `kms` or `tee` |
| `KMS_PROVIDER` | If kms | `local`, `aws`, or `vault` |
| `KMS_MASTER_KEY` | If local | 32-byte hex master key |
| `RPC_URL` | No | EVM RPC URL for chain operations |
| `PORT` | No | Server port (default: 8080) |

## Project Structure

```
better-wallet/
├── cmd/server/           # Main application entry point
├── dashboard/            # Next.js dashboard (DB schema management)
├── internal/
│   ├── api/              # HTTP handlers (REST + JSON-RPC)
│   ├── app/              # Business logic (AgentService)
│   ├── config/           # Configuration
│   ├── crypto/           # Cryptographic utilities
│   ├── eth/              # EVM RPC client
│   ├── keyexec/          # Key execution backends (KMS/TEE)
│   ├── middleware/       # Auth middleware (Principal/Agent)
│   └── storage/          # Database repositories
├── pkg/types/            # Shared type definitions
├── tests/
│   ├── integration/      # Integration tests
│   └── security/         # Security tests
└── docs/                 # Documentation
```

## Running Tests

```bash
# Unit tests
go test ./...

# Integration tests
go test -tags=integration ./tests/integration/...

# Security tests
go test -tags=security ./tests/security/...

# All tests
go test ./... && go test -tags=integration,security ./tests/...
```

## Security Considerations

- **Private keys never leave KMS/TEE** - Keys are protected by hardware security
- **Agent credentials are bcrypt hashed** - Secrets stored securely
- **Timing attack prevention** - Constant-time comparisons for auth
- **Chain ID validation** - Prevents cross-chain transaction issues
- **Contract allowlists** - Restrict which contracts agents can interact with
- **Rate limiting** - Prevent runaway agents from draining wallets

## License

Better Wallet is licensed under the [MIT License](LICENSE).

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

Built for the AI Agent economy.
