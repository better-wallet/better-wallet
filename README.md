# Better Wallet

**Better Wallet** is an open-source, self-hosted, modular key management and wallet infrastructure for blockchain applications. Built with Go, it provides enterprise-grade security with a focus on simplicity and ease of deployment.

## 🎯 Key Features

- **Self-Hosted First**: Complete control over your infrastructure and data
- **Authentication Agnostic**: Integrates with any OIDC/JWT provider (Auth0, Better Auth, custom IdP, etc.)
- **Dual Key Management**: KMS/Vault (default) or TEE (Trusted Execution Environment) for enhanced security
- **Policy Engine**: Flexible, rule-based access control with default-deny semantics
- **EVM Support**: Built-in Ethereum and EVM-compatible chain support
- **Open Source**: MIT licensed, fully auditable code

## 🏗️ Architecture

Better Wallet follows a clean, layered monolithic architecture:

```
┌─────────────────────────────────────┐
│      REST API (Interface Layer)     │
│   Authentication & Validation        │
└──────────────┬──────────────────────┘
               │
┌──────────────▼──────────────────────┐
│     Application Layer                │
│  Wallet Operations, Session Mgmt     │
└──────┬───────────────────┬──────────┘
       │                   │
┌──────▼────────┐   ┌──────▼──────────┐
│ Policy Engine │   │ Key Exec Layer  │
│ Rule Eval     │   │ KMS/TEE         │
└───────────────┘   └─────────────────┘
       │                   │
┌──────▼───────────────────▼──────────┐
│     Persistence (PostgreSQL)         │
└──────────────────────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21+
- PostgreSQL 15+
- An OIDC/JWT authentication provider

### Installation

1. **Clone the repository**
```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet
```

2. **Set up the database**
```bash
# Create a PostgreSQL database
createdb better_wallet

# Set up Dashboard and push schema
cd dashboard
bun install
DATABASE_URL=postgres://user:pass@localhost:5432/better_wallet bun run db:push
cd ..
```

3. **Configure environment variables**

Create `.env` for the Go backend:
```env
# Database
POSTGRES_DSN=postgres://user:pass@localhost:5432/better_wallet?sslmode=disable

# Key Execution Backend
EXECUTION_BACKEND=kms
KMS_KEY_ID=your-master-key-id

# Server
PORT=8080
```

Create `dashboard/.env` for the Dashboard:
```env
DATABASE_URL=postgres://user:pass@localhost:5432/better_wallet?sslmode=disable
```

4. **Build and run**
```bash
# Install dependencies
go mod download

# Build
go build -o bin/better-wallet ./cmd/server

# Run
./bin/better-wallet
```

The server will start on `http://localhost:8080`.

## 📖 API Documentation

### Authentication

All API endpoints (except `/health`) require **App authentication**:

```
X-App-Id: <app_id>
X-App-Secret: <app_secret>
```

Treat `X-App-Secret` as a long-lived credential and ensure it is never logged. The server strips
`X-App-Secret` (and user `Authorization` tokens) from requests after authentication.

Many endpoints that operate on **user-owned** resources also require a user JWT:

```
Authorization: Bearer <your-jwt-token>
```

### Authorization Signatures (Canonical JSON)

Certain privileged operations require an additional request signature:

- `PATCH /v1/wallets/{wallet_id}`
- `DELETE /v1/wallets/{wallet_id}`
- `PATCH /v1/policies/{policy_id}`
- `DELETE /v1/policies/{policy_id}`
- `PATCH /v1/key-quorums/{key_quorum_id}`
- `DELETE /v1/key-quorums/{key_quorum_id}`
- `POST /v1/wallets/{wallet_id}/rpc`

Header:

```
X-Authorization-Signature: <sig>[,<sig>...]
```

The signature is a base64-encoded P-256 ECDSA signature over an RFC 8785 canonical JSON payload:

```json
{
  "version": "v1",
  "method": "POST",
  "url": "https://your-api.example.com/v1/wallets/<id>/rpc",
  "body": "{...raw request body...}",
  "headers": {
    "x-app-id": "<app_id>",
    "x-idempotency-key": "<optional>"
  }
}
```

Note: set `BETTER_WALLET_CANONICAL_URL_MODE=relative` to use `url` as path-only (legacy mode).

### Endpoints

#### Health Check
```
GET /health
```

#### Create Wallet
```
POST /v1/wallets
Content-Type: application/json

{
  "chain_type": "ethereum",
  "exec_backend": "kms"
}

Response:
{
  "id": "uuid",
  "address": "0x...",
  "chain_type": "ethereum",
  "created_at": "2025-01-01T00:00:00Z"
}
```

#### List Wallets
```
GET /v1/wallets

Response:
[
  {
    "id": "uuid",
    "address": "0x...",
    "chain_type": "ethereum",
    "created_at": "2025-01-01T00:00:00Z"
  }
]
```

#### Sign Transaction
```
POST /v1/wallets/{wallet_id}/sign
Content-Type: application/json

{
  "to": "0x...",
  "value": "1000000000000000000",
  "chain_id": 1,
  "nonce": 0,
  "gas_limit": 21000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": "0x"
}

Response:
{
  "tx_hash": "0x...",
  "signed_tx": "0x..."
}
```

## 🔐 Security Model

### Key Management

Better Wallet uses a **2-of-2 key splitting** approach:

- **Auth Share**: Encrypted and stored in PostgreSQL
- **Exec Share**: Managed by the execution backend (KMS/TEE)

Keys are only reconstructed in memory during signing operations and immediately cleared afterward.

### Policy Engine

The policy engine enforces access control with:

- **Default Deny**: All actions are denied unless explicitly allowed
- **Rule-based Evaluation**: Policies define rules with conditions
- **Audit Trail**: All policy decisions are logged

Example policy structure:
```json
{
  "rules": [
    {
      "action": "sign_transaction",
      "conditions": [
        {
          "type": "max_value",
          "value": "1000000000000000000"
        },
        {
          "type": "address_whitelist",
          "addresses": ["0x..."]
        }
      ]
    }
  ]
}
```

## 🛠️ Development

### Project Structure

```
better-wallet/
├── cmd/
│   └── server/          # Main application entry point
├── dashboard/           # Next.js dashboard (manages DB schema)
│   └── src/server/db/   # Drizzle schema (single source of truth)
├── internal/
│   ├── api/             # HTTP handlers and server
│   ├── app/             # Application/business logic layer
│   ├── config/          # Configuration management
│   ├── crypto/          # Cryptographic utilities
│   ├── keyexec/         # Key execution backends (KMS/TEE)
│   ├── middleware/      # HTTP middleware (auth, logging)
│   ├── policy/          # Policy engine
│   └── storage/         # Database repositories
├── pkg/
│   ├── errors/          # Error definitions
│   └── types/           # Shared type definitions
└── docs/                # Documentation
```

### Running Tests

```bash
go test ./...
```

### Database Schema

The database schema is managed by Drizzle in the `dashboard/` project. To update the schema:

```bash
cd dashboard

# Push schema changes directly to database
bun run db:push

# Or generate migration files
bun run db:generate

# Open Drizzle Studio to view/edit data
bun run db:studio
```

## 🗺️ Roadmap

### ✅ Phase 1 - MVP (Current)
- Go monolith + PostgreSQL
- KMS/Vault execution backend
- EVM support
- REST API
- Policy engine with rule-based access control
- OIDC/JWT authentication
- Complete audit logging

### 🚧 Phase 2 - Enhanced Security
- TEE backend (production-ready)
- On-Device mode
- Enhanced policies (ABI parsing, EIP-712 support)
- Advanced recovery options
- Performance optimizations and horizontal scaling

### 📋 Phase 3 - Multi-Chain & Scale
- Multi-chain support (Solana, Bitcoin, Cosmos)
- Optional caching layer for high throughput
- Advanced observability (OTLP, metrics, tracing)
- Session signer management UI

### 🎯 Phase 4 - Enterprise & Ecosystem
- Account Abstraction / Paymaster integration
- Developer SDKs (JavaScript, Python, Rust)
- Admin UI and dashboard
- Compliance modules (SOC 2, ISO 27001)
- Optional managed SaaS offering

## 📝 License

Better Wallet is licensed under the [MIT License](LICENSE).

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## 🔗 Links

- **Documentation**: [docs/](./docs)
- **Issue Tracker**: [GitHub Issues](https://github.com/better-wallet/better-wallet/issues)

---

Built with ❤️ by the Better Wallet Team
