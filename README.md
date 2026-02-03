# Better Wallet

**Secure wallet infrastructure for AI Agents.**

Give your AI agents on-chain superpowers — without giving them your keys.

[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/better-wallet/better-wallet/actions/workflows/test.yml/badge.svg)](https://github.com/better-wallet/better-wallet/actions)

---

## The Problem

AI Agents need to interact with blockchains — swap tokens, mint NFTs, sign messages. But how do you give an agent wallet access without risking your funds?

| Traditional Approach | The Risk |
|---------------------|----------|
| Give agent the private key | Agent compromised = funds gone |
| Manual approval for every tx | Defeats the purpose of automation |
| Shared hot wallet | No isolation between agents |

**Better Wallet** solves this with a simple principle: **Agents request, humans control.**

## How It Works

```
┌─────────────────┐         ┌─────────────────────────────────┐
│                 │         │         Better Wallet           │
│    AI Agent     │────────▶│  ┌─────────────────────────┐   │
│                 │ Request │  │   Validate Credential   │   │
│  (holds credential,       │  │   Check Permissions     │   │
│   not private key)        │  │   Enforce Rate Limits   │   │
│                 │         │  └───────────┬─────────────┘   │
└─────────────────┘         │              │                  │
                            │              ▼                  │
                            │  ┌─────────────────────────┐   │
                            │  │   Sign Transaction      │   │
                            │  │   (KMS/TEE protected)   │   │
                            │  └─────────────────────────┘   │
                            └─────────────────────────────────┘
```

1. **Principal** (you) creates a wallet and issues credentials to agents
2. **Agent** uses credential to request signing via JSON-RPC
3. **Better Wallet** validates permissions, enforces limits, then signs
4. **Private keys** never leave the secure enclave — agents can't extract them

## Features

### Security First

- **Key Isolation** — Private keys protected by KMS/TEE, never exposed to agents
- **Capability-Based Access** — Define exactly what each agent can do
- **Contract Allowlists** — Restrict which contracts agents can interact with
- **Rate Limits** — Cap transaction value and frequency per agent

### Kill Switch

- **Pause** — Temporarily disable an agent credential
- **Revoke** — Permanently disable a credential
- **Kill Wallet** — Emergency stop that blocks ALL credentials instantly

### Full Visibility

- **Audit Logs** — Every operation recorded with full context
- **Dashboard** — Web UI for managing wallets and credentials
- **Prometheus Metrics** — Monitor agent activity in real-time

### Self-Hosted

- **Your Infrastructure** — Complete control over your data
- **Open Source** — MIT licensed, no vendor lock-in
- **EVM Compatible** — Works with Ethereum, Polygon, Arbitrum, Base, and more

## Quick Start

### Option 1: Docker (Recommended)

```bash
# Clone the repo
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Start with Docker Compose
cp .env.example .env
# Edit .env with your database credentials
docker-compose up -d
```

The API is now running at `http://localhost:8080`.

### Option 2: From Source

```bash
# Prerequisites: Go 1.21+, PostgreSQL 15+

# Clone and build
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet
go build -o bin/server ./cmd/server

# Set up database
createdb better_wallet
go run ./cmd/migrate up

# Configure and run
cp .env.example .env
# Edit .env with your settings
./bin/server
```

### Create Your First Agent Wallet

```bash
# 1. Register as a Principal (via dashboard or API)
#    You'll receive an API key: aw_pk_xxx.secret

# 2. Create a wallet
curl -X POST http://localhost:8080/v1/wallets \
  -H "Authorization: Bearer $PRINCIPAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Trading Agent Wallet"}'

# 3. Create an agent credential with permissions
curl -X POST http://localhost:8080/v1/wallets/{wallet_id}/credentials \
  -H "Authorization: Bearer $PRINCIPAL_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "DeFi Trading Agent",
    "capabilities": {
      "operations": ["transfer", "sign_typed_data"],
      "allowed_contracts": ["0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"]
    },
    "limits": {
      "max_value_per_tx": "1000000000000000000",
      "max_tx_per_hour": 100
    }
  }'
# Response includes: aw_ag_xxx.secret (save this!)

# 4. Your agent can now sign transactions
curl -X POST http://localhost:8080/v1/agent/rpc \
  -H "Authorization: Bearer $AGENT_CREDENTIAL" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{"to": "0x...", "value": "0x0", "data": "0x..."}],
    "id": 1
  }'
```

**[Full Documentation →](./docs/README.md)**

## Use Cases

### Autonomous Trading Agent

```json
{
  "capabilities": {
    "operations": ["transfer", "sign_typed_data"],
    "allowed_contracts": ["0x...uniswap", "0x...1inch"]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_value_per_day": "10000000000000000000",
    "max_tx_per_hour": 50
  }
}
```
Agent can trade on approved DEXs with daily spending caps.

### NFT Minting Agent

```json
{
  "capabilities": {
    "operations": ["transfer"],
    "allowed_contracts": ["0x...nft_contract"]
  },
  "limits": {
    "max_value_per_tx": "100000000000000000",
    "max_tx_per_day": 100
  }
}
```
Agent can only mint from specific contracts, limited to 0.1 ETH per tx.

### Signing-Only Agent

```json
{
  "capabilities": {
    "operations": ["sign_message", "sign_typed_data"]
  },
  "limits": {
    "max_tx_per_hour": 1000
  }
}
```
Agent can sign messages for authentication but cannot transfer any funds.

## Why Better Wallet?

| Feature | Better Wallet | Custodial APIs | Raw Private Keys |
|---------|--------------|----------------|------------------|
| Self-hosted | ✅ | ❌ | ✅ |
| Key isolation | ✅ | ✅ | ❌ |
| Fine-grained permissions | ✅ | Limited | ❌ |
| Contract allowlists | ✅ | ❌ | ❌ |
| Rate limiting | ✅ | ✅ | ❌ |
| Kill switch | ✅ | ✅ | ❌ |
| Open source | ✅ | ❌ | N/A |
| No vendor lock-in | ✅ | ❌ | ✅ |

## Documentation

- **[Overview](./docs/agent-wallet/overview.md)** — Core concepts and security model
- **[Quick Start](./docs/agent-wallet/quickstart.md)** — Detailed setup guide
- **[API Reference](./docs/agent-wallet/api-reference.md)** — Complete API documentation
- **[Deployment](./docs/deployment/overview.md)** — Production deployment guides
- **[Security](./docs/security/architecture.md)** — Security architecture

## Community

- **[GitHub Issues](https://github.com/better-wallet/better-wallet/issues)** — Bug reports & feature requests
- **[GitHub Discussions](https://github.com/better-wallet/better-wallet/discussions)** — Questions & ideas
- **[Twitter](https://twitter.com/betterwallet)** — Updates & announcements

## Contributing

We welcome contributions! See [Development Setup](./docs/contributing/development-setup.md) to get started.

```bash
# Run tests
go test ./...

# Run linter
golangci-lint run
```

## License

Better Wallet is open source under the [MIT License](LICENSE).

---

<p align="center">
  <b>Built for the agentic future.</b><br>
  <sub>If you find this useful, please star the repo!</sub>
</p>
