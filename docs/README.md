# Better Wallet Documentation

Welcome to the Better Wallet documentation. Better Wallet is a self-hosted, modular key management and wallet infrastructure for blockchain applications.

## What is Better Wallet?

Better Wallet provides enterprise-grade embedded wallet capabilities with:

- **Self-Hosted Architecture**: Complete control over your deployment and data
- **Authentication-Agnostic**: Integrates with any OIDC/JWT provider (Auth0, Clerk, Better Auth, etc.)
- **Dual Key Management**: KMS/Vault (default) or TEE (AWS Nitro Enclaves) backends
- **Flexible Policy Engine**: Rule-based access control with default-deny security
- **2-of-2 Key Splitting**: Shamir's Secret Sharing for cryptographic material protection

## Quick Navigation

### Getting Started

| Document | Description |
|----------|-------------|
| [Introduction](./getting-started/introduction.md) | What is Better Wallet and when to use it |
| [Quick Start](./getting-started/quickstart.md) | Get running in under 5 minutes |
| [Core Concepts](./getting-started/core-concepts.md) | Understand wallets, policies, and keys |
| [Architecture Overview](./getting-started/architecture-overview.md) | System design and data flow |
| [First Integration](./getting-started/first-integration.md) | Build your first app |

### For Application Developers

| Section | What You'll Learn |
|---------|-------------------|
| [Authentication](./authentication/) | JWT setup, authorization signatures, security model |
| [Wallets](./wallets/) | Creating and managing blockchain wallets |
| [Signing](./signing/) | Transaction, message, and typed data signing |
| [Policies](./policies/) | Access control rules and policy engine |
| [Session Signers](./session-signers/) | Delegated temporary signing |
| [API Reference](./api-reference/) | Complete REST API documentation |
| [Integration Guides](./integration/) | Next.js, Node.js framework guides |

### For DevOps/SRE Teams

| Section | What You'll Learn |
|---------|-------------------|
| [Deployment](./deployment/) | Docker, Kubernetes, bare-metal setup |
| [Environment Variables](./deployment/environment-variables.md) | Complete configuration reference |
| [Monitoring](./deployment/monitoring.md) | Metrics, logging, alerting |
| [Backup & Recovery](./deployment/backup-recovery.md) | Data protection and disaster recovery |
| [Security](./security/) | Cryptographic details, threat model, hardening |

### API Reference (Endpoints)

| Endpoint | Description |
|----------|-------------|
| [Wallets](./api-reference/endpoints/wallets.md) | Wallet CRUD and signing operations |
| [Policies](./api-reference/endpoints/policies.md) | Policy management |
| [Authorization Keys](./api-reference/endpoints/authorization-keys.md) | P-256 key registration |
| [Session Signers](./api-reference/endpoints/session-signers.md) | Delegated signing sessions |
| [Condition Sets](./api-reference/endpoints/condition-sets.md) | Reusable policy value sets |
| [Key Quorums](./api-reference/endpoints/key-quorums.md) | M-of-N multi-signature |

### Advanced Topics

| Section | Description |
|---------|-------------|
| [Policy Field Sources](./policies/field-sources.md) | All available fields for policy rules |
| [Policy Examples](./policies/examples.md) | Real-world policy patterns |
| [Contributing](./contributing/) | Development setup, code guidelines |
| [Reference](./reference/) | Glossary, FAQ, changelog |

## Installation

### Docker (Recommended)

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Configure environment
cat > .env << 'EOF'
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
EOF

# Start services
docker-compose up -d

# Verify installation
curl http://localhost:8080/health
# Response: {"status":"ok"}
```

### From Source

```bash
# Prerequisites: Go 1.21+, PostgreSQL 15+

# Clone and build
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet
make build

# Configure and run
cp .env.example .env
# Edit .env with your settings
./bin/better-wallet
```

See [Deployment Guide](./deployment/) for detailed installation options.

## Core Concepts at a Glance

### Wallets

Blockchain wallets with cryptographic keys protected by 2-of-2 secret sharing. Each wallet has:
- An **owner** (authorization key or key quorum) for high-risk operations
- **Policies** that control what operations are allowed
- Optional **session signers** for delegated access

### Policies

Rule-based access control with default-deny semantics:
- Evaluate transaction parameters (to, value, data)
- Decode and validate contract calls
- Support EIP-712 typed data constraints
- Time-based and rate-limit conditions

### Authorization

Multi-layer authentication:
1. **App Authentication**: X-App-Id and X-App-Secret headers
2. **User Authentication**: JWT bearer token from your OIDC provider
3. **Authorization Signatures**: P-256 signatures for high-risk operations

## API Example

Create a wallet and sign a transaction:

```bash
# Create a wallet
curl -X POST http://localhost:8080/v1/wallets \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'

# Sign a transaction
curl -X POST http://localhost:8080/v1/wallets/{wallet_id}/rpc \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
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

## Support

- **GitHub Issues**: [Bug reports and feature requests](https://github.com/better-wallet/better-wallet/issues)
- **GitHub Discussions**: [Questions and community support](https://github.com/better-wallet/better-wallet/discussions)

## License

Better Wallet is open source under the [MIT License](https://github.com/better-wallet/better-wallet/blob/main/LICENSE).
