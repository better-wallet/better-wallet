# Introduction to Better Wallet

Better Wallet is a self-hosted, modular key management and wallet infrastructure for blockchain applications. It enables you to embed secure wallet functionality into your applications while maintaining complete control over deployment and data.

## What is Better Wallet?

Better Wallet is the infrastructure layer that handles:

- **Key Generation**: Secure creation of blockchain keypairs
- **Key Storage**: 2-of-2 Shamir's Secret Sharing with KMS/TEE protection
- **Transaction Signing**: Sign transactions, messages, and EIP-712 typed data
- **Access Control**: Policy engine for fine-grained operation control
- **Audit Trail**: Complete logging of all wallet operations

Unlike hosted wallet solutions, Better Wallet is designed to be self-hosted, giving you:

1. **Data Sovereignty**: Keys and user data stay in your infrastructure
2. **Compliance Control**: Meet regulatory requirements by controlling where data resides
3. **Authentication Freedom**: Use any OIDC/JWT provider (Auth0, Clerk, Better Auth, custom)
4. **Customization**: Extend with custom KMS providers or TEE platforms

## When to Use Better Wallet

### Ideal Use Cases

| Use Case | Why Better Wallet Fits |
|----------|------------------------|
| **Gaming with in-app wallets** | Users don't manage keys, seamless UX |
| **DeFi applications** | Policy engine enforces transaction limits |
| **Enterprise blockchain apps** | Self-hosted for compliance, audit logging |
| **Telegram/Discord bots** | Session signers for automated operations |
| **B2B wallet infrastructure** | Multi-tenant architecture, per-app config |
| **NFT minting services** | Server wallets with rate-limited signing |

### When to Consider Alternatives

- **Consumer non-custodial wallets**: Users want full key control (consider client-side solutions)
- **Hardware wallet integration**: Users have existing hardware wallets
- **Simple one-off transactions**: Direct RPC calls may be simpler

## Key Differentiators

### vs. Privy

| Aspect | Privy | Better Wallet |
|--------|-------|---------------|
| Deployment | SaaS only | Self-hosted first |
| Authentication | Built-in 15+ methods | Bring your own (OIDC/JWT) |
| Source Code | Closed source | MIT open source |
| Data Location | Privy infrastructure | Your infrastructure |
| Pricing | Per-user fees | Self-hosted (free) |

### vs. Building Custom

| Aspect | Custom Solution | Better Wallet |
|--------|-----------------|---------------|
| Development time | Months | Days |
| Security expertise | Required | Built-in |
| Key management | Build from scratch | KMS/TEE ready |
| Policy engine | Build from scratch | Production-ready |
| Maintenance | Ongoing burden | Community-supported |

## Architecture Overview

Better Wallet uses a layered monolithic architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                     Your Application                         │
│                  (Web, Mobile, Server)                       │
└─────────────────────────────┬───────────────────────────────┘
                              │ REST API
┌─────────────────────────────▼───────────────────────────────┐
│                    Interface Layer                           │
│              (Authentication, Validation)                    │
├─────────────────────────────────────────────────────────────┤
│                   Application Layer                          │
│            (Business Logic, Orchestration)                   │
├──────────────────────┬──────────────────────────────────────┤
│    Policy Engine     │        Key Execution Layer            │
│   (Rule Evaluation)  │         (KMS or TEE)                  │
├──────────────────────┴──────────────────────────────────────┤
│                    Storage Layer                             │
│                    (PostgreSQL)                              │
└─────────────────────────────────────────────────────────────┘
```

### Layer Responsibilities

| Layer | Purpose | Does Not |
|-------|---------|----------|
| **Interface** | Auth, validation, rate limiting | Business logic |
| **Application** | Orchestrate operations, manage sessions | Hold keys |
| **Policy Engine** | Evaluate rules, return ALLOW/DENY | Persist state |
| **Key Execution** | Reconstruct keys, sign, clear memory | Business logic |
| **Storage** | Persist all data to PostgreSQL | Process data |

## Security Model

### Default-Deny

All operations are denied unless explicitly allowed by policy rules. This prevents accidental exposure of wallet operations.

### 2-of-2 Key Splitting

Private keys are never stored whole. They're split into:
- **Auth Share**: Encrypted in PostgreSQL (KMS-encrypted)
- **Exec Share**: Managed by execution backend (KMS or TEE)

Keys are only reconstructed in memory during signing, then immediately cleared.

### Multi-Layer Authentication

1. **App-Level**: Your app authenticates with App ID + Secret
2. **User-Level**: Users authenticate via JWT from your OIDC provider
3. **Operation-Level**: High-risk operations require P-256 authorization signatures

## Supported Blockchains

| Chain | Status | Features |
|-------|--------|----------|
| **Ethereum** | Production | Transactions, messages, EIP-712, EIP-7702 |
| **Solana** | Planned | Ed25519 signing |
| **Bitcoin** | Planned | ECDSA signing |

## Technology Stack

| Component | Technology |
|-----------|------------|
| Language | Go 1.21+ |
| Database | PostgreSQL 15+ |
| HTTP | Standard library net/http |
| Crypto | Go stdlib + go-ethereum |
| JWT | golang-jwt/jwt |

No external message queues, caches, or complex dependencies required.

## Next Steps

1. [Quick Start](./quickstart.md) - Get running in 5 minutes
2. [Core Concepts](./core-concepts.md) - Understand the building blocks
3. [Architecture Overview](./architecture-overview.md) - Deep dive into system design
4. [First Integration](./first-integration.md) - Build your first app

## Community

- **GitHub**: [better-wallet/better-wallet](https://github.com/better-wallet/better-wallet)
- **License**: MIT
