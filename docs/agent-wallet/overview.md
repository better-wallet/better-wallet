# Agent Wallet Overview

Better Wallet is a self-hosted wallet infrastructure designed specifically for **AI Agents**. It provides secure, controlled on-chain execution where agents can only request signing, never control private keys.

## Why Agent Wallet?

Traditional wallet solutions are designed for human users with interactive UIs. AI Agents have different requirements:

| Human Wallets | Agent Wallets |
|---------------|---------------|
| Interactive approval | Programmatic access |
| User holds keys | Keys protected by KMS/TEE |
| Manual rate limiting | Automated rate limits |
| Trust the user | Trust boundaries enforced |

Agent Wallet addresses these needs with:

- **Separation of concerns**: Agents request, service signs
- **Capability-based security**: Fine-grained permissions
- **Rate limiting**: Prevent runaway agents
- **Kill switch**: Instant revocation when needed
- **Audit trail**: Full operation logging

## Core Entities

### Principal

A **Principal** is a human or organization that owns agent wallets. Principals:

- Create and manage Agent Wallets
- Grant Agent Credentials to AI agents
- Monitor agent activity
- Pause, resume, or revoke agent access
- Trigger kill switch in emergencies

Principals authenticate with an **API Key**:
```
Authorization: Bearer aw_pk_<prefix>.<secret>
```

### Agent Wallet

An **Agent Wallet** is a blockchain wallet owned by a Principal:

- Private key protected by KMS or TEE (never exposed)
- Supports all EVM-compatible chains
- Can have multiple Agent Credentials
- Has status: `active`, `paused`, or `killed`

When a wallet is **killed**, ALL credentials are immediately blocked.

### Agent Credential

An **Agent Credential** is a capability token granted to an AI agent:

- Bound to a specific wallet
- Defines allowed operations
- Specifies contract allowlists
- Sets rate limits
- Has status: `active`, `paused`, or `revoked`

Agents authenticate with their credential:
```
Authorization: Bearer aw_ag_<prefix>.<secret>
```

## Security Model

### Five Principles

1. **Separation** — Agent runtime and signing service are completely isolated. Agents never have access to private keys.

2. **Least Privilege** — Each Agent Credential grants only the capabilities needed for its specific task.

3. **Default Deny** — Any operation not explicitly allowed by the credential is denied.

4. **Auditable** — All operations are recorded with full context (credential, wallet, operation, result).

5. **Revocable** — Principal can revoke agent permissions instantly via pause, revoke, or kill switch.

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Agent Wallet Service                    │    │
│  │  - Validates credentials                             │    │
│  │  - Enforces capabilities                             │    │
│  │  - Checks rate limits                                │    │
│  │  - Signs transactions                                │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Key Storage (KMS/TEE)                   │    │
│  │  - Private keys never leave                          │    │
│  │  - Hardware-protected signing                        │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ JSON-RPC API
                           │
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                             │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   AI Agent                           │    │
│  │  - Holds Agent Credential                            │    │
│  │  - Requests signing operations                       │    │
│  │  - Cannot access private keys                        │    │
│  │  - Subject to rate limits                            │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

## Capabilities

### Operations

Operations define what signing methods an agent can use:

| Operation | JSON-RPC Methods | Description |
|-----------|------------------|-------------|
| `transfer` | `eth_sendTransaction`, `eth_signTransaction` | Send ETH/tokens |
| `sign_message` | `personal_sign` | Sign arbitrary messages (EIP-191) |
| `sign_typed_data` | `eth_signTypedData_v4` | Sign typed data (EIP-712) |
| `contract_deploy` | `eth_sendTransaction` (empty `to`) | Deploy smart contracts |
| `*` | All methods | Wildcard - all operations |

Example: An agent with `["transfer", "sign_typed_data"]` can send transactions and sign EIP-712 data, but cannot use `personal_sign`.

### Contract Allowlist

Restrict which contracts an agent can interact with:

```json
{
  "capabilities": {
    "allowed_contracts": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
    ]
  }
}
```

If `allowed_contracts` is empty, all contracts are allowed.

### Rate Limits

Prevent runaway agents from draining wallets:

| Limit | Description | Example |
|-------|-------------|---------|
| `max_value_per_tx` | Maximum wei per transaction | `"1000000000000000000"` (1 ETH) |
| `max_value_per_hour` | Maximum wei per rolling hour | `"5000000000000000000"` (5 ETH) |
| `max_value_per_day` | Maximum wei per rolling day | `"10000000000000000000"` (10 ETH) |
| `max_tx_per_hour` | Maximum transactions per hour | `100` |
| `max_tx_per_day` | Maximum transactions per day | `1000` |

If a limit is `0` or empty, it's not enforced.

## Lifecycle Management

### Credential States

```
                    ┌─────────┐
         create     │         │
        ─────────►  │ active  │
                    │         │
                    └────┬────┘
                         │
              ┌──────────┼──────────┐
              │          │          │
              ▼          │          ▼
         ┌────────┐      │     ┌─────────┐
         │        │      │     │         │
         │ paused │◄─────┘     │ revoked │
         │        │            │         │
         └────┬───┘            └─────────┘
              │                     ▲
              │      resume         │
              └─────────────────────┘
                    (not possible)
```

- **active**: Credential can be used for signing
- **paused**: Temporarily disabled, can be resumed
- **revoked**: Permanently disabled, cannot be resumed

### Wallet States

```
         ┌─────────┐
         │         │
         │ active  │
         │         │
         └────┬────┘
              │
    ┌─────────┼─────────┐
    │         │         │
    ▼         │         ▼
┌────────┐    │    ┌────────┐
│        │    │    │        │
│ paused │◄───┘    │ killed │
│        │         │        │
└────┬───┘         └────────┘
     │                  ▲
     │    resume        │
     └──────────────────┘
         (not possible)
```

- **active**: Wallet can be used
- **paused**: Temporarily disabled, can be resumed
- **killed**: Emergency stop, ALL credentials blocked permanently

## Use Cases

### DeFi Trading Agent

```json
{
  "name": "DeFi Trading Agent",
  "capabilities": {
    "operations": ["transfer", "sign_typed_data"],
    "allowed_contracts": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45"
    ]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_value_per_hour": "5000000000000000000",
    "max_tx_per_hour": 50
  }
}
```

### NFT Minting Agent

```json
{
  "name": "NFT Minting Agent",
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

### Message Signing Agent

```json
{
  "name": "Auth Signing Agent",
  "capabilities": {
    "operations": ["sign_message", "sign_typed_data"]
  },
  "limits": {
    "max_tx_per_hour": 1000
  }
}
```

## Next Steps

- [Quick Start](./quickstart.md) - Get running in 5 minutes
- [API Reference](./api-reference.md) - Complete API documentation
