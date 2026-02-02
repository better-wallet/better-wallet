# Security Architecture

Better Wallet is designed with security as a foundational principle for AI Agent wallet infrastructure. This document provides a comprehensive overview of the security architecture.

## Security Design Principles

### 1. Separation

Agent runtime and signing service are completely isolated:
- Agents can only **request** signing operations
- Agents **never** have access to private keys
- Keys are protected by KMS or TEE

### 2. Least Privilege

Each Agent Credential grants only necessary capabilities:
- Specific operations (transfer, sign_message, etc.)
- Contract allowlists
- Rate limits (per-tx, hourly, daily)

### 3. Default Deny

All operations are denied unless explicitly allowed:
- Empty operations list = all allowed (explicit choice)
- Specific operations list = only those allowed
- Contract allowlist = only listed contracts

### 4. Auditability

Complete audit trail of all operations:
- Credential ID, wallet ID, operation
- Policy result, transaction hash
- Client IP, user agent, timestamp

### 5. Revocability

Principal can revoke agent permissions instantly:
- **Pause**: Temporarily disable (can resume)
- **Revoke**: Permanently disable credential
- **Kill**: Emergency stop for entire wallet

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                    TRUSTED ZONE                              │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Agent Wallet Service                    │    │
│  │  - Validates credentials (bcrypt)                    │    │
│  │  - Enforces capabilities                             │    │
│  │  - Checks rate limits                                │    │
│  │  - Signs transactions                                │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │              Key Storage (KMS/TEE)                   │    │
│  │  - Private keys never leave                          │    │
│  │  - 2-of-2 Shamir secret sharing                      │    │
│  │  - Hardware-protected signing (TEE)                  │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ JSON-RPC API (HTTPS)
                           │
┌─────────────────────────────────────────────────────────────┐
│                   UNTRUSTED ZONE                             │
│                                                              │
│  ┌─────────────────────────────────────────────────────┐    │
│  │                   AI Agent                           │    │
│  │  - Holds Agent Credential (aw_ag_xxx.secret)         │    │
│  │  - Requests signing operations                       │    │
│  │  - Cannot access private keys                        │    │
│  │  - Subject to rate limits                            │    │
│  └─────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Key Protection Architecture

### 2-of-2 Shamir's Secret Sharing

Private keys are split using Shamir's Secret Sharing with threshold 2-of-2:

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Generation                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  1. Generate 256-bit random seed (CSPRNG)           │    │
│  │  2. Derive private key                               │    │
│  │  3. Split into 2 shares using Shamir SSS            │    │
│  │  4. Immediately clear original key from memory      │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│      Auth Share         │     │      Exec Share         │
│  ─────────────────────  │     │  ─────────────────────  │
│  • Encrypted with KMS   │     │  • Managed by backend   │
│  • Stored in PostgreSQL │     │  • KMS: encrypted blob  │
│  • Bound to wallet ID   │     │  • TEE: sealed storage  │
└─────────────────────────┘     └─────────────────────────┘
```

### Share Security Properties

| Property | Auth Share | Exec Share (KMS) | Exec Share (TEE) |
|----------|------------|------------------|------------------|
| Storage location | PostgreSQL | PostgreSQL | Enclave memory |
| Encryption | KMS envelope | KMS envelope | Enclave sealing |
| Access control | DB auth + app auth | KMS IAM | Attestation |
| Compromise impact | Useless alone | Useless alone | Useless alone |

### Key Reconstruction

Keys are reconstructed only during signing:

```
┌─────────────────────────────────────────────────────────────┐
│                   Signing Process                            │
│                                                             │
│  1. Verify agent credential (bcrypt)                        │
│  2. Check credential status (active/paused/revoked)         │
│  3. Check wallet status (active/paused/killed)              │
│  4. Verify capability (operation allowed?)                  │
│  5. Check contract allowlist (if configured)                │
│  6. Check rate limits (tx count, value)                     │
│  7. Retrieve auth_share from PostgreSQL                     │
│  8. Decrypt auth_share with KMS                             │
│  9. Request exec_share from execution backend               │
│     └─ KMS: Decrypt from blob                               │
│     └─ TEE: Reconstruct inside enclave only                 │
│  10. Combine shares to reconstruct private key              │
│  11. Sign transaction                                       │
│  12. IMMEDIATELY clear key from memory (zeroize)            │
│  13. Return signature                                       │
└─────────────────────────────────────────────────────────────┘
```

## Authentication Security

### Two-Layer Authentication

```
┌─────────────────────────────────────────────────────────────┐
│  Principal Authentication (Wallet Management)                │
│  ─────────────────────────────────────────                   │
│  • API Key: aw_pk_<prefix>.<secret>                          │
│  • Secret stored bcrypt-hashed in database                   │
│  • Timing-attack prevention with dummy hash                  │
│  • Used for: wallet creation, credential management          │
├─────────────────────────────────────────────────────────────┤
│  Agent Authentication (Signing Operations)                   │
│  ──────────────────────────────────────────                  │
│  • Credential: aw_ag_<prefix>.<secret>                       │
│  • Secret stored bcrypt-hashed in database                   │
│  • Bound to specific wallet                                  │
│  • Subject to capabilities and rate limits                   │
│  • Used for: JSON-RPC signing API                            │
└─────────────────────────────────────────────────────────────┘
```

### Credential Security

```go
// Secrets are bcrypt-hashed before storage
hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

// Verification uses constant-time comparison
err := bcrypt.CompareHashAndPassword(storedHash, providedSecret)

// Timing-attack prevention: always compare against something
hashToCompare := dummyHash
if credential != nil {
    hashToCompare = credential.SecretHash
}
bcrypt.CompareHashAndPassword(hashToCompare, providedSecret)
```

### Key Format

```
aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy
│    │             │
│    │             └─ Secret (base64, 24 chars)
│    └─ Prefix ID (base64, 12 chars)
└─ Type: pk=principal, ag=agent
```

## Execution Backends

### KMS Backend

```
┌─────────────────────────────────────────────────────────────┐
│                    KMS Backend                               │
│                                                             │
│  ┌─────────────────────────────────────────────────────┐   │
│  │                 Better Wallet Process                │   │
│  │                                                      │   │
│  │  Auth Share ──decrypt──▶ KMS Provider ──▶ Plaintext │   │
│  │  Exec Share ──decrypt──▶ KMS Provider ──▶ Plaintext │   │
│  │                              │                       │   │
│  │  Plaintext shares ──combine──▶ Private Key          │   │
│  │                              │                       │   │
│  │  Private Key ──sign──▶ Signature                    │   │
│  │                              │                       │   │
│  │  ──zeroize──▶ Clear from memory                     │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

**Supported Providers**:

| Provider | Encryption | Key Management |
|----------|------------|----------------|
| Local | AES-256-GCM | Master key in env var |
| AWS KMS | AES-256-GCM | AWS-managed keys |
| Vault | Transit engine | Vault-managed keys |

### TEE Backend (AWS Nitro)

```
┌─────────────────────────────────────────────────────────────┐
│                     EC2 Instance                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Parent Process (Untrusted)                │  │
│  │                                                        │  │
│  │  • Handles HTTP requests                               │  │
│  │  • Validates credentials                               │  │
│  │  • Checks capabilities and rate limits                 │  │
│  │  • CANNOT access private keys                          │  │
│  │                                                        │  │
│  │  [Sign Request] ──vsock──▶ Enclave                    │  │
│  └────────────────────────────┬──────────────────────────┘  │
│                               │                             │
│  ┌────────────────────────────▼──────────────────────────┐  │
│  │              Nitro Enclave (Trusted)                   │  │
│  │                                                        │  │
│  │  • Receives encrypted auth_share                       │  │
│  │  • Decrypts with sealed master key                     │  │
│  │  • Reconstructs private key INSIDE enclave             │  │
│  │  • Signs transaction                                   │  │
│  │  • Returns ONLY signature (never the key)              │  │
│  │                                                        │  │
│  │  Private key NEVER leaves enclave memory               │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Rate Limiting

### Per-Credential Limits

| Limit | Description |
|-------|-------------|
| `max_value_per_tx` | Maximum wei per transaction |
| `max_value_per_hour` | Maximum wei per rolling hour |
| `max_value_per_day` | Maximum wei per rolling day |
| `max_tx_per_hour` | Maximum transactions per hour |
| `max_tx_per_day` | Maximum transactions per day |

### Enforcement

```
┌─────────────────────────────────────────────────────────────┐
│                  Rate Limit Check                            │
│                                                             │
│  1. Get current usage from database                          │
│     - Hourly: tx_count, total_value                          │
│     - Daily: tx_count, total_value                           │
│                                                             │
│  2. Check transaction count limits                           │
│     - hourly.tx_count < max_tx_per_hour?                     │
│     - daily.tx_count < max_tx_per_day?                       │
│                                                             │
│  3. Check value limits                                       │
│     - tx_value <= max_value_per_tx?                          │
│     - hourly.total + tx_value <= max_value_per_hour?         │
│     - daily.total + tx_value <= max_value_per_day?           │
│                                                             │
│  4. If any check fails → DENY with specific error            │
│                                                             │
│  5. After successful signing → record transaction            │
└─────────────────────────────────────────────────────────────┘
```

## Threat Model

### Threat Categories

#### External Attackers

| Threat | Mitigation |
|--------|------------|
| Credential theft | bcrypt hashing, HTTPS only |
| Replay attacks | Nonce management |
| Rate limit bypass | Server-side enforcement |
| Contract injection | Allowlist validation |
| Chain ID manipulation | Strict validation, RPC mismatch check |

#### Insider Threats

| Threat | Mitigation |
|--------|------------|
| Database admin access | Key splitting (shares useless alone) |
| Server admin access | TEE backend isolates keys |
| Code tampering | Open source, reproducible builds |
| Log snooping | Sensitive data redacted |

#### Infrastructure Compromise

| Threat | Mitigation |
|--------|------------|
| Database breach | Shares encrypted with KMS |
| Server memory dump | Keys cleared after use |
| KMS compromise | Still need auth share |
| Full infrastructure | TEE provides hardware isolation |

### Attack Scenarios

#### Scenario 1: Agent Credential Stolen

```
Attacker obtains agent credential
  │
  ├─ Can: Make signing requests within limits
  │
  └─ Mitigations:
     - Rate limits cap damage
     - Contract allowlist restricts targets
     - Principal can revoke immediately
     - Kill switch stops all activity
```

#### Scenario 2: Database Breach

```
Attacker gains read access to PostgreSQL
  │
  ├─ Obtains: Encrypted auth_shares
  │           Encrypted exec_shares (KMS backend)
  │           Hashed credential secrets
  │
  └─ Cannot: Decrypt shares (needs KMS access)
             Recover secrets (bcrypt)
             Sign transactions
```

#### Scenario 3: Runaway Agent

```
AI Agent starts making excessive transactions
  │
  ├─ Blocked by: Rate limits (tx count, value)
  │
  └─ Response:
     - Automatic denial after limit reached
     - Principal notified
     - Can pause/revoke credential
     - Kill switch for emergency
```

## Security Controls Summary

### Preventive Controls

| Control | Implementation |
|---------|----------------|
| Authentication | bcrypt-hashed credentials |
| Authorization | Capability-based, default-deny |
| Key protection | 2-of-2 splitting, TEE option |
| Rate limiting | Per-credential limits |
| Contract allowlist | Whitelist validation |

### Detective Controls

| Control | Implementation |
|---------|----------------|
| Audit logging | All operations logged |
| Rate limit tracking | Per-credential usage |
| Status monitoring | Credential/wallet status |

### Corrective Controls

| Control | Implementation |
|---------|----------------|
| Pause | Temporarily disable credential |
| Revoke | Permanently disable credential |
| Kill switch | Emergency stop for wallet |

## Next Steps

- [Environment Variables](./environment-variables.md) - Configuration reference
- [Deployment Overview](./overview.md) - Production deployment guide
