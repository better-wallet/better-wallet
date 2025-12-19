# Security Architecture

Better Wallet is designed with security as a foundational principle. This document provides a comprehensive overview of the security architecture, including key protection mechanisms, threat model, and security controls.

## Security Design Principles

### 1. Default-Deny

All operations are denied unless explicitly allowed:
- Policy engine defaults to DENY
- No implicit permissions
- Explicit rules required for any operation

### 2. Defense in Depth

Multiple layers of security controls:
- Network layer (TLS, firewalls)
- Application layer (authentication, authorization)
- Data layer (encryption at rest and in transit)
- Cryptographic layer (key splitting, secure computation)

### 3. Minimal Trust

- Private keys never stored whole
- Key reconstruction only in isolated environments
- Least privilege access for all components

### 4. Auditability

- Complete audit trail of all operations
- Cryptographic integrity of audit records
- Tamper-evident logging

## Key Protection Architecture

### 2-of-2 Shamir's Secret Sharing

Private keys are split using Shamir's Secret Sharing with threshold 2-of-2:

```
┌─────────────────────────────────────────────────────────────┐
│                    Key Generation                            │
│  ┌─────────────────────────────────────────────────────┐    │
│  │  1. Generate 256-bit random seed (CSPRNG)           │    │
│  │  2. Derive private key via BIP-39/BIP-32            │    │
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
│  1. Verify authentication (JWT, app credentials)            │
│  2. Verify authorization (policy, ownership)                │
│  3. Retrieve auth_share from PostgreSQL                     │
│  4. Decrypt auth_share with KMS                             │
│  5. Request exec_share from execution backend               │
│     └─ KMS: Decrypt from blob                               │
│     └─ TEE: Reconstruct inside enclave only                 │
│  6. Combine shares to reconstruct private key               │
│  7. Sign transaction                                        │
│  8. IMMEDIATELY clear key from memory (zeroize)             │
│  9. Return signature                                        │
└─────────────────────────────────────────────────────────────┘
```

### Memory Security

```go
// Key zeroization pattern used in Better Wallet
func zeroKey(key []byte) {
    for i := range key {
        key[i] = 0
    }
}

// Usage in signing
defer zeroKey(privateKey)
signature := sign(privateKey, message)
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

**Security Boundaries**:
- KMS provider controls decryption access
- Private key exists in server memory briefly
- Compromise of server memory could expose key during signing

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
│  │  • Evaluates policies                                  │  │
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

**Security Boundaries**:
- Enclave is hardware-isolated from parent instance
- Even with root access to EC2, cannot read enclave memory
- Attestation proves enclave is running expected code
- Private key never exists outside enclave

**Attestation Flow**:
```
1. Enclave generates attestation document
2. Document includes:
   - PCR values (code measurements)
   - Enclave public key
   - AWS signature
3. Client verifies:
   - AWS signature validity
   - PCR values match expected code
   - Enclave identity
4. Establishes secure channel to enclave
```

## Authentication Security

### Multi-Layer Authentication

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 1: App Authentication                                 │
│  ─────────────────────────────                               │
│  • X-App-Id identifies the application                       │
│  • X-App-Secret verifies app identity                        │
│  • Secrets stored bcrypt-hashed in database                  │
│  • Rate limiting per app                                     │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: User Authentication                                │
│  ───────────────────────────                                 │
│  • JWT bearer token from OIDC provider                       │
│  • Signature verified against JWKS                           │
│  • Claims validated (iss, aud, exp, sub)                     │
│  • User mapped to internal ID                                │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Authorization Signature                            │
│  ────────────────────────────────                            │
│  • P-256 ECDSA signature over canonical payload              │
│  • Required for high-risk operations                         │
│  • Prevents unauthorized privileged actions                  │
│  • Supports M-of-N key quorums                               │
└─────────────────────────────────────────────────────────────┘
```

### JWT Security

| Check | Purpose |
|-------|---------|
| Signature verification | Ensure token from trusted issuer |
| Issuer (`iss`) validation | Prevent token substitution |
| Audience (`aud`) validation | Prevent token reuse across apps |
| Expiration (`exp`) check | Limit token lifetime |
| Not-before (`nbf`) check | Prevent early use |

### App Secret Security

```go
// Secrets are bcrypt-hashed before storage
hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)

// Verification uses constant-time comparison
err := bcrypt.CompareHashAndPassword(storedHash, providedSecret)
```

## Authorization Security

### Policy Engine Security

```
┌─────────────────────────────────────────────────────────────┐
│                  Policy Evaluation                           │
│                                                             │
│  Input: Transaction parameters                               │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  to: "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"   │   │
│  │  value: "1000000000000000000"                        │   │
│  │  data: "0x38ed1739..."                               │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                              │
│                              ▼                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Rule 1: Check address whitelist                    │   │
│  │  Rule 2: Check value limit                          │   │
│  │  Rule 3: Check function selector                    │   │
│  │  ...                                                 │   │
│  │  Default: DENY                                       │   │
│  └─────────────────────────────────────────────────────┘   │
│                              │                              │
│  Output: ALLOW or DENY with reason                          │
└─────────────────────────────────────────────────────────────┘
```

### Authorization Key Security

| Aspect | Implementation |
|--------|----------------|
| Algorithm | P-256 (NIST P-256/prime256v1) |
| Signature | ECDSA with SHA-256 |
| Payload | RFC 8785 canonical JSON |
| Replay prevention | Idempotency keys |
| Key storage | Client-side (KMS/HSM recommended) |

## Data Security

### Encryption at Rest

| Data | Encryption Method |
|------|-------------------|
| Auth shares | KMS envelope encryption |
| Exec shares (KMS) | KMS envelope encryption |
| Exec shares (TEE) | Enclave sealing |
| App secrets | bcrypt hashing |
| Audit logs | Database encryption (optional) |

### Encryption in Transit

| Connection | Protocol |
|------------|----------|
| Client → API | TLS 1.2+ |
| API → PostgreSQL | TLS 1.2+ (configurable) |
| API → KMS | TLS 1.2+ |
| API → TEE | vsock (isolated) |
| API → RPC nodes | HTTPS |

### Sensitive Data Handling

```go
// Headers containing secrets are redacted in logs
redactedHeaders := []string{
    "Authorization",
    "X-App-Secret",
    "X-Authorization-Signature",
}

// Sensitive fields never logged
type WalletShare struct {
    BlobEncrypted []byte `json:"-"` // Excluded from JSON
}
```

## Threat Model

### Assumptions

| Assumption | Description |
|------------|-------------|
| Trusted infrastructure | Cloud provider acts in good faith |
| Secure key generation | CSPRNG provides adequate randomness |
| Cryptographic primitives | P-256, AES-256, SHA-256 are secure |
| Network security | TLS provides confidentiality/integrity |

### Threat Categories

#### External Attackers

| Threat | Mitigation |
|--------|------------|
| API abuse | Authentication, rate limiting |
| Token theft | Short-lived JWTs, HTTPS only |
| Replay attacks | Idempotency keys, timestamps |
| Policy bypass | Default-deny, strict validation |
| SQL injection | Parameterized queries (pgx) |
| XSS/CSRF | API-only (no web UI in core) |

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

#### Scenario 1: Database Breach

```
Attacker gains read access to PostgreSQL
  │
  ├─ Obtains: Encrypted auth_shares
  │           Encrypted exec_shares (KMS backend)
  │           Hashed app secrets
  │
  └─ Cannot: Decrypt shares (needs KMS access)
             Recover app secrets (bcrypt)
             Sign transactions
```

#### Scenario 2: KMS Key Compromise

```
Attacker obtains KMS decryption capability
  │
  ├─ Can decrypt: Exec shares
  │
  └─ Cannot: Obtain auth shares (need DB access)
             Reconstruct keys (need both shares)
             Sign transactions
```

#### Scenario 3: Server Memory Access (KMS Backend)

```
Attacker has memory read during signing
  │
  ├─ May obtain: Private key (brief window)
  │
  └─ Mitigations: TEE backend (key never in main memory)
                  Short signing window
                  Memory zeroization
```

#### Scenario 4: Full Compromise (TEE Backend)

```
Attacker has root access to EC2 instance
  │
  ├─ Can access: Parent process memory
  │              Network traffic
  │              Encrypted auth_shares
  │
  └─ Cannot: Access enclave memory (hardware isolation)
             Decrypt sealed data
             Sign without policy approval
```

## Security Controls Summary

### Preventive Controls

| Control | Implementation |
|---------|----------------|
| Authentication | Multi-layer (app, user, signature) |
| Authorization | Policy engine, default-deny |
| Key protection | 2-of-2 splitting, TEE option |
| Input validation | Schema validation, sanitization |
| Rate limiting | Per-app configurable limits |

### Detective Controls

| Control | Implementation |
|---------|----------------|
| Audit logging | All operations logged |
| Request tracing | Trace IDs across layers |
| Anomaly detection | Rate spike alerts |
| Failed auth tracking | Log and alert on failures |

### Corrective Controls

| Control | Implementation |
|---------|----------------|
| Key rotation | Rotate authorization keys |
| Session revocation | Immediately invalidate sessions |
| App suspension | Disable compromised apps |
| Incident response | Documented procedures |

## Compliance Considerations

| Standard | Relevant Controls |
|----------|-------------------|
| SOC 2 | Audit logging, access control, encryption |
| PCI DSS | Key management, encryption, logging |
| GDPR | Data encryption, audit trails |
| HIPAA | Access controls, encryption, audit |

## Next Steps

- [Deployment Overview](../deployment/overview.md) - Production deployment guide
- [Environment Variables](../deployment/environment-variables.md) - KMS/TEE configuration
- [TLS Configuration](../deployment/tls-configuration.md) - HTTPS setup
- [Authentication](../authentication/overview.md) - Multi-layer authentication
