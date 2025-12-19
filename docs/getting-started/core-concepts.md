# Core Concepts

This guide explains the fundamental concepts in Better Wallet. Understanding these will help you build secure and efficient integrations.

## Wallets

A **wallet** represents a blockchain account with a cryptographically secured keypair.

### Wallet Properties

| Property | Description |
|----------|-------------|
| `id` | Unique identifier (UUID) |
| `address` | Blockchain address (e.g., `0x742d...`) |
| `chain_type` | Blockchain type (`ethereum`, `solana`, etc.) |
| `exec_backend` | Key execution backend (`kms` or `tee`) |
| `owner_id` | Authorization key or key quorum that controls the wallet |
| `user_id` | Associated user (optional, for user-owned wallets) |

### Wallet Types

#### User Wallets

Wallets associated with an end user (via JWT `sub` claim):

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": "user-uuid",
  "owner_id": "auth-key-uuid",
  "chain_type": "ethereum",
  "address": "0x..."
}
```

#### App-Managed Wallets

Wallets managed by your application (no user association):

```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "user_id": null,
  "owner_id": null,
  "chain_type": "ethereum",
  "address": "0x..."
}
```

App-managed wallets are useful for treasury wallets, fee payers, or system operations.

## Key Management

Better Wallet never stores private keys in plain form. Instead, keys are protected using **2-of-2 Shamir's Secret Sharing**.

### Key Splitting

When a wallet is created:

1. Private key is generated using CSPRNG
2. Key is split into 2 shares using Shamir's Secret Sharing
3. Shares are stored separately:
   - **Auth Share**: Encrypted with KMS and stored in PostgreSQL
   - **Exec Share**: Managed by the execution backend (KMS or TEE)

```
┌─────────────────┐
│  Private Key    │
│  (generated)    │
└────────┬────────┘
         │ Split (2-of-2)
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│ Auth  │ │ Exec  │
│ Share │ │ Share │
└───┬───┘ └───┬───┘
    │         │
    ▼         ▼
┌───────┐ ┌───────┐
│  PG   │ │ KMS/  │
│(enc.) │ │ TEE   │
└───────┘ └───────┘
```

### Signing Process

During signing:

1. Auth share is retrieved and decrypted
2. Exec share is retrieved from KMS/TEE
3. Shares are combined to reconstruct the private key
4. Transaction is signed
5. Private key is immediately cleared from memory

This ensures the full private key only exists briefly during signing operations.

## Execution Backends

### KMS Backend (Default)

Uses external key management services for share encryption:

| Provider | Description |
|----------|-------------|
| `local` | Local AES-GCM encryption (development) |
| `aws-kms` | AWS Key Management Service |
| `vault` | HashiCorp Vault Transit engine |

Best for: Self-hosted deployments with existing KMS infrastructure.

### TEE Backend

Uses Trusted Execution Environments for maximum security:

| Platform | Description |
|----------|-------------|
| `dev` | Development mode (TCP) |
| `aws-nitro` | AWS Nitro Enclaves |

Best for: High-security requirements where keys should never exist in main memory.

## Authorization Keys

An **authorization key** is a P-256 public key used to sign requests for high-risk operations.

### When Authorization is Required

- Updating wallet ownership
- Modifying policies
- Deleting wallets or policies
- Transferring wallet ownership

### Authorization Flow

```
┌──────────────┐     ┌─────────────────────────────┐
│ Your Server  │     │     Better Wallet API       │
└──────┬───────┘     └─────────────┬───────────────┘
       │                           │
       │  1. Create auth key       │
       │  (P-256 keypair)          │
       │                           │
       │  2. Register public key   │
       │──────────────────────────▶│
       │                           │
       │  3. For high-risk ops:    │
       │     Sign canonical payload│
       │                           │
       │  4. Send request +        │
       │     X-Authorization-Sig   │
       │──────────────────────────▶│
       │                           │
       │                           │ 5. Verify signature
       │                           │
       │  6. Operation executed    │
       │◀──────────────────────────│
       │                           │
```

See [Authorization Signatures](../authentication/authorization-signatures.md) for implementation details.

## Key Quorums

A **key quorum** enables M-of-N threshold signatures for high-value operations.

### Example: 2-of-3 Quorum

```json
{
  "id": "quorum-uuid",
  "threshold": 2,
  "key_ids": [
    "auth-key-1-uuid",
    "auth-key-2-uuid",
    "auth-key-3-uuid"
  ]
}
```

Any 2 of the 3 authorization keys must sign to authorize an operation.

### Use Cases

| Scenario | Configuration |
|----------|---------------|
| Dual-control treasury | 2-of-2 |
| Team wallet | 2-of-3 |
| Enterprise approval | 3-of-5 |

## Policies

A **policy** defines rules that control what operations a wallet can perform.

### Default-Deny Model

Better Wallet uses default-deny security:
- If no rule explicitly allows an operation, it is denied
- Rules are evaluated in order; first match wins

### Policy Structure

```json
{
  "version": "1.0",
  "name": "Limited transfers",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow small transfers to trusted addresses",
      "method": "eth_sendTransaction",
      "conditions": [
        {
          "field_source": "ethereum_transaction",
          "field": "value",
          "operator": "lte",
          "value": "1000000000000000000"
        },
        {
          "field_source": "ethereum_transaction",
          "field": "to",
          "operator": "in_condition_set",
          "value": "trusted-addresses-set-id"
        }
      ],
      "action": "ALLOW"
    },
    {
      "name": "Deny all other transactions",
      "method": "*",
      "conditions": [],
      "action": "DENY"
    }
  ]
}
```

### Field Sources

Policies can evaluate data from different sources:

| Field Source | Description |
|--------------|-------------|
| `ethereum_transaction` | Raw transaction fields (to, value, data) |
| `ethereum_calldata` | Decoded contract function calls |
| `ethereum_typed_data_domain` | EIP-712 domain fields |
| `ethereum_typed_data_message` | EIP-712 message fields |
| `ethereum_message` | Personal message content |
| `system` | System fields (timestamp) |

See [Policy Engine](../policies/overview.md) for complete documentation.

## Session Signers

A **session signer** is a temporary, scoped signing capability delegated by a wallet owner.

### Session Signer Properties

| Property | Description |
|----------|-------------|
| `signer_id` | Identifier for this session |
| `wallet_id` | Wallet this session can sign for |
| `ttl_expires_at` | When the session expires |
| `policy_override_id` | Optional policy that overrides wallet policies |
| `max_value` | Maximum transaction value allowed |
| `max_txs` | Maximum number of transactions allowed |
| `allowed_methods` | Restricted signing methods |

### Use Cases

| Scenario | Configuration |
|----------|---------------|
| **Game session** | 1-hour TTL, small value limit |
| **Trading bot** | 24-hour TTL, specific contract only |
| **Telegram bot** | Policy override, revocable |
| **Batch mint** | Limited tx count, specific method |

### Session Flow

```
1. User creates wallet with owner key
2. User creates session signer with limits
3. Your backend signs using session signer ID
4. Session signer policies + limits enforced
5. Session expires or is revoked
```

See [Session Signers](../session-signers/overview.md) for implementation.

## Condition Sets

A **condition set** is a reusable collection of values for policy conditions.

### Example: Trusted Addresses

```json
{
  "id": "trusted-addresses-uuid",
  "name": "Trusted DEX Contracts",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0x1111111254EEB25477B68fb85Ed929f73A960582",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564"
  ]
}
```

Use in policy:
```json
{
  "field_source": "ethereum_transaction",
  "field": "to",
  "operator": "in_condition_set",
  "value": "trusted-addresses-uuid"
}
```

Benefits:
- Reuse across multiple policies
- Update once, apply everywhere
- Easier auditing

## Users

A **user** maps external identity (JWT `sub` claim) to Better Wallet's internal user ID.

### User Creation

Users are created automatically when:
- A JWT with a new `sub` claim authenticates
- Or explicitly via the API

### User Properties

```json
{
  "id": "internal-uuid",
  "external_sub": "auth0|123456789",
  "created_at": "2025-01-01T00:00:00Z"
}
```

## Audit Logs

Every operation is recorded in the **audit log** for compliance and debugging.

### Audit Entry Fields

| Field | Description |
|-------|-------------|
| `actor` | Who performed the action (user sub) |
| `action` | What was done (create_wallet, sign_tx) |
| `resource_type` | Type of resource (wallet, policy) |
| `resource_id` | ID of affected resource |
| `policy_result` | ALLOW/DENY and reason |
| `tx_hash` | Transaction hash (if applicable) |
| `request_digest` | Hash of request for verification |

### Example Query

```bash
curl "http://localhost:8080/v1/audit?resource_type=wallet&resource_id=WALLET_ID" \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Concept Relationships

```
┌─────────────┐     owns      ┌──────────────────┐
│    User     │──────────────▶│      Wallet      │
└─────────────┘               └────────┬─────────┘
                                       │
                              ┌────────┴─────────┐
                              │                  │
                              ▼                  ▼
                    ┌──────────────┐    ┌──────────────┐
                    │   Policies   │    │Authorization │
                    │   (rules)    │    │    Key       │
                    └──────────────┘    └──────────────┘
                              │                  │
                              │                  ▼
                              │         ┌──────────────┐
                              │         │ Key Quorum   │
                              │         │   (M-of-N)   │
                              │         └──────────────┘
                              │
                              ▼
                    ┌──────────────┐    ┌──────────────┐
                    │ Condition    │    │   Session    │
                    │    Sets      │◀───│   Signers    │
                    └──────────────┘    └──────────────┘
```

## Next Steps

Now that you understand the core concepts:

1. **[Architecture Overview](./architecture-overview.md)** - Deep dive into system design
2. **[First Integration](./first-integration.md)** - Build your first application
3. **[Authentication](../authentication/overview.md)** - Set up authentication
4. **[Policies](../policies/overview.md)** - Configure access control
