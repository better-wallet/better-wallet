# Wallets Overview

Wallets are the core resource in Better Wallet. Each wallet represents a blockchain account with a securely managed private key. This guide covers wallet creation, management, and ownership.

## What is a Wallet?

A Better Wallet wallet is:

- A **blockchain account** with an address and private key
- Protected by **2-of-2 key splitting** (auth share + exec share)
- Controlled by **policies** that define allowed operations
- Optionally owned by an **authorization key** or **key quorum**

```
┌─────────────────────────────────────────────────────────────┐
│                        Wallet                                │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  id: "550e8400-e29b-41d4-a716-446655440000"         │   │
│  │  address: "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"│   │
│  │  chain_type: "ethereum"                              │   │
│  │  exec_backend: "kms"                                 │   │
│  └─────────────────────────────────────────────────────┘   │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │   Auth Share    │  │   Exec Share    │                 │
│  │  (PostgreSQL)   │  │   (KMS/TEE)     │                 │
│  └─────────────────┘  └─────────────────┘                 │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                 │
│  │    Policies     │  │     Owner       │                 │
│  │  (access rules) │  │  (auth key/     │                 │
│  │                 │  │   quorum)       │                 │
│  └─────────────────┘  └─────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

## Wallet Types

### User Wallets

Associated with an end user (via JWT `sub` claim):

```json
{
  "id": "wallet-uuid",
  "user_id": "user-uuid",
  "owner_id": "auth-key-uuid",
  "chain_type": "ethereum",
  "address": "0x..."
}
```

**Characteristics:**
- Tied to a specific user
- User's JWT required for operations
- Can have owner (authorization key) for high-risk ops

### App-Managed Wallets

Controlled by your application without a specific user:

```json
{
  "id": "wallet-uuid",
  "user_id": null,
  "owner_id": null,
  "chain_type": "ethereum",
  "address": "0x..."
}
```

**Characteristics:**
- No user association
- App controls via app credentials
- Ideal for treasury, fee payers, system wallets

## Creating Wallets

### Basic Wallet Creation

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user-uuid",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": null,
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Parameters

| Parameter | Type | Description | Required |
|-----------|------|-------------|----------|
| `chain_type` | string | Blockchain type | Yes |
| `exec_backend` | string | Execution backend (`kms`, `tee`) | Yes |
| `owner_id` | UUID | Authorization key or quorum ID | No |

### Supported Chains

| Chain Type | Status | Address Format |
|------------|--------|----------------|
| `ethereum` | Production | `0x` + 40 hex chars |
| `solana` | Planned | Base58 |
| `bitcoin` | Planned | Various formats |

### Execution Backends

| Backend | Description | Use Case |
|---------|-------------|----------|
| `kms` | Key shares encrypted with KMS | Default, self-hosted |
| `tee` | Key operations in Nitro Enclave | High-security |

## Wallet with Owner

Create a wallet with an authorization key owner:

```bash
# First, register an authorization key
AUTH_KEY=$(curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "..." \
  -d '{"public_key": "BASE64...", "algorithm": "p256"}')

AUTH_KEY_ID=$(echo $AUTH_KEY | jq -r '.id')

# Create wallet with owner
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "..." \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "'$AUTH_KEY_ID'"
  }'
```

With an owner, you can:
- Transfer wallet ownership
- Create session signers
- Perform other high-risk operations

## Listing Wallets

### List All Wallets

```bash
curl "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "wallets": [
    {
      "id": "550e8400-...",
      "chain_type": "ethereum",
      "address": "0x742d35Cc...",
      "exec_backend": "kms",
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Filtering

```bash
# By chain type
curl "http://localhost:8080/v1/wallets?chain_type=ethereum"

# With pagination
curl "http://localhost:8080/v1/wallets?limit=10&offset=20"
```

## Getting Wallet Details

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user-uuid",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": "auth-key-uuid",
  "policies": [
    {
      "id": "policy-uuid",
      "name": "Default trading policy"
    }
  ],
  "created_at": "2025-01-15T10:00:00Z"
}
```

## Attaching Policies

Link a policy to control wallet operations:

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "policy-uuid"
  }'
```

### Multiple Policies

A wallet can have multiple policies. **All policies must allow** an operation:

```
Wallet policies: [PolicyA, PolicyB, PolicyC]

Transaction Request
     │
     ├─▶ PolicyA: ALLOW
     │
     ├─▶ PolicyB: ALLOW
     │
     ├─▶ PolicyC: DENY ──▶ DENIED (PolicyC rejected)
     │
     └─▶ If all ALLOW ──▶ ALLOWED
```

## Detaching Policies

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/policies/$POLICY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

## Wallet Ownership

### Why Ownership Matters

Wallets with owners require authorization signatures for:
- Transferring ownership
- Creating session signers
- Deleting the wallet

### Transfer Ownership

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $CURRENT_OWNER_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "new_owner_id": "new-auth-key-uuid"
  }'
```

The current owner must sign the request.

### Quorum Ownership

For multi-sig control, use a key quorum:

```bash
# Create quorum
QUORUM=$(curl -X POST "http://localhost:8080/v1/key-quorums" \
  -H "..." \
  -d '{
    "threshold": 2,
    "key_ids": ["key-1-uuid", "key-2-uuid", "key-3-uuid"]
  }')

# Create wallet with quorum owner
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "..." \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "'$(echo $QUORUM | jq -r '.id')'"
  }'
```

High-risk operations require M-of-N signatures.

## Deleting Wallets

**Warning**: Deleting a wallet permanently destroys the key material.

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_ID"
```

### What Gets Deleted

- Wallet record
- All key shares (auth + exec)
- Policy attachments
- Session signers
- Audit records are **retained**

## Wallet Lifecycle

```
┌─────────────────────────────────────────────────────────────┐
│                        CREATE                                │
│  • Generate keypair                                          │
│  • Split into shares                                         │
│  • Store encrypted shares                                    │
│  • Return address                                            │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        ACTIVE                                │
│  • Attach policies                                           │
│  • Sign transactions                                         │
│  • Create session signers                                    │
│  • Transfer ownership                                        │
└─────────────────────────────┬───────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                        DELETE                                │
│  • Destroy all shares                                        │
│  • Remove from database                                      │
│  • Retain audit trail                                        │
└─────────────────────────────────────────────────────────────┘
```

## Best Practices

### 1. Always Set an Owner for Production Wallets

```json
{
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "owner_id": "auth-key-uuid"
}
```

### 2. Attach Restrictive Policies

```bash
# Create and attach a policy immediately
POLICY=$(curl -X POST "http://localhost:8080/v1/policies" ...)
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/policies" \
  -d '{"policy_id": "'$(echo $POLICY | jq -r '.id')'"}'
```

### 3. Use Idempotency Keys

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-Idempotency-Key: create-wallet-user123-$(date +%s)" \
  ...
```

### 4. Use TEE for High-Value Wallets

```json
{
  "chain_type": "ethereum",
  "exec_backend": "tee"
}
```

## Error Handling

| Error Code | Meaning | Resolution |
|------------|---------|------------|
| `wallet_not_found` | Wallet doesn't exist | Check wallet ID |
| `wallet_already_exists` | Duplicate idempotency key | Use new key or same request |
| `invalid_chain_type` | Unsupported chain | Use supported chain |
| `invalid_exec_backend` | Unknown backend | Use `kms` or `tee` |
| `owner_not_found` | Owner key doesn't exist | Register key first |
| `not_authorized` | User doesn't own wallet | Check JWT sub |

## Next Steps

- [Creating Wallets](./creating-wallets.md) - Detailed creation guide
- [Managing Wallets](./managing-wallets.md) - List, update, delete
- [Wallet Ownership](./wallet-ownership.md) - Authorization keys and quorums
- [Signing](../signing/overview.md) - Sign transactions
- [Policies](../policies/overview.md) - Access control
