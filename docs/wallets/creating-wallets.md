# Creating Wallets

Detailed guide to creating wallets with various configurations.

## Basic Wallet Creation

### Simple User Wallet

Create a wallet for the authenticated user:

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'
```

The wallet is automatically associated with the user from the JWT `sub` claim.

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user-uuid-from-jwt-sub",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": null,
  "created_at": "2025-01-15T10:00:00Z"
}
```

---

## Wallet with Owner

Create a wallet controlled by an authorization key:

### Step 1: Register Authorization Key

```bash
# Generate P-256 key pair
openssl ecparam -name prime256v1 -genkey -noout -out owner_key.pem
openssl ec -in owner_key.pem -pubout -outform DER | tail -c 65 | base64 > owner_pub.b64

# Register the public key
curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "'$(cat owner_pub.b64)'",
    "algorithm": "p256",
    "owner_entity": "user-device-1"
  }'
```

### Step 2: Create Wallet with Owner

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "AUTH_KEY_UUID"
  }'
```

### Benefits of Ownership

| Operation | Without Owner | With Owner |
|-----------|---------------|------------|
| Sign transactions | ✅ JWT only | ✅ JWT only |
| Create session signers | ❌ Not available | ✅ Requires signature |
| Transfer ownership | ❌ Not available | ✅ Requires signature |
| Delete wallet | ✅ JWT only | ✅ Requires signature |

---

## Wallet with Quorum Owner

For multi-signature control, use a key quorum:

### Step 1: Register Multiple Keys

```bash
# Register 3 authorization keys (for each signer)
for i in 1 2 3; do
  curl -X POST "http://localhost:8080/v1/authorization-keys" \
    -H "..." \
    -d '{
      "public_key": "'$(cat signer${i}_pub.b64)'",
      "algorithm": "p256",
      "owner_entity": "signer-'$i'"
    }'
done
```

### Step 2: Create Quorum

```bash
curl -X POST "http://localhost:8080/v1/key-quorums" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Treasury Quorum",
    "threshold": 2,
    "member_ids": ["key-uuid-1", "key-uuid-2", "key-uuid-3"]
  }'
```

### Step 3: Create Wallet with Quorum

```bash
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Idempotency-Key: $(uuidgen)" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "QUORUM_UUID"
  }'
```

High-risk operations now require 2-of-3 signatures.

---

## Execution Backend Selection

### KMS Backend (Default)

```json
{
  "chain_type": "ethereum",
  "exec_backend": "kms"
}
```

**Key characteristics:**
- Key shares encrypted with KMS (AWS KMS, Vault, or local)
- Keys reconstructed in server memory during signing
- Suitable for most use cases

### TEE Backend

```json
{
  "chain_type": "ethereum",
  "exec_backend": "tee"
}
```

**Key characteristics:**
- Keys reconstructed only inside Nitro Enclave
- Parent instance never sees complete key
- Higher security for high-value wallets
- Requires AWS Nitro Enclave infrastructure

### Choosing a Backend

| Factor | KMS | TEE |
|--------|-----|-----|
| Setup complexity | Low | High |
| Infrastructure cost | Low | Medium |
| Key exposure risk | Server memory | Enclave only |
| Performance | Faster | Slightly slower |
| Cloud requirement | Any | AWS Nitro only |

---

## Idempotency

Always use idempotency keys for wallet creation:

```bash
# Same idempotency key = same wallet returned
IDEM_KEY="create-wallet-user123-$(date +%Y%m%d)"

curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-Idempotency-Key: $IDEM_KEY" \
  ...
```

### Idempotency Behavior

| Scenario | Result |
|----------|--------|
| First request | Creates wallet, returns 201 |
| Same key, same body | Returns existing wallet, 200 |
| Same key, different body | Returns error, 409 |
| Different key | Creates new wallet, 201 |

---

## Batch Creation

Create multiple wallets efficiently:

```javascript
async function createWallets(userToken, count) {
  const promises = [];

  for (let i = 0; i < count; i++) {
    promises.push(
      fetch('/v1/wallets', {
        method: 'POST',
        headers: {
          'X-App-Id': APP_ID,
          'X-App-Secret': APP_SECRET,
          'Authorization': `Bearer ${userToken}`,
          'X-Idempotency-Key': `batch-${Date.now()}-${i}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          chain_type: 'ethereum',
          exec_backend: 'kms',
        }),
      })
    );
  }

  return Promise.all(promises);
}
```

---

## Post-Creation Setup

### Attach Policy Immediately

```bash
# Create wallet
WALLET=$(curl -X POST "http://localhost:8080/v1/wallets" ...)
WALLET_ID=$(echo $WALLET | jq -r '.id')

# Attach restrictive policy
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/policies" \
  -H "..." \
  -d '{"policy_id": "default-policy-uuid"}'
```

### Fund the Wallet

After creation, the wallet needs ETH for gas:

```javascript
// Get wallet address
const wallet = await createWallet(userToken);

// Fund from faucet (testnet) or treasury (mainnet)
await fundWallet(wallet.address, '0.1'); // 0.1 ETH
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `invalid_chain_type` | Unsupported chain | Use `ethereum` |
| `invalid_exec_backend` | Unknown backend | Use `kms` or `tee` |
| `owner_not_found` | Owner key doesn't exist | Register key first |
| `duplicate_key` | Idempotency key reused with different body | Use new key |
| `tee_unavailable` | TEE backend not configured | Use `kms` or configure TEE |

---

## Best Practices

1. **Always use idempotency keys** to prevent duplicate wallets
2. **Set an owner** for production wallets requiring high-risk operations
3. **Attach policies immediately** after creation
4. **Use TEE** for high-value wallets (treasury, etc.)
5. **Document wallet purposes** using owner_entity field on auth keys
