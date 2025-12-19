# Wallet Ownership

Deep dive into wallet ownership, authorization keys, quorums, and ownership transfer.

## Understanding Ownership

### What is a Wallet Owner?

A wallet owner is an entity that can authorize high-risk operations:

- **Authorization Key**: Single P-256 key for signing
- **Key Quorum**: M-of-N threshold signature group

```
┌─────────────────────────────────────────────────────────────┐
│                         Wallet                               │
│  owner_id: "auth-key-uuid" or "quorum-uuid"                 │
└─────────────────────────────┬───────────────────────────────┘
                              │
              ┌───────────────┴───────────────┐
              ▼                               ▼
┌─────────────────────────┐     ┌─────────────────────────┐
│   Authorization Key     │     │      Key Quorum         │
│   (Single Signer)       │     │     (M-of-N Signers)    │
│                         │     │                         │
│   • 1 signature needed  │     │   • M signatures needed │
│   • Simpler management  │     │   • Distributed control │
│   • Single point of     │     │   • No single point of  │
│     failure             │     │     failure             │
└─────────────────────────┘     └─────────────────────────┘
```

### Owned vs Unowned Wallets

| Feature | Unowned | Owned |
|---------|---------|-------|
| Sign transactions | ✅ | ✅ |
| Sign messages | ✅ | ✅ |
| Create session signers | ❌ | ✅ |
| Transfer ownership | ❌ | ✅ |
| Delete wallet | ✅ (JWT only) | ✅ (requires signature) |

---

## Setting Initial Owner

### At Creation Time

```bash
# First, register an authorization key
AUTH_KEY=$(curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "BASE64_ENCODED_P256_PUBLIC_KEY",
    "algorithm": "p256",
    "owner_entity": "user-primary-key"
  }')

AUTH_KEY_ID=$(echo $AUTH_KEY | jq -r '.id')

# Create wallet with owner
curl -X POST "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms",
    "owner_id": "'$AUTH_KEY_ID'"
  }'
```

### After Creation (Assign Owner)

```bash
# Build canonical payload
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/owner{\"owner_id\":\"$AUTH_KEY_ID\"}$APP_ID$IDEMPOTENCY_KEY"

# Sign with the key that will become owner
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign new_owner.pem | base64)

# Assign owner
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "owner_id": "'$AUTH_KEY_ID'"
  }'
```

---

## Transferring Ownership

### Single Owner Transfer

Transfer from one authorization key to another:

```bash
# Build canonical payload
BODY='{"new_owner_id":"'$NEW_OWNER_KEY_ID'"}'
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/transfer-ownership${BODY}$APP_ID$IDEMPOTENCY_KEY"

# Current owner signs the transfer
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign current_owner.pem | base64)

# Execute transfer
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/transfer-ownership" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $CURRENT_OWNER_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d "$BODY"
```

### Transfer to Quorum

Transfer from single key to multi-sig quorum:

```bash
# Create quorum first
QUORUM=$(curl -X POST "http://localhost:8080/v1/key-quorums" \
  -H "..." \
  -d '{
    "name": "Wallet Quorum",
    "threshold": 2,
    "member_ids": ["key-1", "key-2", "key-3"]
  }')

QUORUM_ID=$(echo $QUORUM | jq -r '.id')

# Transfer to quorum
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/transfer-ownership" \
  -H "X-Authorization-Signature: $CURRENT_OWNER_SIGNATURE" \
  -H "X-Authorization-Key-Id: $CURRENT_OWNER_KEY_ID" \
  -H "..." \
  -d '{"new_owner_id": "'$QUORUM_ID'"}'
```

### Quorum Owner Transfer

When a quorum owns the wallet, transfers require M signatures:

```bash
# Build canonical payload
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/transfer-ownership..."

# Collect M signatures from quorum members
SIG1=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member1.pem | base64)
SIG2=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign member2.pem | base64)

# Execute transfer with multiple signatures
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/transfer-ownership" \
  -H "X-Authorization-Signatures: [\"$SIG1\",\"$SIG2\"]" \
  -H "X-Authorization-Key-Ids: [\"$KEY_ID_1\",\"$KEY_ID_2\"]" \
  -H "..." \
  -d '{"new_owner_id": "'$NEW_OWNER_ID'"}'
```

---

## Key Quorums

### Creating a Quorum

```bash
curl -X POST "http://localhost:8080/v1/key-quorums" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Treasury Quorum",
    "threshold": 2,
    "member_ids": [
      "cfo-auth-key-uuid",
      "cto-auth-key-uuid",
      "ceo-auth-key-uuid"
    ]
  }'
```

### Quorum Configurations

| Configuration | Use Case |
|---------------|----------|
| 2-of-3 | Standard corporate wallet |
| 3-of-5 | High-security treasury |
| 2-of-2 | Dual control |
| 1-of-N | Any authorized signer |

### Signing with Quorum

Operations on quorum-owned wallets require M signatures:

```javascript
async function signWithQuorum(walletId, operation, quorumMembers) {
  const payload = buildCanonicalPayload(operation);

  // Collect signatures from M members
  const signatures = [];
  const keyIds = [];

  for (const member of quorumMembers) {
    const sig = await member.sign(payload);
    signatures.push(sig);
    keyIds.push(member.keyId);
  }

  // Submit with all signatures
  return fetch(`/v1/wallets/${walletId}/...`, {
    headers: {
      'X-Authorization-Signatures': JSON.stringify(signatures),
      'X-Authorization-Key-Ids': JSON.stringify(keyIds),
      ...
    }
  });
}
```

---

## Authorization Signature Format

### Canonical Payload

```
version + method + path + canonical_json_body + app_id + idempotency_key
```

Example:
```
1.0POST/v1/wallets/uuid/transfer-ownership{"new_owner_id":"key-uuid"}app-uuid-123idempotency-key-456
```

### Signature Generation

```javascript
const crypto = require('crypto');

function createAuthSignature(
  method,
  path,
  body,
  appId,
  idempotencyKey,
  privateKeyPem
) {
  // Canonical JSON (sorted keys)
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());

  // Build payload
  const payload = `1.0${method}${path}${canonicalBody}${appId}${idempotencyKey}`;

  // Sign with P-256
  const sign = crypto.createSign('SHA256');
  sign.update(payload);
  return sign.sign(privateKeyPem, 'base64');
}
```

---

## Renouncing Ownership

Remove owner to make wallet unowned:

```bash
# Current owner signs renunciation
PAYLOAD="1.0DELETE/v1/wallets/$WALLET_ID/owner{}$APP_ID$IDEMPOTENCY_KEY"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign owner.pem | base64)

curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID" \
  -H "..."
```

**Warning**: After renouncing ownership:
- Cannot create session signers
- Cannot transfer ownership back
- Wallet deletion only requires JWT

---

## Security Considerations

### Key Storage

| Storage Method | Security | Convenience |
|----------------|----------|-------------|
| Hardware security module (HSM) | Highest | Low |
| Secure enclave (mobile) | High | Medium |
| Encrypted file | Medium | Medium |
| Environment variable | Low | High |

### Best Practices

1. **Use quorums for high-value wallets**
   - No single point of failure
   - Requires compromise of multiple keys

2. **Separate key storage**
   - Store quorum member keys in different locations
   - Use different security mechanisms

3. **Regular key rotation**
   - Transfer to new keys periodically
   - Revoke old keys after transfer

4. **Audit ownership changes**
   - Monitor `wallet.ownership_transferred` events
   - Alert on unexpected transfers

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `not_authorized` | Invalid owner signature | Verify signing key |
| `insufficient_signatures` | Not enough quorum signatures | Collect M signatures |
| `invalid_signature` | Signature verification failed | Check payload format |
| `owner_not_found` | Owner key doesn't exist | Verify key is registered |
| `quorum_not_found` | Quorum doesn't exist | Create quorum first |

---

## Ownership Audit Trail

All ownership operations are logged:

```json
{
  "event_type": "wallet.ownership_transferred",
  "wallet_id": "wallet-uuid",
  "details": {
    "previous_owner_id": "old-key-uuid",
    "new_owner_id": "new-key-uuid",
    "authorized_by": ["key-uuid-1", "key-uuid-2"]
  },
  "created_at": "2025-01-15T10:00:00Z"
}
```
