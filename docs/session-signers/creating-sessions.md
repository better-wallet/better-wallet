# Creating Session Signers

Detailed guide to creating and configuring session signers.

## Prerequisites

Before creating a session signer, you need:

1. **A wallet with an owner** (authorization key or quorum)
2. **A registered authorization key** for the signer
3. **Owner's signature** authorizing the session creation

---

## Basic Session Creation

### Step 1: Register Signer's Authorization Key

```bash
# Generate key pair for the session signer
openssl ecparam -name prime256v1 -genkey -noout -out signer_key.pem
openssl ec -in signer_key.pem -pubout -outform DER | tail -c 65 | base64 > signer_pub.b64

# Register the public key
SIGNER_KEY=$(curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "'$(cat signer_pub.b64)'",
    "algorithm": "p256",
    "owner_entity": "trading-bot-server"
  }')

SIGNER_KEY_ID=$(echo $SIGNER_KEY | jq -r '.id')
```

### Step 2: Create Authorization Signature

```bash
# Build canonical payload
IDEMPOTENCY_KEY=$(uuidgen)
BODY=$(cat <<EOF
{"expires_at":"2025-01-22T10:00:00Z","signer_id":"$SIGNER_KEY_ID","wallet_id":"$WALLET_ID"}
EOF
)

# Sort JSON keys for canonical form
CANONICAL_BODY=$(echo $BODY | jq -Sc '.')

PAYLOAD="1.0POST/v1/wallets/${WALLET_ID}/session_signers${CANONICAL_BODY}${APP_ID}${IDEMPOTENCY_KEY}"

# Sign with wallet owner's key
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign owner_key.pem | base64)
```

### Step 3: Create Session Signer

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "signer_id": "'$SIGNER_KEY_ID'",
    "expires_at": "2025-01-22T10:00:00Z"
  }'
```

---

## Configuration Options

### Time-Limited Session

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z"
}
```

### Value-Limited Session

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000"
}
```

`max_value` is the cumulative limit across all transactions in wei.

### Transaction-Count Limited

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_txs": 100
}
```

### With Policy Override

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "policy_override_id": "restrictive-policy-uuid"
}
```

### Fully Configured Session

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100,
  "policy_override_id": "bot-policy-uuid"
}
```

---

## Expiration Strategies

### Short-Lived (Interactive)

For user sessions, browser extensions:

```json
{
  "expires_at": "2025-01-15T11:00:00Z"  // 1 hour
}
```

### Medium-Term (Automated Tasks)

For daily batch jobs, scheduled tasks:

```json
{
  "expires_at": "2025-01-16T10:00:00Z"  // 24 hours
}
```

### Long-Running (Persistent Services)

For always-on services, trading bots:

```json
{
  "expires_at": "2025-01-22T10:00:00Z"  // 1 week
}
```

### Best Practice

```javascript
// Calculate expiration based on use case
function getExpiration(duration) {
  const now = new Date();
  now.setSeconds(now.getSeconds() + duration);
  return now.toISOString();
}

// Examples
const oneHour = getExpiration(3600);
const oneDay = getExpiration(86400);
const oneWeek = getExpiration(604800);
```

---

## Response Format

```json
{
  "id": "770e9400-f29b-41d4-b716-557766550000",
  "wallet_id": "550e8400-e29b-41d4-a716-446655440000",
  "signer_id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100,
  "used_value": "0",
  "used_txs": 0,
  "policy_override_id": "policy-uuid",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z"
}
```

---

## Programmatic Creation

### Node.js Example

```javascript
const crypto = require('crypto');

async function createSessionSigner(
  walletId,
  signerKeyId,
  ownerPrivateKey,
  ownerKeyId,
  options = {}
) {
  const idempotencyKey = crypto.randomUUID();

  // Build request body (wallet_id is in URL path)
  const body = {
    signer_id: signerKeyId,
    expires_at: options.expiresAt || getDefaultExpiration(),
  };

  if (options.maxValue) body.max_value = options.maxValue;
  if (options.maxTxs) body.max_txs = options.maxTxs;
  if (options.policyOverrideId) body.policy_override_id = options.policyOverrideId;

  // Create canonical payload
  const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
  const payload = `1.0POST/v1/wallets/${walletId}/session_signers${canonicalBody}${APP_ID}${idempotencyKey}`;

  // Sign with owner's key
  const sign = crypto.createSign('SHA256');
  sign.update(payload);
  const signature = sign.sign(ownerPrivateKey, 'base64');

  // Create session
  const response = await fetch(`${API_URL}/v1/wallets/${walletId}/session_signers`, {
    method: 'POST',
    headers: {
      'X-App-Id': APP_ID,
      'X-App-Secret': APP_SECRET,
      'Authorization': `Bearer ${userToken}`,
      'X-Authorization-Signature': signature,
      'X-Authorization-Key-Id': ownerKeyId,
      'X-Idempotency-Key': idempotencyKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(body),
  });

  return response.json();
}
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `wallet_not_found` | Invalid wallet ID | Verify wallet exists |
| `not_owner` | Signer doesn't own wallet | Use owner's signature |
| `signer_not_found` | Signer key not registered | Register key first |
| `invalid_expiration` | Expiration in the past | Use future timestamp |
| `invalid_signature` | Bad authorization signature | Check payload format |
| `session_exists` | Active session for signer | Revoke existing first |

---

## Idempotency

Always use idempotency keys:

```bash
IDEM_KEY="create-session-${WALLET_ID}-${SIGNER_KEY_ID}-$(date +%Y%m%d)"
```

Same idempotency key with same body returns existing session.
