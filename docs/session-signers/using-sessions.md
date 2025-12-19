# Using Session Signers

Guide to signing transactions with session signers.

## Overview

Once a session signer is created, the signer key can authorize transactions on behalf of the wallet without requiring the owner's signature for each operation.

---

## Signing with a Session

### Basic Transaction Signing

```bash
# Generate signature with session signer's key
IDEMPOTENCY_KEY=$(uuidgen)
BODY='{"to":"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb","value":"1000000000000000000","chain_id":1}'
CANONICAL_BODY=$(echo $BODY | jq -Sc '.')

PAYLOAD="1.0POST/v1/wallets/${WALLET_ID}/sign-transaction${CANONICAL_BODY}${APP_ID}${IDEMPOTENCY_KEY}"

# Sign with SESSION SIGNER's key (not owner's key)
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign signer_key.pem | base64)

# Submit transaction
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/sign-transaction" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $SIGNER_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d "$BODY"
```

### Response

```json
{
  "signed_transaction": "0x02f87001...",
  "transaction_hash": "0xabc123..."
}
```

---

## Session vs Owner Signing

| Aspect | Owner Signing | Session Signing |
|--------|--------------|-----------------|
| Key used | Wallet owner's key | Session signer's key |
| Header | `X-Authorization-Key-Id: owner-key-id` | `X-Authorization-Key-Id: signer-key-id` |
| Policy | Wallet policies | Override policy (if set) |
| Limits | No built-in limits | TTL, max_value, max_txs |
| Revocable | No | Yes |

---

## Authentication Flow

```
Session Signer Request
        │
        ▼
┌───────────────────┐
│ Verify Signature  │ ← Using signer's public key
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Find Session      │ ← Match signer_id + wallet_id
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Check Session     │ ← Status, expiration, limits
│ Validity          │
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Evaluate Policy   │ ← Override or wallet policies
└───────────────────┘
        │
        ▼
┌───────────────────┐
│ Sign Transaction  │ ← If all checks pass
└───────────────────┘
```

---

## Operations Available to Session Signers

### Transaction Signing

```bash
POST /v1/wallets/{wallet_id}/sign-transaction
```

Session signers can sign transactions within their configured limits.

### Message Signing

```bash
POST /v1/wallets/{wallet_id}/sign-message
```

Sign personal messages (EIP-191) if policy allows.

### Typed Data Signing

```bash
POST /v1/wallets/{wallet_id}/sign-typed-data
```

Sign EIP-712 typed data (permits, orders) if policy allows.

---

## Handling Session Limits

### Before Signing

Check remaining budget before attempting transactions:

```javascript
async function checkSessionBudget(walletId, sessionId, txValue) {
  // List session signers for the wallet and find this session
  const sessions = await fetch(`/v1/wallets/${walletId}/session_signers`, {
    headers: { ... }
  }).then(r => r.json());

  const session = sessions.session_signers?.find(s => s.id === sessionId);

  // Check if session is still valid
  if (session.status !== 'active') {
    throw new Error(`Session is ${session.status}`);
  }

  // Check expiration
  if (new Date(session.expires_at) < new Date()) {
    throw new Error('Session has expired');
  }

  // Check transaction count
  if (session.max_txs && session.used_txs >= session.max_txs) {
    throw new Error('Transaction limit reached');
  }

  // Check value budget
  if (session.max_value) {
    const remaining = BigInt(session.max_value) - BigInt(session.used_value);
    if (BigInt(txValue) > remaining) {
      throw new Error(`Insufficient value budget: ${remaining} wei remaining`);
    }
  }

  return session;
}
```

### After Signing

Counters are automatically updated:

```json
{
  "id": "session-uuid",
  "used_value": "1000000000000000000",
  "used_txs": 1,
  "status": "active"
}
```

---

## Error Handling

### Session Errors

| Error Code | Cause | Solution |
|------------|-------|----------|
| `session_not_found` | Invalid session or signer | Verify session exists |
| `session_expired` | Past `expires_at` | Create new session |
| `session_revoked` | Session was revoked | Create new session |
| `session_exhausted` | Limits reached | Create new session |
| `session_value_exceeded` | Transaction exceeds budget | Reduce value or new session |
| `session_limit_exceeded` | Transaction count limit | Create new session |

### Policy Errors

| Error Code | Cause | Solution |
|------------|-------|----------|
| `policy_denied` | Policy rejected transaction | Check policy rules |
| `invalid_signature` | Bad authorization signature | Verify signing process |

### Example Error Response

```json
{
  "error": {
    "code": "session_value_exceeded",
    "message": "Transaction value exceeds session limit",
    "details": {
      "requested_value": "5000000000000000000",
      "remaining_value": "2000000000000000000",
      "session_id": "session-uuid"
    }
  }
}
```

---

## Programmatic Usage

### Node.js Session Signer Client

```javascript
const crypto = require('crypto');

class SessionSigner {
  constructor(walletId, signerKeyId, privateKeyPem, apiConfig) {
    this.walletId = walletId;
    this.signerKeyId = signerKeyId;
    this.privateKey = crypto.createPrivateKey(privateKeyPem);
    this.apiConfig = apiConfig;
  }

  async signTransaction(to, value, chainId, data = '0x') {
    const idempotencyKey = crypto.randomUUID();

    const body = {
      to,
      value: value.toString(),
      chain_id: chainId,
      data,
    };

    const canonicalBody = JSON.stringify(body, Object.keys(body).sort());
    const payload = `1.0POST/v1/wallets/${this.walletId}/sign-transaction${canonicalBody}${this.apiConfig.appId}${idempotencyKey}`;

    const sign = crypto.createSign('SHA256');
    sign.update(payload);
    const signature = sign.sign(this.privateKey, 'base64');

    const response = await fetch(
      `${this.apiConfig.baseUrl}/v1/wallets/${this.walletId}/sign-transaction`,
      {
        method: 'POST',
        headers: {
          'X-App-Id': this.apiConfig.appId,
          'X-App-Secret': this.apiConfig.appSecret,
          'Authorization': `Bearer ${this.apiConfig.userToken}`,
          'X-Authorization-Signature': signature,
          'X-Authorization-Key-Id': this.signerKeyId,
          'X-Idempotency-Key': idempotencyKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error?.message || 'Signing failed');
    }

    return response.json();
  }

  async signMessage(message) {
    const idempotencyKey = crypto.randomUUID();

    const body = { message };
    const canonicalBody = JSON.stringify(body);
    const payload = `1.0POST/v1/wallets/${this.walletId}/sign-message${canonicalBody}${this.apiConfig.appId}${idempotencyKey}`;

    const sign = crypto.createSign('SHA256');
    sign.update(payload);
    const signature = sign.sign(this.privateKey, 'base64');

    const response = await fetch(
      `${this.apiConfig.baseUrl}/v1/wallets/${this.walletId}/sign-message`,
      {
        method: 'POST',
        headers: {
          'X-App-Id': this.apiConfig.appId,
          'X-App-Secret': this.apiConfig.appSecret,
          'Authorization': `Bearer ${this.apiConfig.userToken}`,
          'X-Authorization-Signature': signature,
          'X-Authorization-Key-Id': this.signerKeyId,
          'X-Idempotency-Key': idempotencyKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(body),
      }
    );

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error?.message || 'Signing failed');
    }

    return response.json();
  }
}

// Usage
const signer = new SessionSigner(
  'wallet-uuid',
  'signer-key-uuid',
  fs.readFileSync('signer_key.pem'),
  {
    baseUrl: 'http://localhost:8080',
    appId: process.env.APP_ID,
    appSecret: process.env.APP_SECRET,
    userToken: jwt,
  }
);

const result = await signer.signTransaction(
  '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
  '1000000000000000000',  // 1 ETH
  1  // mainnet
);
```

---

## Automated Bot Pattern

### Trading Bot Example

```javascript
class TradingBot {
  constructor(sessionSigner, sessionId) {
    this.signer = sessionSigner;
    this.sessionId = sessionId;
  }

  async executeTrade(dexAddress, swapData, value) {
    // 1. Check session status
    const session = await this.checkSession();
    if (!session.canTrade) {
      throw new Error(session.reason);
    }

    // 2. Execute trade
    const result = await this.signer.signTransaction(
      dexAddress,
      value,
      1,  // mainnet
      swapData
    );

    console.log(`Trade executed: ${result.transaction_hash}`);
    return result;
  }

  async checkSession() {
    // List session signers for the wallet
    const response = await fetch(`/v1/wallets/${this.walletId}/session_signers`, {
      headers: { ... }
    });
    const sessions = await response.json();
    const session = sessions.session_signers?.find(s => s.id === this.sessionId);

    // Check all conditions
    if (session.status !== 'active') {
      return { canTrade: false, reason: `Session ${session.status}` };
    }

    if (new Date(session.expires_at) < new Date()) {
      return { canTrade: false, reason: 'Session expired' };
    }

    if (session.max_txs && session.used_txs >= session.max_txs) {
      return { canTrade: false, reason: 'Transaction limit reached' };
    }

    return { canTrade: true, session };
  }

  async run(interval = 60000) {
    while (true) {
      try {
        const opportunity = await this.findOpportunity();
        if (opportunity) {
          await this.executeTrade(
            opportunity.dex,
            opportunity.data,
            opportunity.value
          );
        }
      } catch (error) {
        if (error.message.includes('session')) {
          console.log('Session issue, stopping bot');
          break;
        }
        console.error('Trade error:', error.message);
      }

      await new Promise(r => setTimeout(r, interval));
    }
  }
}
```

---

## Best Practices

### 1. Check Before Signing

Always verify session status before attempting to sign:

```javascript
const session = await getSession(sessionId);
if (session.status !== 'active') {
  await refreshSession();
}
```

### 2. Handle Exhaustion Gracefully

```javascript
try {
  await signer.signTransaction(...);
} catch (error) {
  if (error.code === 'session_exhausted') {
    // Create new session or alert operator
    await notifyOperator('Session limits reached');
  }
}
```

### 3. Monitor Usage Proactively

```javascript
// Alert at 80% usage
if (session.used_txs > session.max_txs * 0.8) {
  await alertOperator('Session approaching transaction limit');
}
```

### 4. Use Specific Error Handling

```javascript
switch (error.code) {
  case 'session_expired':
    return 'Session has expired, please create a new one';
  case 'session_value_exceeded':
    return `Insufficient budget: ${error.details.remaining_value} wei remaining`;
  case 'policy_denied':
    return 'Transaction not allowed by policy';
  default:
    return 'Signing failed';
}
```

---

## Next Steps

- [Session Limits](./session-limits.md) - Detailed limit configuration
- [Policy Overrides](./policy-overrides.md) - Custom policies for sessions
- [Revoking Sessions](./revoking-sessions.md) - How to revoke sessions
