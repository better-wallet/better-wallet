# Session Signer Limits

Detailed guide to configuring and managing session signer limits.

## Types of Limits

| Limit | Parameter | Description |
|-------|-----------|-------------|
| Time | `expires_at` | Absolute expiration timestamp |
| Value | `max_value` | Cumulative transaction value in wei |
| Count | `max_txs` | Total number of transactions |

---

## Time Limits (TTL)

### Configuration

```json
{
  "expires_at": "2025-01-22T10:00:00Z"
}
```

### Behavior

- Session becomes invalid after `expires_at`
- All signing requests are rejected with `session_expired`
- No partial extension; create new session if needed

### Common Durations

| Use Case | Duration | Example |
|----------|----------|---------|
| Interactive session | 1 hour | `+3600 seconds` |
| Daily bot | 24 hours | `+86400 seconds` |
| Weekly service | 7 days | `+604800 seconds` |
| Monthly process | 30 days | `+2592000 seconds` |

### Best Practices

```javascript
// Short TTL for user-facing sessions
const interactiveExpiry = new Date(Date.now() + 60 * 60 * 1000); // 1 hour

// Longer TTL for automated services
const serviceExpiry = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

// Always use ISO 8601 format
const expiresAt = expiry.toISOString();
```

---

## Value Limits

### Configuration

```json
{
  "max_value": "10000000000000000000"
}
```

`max_value` is in wei (10^18 = 1 ETH).

### Behavior

1. Each transaction's `value` is checked against remaining budget
2. Cumulative total tracked in `used_value`
3. Transaction rejected if `value > (max_value - used_value)`

### Example Scenario

```
max_value: 10 ETH (10000000000000000000 wei)

Transaction 1: 3 ETH → used_value: 3 ETH → remaining: 7 ETH ✓
Transaction 2: 5 ETH → used_value: 8 ETH → remaining: 2 ETH ✓
Transaction 3: 4 ETH → REJECTED (exceeds remaining 2 ETH) ✗
Transaction 4: 2 ETH → used_value: 10 ETH → remaining: 0 ETH ✓
Transaction 5: any → REJECTED (limit exhausted) ✗
```

### Common Value Limits

| Use Case | Limit | Wei |
|----------|-------|-----|
| Micro-transactions | 0.1 ETH | `100000000000000000` |
| Small transfers | 1 ETH | `1000000000000000000` |
| Medium operations | 10 ETH | `10000000000000000000` |
| Large treasury | 100 ETH | `100000000000000000000` |

### Checking Remaining Budget

```javascript
const session = await getSessionSigner(sessionId);
const remaining = BigInt(session.max_value) - BigInt(session.used_value);
console.log(`Remaining budget: ${remaining / BigInt(10**18)} ETH`);
```

---

## Transaction Count Limits

### Configuration

```json
{
  "max_txs": 100
}
```

### Behavior

1. Each successful signing increments `used_txs`
2. Failed policy evaluations don't count
3. Transaction rejected when `used_txs >= max_txs`

### Example Scenario

```
max_txs: 5

Sign 1: used_txs: 1 ✓
Sign 2: used_txs: 2 ✓
Sign 3: used_txs: 3 ✓
Sign 4: used_txs: 4 ✓
Sign 5: used_txs: 5 ✓
Sign 6: REJECTED (limit reached) ✗
```

### Common Count Limits

| Use Case | Limit |
|----------|-------|
| Single action | 1 |
| Small batch | 10 |
| Daily operations | 100 |
| High-frequency | 1000 |

---

## Combined Limits

Combine multiple limits for fine-grained control:

```json
{
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100
}
```

### Evaluation Order

```
1. Check expires_at → if expired, reject
2. Check max_txs → if reached, reject
3. Check max_value → if exceeded, reject
4. Evaluate policy → if denied, reject
5. Sign transaction → increment counters
```

### Example: DCA Bot Configuration

```json
{
  "expires_at": "2025-01-22T10:00:00Z",  // 1 week
  "max_value": "7000000000000000000",     // 7 ETH total (1 ETH/day)
  "max_txs": 7                             // One transaction per day
}
```

---

## Monitoring Limits

### Get Session Status

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "id": "session-uuid",
  "max_value": "10000000000000000000",
  "used_value": "5000000000000000000",
  "max_txs": 100,
  "used_txs": 45,
  "expires_at": "2025-01-22T10:00:00Z",
  "status": "active"
}
```

### Calculate Remaining

```javascript
function getSessionLimits(session) {
  const now = new Date();
  const expiry = new Date(session.expires_at);

  return {
    timeRemaining: Math.max(0, expiry - now),
    valueRemaining: session.max_value
      ? BigInt(session.max_value) - BigInt(session.used_value)
      : null,
    txsRemaining: session.max_txs
      ? session.max_txs - session.used_txs
      : null,
    isActive: session.status === 'active' && expiry > now,
  };
}
```

---

## Limit Exhaustion

### Status Values

| Status | Cause |
|--------|-------|
| `active` | Within all limits |
| `expired` | Past `expires_at` |
| `exhausted` | Reached `max_value` or `max_txs` |
| `revoked` | Manually revoked |

### Error Responses

**Time Expired:**
```json
{
  "error": {
    "code": "session_expired",
    "message": "Session has expired",
    "details": {
      "expired_at": "2025-01-22T10:00:00Z"
    }
  }
}
```

**Value Exceeded:**
```json
{
  "error": {
    "code": "session_value_exceeded",
    "message": "Transaction value exceeds session limit",
    "details": {
      "requested_value": "5000000000000000000",
      "remaining_value": "2000000000000000000"
    }
  }
}
```

**Count Reached:**
```json
{
  "error": {
    "code": "session_limit_exceeded",
    "message": "Session transaction limit reached",
    "details": {
      "max_txs": 100,
      "used_txs": 100
    }
  }
}
```

---

## Best Practices

### 1. Use Minimal Limits

Only allow what's needed:

```json
{
  "max_value": "100000000000000000",  // Only 0.1 ETH
  "max_txs": 10                        // Only 10 transactions
}
```

### 2. Combine with Policy Override

Limits + restrictive policy = defense in depth:

```json
{
  "max_value": "1000000000000000000",
  "max_txs": 50,
  "policy_override_id": "approved-contracts-only"
}
```

### 3. Monitor Before Exhaustion

Alert when approaching limits:

```javascript
function checkLimitWarnings(session) {
  const warnings = [];

  // Time warning (1 hour remaining)
  const timeRemaining = new Date(session.expires_at) - new Date();
  if (timeRemaining < 3600000) {
    warnings.push('Session expiring soon');
  }

  // Value warning (10% remaining)
  if (session.max_value) {
    const valueRemaining = BigInt(session.max_value) - BigInt(session.used_value);
    if (valueRemaining < BigInt(session.max_value) / 10n) {
      warnings.push('Value limit almost reached');
    }
  }

  // Count warning (10% remaining)
  if (session.max_txs) {
    const txsRemaining = session.max_txs - session.used_txs;
    if (txsRemaining < session.max_txs * 0.1) {
      warnings.push('Transaction limit almost reached');
    }
  }

  return warnings;
}
```

### 4. Graceful Renewal

Create new session before old one expires:

```javascript
async function ensureActiveSession(walletId, signerKeyId) {
  const sessions = await listSessionSigners(walletId);
  const existing = sessions.find(s =>
    s.signer_id === signerKeyId && s.status === 'active'
  );

  if (!existing) {
    return createNewSession(walletId, signerKeyId);
  }

  // Renew if expiring within 1 hour
  const timeRemaining = new Date(existing.expires_at) - new Date();
  if (timeRemaining < 3600000) {
    await revokeSession(existing.id);
    return createNewSession(walletId, signerKeyId);
  }

  return existing;
}
```
