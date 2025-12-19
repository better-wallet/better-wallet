# Revoking Session Signers

Guide to revoking and managing session signer lifecycle.

## Overview

Session signers can be revoked before their expiration to:

- Terminate compromised sessions immediately
- Clean up unused sessions
- Rotate session credentials
- Respond to security incidents

---

## Revoking a Session

### Basic Revocation

```bash
# Create authorization signature
IDEMPOTENCY_KEY=$(uuidgen)
PAYLOAD="1.0DELETE/v1/wallets/${WALLET_ID}/session_signers/${SESSION_ID}${APP_ID}${IDEMPOTENCY_KEY}"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign owner_key.pem | base64)

# Revoke session
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers/$SESSION_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY"
```

### Response

```json
{
  "id": "session-uuid",
  "status": "revoked",
  "revoked_at": "2025-01-15T12:00:00Z"
}
```

---

## Who Can Revoke Sessions

| Actor | Can Revoke | Method |
|-------|------------|--------|
| Wallet owner | Yes | Owner's authorization signature |
| Quorum members | Yes | M-of-N signatures |
| Session signer itself | No | Sessions cannot self-revoke |
| App admin | No | Requires owner authorization |

---

## Revocation Effects

### Immediate Impact

```
Before Revocation:
Session Status: active
Signing Requests: ✓ Allowed

After Revocation:
Session Status: revoked
Signing Requests: ✗ Rejected
```

### What Happens

1. Session status changes to `revoked`
2. All future signing requests fail immediately
3. No in-flight transactions are affected
4. Session record retained for audit purposes
5. Counters (`used_value`, `used_txs`) preserved

---

## Session Lifecycle

```
┌─────────────────────────────────────────────────────────────────┐
│                        Session Lifecycle                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│   Created ──────► Active ──────► Expired                        │
│                     │                                           │
│                     │ (manual revoke)                           │
│                     │                                           │
│                     ▼                                           │
│                  Revoked                                        │
│                                                                 │
│   ─────────────────────────────────────────────────────         │
│   Created ──────► Active ──────► Exhausted                      │
│                                  (limits reached)               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Status Values

| Status | Description | Can Sign |
|--------|-------------|----------|
| `active` | Within all limits | Yes |
| `expired` | Past `expires_at` | No |
| `exhausted` | Reached `max_value` or `max_txs` | No |
| `revoked` | Manually revoked by owner | No |

---

## Bulk Revocation

### List All Sessions for Wallet

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID/session-signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "session_signers": [
    {
      "id": "session-1",
      "signer_id": "signer-key-1",
      "status": "active",
      "expires_at": "2025-01-22T10:00:00Z"
    },
    {
      "id": "session-2",
      "signer_id": "signer-key-2",
      "status": "active",
      "expires_at": "2025-01-20T10:00:00Z"
    }
  ]
}
```

### Revoke All Active Sessions

```javascript
async function revokeAllSessions(walletId, ownerPrivateKey, ownerKeyId) {
  // 1. List all sessions
  const sessions = await listSessionSigners(walletId);

  // 2. Filter active sessions
  const activeSessions = sessions.filter(s => s.status === 'active');

  // 3. Revoke each one
  const results = [];
  for (const session of activeSessions) {
    try {
      const result = await revokeSession(session.id, ownerPrivateKey, ownerKeyId);
      results.push({ id: session.id, status: 'revoked' });
    } catch (error) {
      results.push({ id: session.id, status: 'error', error: error.message });
    }
  }

  return results;
}
```

---

## Programmatic Revocation

### Node.js Example

```javascript
const crypto = require('crypto');

async function revokeSession(walletId, sessionId, ownerPrivateKey, ownerKeyId) {
  const idempotencyKey = crypto.randomUUID();

  // Build payload (no body for DELETE)
  const payload = `1.0DELETE/v1/wallets/${walletId}/session_signers/${sessionId}${APP_ID}${idempotencyKey}`;

  // Sign with owner's key
  const sign = crypto.createSign('SHA256');
  sign.update(payload);
  const signature = sign.sign(ownerPrivateKey, 'base64');

  const response = await fetch(`${API_URL}/v1/wallets/${walletId}/session_signers/${sessionId}`, {
    method: 'DELETE',
    headers: {
      'X-App-Id': APP_ID,
      'X-App-Secret': APP_SECRET,
      'Authorization': `Bearer ${userToken}`,
      'X-Authorization-Signature': signature,
      'X-Authorization-Key-Id': ownerKeyId,
      'X-Idempotency-Key': idempotencyKey,
    },
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error?.message || 'Revocation failed');
  }

  return response.json();
}
```

---

## Emergency Revocation

### Security Incident Response

When a session signer key may be compromised:

```javascript
async function emergencyRevoke(walletId, compromisedSignerKeyId) {
  console.log('🚨 Emergency session revocation initiated');

  // 1. Find all sessions for the compromised key
  const sessions = await listSessionSigners(walletId);
  const targetSessions = sessions.filter(
    s => s.signer_id === compromisedSignerKeyId && s.status === 'active'
  );

  console.log(`Found ${targetSessions.length} active sessions to revoke`);

  // 2. Revoke immediately
  for (const session of targetSessions) {
    await revokeSession(session.id);
    console.log(`Revoked session: ${session.id}`);
  }

  // 3. Alert security team
  await alertSecurityTeam({
    event: 'emergency_session_revocation',
    wallet_id: walletId,
    compromised_key: compromisedSignerKeyId,
    sessions_revoked: targetSessions.length,
  });

  // 4. Consider additional measures
  // - Rotate authorization keys
  // - Review recent transactions
  // - Check audit logs

  return {
    revoked: targetSessions.length,
    timestamp: new Date().toISOString(),
  };
}
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `session_not_found` | Invalid session ID | Verify session exists |
| `session_already_revoked` | Session was already revoked | No action needed |
| `not_owner` | Signer isn't wallet owner | Use owner's signature |
| `invalid_signature` | Bad authorization signature | Check signature format |

### Error Response Example

```json
{
  "error": {
    "code": "not_owner",
    "message": "Only wallet owner can revoke sessions",
    "details": {
      "wallet_id": "wallet-uuid",
      "session_id": "session-uuid"
    }
  }
}
```

---

## Audit Trail

All revocations are logged:

```json
{
  "event_type": "session_signer_revoked",
  "timestamp": "2025-01-15T12:00:00Z",
  "actor": {
    "type": "authorization_key",
    "id": "owner-key-uuid"
  },
  "resource": {
    "type": "session_signer",
    "id": "session-uuid"
  },
  "details": {
    "wallet_id": "wallet-uuid",
    "signer_id": "signer-key-uuid",
    "previous_status": "active",
    "used_value": "5000000000000000000",
    "used_txs": 42
  }
}
```

### Query Revocation History

```bash
curl "http://localhost:8080/v1/audit-logs?event_type=session_signer_revoked&wallet_id=$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Best Practices

### 1. Revoke Before Key Rotation

```javascript
async function rotateSessionKey(walletId, oldKeyId, newKeyId) {
  // 1. Revoke old sessions
  const oldSessions = await findSessionsBySignerKey(walletId, oldKeyId);
  for (const session of oldSessions) {
    await revokeSession(session.id);
  }

  // 2. Create new session with new key
  const newSession = await createSessionSigner(walletId, newKeyId, {
    expiresAt: getExpiration(86400),  // 24 hours
  });

  return newSession;
}
```

### 2. Implement Session Monitoring

```javascript
async function monitorSessions(walletId) {
  const sessions = await listSessionSigners(walletId);

  for (const session of sessions) {
    // Check for suspicious activity
    if (session.status === 'active') {
      const usageRate = session.used_txs / getSessionAge(session);

      if (usageRate > THRESHOLD_TXS_PER_MINUTE) {
        await alertOperator({
          type: 'high_session_usage',
          session_id: session.id,
          usage_rate: usageRate,
        });
      }
    }
  }
}
```

### 3. Cleanup Expired Sessions

While expired sessions can't sign, consider periodic cleanup:

```javascript
async function cleanupExpiredSessions(walletId) {
  const sessions = await listSessionSigners(walletId);
  const now = new Date();

  const expiredSessions = sessions.filter(
    s => new Date(s.expires_at) < now && s.status === 'active'
  );

  // Log for audit purposes (sessions auto-expire, but logging helps)
  console.log(`Found ${expiredSessions.length} expired sessions`);
}
```

### 4. Implement Revocation Webhooks

```javascript
// After revocation, notify dependent systems
async function onSessionRevoked(session) {
  await Promise.all([
    notifyTradingBot(session.id, 'revoked'),
    updateDashboard(session.wallet_id),
    logSecurityEvent(session),
  ]);
}
```

---

## Comparison: Revoke vs Let Expire

| Scenario | Recommendation |
|----------|----------------|
| Key compromised | Revoke immediately |
| Session no longer needed | Revoke to clean up |
| Short TTL remaining | Let expire |
| Automated rotation | Revoke old, create new |
| User logged out | Revoke associated sessions |

---

## Next Steps

- [Creating Sessions](./creating-sessions.md) - Create new sessions after revocation
- [Session Limits](./session-limits.md) - Configure session constraints
- [Policy Overrides](./policy-overrides.md) - Restrict session permissions
