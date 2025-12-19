# App Credentials Guide

Configure and manage application credentials for Better Wallet API access.

## Overview

Better Wallet uses a multi-layer authentication system:

1. **App Credentials** (this guide): Identifies your application
2. **User JWT**: Identifies the end user
3. **Authorization Signatures**: Authorizes high-risk operations

All API requests require app credentials via headers.

## Credential Types

### App ID

- Public identifier for your application
- Safe to include in client-side code
- Format: UUID

### App Secret

- Private key for server-to-server authentication
- **Never expose in client-side code**
- Format: Base64-encoded random bytes

---

## Creating Credentials

### Via Dashboard

1. Log in to the Better Wallet dashboard
2. Click **Create Application**
3. Enter application name and settings
4. Copy the generated App ID and App Secret

> **Important**: The App Secret is only shown once. Store it securely.

### Credential Structure

```json
{
  "app_id": "550e8400-e29b-41d4-a716-446655440000",
  "app_secret": "Kx7vB2mP9qN3rS6wY1aD4fG8hJ0lZ5cX..."
}
```

---

## Using Credentials

### Request Headers

Every API request must include app credentials:

| Header | Value | Description |
|--------|-------|-------------|
| `X-App-Id` | Your App ID | Application identifier |
| `X-App-Secret` | Your App Secret | Application authentication |
| `Authorization` | Bearer JWT | User authentication (required for most `/v1/*` endpoints; see exceptions in [Authentication Overview](./overview.md)) |

### Example Request

```bash
curl "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-App-Secret: Kx7vB2mP9qN3rS6wY1aD4fG8hJ0lZ5cX..." \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIs..." \
  -H "Content-Type: application/json"
```

---

## Security Architecture

### Client-Side vs Server-Side

```
┌─────────────────────────────────────────────────────────────┐
│  BROWSER (Client-Side)                                      │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Can store: App ID, User JWT                         │   │
│  │  Cannot store: App Secret                            │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ API calls with JWT only
┌─────────────────────────────────────────────────────────────┐
│  YOUR BACKEND (Server-Side)                                 │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Stores: App ID + App Secret (environment variables) │   │
│  │  Adds: X-App-Id, X-App-Secret headers                │   │
│  │  Forwards: User JWT                                  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼ Full authenticated request
┌─────────────────────────────────────────────────────────────┐
│  BETTER WALLET                                              │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  Validates: App credentials + JWT                    │   │
│  │  Returns: Wallet data                               │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Proxy Pattern (Recommended)

Use your backend as a proxy to add app credentials:

```javascript
// Your backend (Node.js/Express example)
app.post('/api/wallets', async (req, res) => {
  // Forward user's JWT
  const userToken = req.headers.authorization;

  const response = await fetch('http://better-wallet:8080/v1/wallets', {
    method: 'POST',
    headers: {
      // User authentication (forwarded)
      'Authorization': userToken,
      // App authentication (added server-side)
      'X-App-Id': process.env.BETTER_WALLET_APP_ID,
      'X-App-Secret': process.env.BETTER_WALLET_APP_SECRET,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(req.body),
  });

  res.json(await response.json());
});
```

### Direct Client Access (Not Recommended)

If you must access Better Wallet directly from clients:

1. Create a separate "client" app with restricted permissions
2. Use additional authorization signatures for sensitive operations
3. Implement rate limiting on your side
4. Monitor for abuse

---

## Credential Storage

### Environment Variables (Recommended)

```bash
# .env (local development)
BETTER_WALLET_APP_ID=550e8400-e29b-41d4-a716-446655440000
BETTER_WALLET_APP_SECRET=Kx7vB2mP9qN3rS6wY1aD4fG8hJ0lZ5cX...

# Load in your app
const appId = process.env.BETTER_WALLET_APP_ID;
const appSecret = process.env.BETTER_WALLET_APP_SECRET;
```

### Secrets Manager (Production)

For production deployments, use a secrets manager:

**AWS Secrets Manager:**
```javascript
const { SecretsManager } = require('@aws-sdk/client-secrets-manager');

const client = new SecretsManager({ region: 'us-east-1' });
const secret = await client.getSecretValue({ SecretId: 'better-wallet-credentials' });
const { appId, appSecret } = JSON.parse(secret.SecretString);
```

**HashiCorp Vault:**
```javascript
const vault = require('node-vault')({ endpoint: 'https://vault:8200' });
const { data } = await vault.read('secret/better-wallet');
const { app_id, app_secret } = data.data;
```

---

## Credential Rotation

### When to Rotate

- Suspected credential compromise
- Employee with access leaves
- Regular security policy (e.g., every 90 days)
- After a security incident

### Rotation Process

1. **Generate new credentials** in the dashboard
2. **Update your deployment** with new credentials
3. **Verify new credentials work** in staging
4. **Deploy to production**
5. **Revoke old credentials** (if supported)

### Zero-Downtime Rotation

For zero-downtime rotation:

1. Create a new app or request additional credentials
2. Update your service to use new credentials
3. Monitor for errors
4. Remove old credentials from your config

---

## Multiple Applications

### Separation by Environment

Create separate apps for each environment:

| Environment | App Name | Purpose |
|-------------|----------|---------|
| Development | `myapp-dev` | Local development |
| Staging | `myapp-staging` | Testing |
| Production | `myapp-prod` | Live traffic |

### Separation by Service

Create separate apps for different services:

| Service | App Name | Purpose |
|---------|----------|---------|
| Web App | `myapp-web` | User-facing frontend |
| Backend API | `myapp-api` | Server operations |
| Admin Tool | `myapp-admin` | Administrative access |

---

## Rate Limiting

App credentials are subject to rate limits:

| Tier | Requests/Second | Burst |
|------|-----------------|-------|
| Default | 100 | 200 |
| Custom | Configurable | Configurable |

Configure per-app rate limits in the dashboard.

### Handling Rate Limits

```javascript
async function makeRequest(url, options, retries = 3) {
  const response = await fetch(url, options);

  if (response.status === 429 && retries > 0) {
    const retryAfter = response.headers.get('Retry-After') || '1';
    await sleep(parseInt(retryAfter) * 1000);
    return makeRequest(url, options, retries - 1);
  }

  return response;
}
```

---

## Audit Trail

All API requests are logged with:

- App ID
- User ID (from JWT)
- Operation performed
- Timestamp
- Request ID

Access audit logs via the dashboard or API.

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_app_credentials` | Wrong App ID or Secret | Verify credentials |
| `app_not_found` | App doesn't exist | Check App ID |
| `app_disabled` | App has been disabled | Enable in dashboard |
| `rate_limit_exceeded` | Too many requests | Implement backoff |

### Verification Script

```bash
# Test your credentials
curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:8080/health" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET"

# 200 = Success
# 401 = Invalid credentials
# 404 = App not found
```

---

## Best Practices

1. **Never commit credentials** to version control
2. **Use environment variables** or secrets managers
3. **Rotate regularly** (at least every 90 days)
4. **Separate by environment** (dev, staging, prod)
5. **Monitor usage** via audit logs
6. **Use the proxy pattern** for client apps
7. **Implement retry logic** for rate limits
