# JWT Setup Guide

Configure JWT authentication for Better Wallet integration.

## Overview

Better Wallet is authentication-agnostic and works with any OIDC-compliant identity provider. This guide covers setting up JWT validation for your application.

## Prerequisites

- An OIDC-compliant identity provider (Auth0, Clerk, Firebase, Cognito, etc.)
- Your provider's JWKS URI and issuer URL
- A Better Wallet application created via the dashboard

## Supported Providers

| Provider | JWKS URI Pattern | Issuer Pattern |
|----------|------------------|----------------|
| Auth0 | `https://{domain}/.well-known/jwks.json` | `https://{domain}/` |
| Clerk | `https://{frontend-api}/.well-known/jwks.json` | `https://{frontend-api}` |
| Firebase | `https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com` | `https://securetoken.google.com/{project-id}` |
| AWS Cognito | `https://cognito-idp.{region}.amazonaws.com/{pool-id}/.well-known/jwks.json` | `https://cognito-idp.{region}.amazonaws.com/{pool-id}` |
| Supabase | `https://{project-ref}.supabase.co/auth/v1/.well-known/jwks.json` | `https://{project-ref}.supabase.co/auth/v1` |
| Custom | Your JWKS endpoint | Your issuer URL |

---

## Configuration

### Dashboard Setup

1. Navigate to your application in the Better Wallet dashboard
2. Go to **Settings** → **Authentication**
3. Configure the following:

| Setting | Description | Example |
|---------|-------------|---------|
| **JWKS URI** | URL to fetch public keys | `https://example.auth0.com/.well-known/jwks.json` |
| **Issuer** | Expected `iss` claim | `https://example.auth0.com/` |
| **Audience** | Expected `aud` claim | `https://api.myapp.com` |

### JWT Requirements

Better Wallet validates the following JWT claims:

| Claim | Required | Description |
|-------|----------|-------------|
| `sub` | Yes | User identifier (maps to Better Wallet user) |
| `iss` | Yes | Must match configured issuer |
| `aud` | Yes | Must match configured audience |
| `exp` | Yes | Token expiration time |
| `iat` | Yes | Token issued time |

### Example JWT Payload

```json
{
  "sub": "user_abc123",
  "iss": "https://example.auth0.com/",
  "aud": "https://api.myapp.com",
  "iat": 1705312800,
  "exp": 1705316400,
  "email": "user@example.com"
}
```

---

## Provider-Specific Setup

### Auth0

1. Create an Auth0 Application (Regular Web App or SPA)
2. Create an Auth0 API with your audience
3. Configure your Better Wallet app:

```
JWKS URI: https://YOUR_DOMAIN.auth0.com/.well-known/jwks.json
Issuer: https://YOUR_DOMAIN.auth0.com/
Audience: https://api.yourapp.com
```

**Getting tokens in your app:**

```javascript
// Auth0 React SDK
import { useAuth0 } from '@auth0/auth0-react';

const { getAccessTokenSilently } = useAuth0();

const token = await getAccessTokenSilently({
  authorizationParams: {
    audience: 'https://api.yourapp.com',
  },
});

// Use token with Better Wallet
fetch('/api/wallets', {
  headers: {
    'Authorization': `Bearer ${token}`,
    'X-App-Id': APP_ID,
    'X-App-Secret': APP_SECRET,
  },
});
```

### Clerk

1. Enable JWT Templates in Clerk Dashboard
2. Create a custom JWT template (or use the default)
3. Configure your Better Wallet app:

```
JWKS URI: https://YOUR_FRONTEND_API.clerk.accounts.dev/.well-known/jwks.json
Issuer: https://YOUR_FRONTEND_API.clerk.accounts.dev
Audience: your-app-name
```

**Getting tokens:**

```javascript
// Clerk React
import { useAuth } from '@clerk/clerk-react';

const { getToken } = useAuth();

const token = await getToken({ template: 'better-wallet' });
```

### Firebase Auth

1. Get your Firebase project ID
2. Configure your Better Wallet app:

```
JWKS URI: https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com
Issuer: https://securetoken.google.com/YOUR_PROJECT_ID
Audience: YOUR_PROJECT_ID
```

**Getting tokens:**

```javascript
import { getAuth } from 'firebase/auth';

const auth = getAuth();
const token = await auth.currentUser.getIdToken();
```

### AWS Cognito

1. Create a User Pool and App Client
2. Configure your Better Wallet app:

```
JWKS URI: https://cognito-idp.REGION.amazonaws.com/POOL_ID/.well-known/jwks.json
Issuer: https://cognito-idp.REGION.amazonaws.com/POOL_ID
Audience: YOUR_APP_CLIENT_ID
```

**Getting tokens:**

```javascript
import { fetchAuthSession } from 'aws-amplify/auth';

const session = await fetchAuthSession();
const token = session.tokens?.idToken?.toString();
```

### Supabase Auth

1. Get your Supabase project reference
2. Configure your Better Wallet app:

```
JWKS URI: https://YOUR_PROJECT_REF.supabase.co/auth/v1/.well-known/jwks.json
Issuer: https://YOUR_PROJECT_REF.supabase.co/auth/v1
Audience: authenticated
```

**Getting tokens:**

```javascript
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(url, anonKey);
const { data: { session } } = await supabase.auth.getSession();
const token = session?.access_token;
```

---

## Custom JWT Provider

For self-hosted or custom identity providers:

### Requirements

1. **JWKS Endpoint**: Serve public keys in JWKS format
2. **RS256 or ES256**: Use RSA or ECDSA signing
3. **Standard Claims**: Include `sub`, `iss`, `aud`, `exp`, `iat`

### JWKS Format

```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "alg": "RS256",
      "kid": "key-id-1",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

### Example: Node.js JWT Signing

```javascript
const jwt = require('jsonwebtoken');
const fs = require('fs');

const privateKey = fs.readFileSync('private.pem');

const token = jwt.sign(
  {
    sub: 'user-123',
    aud: 'https://api.myapp.com',
  },
  privateKey,
  {
    algorithm: 'RS256',
    issuer: 'https://auth.myapp.com',
    expiresIn: '1h',
    keyid: 'key-id-1',
  }
);
```

---

## User ID Mapping

Better Wallet maps JWT `sub` claims to internal users:

```
JWT sub: "auth0|user_abc123"
      ↓
Better Wallet user_id: UUID
      ↓
User's wallets, sessions, etc.
```

### First Request

On first API request with a new `sub` value:
1. Better Wallet creates a new user record
2. Maps the `sub` to an internal UUID
3. Returns the new user context

### Subsequent Requests

1. JWT `sub` is looked up in the user mapping
2. Request is processed in that user's context
3. Wallet ownership verified against user_id

---

## Token Handling Best Practices

### Client-Side

```javascript
// Store tokens securely
// - Use httpOnly cookies when possible
// - Never store in localStorage for sensitive apps
// - Implement token refresh before expiration

async function makeAuthenticatedRequest(url, options = {}) {
  const token = await getToken();

  return fetch(url, {
    ...options,
    headers: {
      ...options.headers,
      'Authorization': `Bearer ${token}`,
      'X-App-Id': APP_ID,
      'X-App-Secret': APP_SECRET,
    },
  });
}
```

### Server-Side (Proxy Pattern)

```javascript
// Backend proxies requests, adding app credentials
app.post('/api/wallets', async (req, res) => {
  const token = req.headers.authorization;

  const response = await fetch('http://better-wallet:8080/v1/wallets', {
    method: 'POST',
    headers: {
      'Authorization': token,
      'X-App-Id': process.env.BETTER_WALLET_APP_ID,
      'X-App-Secret': process.env.BETTER_WALLET_APP_SECRET,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(req.body),
  });

  res.json(await response.json());
});
```

---

## Troubleshooting

### Common Errors

| Error | Cause | Solution |
|-------|-------|----------|
| `invalid_token` | JWT validation failed | Check issuer, audience, expiration |
| `token_expired` | JWT past expiration | Refresh the token |
| `invalid_signature` | JWKS key mismatch | Verify JWKS URI is correct |
| `missing_claim` | Required claim absent | Ensure `sub` is in token |

### Debugging

1. **Decode your JWT** at [jwt.io](https://jwt.io)
2. **Verify claims** match your configuration
3. **Check JWKS** is accessible from Better Wallet server
4. **Review logs** for detailed error messages

### Clock Skew

Better Wallet allows configurable clock skew (default 1 minute):

```bash
JWT_CLOCK_SKEW=1m
```

Increase if you see timing-related errors.

---

## Security Considerations

1. **Always use HTTPS** for JWKS endpoints
2. **Rotate keys periodically** and publish new keys to JWKS before removing old ones
3. **Use short token lifetimes** (1 hour or less)
4. **Validate audience** to prevent token reuse across services
5. **Keep app secrets secure** - never expose in client-side code
