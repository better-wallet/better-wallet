# Authentication Overview

Better Wallet implements a multi-layer authentication system designed for security without vendor lock-in. This guide explains each authentication layer and how they work together.

## Authentication Layers

Better Wallet uses three distinct authentication layers:

```
┌──────────────────────────────────────────────────────────────────┐
│                        Client Request                            │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
┌─────────────────────────────────▼────────────────────────────────┐
│  Layer 1: App Authentication                                     │
│  ─────────────────────────────────                               │
│  Headers: X-App-Id, X-App-Secret                                 │
│  Purpose: Identify and authenticate your application             │
│  All endpoints: Required                                         │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
┌─────────────────────────────────▼────────────────────────────────┐
│  Layer 2: User Authentication                                    │
│  ───────────────────────────────                                 │
│  Header: Authorization: Bearer <JWT>                             │
│  Purpose: Identify the end user                                  │
│  Default: Required for all /v1/* endpoints                       │
│  Exceptions: POST /v1/wallets, POST /v1/policies, POST /v1/wallets/{id}/rpc │
└─────────────────────────────────┬────────────────────────────────┘
                                  │
┌─────────────────────────────────▼────────────────────────────────┐
│  Layer 3: Authorization Signature (Optional)                     │
│  ────────────────────────────────────────────                    │
│  Headers: X-Authorization-Signature, X-Authorization-Key-Id      │
│  Purpose: Authorize high-risk operations                         │
│  High-risk ops: Required                                         │
└──────────────────────────────────────────────────────────────────┘
```

## Layer Comparison

| Layer | Purpose | Mechanism | When Required |
|-------|---------|-----------|---------------|
| **App Auth** | Identify your application | API key pair | All API calls |
| **User Auth** | Identify end users | JWT bearer token | All /v1/* endpoints by default (see exceptions below) |
| **Auth Signature** | Authorize sensitive ops | P-256 signature | High-risk operations |

### User Authentication Exceptions

The following endpoints allow **app-only authentication** (no user JWT required):

| Endpoint | Purpose |
|----------|---------|
| `POST /v1/wallets` | App-managed wallet creation |
| `POST /v1/policies` | App-managed policy creation |
| `POST /v1/wallets/{id}/rpc` | RPC proxy requests (authorization signature required) |

All other `/v1/*` endpoints require a valid user JWT token.

## Layer 1: App Authentication

Every API request must include app credentials to identify your application.

### Required Headers

| Header | Description | Example |
|--------|-------------|---------|
| `X-App-Id` | Your application's UUID | `550e8400-e29b-41d4-a716-446655440000` |
| `X-App-Secret` | Your application's secret key | `bw_secret_xyz123...` |

### Example Request

```bash
curl http://localhost:8080/v1/wallets \
  -H "X-App-Id: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-App-Secret: bw_secret_xyz123abc456" \
  -H "Authorization: Bearer <jwt>"
```

### Obtaining App Credentials

1. Access the Better Wallet Dashboard
2. Create a new application
3. Copy the App ID and App Secret
4. Store the secret securely (shown only once)

### Security Best Practices

- **Never expose** App Secret in client-side code
- **Rotate secrets** periodically or after suspected compromise
- **Use environment variables** to store secrets
- **Limit secret scope** using per-environment credentials

See [App Credentials](./app-credentials.md) for detailed configuration.

## Layer 2: User Authentication

User authentication verifies the identity of end users using JWT tokens from your OIDC provider.

### Required Header

| Header | Format |
|--------|--------|
| `Authorization` | `Bearer <JWT_TOKEN>` |

### JWT Requirements

Your JWT must include:

| Claim | Description | Example |
|-------|-------------|---------|
| `iss` | Issuer URL (must match app config) | `https://auth.example.com/` |
| `aud` | Audience (must match app config) | `https://api.example.com` |
| `sub` | Subject (unique user identifier) | `auth0\|123456789` |
| `exp` | Expiration time | Unix timestamp |

### Example JWT Payload

```json
{
  "iss": "https://your-tenant.auth0.com/",
  "aud": "https://api.yourapp.com",
  "sub": "auth0|123456789",
  "iat": 1704067200,
  "exp": 1704153600
}
```

### User Mapping

Better Wallet maps JWT `sub` claims to internal user IDs:

```
JWT sub: "auth0|123456789"
         ↓
Internal User ID: "550e8400-e29b-41d4-a716-446655440000"
```

Users are created automatically on first authentication.

See [JWT Setup](./jwt-setup.md) for detailed configuration.

## Layer 3: Authorization Signatures

High-risk operations require cryptographic proof of authorization using P-256 ECDSA signatures.

### When Required

| Operation | Authorization Required |
|-----------|------------------------|
| Create wallet | No |
| Sign transaction | No (policy-controlled) |
| Update wallet owner | **Yes** |
| Delete wallet | **Yes** |
| Update policy | **Yes** |
| Delete policy | **Yes** |
| Transfer ownership | **Yes** |

### Required Headers

| Header | Description |
|--------|-------------|
| `X-Authorization-Signature` | P-256 signature of canonical payload |
| `X-Authorization-Key-Id` | ID of the authorization key used |
| `X-Idempotency-Key` | Unique key for the request (recommended) |

### Signature Flow

```
1. Build canonical payload:
   version + method + path + body + app_id + idempotency_key

2. Hash payload (SHA-256)

3. Sign hash with P-256 private key

4. Include signature in request headers
```

### Example

```bash
# Canonical payload (simplified)
PAYLOAD="1.0POST/v1/wallets/123/owner{\"new_owner_id\":\"456\"}app-id-hereidemp-key-here"

# Sign (using OpenSSL)
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign private_key.pem | base64)

# Request
curl -X POST "http://localhost:8080/v1/wallets/123/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: auth-key-uuid" \
  -H "X-Idempotency-Key: unique-request-id" \
  -H "Content-Type: application/json" \
  -d '{"new_owner_id": "456"}'
```

See [Authorization Signatures](./authorization-signatures.md) for implementation details.

## Authentication Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Your Application                                │
└─────────────────────────────────────┬───────────────────────────────────────┘
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        │                             │                             │
        ▼                             ▼                             ▼
┌───────────────────┐   ┌───────────────────┐   ┌───────────────────┐
│  OIDC Provider    │   │   Better Wallet   │   │  Your Backend     │
│  (Auth0, Clerk)   │   │       API         │   │  (holds auth key) │
└─────────┬─────────┘   └─────────┬─────────┘   └─────────┬─────────┘
          │                       │                       │
          │ 1. User logs in       │                       │
          │◀──────────────────────│                       │
          │                       │                       │
          │ 2. Returns JWT        │                       │
          │──────────────────────▶│                       │
          │                       │                       │
          │                       │ 3. API call with:     │
          │                       │    - X-App-Id         │
          │                       │    - X-App-Secret     │
          │                       │    - Bearer JWT       │
          │                       │◀──────────────────────│
          │                       │                       │
          │ 4. Validate JWT       │                       │
          │◀──────────────────────│                       │
          │                       │                       │
          │ 5. JWT verified       │                       │
          │──────────────────────▶│                       │
          │                       │                       │
          │                       │ 6. Process request    │
          │                       │                       │
          │                       │ 7. Return response    │
          │                       │──────────────────────▶│
```

## Session Signers

For delegated operations (bots, automated systems), use session signers instead of full authorization:

```bash
# Create a session signer
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session-signers" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID" \
  -d '{
    "signer_id": "bot-session-123",
    "ttl": 3600,
    "max_value": "1000000000000000000",
    "max_txs": 100
  }'

# Use session signer for signing (sign with session signer's key)
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SESSION_SIGNER_SIGNATURE" \
  -H "X-Authorization-Key-Id: $SESSION_SIGNER_AUTH_KEY_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{"to": "0x...", "value": "0x16345785d8a0000", "chain_id": 1, "nonce": "0x0", "gas_limit": "0x5208", "max_fee_per_gas": "0x6fc23ac00", "max_priority_fee_per_gas": "0x77359400"}],
    "id": 1
  }'
```

See [Session Signers](../session-signers/overview.md) for complete documentation.

## Error Responses

### App Authentication Errors

```json
{
  "error": {
    "code": "invalid_app_credentials",
    "message": "Invalid app ID or secret"
  }
}
```

### User Authentication Errors

```json
{
  "error": {
    "code": "invalid_token",
    "message": "JWT validation failed: token expired"
  }
}
```

### Authorization Signature Errors

```json
{
  "error": {
    "code": "invalid_signature",
    "message": "Authorization signature verification failed"
  }
}
```

## Security Considerations

### Token Security

- Use short-lived JWTs (< 1 hour)
- Implement token refresh flows
- Never store tokens in localStorage (use httpOnly cookies)

### Secret Security

- Store App Secret in secure vaults
- Use different secrets per environment
- Rotate secrets after team member departures

### Network Security

- Always use HTTPS in production
- Implement request signing for server-to-server calls
- Use IP allowlisting where possible

## Next Steps

- [JWT Setup](./jwt-setup.md) - Configure your OIDC provider
- [App Credentials](./app-credentials.md) - Detailed app auth guide
- [Authorization Signatures](./authorization-signatures.md) - Implement request signing
- [Security Architecture](../security/architecture.md) - Understand the full security architecture
