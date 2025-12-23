# First Integration Guide

This guide walks you through building your first application with Better Wallet. By the end, you'll have a working integration that creates wallets and signs transactions.

## Prerequisites

- Better Wallet running (see [Quick Start](./quickstart.md))
- An OIDC provider (Auth0, Clerk, Better Auth, or similar)
- curl or similar HTTP client

## Step 1: Configure Your OIDC Provider

Better Wallet consumes JWTs from any OIDC provider. You need to configure your provider's details.

### Using the Dashboard

1. Start the dashboard:
   ```bash
   cd dashboard
   bun run dev
   # Open http://localhost:3000
   ```

2. Create a new application

3. Configure authentication settings:
   - **Kind**: `oidc` or `jwt`
   - **Issuer**: Your provider's issuer URL (e.g., `https://your-tenant.auth0.com/`)
   - **Audience**: Expected audience claim (e.g., `https://api.yourapp.com`)
   - **JWKS URI**: JWKS endpoint (e.g., `https://your-tenant.auth0.com/.well-known/jwks.json`)

4. Note your credentials:
   - **App ID**: UUID identifying your app
   - **App Secret**: Secret key (shown once, store securely)

### Common OIDC Providers

| Provider | Issuer Format | JWKS URI |
|----------|---------------|----------|
| Auth0 | `https://{tenant}.auth0.com/` | `https://{tenant}.auth0.com/.well-known/jwks.json` |
| Clerk | `https://{frontend-api}.clerk.accounts.dev` | `https://{frontend-api}.clerk.accounts.dev/.well-known/jwks.json` |
| Okta | `https://{domain}.okta.com` | `https://{domain}.okta.com/oauth2/v1/keys` |
| Better Auth | Your configured issuer | Your configured JWKS endpoint |

## Step 2: Obtain a JWT Token

Get a JWT token from your OIDC provider. This represents an authenticated user.

### Example: Auth0 Client Credentials

```bash
curl -X POST "https://YOUR_TENANT.auth0.com/oauth/token" \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "YOUR_CLIENT_ID",
    "client_secret": "YOUR_CLIENT_SECRET",
    "audience": "https://api.yourapp.com",
    "grant_type": "client_credentials"
  }'
```

Response:
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEyMzQ1NiJ9...",
  "token_type": "Bearer"
}
```

### For Testing

You can create a test JWT at [jwt.io](https://jwt.io) with:
- Valid signature (RS256 with your provider's keys)
- `iss` matching your configured issuer
- `aud` matching your configured audience
- `sub` for the user identifier

## Step 3: Create Your First Wallet

Set up environment variables for convenience:

```bash
export BW_API="http://localhost:8080"
export APP_ID="your-app-id"
export APP_SECRET="your-app-secret"
export JWT_TOKEN="your-jwt-token"
```

Create a wallet:

```bash
curl -X POST "$BW_API/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "created_at": "2025-01-15T10:30:00Z"
}
```

Store the wallet ID:
```bash
export WALLET_ID="550e8400-e29b-41d4-a716-446655440000"
```

## Step 4: List Your Wallets

Retrieve all wallets for the authenticated user:

```bash
curl "$BW_API/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN"
```

Response:
```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "chain_type": "ethereum",
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "created_at": "2025-01-15T10:30:00Z"
    }
  ]
}
```

## Step 5: Get Wallet Details

Retrieve a specific wallet:

```bash
curl "$BW_API/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN"
```

## Step 6: Sign a Transaction

Sign an Ethereum transaction using the unified `/rpc` endpoint with JSON-RPC 2.0 format:

```bash
curl -X POST "$BW_API/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0x1234567890123456789012345678901234567890",
      "value": "0xde0b6b3a7640000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x5208",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400"
    }],
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "signed_transaction": "0x02f87001808477359400850708d7c00082520894123456789012345678901234567890123456789088de0b6b3a764000080c001a0...",
    "tx_hash": "0xabc123def456..."
  },
  "id": 1
}
```

### Transaction Parameters

| Parameter | Description | Example |
|-----------|-------------|---------|
| `to` | Recipient address | `0x123...` |
| `value` | Amount in wei | `"1000000000000000000"` (1 ETH) |
| `chain_id` | Network ID | `1` (mainnet), `11155111` (sepolia) |
| `nonce` | Transaction count | `0` |
| `gas_limit` | Max gas units | `21000` (simple transfer) |
| `gas_fee_cap` | Max fee per gas (EIP-1559) | `"30000000000"` (30 gwei) |
| `gas_tip_cap` | Priority fee (EIP-1559) | `"2000000000"` (2 gwei) |
| `data` | Contract call data | `"0x..."` (optional) |

## Step 7: Sign a Personal Message

Sign a message for authentication (e.g., "Sign in with Ethereum"):

```bash
curl -X POST "$BW_API/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "personal_sign",
    "params": [{
      "message": "Welcome to MyApp!\n\nPlease sign this message to verify your wallet.\n\nNonce: abc123"
    }],
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "0x1234567890abcdef..."
  },
  "id": 1
}
```

## Step 8: Sign EIP-712 Typed Data

Sign structured data (used by many DeFi protocols):

```bash
curl -X POST "$BW_API/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_signTypedData_v4",
    "params": [{
      "typed_data": {
        "types": {
          "EIP712Domain": [
            {"name": "name", "type": "string"},
            {"name": "version", "type": "string"},
            {"name": "chainId", "type": "uint256"},
            {"name": "verifyingContract", "type": "address"}
          ],
          "Permit": [
            {"name": "owner", "type": "address"},
            {"name": "spender", "type": "address"},
            {"name": "value", "type": "uint256"},
            {"name": "nonce", "type": "uint256"},
            {"name": "deadline", "type": "uint256"}
          ]
        },
        "primaryType": "Permit",
        "domain": {
          "name": "USDC",
          "version": "1",
          "chainId": 1,
          "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        },
        "message": {
          "owner": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
          "spender": "0x1234567890123456789012345678901234567890",
          "value": "1000000",
          "nonce": 0,
          "deadline": 1735689600
        }
      }
    }],
    "id": 1
  }'
```

## Step 9: Create a Policy

Add access control to your wallet:

```bash
curl -X POST "$BW_API/v1/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Small transfers only",
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [
        {
          "name": "Allow transfers under 0.1 ETH",
          "method": "*",
          "conditions": [
            {
              "field_source": "ethereum_transaction",
              "field": "value",
              "operator": "lte",
              "value": "100000000000000000"
            }
          ],
          "action": "ALLOW"
        }
      ]
    }
  }'
```

Response:
```json
{
  "id": "policy-uuid",
  "name": "Small transfers only",
  "chain_type": "ethereum",
  "version": "1.0",
  "created_at": "2025-01-15T10:35:00Z"
}
```

## Step 10: Attach Policy to Wallet

Link the policy to your wallet:

```bash
curl -X POST "$BW_API/v1/wallets/$WALLET_ID/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "policy-uuid"
  }'
```

Now, transactions exceeding 0.1 ETH will be denied by the policy engine.

## Complete Example: Node.js Integration

```javascript
const BETTER_WALLET_API = 'http://localhost:8080';
const APP_ID = process.env.APP_ID;
const APP_SECRET = process.env.APP_SECRET;

async function createWallet(jwtToken) {
  const response = await fetch(`${BETTER_WALLET_API}/v1/wallets`, {
    method: 'POST',
    headers: {
      'X-App-Id': APP_ID,
      'X-App-Secret': APP_SECRET,
      'Authorization': `Bearer ${jwtToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      chain_type: 'ethereum',
      exec_backend: 'kms',
    }),
  });

  return response.json();
}

async function signTransaction(walletId, jwtToken, txParams) {
  const rpcBody = {
    jsonrpc: '2.0',
    method: 'eth_sendTransaction',
    params: [txParams],
    id: 1,
  };

  const response = await fetch(
    `${BETTER_WALLET_API}/v1/wallets/${walletId}/rpc`,
    {
      method: 'POST',
      headers: {
        'X-App-Id': APP_ID,
        'X-App-Secret': APP_SECRET,
        'Authorization': `Bearer ${jwtToken}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(rpcBody),
    }
  );

  return response.json();
}

// Usage
async function main() {
  const jwt = await getJwtFromOIDCProvider(); // Your auth logic

  // Create wallet for user
  const wallet = await createWallet(jwt);
  console.log(`Created wallet: ${wallet.address}`);

  // Sign a transaction
  const signed = await signTransaction(wallet.id, jwt, {
    to: '0x1234567890123456789012345678901234567890',
    value: '0xde0b6b3a7640000', // 1 ETH in hex
    chain_id: 1,
    nonce: '0x0',
    gas_limit: '0x5208',
    max_fee_per_gas: '0x6fc23ac00',
    max_priority_fee_per_gas: '0x77359400',
  });

  console.log(`Signed tx: ${signed.result.signed_transaction}`);
}
```

## Error Handling

Better Wallet returns standard HTTP status codes:

| Status | Meaning |
|--------|---------|
| 200 | Success |
| 400 | Invalid request |
| 401 | Authentication required |
| 403 | Policy denied / not authorized |
| 404 | Resource not found |
| 409 | Conflict (duplicate idempotency key) |
| 429 | Rate limited |
| 500 | Server error |

Error response format:
```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied by policy: value exceeds limit",
    "details": {
      "rule_name": "Allow transfers under 0.1 ETH",
      "field": "value",
      "expected": "100000000000000000",
      "actual": "1000000000000000000"
    }
  }
}
```

## Next Steps

You now have a working Better Wallet integration! Next:

1. **[Authentication](../authentication/overview.md)** - Configure multi-layer auth
2. **[Policies](../policies/overview.md)** - Build sophisticated access control
3. **[Session Signers](../session-signers/overview.md)** - Delegate signing for bots/backends
4. **[API Reference](../api-reference/overview.md)** - Explore all endpoints

## Troubleshooting

### "Invalid JWT token"

- Check `iss` matches your configured issuer
- Check `aud` matches your configured audience
- Verify token hasn't expired
- Ensure JWKS endpoint is accessible

### "App not found"

- Verify App ID is correct
- Check App Secret hasn't been rotated

### "Policy denied"

- Check policy rules attached to wallet
- Verify transaction parameters match policy conditions
- Default is DENY if no rules match

### "Wallet not found"

- Ensure wallet ID is correct
- Verify user owns the wallet (JWT sub matches)
