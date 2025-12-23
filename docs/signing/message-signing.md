# Message Signing

Guide to signing personal messages with Better Wallet (EIP-191).

## Overview

Personal message signing creates a signature over arbitrary text, typically used for:

- **Authentication**: Prove wallet ownership without transactions
- **Off-chain signatures**: Sign terms, agreements, or verifications
- **Sign-In with Ethereum (SIWE)**: Web3 authentication standard

All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format.

---

## Basic Message Signing

### Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "personal_sign",
    "params": [{
      "message": "Hello, World!"
    }],
    "id": 1
  }'
```

### Response

```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1b"
  },
  "id": 1
}
```

### Signature Format

The signature is a 65-byte hex string:
- 32 bytes: `r` value
- 32 bytes: `s` value
- 1 byte: `v` value (recovery parameter)

---

## Message Format (EIP-191)

Better Wallet follows EIP-191 for message signing:

```
"\x19Ethereum Signed Message:\n" + len(message) + message
```

### Example

For message `"Hello, World!"` (13 characters):

```
"\x19Ethereum Signed Message:\n13Hello, World!"
```

This prevents signed messages from being replayed as transactions.

---

## Common Use Cases

### Authentication

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "message": "Sign in to MyApp\n\nNonce: a1b2c3d4e5f6\nTimestamp: 2025-01-15T10:00:00Z"
  }'
```

### Terms Acceptance

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "message": "I agree to the Terms of Service v2.0\n\nHash: 0xabc123...\nDate: 2025-01-15"
  }'
```

### Ownership Verification

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "message": "This wallet belongs to user@example.com\nVerification code: XYZ123"
  }'
```

---

## Sign-In with Ethereum (SIWE)

### SIWE Message Format

```
${domain} wants you to sign in with your Ethereum account:
${address}

${statement}

URI: ${uri}
Version: ${version}
Chain ID: ${chainId}
Nonce: ${nonce}
Issued At: ${issuedAt}
```

### Example SIWE Message

```bash
MESSAGE="myapp.com wants you to sign in with your Ethereum account:
0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb

Sign in to MyApp to access your dashboard.

URI: https://myapp.com/login
Version: 1
Chain ID: 1
Nonce: abc123xyz
Issued At: 2025-01-15T10:00:00.000Z"

curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "message": "'"$MESSAGE"'"
  }'
```

### SIWE Libraries

```javascript
// Using siwe library
const { SiweMessage } = require('siwe');

const siweMessage = new SiweMessage({
  domain: 'myapp.com',
  address: walletAddress,
  statement: 'Sign in to MyApp',
  uri: 'https://myapp.com/login',
  version: '1',
  chainId: 1,
  nonce: generateNonce(),
});

const message = siweMessage.prepareMessage();

// Sign with Better Wallet
const { signature } = await signMessage(walletId, message);

// Verify on backend
const verified = await siweMessage.verify({ signature });
```

---

## Verifying Signatures

### Using ethers.js

```javascript
const { ethers } = require('ethers');

const message = 'Hello, World!';
const signature = '0x...'; // From Better Wallet

// Recover signer address
const recoveredAddress = ethers.verifyMessage(message, signature);

// Compare with expected address
if (recoveredAddress.toLowerCase() === walletAddress.toLowerCase()) {
  console.log('Signature valid!');
}
```

### Using web3.js

```javascript
const Web3 = require('web3');
const web3 = new Web3();

const recoveredAddress = web3.eth.accounts.recover(message, signature);
```

### Server-Side Verification (Node.js)

```javascript
const { verifyMessage } = require('ethers');

function verifyWalletSignature(message, signature, expectedAddress) {
  try {
    const recoveredAddress = verifyMessage(message, signature);
    return recoveredAddress.toLowerCase() === expectedAddress.toLowerCase();
  } catch (error) {
    return false;
  }
}
```

---

## Policy Considerations

Message signing can be controlled by policies:

```json
{
  "rules": [
    {
      "name": "Allow SIWE messages",
      "method": "personal_sign",
      "conditions": [
        {
          "field_source": "ethereum_message",
          "field": "content",
          "operator": "contains",
          "value": "wants you to sign in with your Ethereum account"
        }
      ],
      "action": "ALLOW"
    },
    {
      "name": "Deny all other messages",
      "method": "personal_sign",
      "conditions": [],
      "action": "DENY"
    }
  ]
}
```

---

## Security Best Practices

### 1. Include Nonces

```javascript
const message = `Sign in to MyApp\nNonce: ${crypto.randomUUID()}`;
```

Prevents signature replay attacks.

### 2. Include Timestamps

```javascript
const message = `Action: Transfer ownership\nTimestamp: ${new Date().toISOString()}\nExpires: ${expiryTime.toISOString()}`;
```

Allows time-bounded signature validity.

### 3. Include Domain Information

```javascript
const message = `Domain: myapp.com\nAction: Authorize\nNonce: ${nonce}`;
```

Prevents cross-domain signature reuse.

### 4. Use Structured Messages

```javascript
const message = [
  'MyApp Authentication',
  '',
  `Address: ${address}`,
  `Nonce: ${nonce}`,
  `Timestamp: ${timestamp}`,
  `Chain ID: ${chainId}`,
].join('\n');
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `policy_denied` | Policy rejected message | Check policy rules |
| `invalid_message` | Empty or invalid message | Provide valid message |
| `wallet_not_found` | Invalid wallet ID | Verify wallet exists |

---

## Integration Example

### Complete Authentication Flow

```javascript
// 1. Frontend requests nonce from backend
const { nonce } = await fetch('/api/auth/nonce').then(r => r.json());

// 2. Build SIWE message
const message = `myapp.com wants you to sign in with your Ethereum account:
${walletAddress}

Sign in to access your account.

URI: https://myapp.com
Version: 1
Chain ID: 1
Nonce: ${nonce}
Issued At: ${new Date().toISOString()}`;

// 3. Sign with Better Wallet
const response = await fetch(`/api/wallets/${walletId}/rpc`, {
  method: 'POST',
  headers: { ... },
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'personal_sign',
    params: [{ message }],
    id: 1
  })
}).then(r => r.json());
const { signature } = response.result;

// 4. Verify on backend and issue session
const { token } = await fetch('/api/auth/verify', {
  method: 'POST',
  body: JSON.stringify({ message, signature, address: walletAddress })
}).then(r => r.json());

// 5. Use token for authenticated requests
```
