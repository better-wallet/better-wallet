# Authorization Signatures

Authorization signatures provide cryptographic proof that high-risk operations are authorized by wallet owners or key quorums. This document explains the signature format, how to generate signatures, and when they're required.

## Overview

Authorization signatures use **P-256 ECDSA** (NIST P-256/prime256v1) to sign a canonical representation of API requests. This ensures:

- **Non-repudiation**: Only the private key holder can authorize operations
- **Integrity**: Request cannot be tampered with after signing
- **Replay prevention**: Idempotency keys prevent replay attacks

## When Authorization is Required

| Operation | Authorization Required | Signer |
|-----------|------------------------|--------|
| Create wallet | No | - |
| List wallets | No | - |
| Get wallet | No | - |
| Sign transaction | No (policy-controlled) | - |
| **Update wallet owner** | **Yes** | Current owner |
| **Delete wallet** | **Yes** | Owner |
| Create policy | No | - |
| **Update policy** | **Yes** | Policy owner |
| **Delete policy** | **Yes** | Policy owner |
| Create session signer | **Yes** | Wallet owner |
| Revoke session signer | **Yes** | Wallet owner |

## Canonical Payload Format

The signature is computed over a canonical payload using RFC 8785 (JSON Canonicalization Scheme):

```
canonical_payload = version + method + path + canonical_body + app_id + idempotency_key + canonical_headers
```

### Components

| Component | Description | Example |
|-----------|-------------|---------|
| `version` | API version | `"1.0"` |
| `method` | HTTP method (uppercase) | `"POST"`, `"PATCH"`, `"DELETE"` |
| `path` | Request path | `"/v1/wallets/uuid/owner"` |
| `canonical_body` | RFC 8785 canonicalized JSON body | `{"new_owner_id":"uuid"}` |
| `app_id` | Application ID | `"550e8400-e29b-..."` |
| `idempotency_key` | Request idempotency key | `"unique-request-123"` |
| `canonical_headers` | Canonicalized relevant headers | `"x-custom-header:value"` |

### RFC 8785 Canonicalization

RFC 8785 (JCS) ensures deterministic JSON representation:

- Object keys sorted lexicographically
- No whitespace
- Unicode normalization
- Consistent number formatting

Example:
```json
// Input
{"b": 2, "a": 1}

// RFC 8785 Canonical
{"a":1,"b":2}
```

## Signature Generation

### Step 1: Build Canonical Payload

```javascript
const crypto = require('crypto');

function buildCanonicalPayload(request) {
  const version = '1.0';
  const method = request.method.toUpperCase();
  const path = request.path;
  const body = request.body ? canonicalize(request.body) : '';
  const appId = request.headers['x-app-id'];
  const idempotencyKey = request.headers['x-idempotency-key'] || '';

  // Build canonical headers (only specific headers)
  const relevantHeaders = ['x-custom-header']; // Add any custom headers
  const canonicalHeaders = relevantHeaders
    .filter(h => request.headers[h.toLowerCase()])
    .sort()
    .map(h => `${h.toLowerCase()}:${request.headers[h.toLowerCase()]}`)
    .join('\n');

  return `${version}${method}${path}${body}${appId}${idempotencyKey}${canonicalHeaders}`;
}
```

### Step 2: Hash the Payload

```javascript
function hashPayload(canonicalPayload) {
  return crypto.createHash('sha256').update(canonicalPayload).digest();
}
```

### Step 3: Sign with P-256

```javascript
const { sign } = require('crypto');

function signPayload(privateKey, payloadHash) {
  const signature = sign('sha256', payloadHash, {
    key: privateKey,
    dsaEncoding: 'ieee-p1363', // 64-byte raw signature
  });

  return signature.toString('base64');
}
```

### Complete Example (Node.js)

```javascript
const crypto = require('crypto');
const canonicalize = require('canonicalize'); // npm install canonicalize

class AuthorizationSigner {
  constructor(privateKeyPem) {
    this.privateKey = crypto.createPrivateKey(privateKeyPem);
  }

  sign(request) {
    // Build canonical payload
    const payload = this.buildCanonicalPayload(request);

    // Hash
    const hash = crypto.createHash('sha256').update(payload).digest();

    // Sign
    const signature = crypto.sign('sha256', hash, {
      key: this.privateKey,
      dsaEncoding: 'ieee-p1363',
    });

    return signature.toString('base64');
  }

  buildCanonicalPayload(request) {
    const parts = [
      '1.0',
      request.method.toUpperCase(),
      request.path,
      request.body ? canonicalize(JSON.parse(request.body)) : '',
      request.appId,
      request.idempotencyKey || '',
    ];

    return parts.join('');
  }
}

// Usage
const signer = new AuthorizationSigner(fs.readFileSync('private_key.pem'));

const request = {
  method: 'POST',
  path: '/v1/wallets/123/owner',
  body: JSON.stringify({ new_owner_id: '456' }),
  appId: 'app-uuid',
  idempotencyKey: 'unique-key-123',
};

const signature = signer.sign(request);
console.log('Signature:', signature);
```

### Python Example

```python
import hashlib
import json
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_pem_private_key
import base64

def canonicalize(obj):
    """RFC 8785 JSON Canonicalization"""
    return json.dumps(obj, separators=(',', ':'), sort_keys=True)

def sign_request(private_key_pem: bytes, request: dict) -> str:
    # Build canonical payload
    payload_parts = [
        '1.0',
        request['method'].upper(),
        request['path'],
        canonicalize(request.get('body', {})) if request.get('body') else '',
        request['app_id'],
        request.get('idempotency_key', ''),
    ]
    payload = ''.join(payload_parts)

    # Hash
    payload_hash = hashlib.sha256(payload.encode()).digest()

    # Load private key and sign
    private_key = load_pem_private_key(private_key_pem, password=None)
    signature = private_key.sign(payload_hash, ec.ECDSA(hashes.SHA256()))

    return base64.b64encode(signature).decode()

# Usage
with open('private_key.pem', 'rb') as f:
    private_key_pem = f.read()

request = {
    'method': 'POST',
    'path': '/v1/wallets/123/owner',
    'body': {'new_owner_id': '456'},
    'app_id': 'app-uuid',
    'idempotency_key': 'unique-key-123',
}

signature = sign_request(private_key_pem, request)
print(f'Signature: {signature}')
```

### Go Example

```go
package main

import (
    "crypto/ecdsa"
    "crypto/rand"
    "crypto/sha256"
    "crypto/x509"
    "encoding/base64"
    "encoding/json"
    "encoding/pem"
    "fmt"
    "sort"
    "strings"
)

func signRequest(privateKeyPEM []byte, method, path string, body map[string]interface{}, appID, idempotencyKey string) (string, error) {
    // Parse private key
    block, _ := pem.Decode(privateKeyPEM)
    privateKey, err := x509.ParseECPrivateKey(block.Bytes)
    if err != nil {
        return "", err
    }

    // Build canonical payload
    var bodyStr string
    if body != nil {
        bodyBytes, _ := canonicalizeJSON(body)
        bodyStr = string(bodyBytes)
    }

    payload := fmt.Sprintf("1.0%s%s%s%s%s",
        strings.ToUpper(method),
        path,
        bodyStr,
        appID,
        idempotencyKey,
    )

    // Hash and sign
    hash := sha256.Sum256([]byte(payload))
    r, s, err := ecdsa.Sign(rand.Reader, privateKey, hash[:])
    if err != nil {
        return "", err
    }

    // Convert to IEEE P1363 format (r || s)
    signature := append(r.Bytes(), s.Bytes()...)
    return base64.StdEncoding.EncodeToString(signature), nil
}

func canonicalizeJSON(v interface{}) ([]byte, error) {
    // Simple RFC 8785 implementation
    return json.Marshal(v) // Note: use a proper RFC 8785 library in production
}
```

## Using Signatures in Requests

### Request Headers

| Header | Description | Required |
|--------|-------------|----------|
| `X-Authorization-Signature` | Base64-encoded P-256 signature | Yes |
| `X-Authorization-Key-Id` | UUID of the authorization key | Yes |
| `X-Idempotency-Key` | Unique request identifier | Recommended |

### Example Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: MEUCIQDx5qW..." \
  -H "X-Authorization-Key-Id: 550e8400-e29b-41d4-a716-446655440000" \
  -H "X-Idempotency-Key: txn-owner-change-$(date +%s)" \
  -H "Content-Type: application/json" \
  -d '{"new_owner_id": "new-owner-uuid"}'
```

## Key Quorum Signatures

For operations on resources owned by a key quorum, multiple signatures are required:

### M-of-N Signature Format

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "new_owner_id": "new-owner-uuid",
    "signatures": [
      {
        "key_id": "auth-key-1-uuid",
        "signature": "MEUCIQDx5qW..."
      },
      {
        "key_id": "auth-key-2-uuid",
        "signature": "MEQCIH2xyz..."
      }
    ]
  }'
```

The server verifies that:
1. Enough signatures are provided to meet threshold
2. All signatures are from keys in the quorum
3. All signatures are valid for the canonical payload

## Generating P-256 Key Pairs

### Using OpenSSL

```bash
# Generate private key
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem

# Extract public key
openssl ec -in private_key.pem -pubout -out public_key.pem

# View public key in hex (for registration)
openssl ec -in private_key.pem -pubout -outform DER | tail -c 65 | xxd -p
```

### Using Node.js

```javascript
const crypto = require('crypto');
const fs = require('fs');

const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});

// Export PEM
fs.writeFileSync('private_key.pem',
  privateKey.export({ type: 'sec1', format: 'pem' }));
fs.writeFileSync('public_key.pem',
  publicKey.export({ type: 'spki', format: 'pem' }));

// Export public key bytes for API registration
const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
const pubKeyBytes = pubKeyDer.slice(-65); // Last 65 bytes
console.log('Public Key (base64):', pubKeyBytes.toString('base64'));
```

## Registering Authorization Keys

Before using authorization signatures, register the public key:

```bash
curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "BASE64_ENCODED_PUBLIC_KEY_BYTES",
    "algorithm": "p256",
    "owner_entity": "my-backend-server"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "BASE64...",
  "algorithm": "p256",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z"
}
```

## Security Best Practices

### Private Key Storage

| Environment | Recommended Storage |
|-------------|---------------------|
| Development | Encrypted file or env var |
| Production | KMS (AWS, GCP, Vault) |
| High-security | HSM |

### Key Rotation

1. Generate new key pair
2. Register new authorization key
3. Update wallet/policy owner to new key
4. Revoke old key

```bash
# Update wallet owner to new key
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-Authorization-Signature: $OLD_KEY_SIGNATURE" \
  -H "X-Authorization-Key-Id: $OLD_KEY_ID" \
  -d '{"new_owner_id": "new-key-uuid"}'

# Revoke old key
curl -X DELETE "http://localhost:8080/v1/authorization-keys/$OLD_KEY_ID" \
  -H "X-Authorization-Signature: $NEW_KEY_SIGNATURE" \
  -H "X-Authorization-Key-Id: $NEW_KEY_ID"
```

### Idempotency Keys

Always use idempotency keys for authorization-required operations:

```bash
# Generate unique idempotency key
IDEMP_KEY="wallet-owner-change-$(uuidgen)-$(date +%s)"
```

This prevents replay attacks and allows safe request retries.

## Verification Process

The server verifies signatures as follows:

```
1. Extract X-Authorization-Key-Id from headers
2. Load authorization key from database
3. Verify key is active and not revoked
4. Build canonical payload from request
5. Verify signature against canonical payload
6. For quorums: verify threshold signatures met
7. Continue to operation if valid
```

## Troubleshooting

### "Invalid signature"

- Verify canonical payload matches exactly
- Check body is RFC 8785 canonicalized
- Ensure P-256/prime256v1 curve is used
- Verify signature is base64 encoded

### "Authorization key not found"

- Check key ID is correct UUID
- Verify key is registered and active
- Ensure key belongs to correct app

### "Insufficient quorum signatures"

- Provide at least `threshold` signatures
- All signatures must be from quorum members
- Verify each signature individually first

## Next Steps

- [Authorization Keys](../api-reference/endpoints/authorization-keys.md) - Key management
- [Key Quorums](../api-reference/endpoints/key-quorums.md) - Multi-sig setup
- [Security Architecture](../security/architecture.md) - Full security architecture
