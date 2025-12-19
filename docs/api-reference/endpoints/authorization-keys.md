# Authorization Keys API

Complete reference for authorization key management endpoints.

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/authorization-keys` | Register a key |
| GET | `/v1/authorization-keys` | List keys |
| GET | `/v1/authorization-keys/{id}` | Get key details |
| DELETE | `/v1/authorization-keys/{id}` | Revoke a key |

---

## Register Authorization Key

Register a new P-256 public key for signing authorization requests.

### Request

```
POST /v1/authorization-keys
```

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-App-Id` | Yes | Application ID |
| `X-App-Secret` | Yes | Application secret |
| `Authorization` | Yes | Bearer JWT token |
| `X-Idempotency-Key` | Recommended | Unique request identifier |

### Body

```json
{
  "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
  "algorithm": "p256",
  "owner_entity": "backend-server-1"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `public_key` | string | Yes | Base64-encoded P-256 public key (65 bytes uncompressed) |
| `algorithm` | string | Yes | Key algorithm (only `p256` supported) |
| `owner_entity` | string | No | Human-readable identifier for key owner |

### Public Key Format

The public key should be the uncompressed P-256 public key (65 bytes):
- First byte: `0x04` (uncompressed point indicator)
- Next 32 bytes: X coordinate
- Last 32 bytes: Y coordinate

Base64 encode the 65 bytes for the API.

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
  "algorithm": "p256",
  "owner_entity": "backend-server-1",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
# Generate key pair (using OpenSSL)
openssl ecparam -name prime256v1 -genkey -noout -out private_key.pem
openssl ec -in private_key.pem -pubout -outform DER | tail -c 65 | base64 > public_key.b64

# Register the public key
curl -X POST "http://localhost:8080/v1/authorization-keys" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "public_key": "'$(cat public_key.b64)'",
    "algorithm": "p256",
    "owner_entity": "my-backend-server"
  }'
```

---

## List Authorization Keys

List all authorization keys for the application.

### Request

```
GET /v1/authorization-keys
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `status` | string | - | Filter by status (`active`, `revoked`) |
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "authorization_keys": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
      "algorithm": "p256",
      "owner_entity": "backend-server-1",
      "status": "active",
      "created_at": "2025-01-15T10:00:00Z"
    },
    {
      "id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
      "public_key": "BGHiJ9876KLmnOP...",
      "algorithm": "p256",
      "owner_entity": "backup-server",
      "status": "revoked",
      "created_at": "2025-01-10T10:00:00Z",
      "rotated_at": "2025-01-14T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 2,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Example

```bash
# List all active keys
curl "http://localhost:8080/v1/authorization-keys?status=active" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Get Authorization Key

Get details of a specific authorization key.

### Request

```
GET /v1/authorization-keys/{id}
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "public_key": "BFdmW8VdJqmqVp8K8ZHx2Q...",
  "algorithm": "p256",
  "owner_entity": "backend-server-1",
  "status": "active",
  "created_at": "2025-01-15T10:00:00Z",
  "rotated_at": null
}
```

### Example

```bash
curl "http://localhost:8080/v1/authorization-keys/$AUTH_KEY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Revoke Authorization Key

Revoke an authorization key. Revoked keys cannot be used for signing.

### Request

```
DELETE /v1/authorization-keys/{id}
```

### Headers (for Self-Revocation)

If revoking your own key (the key used to sign this request):

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signature` | Yes | Signature using the key being revoked |
| `X-Authorization-Key-Id` | Yes | ID of the key being revoked |

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/authorization-keys/$AUTH_KEY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID"
```

---

## Key Generation Examples

### Node.js

```javascript
const crypto = require('crypto');

// Generate P-256 key pair
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
  namedCurve: 'prime256v1',
});

// Export public key bytes for registration
const pubKeyDer = publicKey.export({ type: 'spki', format: 'der' });
const pubKeyBytes = pubKeyDer.slice(-65); // Last 65 bytes (uncompressed point)
const pubKeyBase64 = pubKeyBytes.toString('base64');

console.log('Public Key (base64):', pubKeyBase64);

// Save private key for signing
const privateKeyPem = privateKey.export({ type: 'sec1', format: 'pem' });
require('fs').writeFileSync('private_key.pem', privateKeyPem);
```

### Python

```python
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import base64

# Generate P-256 key pair
private_key = ec.generate_private_key(ec.SECP256R1())
public_key = private_key.public_key()

# Export public key bytes for registration
pub_key_der = public_key.public_bytes(
    encoding=serialization.Encoding.X962,
    format=serialization.PublicFormat.UncompressedPoint
)
pub_key_base64 = base64.b64encode(pub_key_der).decode()

print(f'Public Key (base64): {pub_key_base64}')

# Save private key
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)
with open('private_key.pem', 'wb') as f:
    f.write(private_pem)
```

### Go

```go
package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "encoding/base64"
    "encoding/pem"
    "fmt"
    "os"
)

func main() {
    // Generate P-256 key pair
    privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

    // Export public key bytes for registration
    pubKeyBytes := elliptic.Marshal(privateKey.Curve, privateKey.X, privateKey.Y)
    pubKeyBase64 := base64.StdEncoding.EncodeToString(pubKeyBytes)

    fmt.Printf("Public Key (base64): %s\n", pubKeyBase64)

    // Save private key
    privKeyBytes, _ := x509.MarshalECPrivateKey(privateKey)
    privKeyPem := pem.EncodeToMemory(&pem.Block{
        Type:  "EC PRIVATE KEY",
        Bytes: privKeyBytes,
    })
    os.WriteFile("private_key.pem", privKeyPem, 0600)
}
```

---

## Using Authorization Keys

Once registered, use the key to sign high-risk operations:

```bash
# Build canonical payload
PAYLOAD="1.0POST/v1/wallets/$WALLET_ID/owner{\"new_owner_id\":\"$NEW_OWNER_ID\"}$APP_ID$IDEMPOTENCY_KEY"

# Sign with private key (simplified - see Authorization Signatures doc for full process)
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -sign private_key.pem | base64)

# Make authorized request
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/owner" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $AUTH_KEY_ID" \
  -H "X-Idempotency-Key: $IDEMPOTENCY_KEY" \
  -H "Content-Type: application/json" \
  -d '{"new_owner_id": "'$NEW_OWNER_ID'"}'
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 400 | `invalid_public_key` | Public key format invalid |
| 400 | `unsupported_algorithm` | Algorithm not supported |
| 401 | `invalid_token` | JWT validation failed |
| 403 | `not_authorized` | Not authorized to revoke |
| 404 | `key_not_found` | Authorization key doesn't exist |
| 409 | `key_in_use` | Key is owner of resources |

### Example Error

```json
{
  "error": {
    "code": "invalid_public_key",
    "message": "Public key format is invalid",
    "details": {
      "expected": "65-byte uncompressed P-256 point, base64 encoded",
      "received_length": 33
    }
  }
}
```
