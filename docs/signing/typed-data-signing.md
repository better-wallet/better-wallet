# Typed Data Signing (EIP-712)

Guide to signing structured typed data with Better Wallet.

## Overview

EIP-712 typed data signing provides:

- **Human-readable signatures**: Users see structured data, not hex blobs
- **Domain separation**: Signatures are bound to specific contracts/apps
- **Type safety**: Data structure is explicitly defined
- **Replay protection**: Domain includes chain ID and contract address

---

## Basic Typed Data Signing

### Request

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/sign-typed-data" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "typed_data": {
      "types": {
        "EIP712Domain": [
          {"name": "name", "type": "string"},
          {"name": "version", "type": "string"},
          {"name": "chainId", "type": "uint256"},
          {"name": "verifyingContract", "type": "address"}
        ],
        "Message": [
          {"name": "content", "type": "string"},
          {"name": "timestamp", "type": "uint256"}
        ]
      },
      "primaryType": "Message",
      "domain": {
        "name": "My App",
        "version": "1",
        "chainId": 1,
        "verifyingContract": "0x1234567890123456789012345678901234567890"
      },
      "message": {
        "content": "Hello, EIP-712!",
        "timestamp": 1705312800
      }
    }
  }'
```

### Response

```json
{
  "signature": "0x..."
}
```

---

## Typed Data Structure

### Components

```json
{
  "types": { },        // Type definitions
  "primaryType": "",   // Main type being signed
  "domain": { },       // Domain separator
  "message": { }       // Actual data
}
```

### Type Definitions

```json
{
  "types": {
    "EIP712Domain": [
      {"name": "name", "type": "string"},
      {"name": "version", "type": "string"},
      {"name": "chainId", "type": "uint256"},
      {"name": "verifyingContract", "type": "address"}
    ],
    "Person": [
      {"name": "name", "type": "string"},
      {"name": "wallet", "type": "address"}
    ],
    "Mail": [
      {"name": "from", "type": "Person"},
      {"name": "to", "type": "Person"},
      {"name": "contents", "type": "string"}
    ]
  }
}
```

### Domain Separator

```json
{
  "domain": {
    "name": "My Application",
    "version": "1",
    "chainId": 1,
    "verifyingContract": "0x..."
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Application name |
| `version` | Yes | Application version |
| `chainId` | Yes | Network chain ID |
| `verifyingContract` | No | Contract address (recommended) |
| `salt` | No | Unique identifier |

---

## Common Use Cases

### ERC-2612 Permit

Token approval without gas:

```json
{
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
    "name": "USD Coin",
    "version": "2",
    "chainId": 1,
    "verifyingContract": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
  },
  "message": {
    "owner": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "spender": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "value": "1000000000",
    "nonce": 0,
    "deadline": 1735689600
  }
}
```

### Uniswap Permit2

```json
{
  "types": {
    "EIP712Domain": [...],
    "PermitSingle": [
      {"name": "details", "type": "PermitDetails"},
      {"name": "spender", "type": "address"},
      {"name": "sigDeadline", "type": "uint256"}
    ],
    "PermitDetails": [
      {"name": "token", "type": "address"},
      {"name": "amount", "type": "uint160"},
      {"name": "expiration", "type": "uint48"},
      {"name": "nonce", "type": "uint48"}
    ]
  },
  "primaryType": "PermitSingle",
  "domain": {
    "name": "Permit2",
    "chainId": 1,
    "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
  },
  "message": {
    "details": {
      "token": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "amount": "1461501637330902918203684832716283019655932542975",
      "expiration": 1735689600,
      "nonce": 0
    },
    "spender": "0x3fC91A3afd70395Cd496C647d5a6CC9D4B2b7FAD",
    "sigDeadline": 1705400000
  }
}
```

### NFT Order (OpenSea Seaport)

```json
{
  "types": {
    "EIP712Domain": [...],
    "OrderComponents": [
      {"name": "offerer", "type": "address"},
      {"name": "zone", "type": "address"},
      {"name": "offer", "type": "OfferItem[]"},
      {"name": "consideration", "type": "ConsiderationItem[]"},
      {"name": "orderType", "type": "uint8"},
      {"name": "startTime", "type": "uint256"},
      {"name": "endTime", "type": "uint256"},
      {"name": "zoneHash", "type": "bytes32"},
      {"name": "salt", "type": "uint256"},
      {"name": "conduitKey", "type": "bytes32"},
      {"name": "counter", "type": "uint256"}
    ],
    "OfferItem": [...],
    "ConsiderationItem": [...]
  },
  "primaryType": "OrderComponents",
  "domain": {
    "name": "Seaport",
    "version": "1.5",
    "chainId": 1,
    "verifyingContract": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"
  },
  "message": {
    "offerer": "0x...",
    ...
  }
}
```

### Gnosis Safe Transaction

```json
{
  "types": {
    "EIP712Domain": [...],
    "SafeTx": [
      {"name": "to", "type": "address"},
      {"name": "value", "type": "uint256"},
      {"name": "data", "type": "bytes"},
      {"name": "operation", "type": "uint8"},
      {"name": "safeTxGas", "type": "uint256"},
      {"name": "baseGas", "type": "uint256"},
      {"name": "gasPrice", "type": "uint256"},
      {"name": "gasToken", "type": "address"},
      {"name": "refundReceiver", "type": "address"},
      {"name": "nonce", "type": "uint256"}
    ]
  },
  "primaryType": "SafeTx",
  "domain": {
    "chainId": 1,
    "verifyingContract": "0xSafeAddress..."
  },
  "message": {...}
}
```

---

## Policy Considerations

Control typed data signing with policies:

```json
{
  "rules": [
    {
      "name": "Allow permits to approved spenders",
      "method": "*",
      "conditions": [
        {
          "field_source": "ethereum_typed_data_domain",
          "field": "verifyingContract",
          "operator": "in_condition_set",
          "value": "approved-tokens-uuid"
        },
        {
          "field_source": "ethereum_typed_data_message",
          "field": "spender",
          "operator": "in_condition_set",
          "value": "approved-spenders-uuid"
        }
      ],
      "action": "ALLOW"
    }
  ]
}
```

### Available Policy Fields

**Domain fields** (`ethereum_typed_data_domain`):
- `name`
- `version`
- `chainId`
- `verifyingContract`
- `salt`

**Message fields** (`ethereum_typed_data_message`):
- Any field in the message object

---

## Building Typed Data

### Using ethers.js

```javascript
const { ethers } = require('ethers');

const domain = {
  name: 'My App',
  version: '1',
  chainId: 1,
  verifyingContract: '0x...'
};

const types = {
  Message: [
    { name: 'content', type: 'string' },
    { name: 'timestamp', type: 'uint256' }
  ]
};

const message = {
  content: 'Hello!',
  timestamp: Math.floor(Date.now() / 1000)
};

// For Better Wallet, construct the full typed data
const typedData = {
  types: {
    EIP712Domain: [
      { name: 'name', type: 'string' },
      { name: 'version', type: 'string' },
      { name: 'chainId', type: 'uint256' },
      { name: 'verifyingContract', type: 'address' }
    ],
    ...types
  },
  primaryType: 'Message',
  domain,
  message
};

// Sign with Better Wallet
const response = await fetch(`/v1/wallets/${walletId}/sign-typed-data`, {
  method: 'POST',
  headers: { ... },
  body: JSON.stringify({ typed_data: typedData })
});
```

### Using viem

```typescript
import { parseAbi } from 'viem';

const typedData = {
  domain: {
    name: 'My App',
    version: '1',
    chainId: 1,
    verifyingContract: '0x...'
  },
  types: {
    Message: [
      { name: 'content', type: 'string' }
    ]
  },
  primaryType: 'Message',
  message: {
    content: 'Hello!'
  }
};
```

---

## Verifying Signatures

### Using ethers.js

```javascript
const { ethers } = require('ethers');

const domain = { ... };
const types = { ... };
const message = { ... };
const signature = '0x...';

const recoveredAddress = ethers.verifyTypedData(
  domain,
  types,
  message,
  signature
);

if (recoveredAddress.toLowerCase() === expectedAddress.toLowerCase()) {
  console.log('Signature valid!');
}
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `invalid_typed_data` | Malformed typed data | Check structure |
| `missing_type` | Type referenced but not defined | Define all types |
| `invalid_domain` | Missing domain fields | Include required fields |
| `policy_denied` | Policy rejected | Check policy rules |

---

## Best Practices

1. **Always include chainId** in domain for replay protection
2. **Include verifyingContract** when signing for a specific contract
3. **Use deadlines** for time-sensitive signatures (permits, orders)
4. **Validate typed data** structure before signing
5. **Track nonces** to prevent signature reuse
6. **Implement policy controls** for sensitive typed data
