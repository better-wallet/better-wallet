# Policy Field Sources Reference

Complete reference for all field sources available in the policy engine.

## Overview

Field sources define where the policy engine extracts data for rule evaluation. Each field source provides access to specific data types and fields relevant to different operation contexts.

## Field Sources

| Field Source | Description | Context |
|--------------|-------------|---------|
| `ethereum_transaction` | Raw Ethereum transaction fields | Transaction signing |
| `ethereum_calldata` | Decoded contract function calls | Contract interactions |
| `ethereum_typed_data_domain` | EIP-712 domain fields | Typed data signing |
| `ethereum_typed_data_message` | EIP-712 message fields | Typed data signing |
| `ethereum_7702_authorization` | EIP-7702 delegation fields | Account abstraction |
| `ethereum_message` | Personal message content | Message signing |
| `system` | System-level metadata | All operations |

---

## ethereum_transaction

Access raw Ethereum transaction fields.

### Available Fields

| Field | Type | Description | Example Value |
|-------|------|-------------|---------------|
| `to` | address | Recipient address | `"0x742d35Cc..."` |
| `from` | address | Sender address (wallet) | `"0x123..."` |
| `value` | string | Transaction value in wei | `"1000000000000000000"` |
| `data` | hex | Transaction calldata | `"0xa9059cbb..."` |
| `chain_id` | integer | Network chain ID | `1` |
| `gas_limit` | integer | Gas limit | `21000` |
| `gas_fee_cap` | string | Max fee per gas (EIP-1559) | `"30000000000"` |
| `gas_tip_cap` | string | Priority fee (EIP-1559) | `"2000000000"` |
| `gas_price` | string | Gas price (legacy) | `"20000000000"` |
| `nonce` | integer | Transaction nonce | `42` |

### Example Rules

**Limit transaction value:**
```json
{
  "name": "Allow transfers up to 1 ETH",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_transaction",
      "field": "value",
      "operator": "lte",
      "value": "1000000000000000000"
    }
  ],
  "action": "ALLOW"
}
```

**Restrict recipient addresses:**
```json
{
  "name": "Allow only approved recipients",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_transaction",
      "field": "to",
      "operator": "in",
      "value": [
        "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
        "0x123456789abcdef123456789abcdef12345678"
      ]
    }
  ],
  "action": "ALLOW"
}
```

**Chain restriction:**
```json
{
  "name": "Mainnet only",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_transaction",
      "field": "chain_id",
      "operator": "eq",
      "value": 1
    }
  ],
  "action": "ALLOW"
}
```

---

## ethereum_calldata

Access decoded contract function parameters.

### How It Works

When `data` contains contract calldata, the policy engine:
1. Extracts the 4-byte function selector
2. Decodes parameters based on ABI encoding
3. Makes individual parameters available as fields

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `function_selector` | hex | 4-byte function identifier |
| `param_0`, `param_1`, ... | varies | Decoded function parameters |

### Common Function Selectors

| Selector | Function | Parameters |
|----------|----------|------------|
| `0xa9059cbb` | `transfer(address,uint256)` | recipient, amount |
| `0x095ea7b3` | `approve(address,uint256)` | spender, amount |
| `0x23b872dd` | `transferFrom(address,address,uint256)` | from, to, amount |
| `0x38ed1739` | `swapExactTokensForTokens(...)` | DEX swap |

### Example Rules

**Restrict to transfer only:**
```json
{
  "name": "Allow only ERC-20 transfers",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_calldata",
      "field": "function_selector",
      "operator": "eq",
      "value": "0xa9059cbb"
    }
  ],
  "action": "ALLOW"
}
```

**Limit approval amounts:**
```json
{
  "name": "Limit approval to 1000 tokens",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_calldata",
      "field": "function_selector",
      "operator": "eq",
      "value": "0x095ea7b3"
    },
    {
      "field_source": "ethereum_calldata",
      "field": "param_1",
      "operator": "lte",
      "value": "1000000000000000000000"
    }
  ],
  "action": "ALLOW"
}
```

---

## ethereum_typed_data_domain

Access EIP-712 typed data domain fields.

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Application name |
| `version` | string | Application version |
| `chainId` | integer | Network chain ID |
| `verifyingContract` | address | Contract address |
| `salt` | bytes32 | Optional salt |

### Example Rules

**Restrict to specific application:**
```json
{
  "name": "Allow only Uniswap permits",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_typed_data_domain",
      "field": "name",
      "operator": "eq",
      "value": "Uniswap V3"
    }
  ],
  "action": "ALLOW"
}
```

**Verify contract address:**
```json
{
  "name": "Allow known contracts only",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_typed_data_domain",
      "field": "verifyingContract",
      "operator": "in_condition_set",
      "value": "approved-contracts-uuid"
    }
  ],
  "action": "ALLOW"
}
```

---

## ethereum_typed_data_message

Access EIP-712 typed data message fields.

### Available Fields

Fields depend on the typed data structure. Common patterns:

**Permit (ERC-2612):**
| Field | Type | Description |
|-------|------|-------------|
| `owner` | address | Token owner |
| `spender` | address | Approved spender |
| `value` | uint256 | Approval amount |
| `nonce` | uint256 | Permit nonce |
| `deadline` | uint256 | Expiration timestamp |

**Order (DEX/NFT):**
| Field | Type | Description |
|-------|------|-------------|
| `maker` | address | Order creator |
| `taker` | address | Order filler |
| `tokenId` | uint256 | NFT token ID |
| `price` | uint256 | Order price |

### Example Rules

**Limit permit amounts:**
```json
{
  "name": "Limit permit to 100 tokens",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_typed_data_message",
      "field": "value",
      "operator": "lte",
      "value": "100000000000000000000"
    }
  ],
  "action": "ALLOW"
}
```

**Restrict spender addresses:**
```json
{
  "name": "Allow approved spenders only",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_typed_data_message",
      "field": "spender",
      "operator": "in_condition_set",
      "value": "approved-spenders-uuid"
    }
  ],
  "action": "ALLOW"
}
```

---

## ethereum_7702_authorization

Access EIP-7702 account delegation fields.

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `delegate` | address | Delegation target contract |
| `chain_id` | integer | Network chain ID |
| `nonce` | integer | Authorization nonce |

### Example Rules

**Restrict delegation targets:**
```json
{
  "name": "Allow approved delegates only",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_7702_authorization",
      "field": "delegate",
      "operator": "in",
      "value": [
        "0x7702DelegateContract1...",
        "0x7702DelegateContract2..."
      ]
    }
  ],
  "action": "ALLOW"
}
```

---

## ethereum_message

Access personal message signing content.

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `content` | string | Message text content |
| `hash` | bytes32 | Message hash |

### Example Rules

**Allow specific message patterns:**
```json
{
  "name": "Allow login messages",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_message",
      "field": "content",
      "operator": "starts_with",
      "value": "Sign in to "
    }
  ],
  "action": "ALLOW"
}
```

---

## system

Access system-level metadata.

### Available Fields

| Field | Type | Description |
|-------|------|-------------|
| `current_unix_timestamp` | integer | Current time as Unix timestamp |
| `wallet_id` | UUID | Wallet being used |
| `user_id` | UUID | Authenticated user |
| `app_id` | UUID | Application ID |

### Example Rules

**Time-based restrictions:**
```json
{
  "name": "Allow during business hours only",
  "method": "*",
  "conditions": [
    {
      "field_source": "system",
      "field": "current_unix_timestamp",
      "operator": "gte",
      "value": "1705312800"
    },
    {
      "field_source": "system",
      "field": "current_unix_timestamp",
      "operator": "lte",
      "value": "1705356000"
    }
  ],
  "action": "ALLOW"
}
```

---

## Combining Field Sources

Rules can combine conditions from multiple field sources:

```json
{
  "name": "Allow small transfers to approved contracts on mainnet",
  "method": "*",
  "conditions": [
    {
      "field_source": "ethereum_transaction",
      "field": "chain_id",
      "operator": "eq",
      "value": 1
    },
    {
      "field_source": "ethereum_transaction",
      "field": "value",
      "operator": "lte",
      "value": "100000000000000000"
    },
    {
      "field_source": "ethereum_transaction",
      "field": "to",
      "operator": "in_condition_set",
      "value": "approved-contracts-uuid"
    }
  ],
  "action": "ALLOW"
}
```

All conditions must match (AND logic).

---

## Field Type Reference

### Address Format
- Checksummed Ethereum address
- 42 characters with `0x` prefix
- Example: `"0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"`

### Value Format (Wei)
- String representation of wei amount
- No decimals, no scientific notation
- 1 ETH = `"1000000000000000000"`

### Hex Format
- Lowercase hex with `0x` prefix
- Example: `"0xa9059cbb"`

### Chain IDs
- Integer value
- Common: 1 (mainnet), 137 (Polygon), 42161 (Arbitrum)
