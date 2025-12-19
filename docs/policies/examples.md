# Policy Examples

Real-world policy examples for common use cases.

## Table of Contents

- [Basic Patterns](#basic-patterns)
- [DeFi Policies](#defi-policies)
- [Gaming Policies](#gaming-policies)
- [Enterprise Policies](#enterprise-policies)
- [Advanced Patterns](#advanced-patterns)

---

## Basic Patterns

### Allow All (Development Only)

```json
{
  "name": "Allow all operations",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow everything",
        "method": "*",
        "conditions": [],
        "action": "ALLOW"
      }
    ]
  }
}
```

> **Warning**: Never use in production.

### Deny All (Lockdown)

```json
{
  "name": "Deny all operations",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Deny everything",
        "method": "*",
        "conditions": [],
        "action": "DENY"
      }
    ]
  }
}
```

### Value Limit

```json
{
  "name": "Max 1 ETH per transaction",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow transactions up to 1 ETH",
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
    ]
  }
}
```

### Whitelist Addresses

```json
{
  "name": "Approved recipients only",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow approved recipients",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in",
            "value": [
              "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
              "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
            ]
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Blocklist Addresses

```json
{
  "name": "Block malicious addresses",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Deny blocked addresses",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "blocked-addresses-uuid"
          }
        ],
        "action": "DENY"
      },
      {
        "name": "Allow all other transactions",
        "method": "*",
        "conditions": [],
        "action": "ALLOW"
      }
    ]
  }
}
```

---

## DeFi Policies

### DEX Swaps Only

Allow interactions only with approved DEX contracts:

```json
{
  "name": "DEX trading only",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow Uniswap V3",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xE592427A0AEce92De3Edee1F18E0157C05861564"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Allow Uniswap V2",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Deny all other",
        "method": "*",
        "conditions": [],
        "action": "DENY"
      }
    ]
  }
}
```

### Limited Token Approvals

Prevent unlimited token approvals:

```json
{
  "name": "Limited token approvals",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Limit approval amount",
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
      },
      {
        "name": "Block unlimited approvals",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "eq",
            "value": "0x095ea7b3"
          }
        ],
        "action": "DENY"
      },
      {
        "name": "Allow other operations",
        "method": "*",
        "conditions": [],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Stablecoin Transfers Only

Restrict to USDC and USDT transfers:

```json
{
  "name": "Stablecoin only",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow ETH transfers under 0.1 ETH",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "data",
            "operator": "eq",
            "value": "0x"
          },
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "100000000000000000"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Allow USDC transfers",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
          },
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "eq",
            "value": "0xa9059cbb"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Allow USDT transfers",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xdAC17F958D2ee523a2206206994597C13D831ec7"
          },
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "eq",
            "value": "0xa9059cbb"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

---

## Gaming Policies

### In-Game Microtransactions

Allow small transactions for in-game purchases:

```json
{
  "name": "Gaming microtransactions",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow game contract interactions",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xGameContractAddress..."
          },
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "10000000000000000"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### NFT Minting

Allow minting from specific NFT contracts:

```json
{
  "name": "NFT minting",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow mint function",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "nft-contracts-uuid"
          },
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "in",
            "value": ["0x40c10f19", "0xa0712d68", "0x1249c58b"]
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

---

## Enterprise Policies

### Multi-Chain with Limits

Different limits for different networks:

```json
{
  "name": "Multi-chain limits",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Mainnet - max 10 ETH",
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
            "value": "10000000000000000000"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Polygon - max 10000 MATIC",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "chain_id",
            "operator": "eq",
            "value": 137
          },
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "10000000000000000000000"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Deny other chains",
        "method": "*",
        "conditions": [],
        "action": "DENY"
      }
    ]
  }
}
```

### Treasury Operations

Strict controls for treasury wallets:

```json
{
  "name": "Treasury policy",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow to approved recipients only",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "treasury-recipients-uuid"
          },
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "100000000000000000000"
          },
          {
            "field_source": "ethereum_transaction",
            "field": "chain_id",
            "operator": "eq",
            "value": 1
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Payroll Disbursements

Allow payments to employee addresses:

```json
{
  "name": "Payroll policy",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow employee payments",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "employee-addresses-uuid"
          },
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "50000000000000000000"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Allow USDC transfers to employees",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
          },
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "eq",
            "value": "0xa9059cbb"
          },
          {
            "field_source": "ethereum_calldata",
            "field": "param_0",
            "operator": "in_condition_set",
            "value": "employee-addresses-uuid"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

---

## Advanced Patterns

### EIP-712 Permit Restrictions

Control typed data signing for permits:

```json
{
  "name": "Permit restrictions",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow permits to approved spenders",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_typed_data_domain",
            "field": "verifyingContract",
            "operator": "in_condition_set",
            "value": "permit-tokens-uuid"
          },
          {
            "field_source": "ethereum_typed_data_message",
            "field": "spender",
            "operator": "in_condition_set",
            "value": "approved-spenders-uuid"
          },
          {
            "field_source": "ethereum_typed_data_message",
            "field": "value",
            "operator": "lte",
            "value": "1000000000000000000000"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Message Signing Patterns

Allow signing specific message patterns:

```json
{
  "name": "Message signing policy",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
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
      }
    ]
  }
}
```

### Condition Set Combinations

Using multiple condition sets together:

```json
{
  "name": "Complex DeFi policy",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Block sanctioned addresses first",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "sanctioned-addresses-uuid"
          }
        ],
        "action": "DENY"
      },
      {
        "name": "Allow approved DeFi protocols",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "approved-defi-protocols-uuid"
          },
          {
            "field_source": "ethereum_transaction",
            "field": "chain_id",
            "operator": "in_condition_set",
            "value": "approved-chains-uuid"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Allow whitelisted EOAs",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "whitelisted-eoas-uuid"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

---

## Best Practices

### Rule Ordering

1. Place DENY rules for blocklists first
2. Place specific ALLOW rules before general ones
3. End with a catch-all DENY or ALLOW based on security posture

### Testing Policies

Use the validation endpoint before deploying:

```bash
curl -X POST "http://localhost:8080/v1/policies/validate" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "rules": { ... }
  }'
```

### Use Condition Sets

For lists that change frequently, use condition sets instead of hardcoded values:

```json
// Instead of:
"value": ["0x123...", "0x456...", "0x789..."]

// Use:
"operator": "in_condition_set",
"value": "my-address-list-uuid"
```

This allows updating the list without modifying the policy.
