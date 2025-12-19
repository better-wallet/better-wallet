# Policy Engine Overview

The policy engine is Better Wallet's access control system. It evaluates rules against transaction parameters and returns ALLOW or DENY decisions. This guide explains how policies work and how to design effective access controls.

## Core Principles

### Default-Deny Security

Better Wallet uses **default-deny** semantics:

- If no rule explicitly allows an operation, it is **denied**
- Rules are evaluated in order; **first match wins**
- An explicit DENY rule takes precedence when matched

```
┌─────────────────────────────────────────────────────────┐
│                   Transaction Request                    │
└─────────────────────────┬───────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────┐
│              Policy Rule Evaluation                      │
│  ┌───────────────────────────────────────────────────┐  │
│  │ Rule 1: Check conditions → Match? → ALLOW/DENY   │  │
│  └───────────────────────────┬───────────────────────┘  │
│                              │ No match                  │
│  ┌───────────────────────────▼───────────────────────┐  │
│  │ Rule 2: Check conditions → Match? → ALLOW/DENY   │  │
│  └───────────────────────────┬───────────────────────┘  │
│                              │ No match                  │
│  ┌───────────────────────────▼───────────────────────┐  │
│  │ Rule N: Check conditions → Match? → ALLOW/DENY   │  │
│  └───────────────────────────┬───────────────────────┘  │
│                              │ No match                  │
│  ┌───────────────────────────▼───────────────────────┐  │
│  │              DEFAULT: DENY                        │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

### Rule Evaluation Logic

- **Rule order matters**: First matching rule determines outcome
- **Conditions use AND logic**: All conditions in a rule must match
- **Multiple policies**: All attached policies must allow the operation

## Policy Structure

A policy consists of:

```json
{
  "version": "1.0",
  "name": "My Policy",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Rule description",
      "method": "eth_sendTransaction",
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
```

### Policy Properties

| Property | Description | Required |
|----------|-------------|----------|
| `version` | Schema version (always `"1.0"`) | Yes |
| `name` | Human-readable policy name | Yes |
| `chain_type` | Blockchain type (`ethereum`) | Yes |
| `rules` | Ordered array of rules | Yes |

### Rule Properties

| Property | Description | Required |
|----------|-------------|----------|
| `name` | Human-readable rule description | Yes |
| `method` | RPC method to match (`*` for any) | Yes |
| `conditions` | Array of conditions (AND logic) | Yes |
| `action` | `ALLOW` or `DENY` | Yes |

### Condition Properties

| Property | Description | Required |
|----------|-------------|----------|
| `field_source` | Data source for the field | Yes |
| `field` | Field name (supports dot notation) | Yes |
| `operator` | Comparison operator | Yes |
| `value` | Expected value | Yes |

## Field Sources

Field sources determine where condition values come from:

| Field Source | Description | Example Fields |
|--------------|-------------|----------------|
| `ethereum_transaction` | Raw transaction parameters | `to`, `value`, `data`, `from` |
| `ethereum_calldata` | Decoded contract calls | `transfer.to`, `approve.amount` |
| `ethereum_typed_data_domain` | EIP-712 domain | `chainId`, `verifyingContract` |
| `ethereum_typed_data_message` | EIP-712 message | Custom message fields |
| `ethereum_7702_authorization` | EIP-7702 delegations | Contract addresses |
| `ethereum_message` | Personal messages | `content`, `length` |
| `system` | System data | `current_unix_timestamp` |

See [Field Sources](./field-sources.md) for complete reference.

## Operators

| Operator | Description | Example Value |
|----------|-------------|---------------|
| `eq` | Equals | `"0x123..."` |
| `neq` | Not equals | `"0x000..."` |
| `lt` | Less than | `"1000000000000000000"` |
| `lte` | Less than or equal | `"1000000000000000000"` |
| `gt` | Greater than | `"0"` |
| `gte` | Greater than or equal | `"100000000000000000"` |
| `in` | Value in array | `["0x123...", "0x456..."]` |
| `in_condition_set` | Value in condition set | `"condition-set-uuid"` |

See [Field Sources](./field-sources.md) for detailed operator examples.

## Example Policies

### Allow All Transactions

```json
{
  "version": "1.0",
  "name": "Allow all",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow everything",
      "method": "*",
      "conditions": [],
      "action": "ALLOW"
    }
  ]
}
```

### Value Limit

```json
{
  "version": "1.0",
  "name": "Max 1 ETH per transaction",
  "chain_type": "ethereum",
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
```

### Address Whitelist

```json
{
  "version": "1.0",
  "name": "Trusted addresses only",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow transfers to trusted addresses",
      "method": "*",
      "conditions": [
        {
          "field_source": "ethereum_transaction",
          "field": "to",
          "operator": "in",
          "value": [
            "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
            "0x1111111254EEB25477B68fb85Ed929f73A960582"
          ]
        }
      ],
      "action": "ALLOW"
    }
  ]
}
```

### Combined Conditions

```json
{
  "version": "1.0",
  "name": "Limited DEX trading",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow small swaps on Uniswap",
      "method": "*",
      "conditions": [
        {
          "field_source": "ethereum_transaction",
          "field": "to",
          "operator": "eq",
          "value": "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        },
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
```

### EIP-712 Typed Data Constraints

```json
{
  "version": "1.0",
  "name": "Permit only for specific contract",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow EIP-2612 permits for USDC only",
      "method": "eth_signTypedData_v4",
      "conditions": [
        {
          "field_source": "ethereum_typed_data_domain",
          "field": "verifyingContract",
          "operator": "eq",
          "value": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
        }
      ],
      "action": "ALLOW"
    }
  ]
}
```

### Using Condition Sets

```json
{
  "version": "1.0",
  "name": "Trading policy with reusable address set",
  "chain_type": "ethereum",
  "rules": [
    {
      "name": "Allow interactions with approved DEXes",
      "method": "*",
      "conditions": [
        {
          "field_source": "ethereum_transaction",
          "field": "to",
          "operator": "in_condition_set",
          "value": "approved-dex-addresses-uuid"
        }
      ],
      "action": "ALLOW"
    }
  ]
}
```

## Creating Policies

### API Request

```bash
curl -X POST "http://localhost:8080/v1/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My trading policy",
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [
        {
          "name": "Allow small trades",
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
  }'
```

### Response

```json
{
  "id": "policy-uuid",
  "name": "My trading policy",
  "chain_type": "ethereum",
  "version": "1.0",
  "owner_id": null,
  "created_at": "2025-01-15T10:00:00Z"
}
```

## Attaching Policies to Wallets

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "policy_id": "policy-uuid"
  }'
```

A wallet can have multiple policies. **All policies must allow** for an operation to proceed.

## Policy Ownership

### App-Owned Policies

Policies with `owner_id: null` are owned by the app and can be modified without authorization signatures:

```json
{
  "id": "policy-uuid",
  "name": "App default policy",
  "owner_id": null
}
```

### User-Owned Policies

Policies with an `owner_id` require authorization signatures to modify:

```json
{
  "id": "policy-uuid",
  "name": "User's custom policy",
  "owner_id": "auth-key-uuid"
}
```

## Policy Evaluation Flow

```
1. Wallet owner initiates signing request

2. System loads all policies attached to wallet

3. For session signers, also load override policy (if set)

4. For each policy:
   a. Iterate through rules in order
   b. For each rule:
      - Check if method matches
      - Evaluate all conditions (AND logic)
      - If all conditions match, apply action
   c. If no rules match, apply default DENY

5. If ALL policies return ALLOW, proceed to signing
   If ANY policy returns DENY, reject with reason
```

## Debugging Policy Denials

When a request is denied, the response includes details:

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied by policy",
    "details": {
      "policy_id": "policy-uuid",
      "policy_name": "Max 1 ETH per transaction",
      "rule_name": "Allow transactions up to 1 ETH",
      "reason": "Condition failed: value (2000000000000000000) > 1000000000000000000"
    }
  }
}
```

See [Policy Examples](./examples.md) for more complex patterns.

## Best Practices

### 1. Start Restrictive

Begin with restrictive policies and expand as needed:

```json
{
  "rules": [
    {
      "name": "Allow specific contract",
      "conditions": [{"field": "to", "operator": "eq", "value": "0x..."}],
      "action": "ALLOW"
    }
    // No catch-all ALLOW = default deny
  ]
}
```

### 2. Use Meaningful Names

```json
{
  "name": "Allow Uniswap V3 swaps up to 0.1 ETH on mainnet",
  "rules": [
    {
      "name": "Uniswap V3 Router - small swaps",
      ...
    }
  ]
}
```

### 3. Leverage Condition Sets

For frequently updated address lists:

```bash
# Create condition set
curl -X POST "http://localhost:8080/v1/condition_sets" \
  -d '{"name": "Approved DEXes", "values": ["0x...", "0x..."]}'

# Use in policy
{"operator": "in_condition_set", "value": "condition-set-uuid"}
```

### 4. Test Before Deployment

Use the policy validation endpoint:

```bash
curl -X POST "http://localhost:8080/v1/policies/validate" \
  -d '{"rules": {...}}'
```

### 5. Consider Time-Based Rules

For time-limited operations:

```json
{
  "conditions": [
    {
      "field_source": "system",
      "field": "current_unix_timestamp",
      "operator": "lte",
      "value": "1735689600"
    }
  ]
}
```

## Next Steps

- [Field Sources](./field-sources.md) - All available field sources and operators
- [Policy Examples](./examples.md) - Real-world policy patterns
- [Condition Sets API](../api-reference/endpoints/condition-sets.md) - Reusable value sets
- [Policies API](../api-reference/endpoints/policies.md) - Policy endpoints
