# Session Policy Overrides

Guide to using policy overrides with session signers.

## Overview

Session signers can use a **policy override** that replaces the wallet's attached policies during evaluation. This enables:

- More restrictive policies for automated signers
- Different rules per use case without modifying wallet policies
- Temporary policy changes for specific sessions

---

## How Policy Overrides Work

### Without Override

```
Session Signer Request
         │
         ▼
┌─────────────────────────┐
│   Wallet Policies       │
│   • Policy A            │
│   • Policy B            │
│   • Policy C            │
└─────────────────────────┘
         │
    Evaluate all
         │
         ▼
    Allow/Deny
```

### With Override

```
Session Signer Request
         │
         ▼
┌─────────────────────────┐
│   Override Policy       │  ← Replaces wallet policies
│   (from session)        │
└─────────────────────────┘
         │
    Evaluate only this
         │
         ▼
    Allow/Deny
```

---

## Creating Policy Overrides

### Step 1: Create Override Policy

```bash
curl -X POST "http://localhost:8080/v1/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Trading Bot Policy",
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [
        {
          "name": "Allow only Uniswap V2",
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
        }
      ]
    }
  }'
```

### Step 2: Create Session with Override

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/session_signers" \
  -H "..." \
  -d '{
    "signer_id": "'$SIGNER_KEY_ID'",
    "expires_at": "2025-01-22T10:00:00Z",
    "policy_override_id": "'$OVERRIDE_POLICY_ID'"
  }'
```

---

## Override vs Wallet Policies

| Aspect | Wallet Policies | Override Policy |
|--------|-----------------|-----------------|
| Applied to | All wallet operations | Only this session |
| Multiple policies | Yes, all must ALLOW | No, single policy |
| Modification | Requires wallet access | Requires session creation |
| Persistence | Until detached | Until session expires |

---

## Common Override Patterns

### Contract-Specific Override

Allow only specific contract interactions:

```json
{
  "name": "DEX-only policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow Uniswap V2",
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
        "name": "Allow Uniswap V3",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "eq",
            "value": "0xE592427A0AEce92De3Edee1F18E0157C05861564"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Function-Specific Override

Allow only specific function calls:

```json
{
  "name": "Swap-only policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow swap functions",
        "conditions": [
          {
            "field_source": "ethereum_calldata",
            "field": "function_selector",
            "operator": "in",
            "value": [
              "0x38ed1739",
              "0x7ff36ab5",
              "0x18cbafe5"
            ]
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

### Value-Capped Override

Add value limits on top of contract restrictions:

```json
{
  "name": "Small trades policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow small swaps on Uniswap",
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
}
```

### Chain-Restricted Override

Limit to specific networks:

```json
{
  "name": "Mainnet-only policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow mainnet only",
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
    ]
  }
}
```

---

## Combined with Session Limits

Override policies work alongside session limits:

```json
{
  "wallet_id": "wallet-uuid",
  "signer_id": "signer-key-uuid",
  "expires_at": "2025-01-22T10:00:00Z",
  "max_value": "10000000000000000000",
  "max_txs": 100,
  "policy_override_id": "restrictive-policy-uuid"
}
```

**Evaluation order:**

1. Check session expiration
2. Check session value/tx limits
3. Evaluate override policy
4. If all pass, sign transaction

---

## Using Condition Sets

Override policies can reference condition sets:

```json
{
  "name": "Approved contracts policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow approved contracts",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "approved-contracts-uuid"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

This allows updating the approved contract list without modifying the policy.

---

## Override Policy Ownership

Override policies can have owners for protection:

```bash
# Create owned policy (requires owner signature to modify)
curl -X POST "http://localhost:8080/v1/policies" \
  -H "..." \
  -d '{
    "name": "Protected bot policy",
    "owner_id": "'$AUTH_KEY_ID'",
    "chain_type": "ethereum",
    "rules": {...}
  }'
```

Owned policies require authorization signatures to update or delete.

---

## Best Practices

### 1. More Restrictive Than Wallet

Override should be stricter than wallet policies:

```
Wallet Policy: Allow up to 10 ETH transfers
Override Policy: Allow up to 0.1 ETH to specific contracts only
```

### 2. Explicit Deny Default

Always end with implicit deny (no catch-all ALLOW):

```json
{
  "rules": [
    { "name": "Specific allow rule", "action": "ALLOW", ... },
    { "name": "Specific allow rule", "action": "ALLOW", ... }
    // No catch-all ALLOW = implicit DENY for everything else
  ]
}
```

### 3. Test Before Production

Validate override policy before creating session:

```bash
curl -X POST "http://localhost:8080/v1/policies/validate" \
  -H "..." \
  -d '{
    "chain_type": "ethereum",
    "rules": {...}
  }'
```

### 4. Document Policy Purpose

Use descriptive names:

```json
{
  "name": "Trading Bot v2 - Uniswap Swaps Only - Max 0.1 ETH"
}
```

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `policy_not_found` | Override policy doesn't exist | Verify policy ID |
| `invalid_policy` | Policy doesn't match chain type | Check chain compatibility |
| `policy_denied` | Override policy rejected tx | Review policy rules |
