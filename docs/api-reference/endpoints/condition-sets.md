# Condition Sets API

Complete reference for condition set management endpoints.

## Overview

Condition sets are reusable collections of values that can be referenced in policy rules using the `in_condition_set` operator. They enable dynamic allow/deny lists without modifying policies.

### Use Cases

- **Whitelist contracts**: Allow interactions only with approved smart contracts
- **Blocklist addresses**: Deny transactions to known malicious addresses
- **Token allowlists**: Restrict transfers to specific ERC-20 tokens
- **Chain allowlists**: Limit operations to specific networks

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/condition-sets` | Create a condition set |
| GET | `/v1/condition-sets` | List condition sets |
| GET | `/v1/condition-sets/{id}` | Get condition set details |
| PATCH | `/v1/condition-sets/{id}` | Update a condition set |
| DELETE | `/v1/condition-sets/{id}` | Delete a condition set |

---

## Create Condition Set

Create a new reusable condition set.

### Request

```
POST /v1/condition-sets
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
  "name": "Approved DEX Contracts",
  "description": "Decentralized exchanges approved for trading",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564"
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable name |
| `description` | string | No | Purpose description |
| `values` | array | Yes | List of values (strings) |

### Value Types

Condition sets store string values. Ensure consistent formatting:

| Value Type | Format | Example |
|------------|--------|---------|
| Address | Checksummed hex | `0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D` |
| Chain ID | Decimal string | `"1"`, `"137"` |
| Function selector | Hex with 0x | `"0xa9059cbb"` |
| Amount | Wei as string | `"1000000000000000000"` |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Approved DEX Contracts",
  "description": "Decentralized exchanges approved for trading",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564"
  ],
  "value_count": 3,
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/condition-sets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Approved DEX Contracts",
    "description": "Decentralized exchanges approved for trading",
    "values": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
    ]
  }'
```

---

## List Condition Sets

List all condition sets for the application.

### Request

```
GET /v1/condition-sets
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "condition_sets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Approved DEX Contracts",
      "description": "Decentralized exchanges approved for trading",
      "value_count": 3,
      "created_at": "2025-01-15T10:00:00Z"
    },
    {
      "id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
      "name": "Blocked Addresses",
      "description": "Known malicious addresses",
      "value_count": 150,
      "created_at": "2025-01-10T10:00:00Z"
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
curl "http://localhost:8080/v1/condition-sets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Get Condition Set

Get details of a specific condition set including all values.

### Request

```
GET /v1/condition-sets/{id}
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Approved DEX Contracts",
  "description": "Decentralized exchanges approved for trading",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564"
  ],
  "value_count": 3,
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": null
}
```

### Example

```bash
curl "http://localhost:8080/v1/condition-sets/$CONDITION_SET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Update Condition Set

Update an existing condition set.

### Request

```
PATCH /v1/condition-sets/{id}
```

### Body

```json
{
  "name": "Updated DEX Contracts",
  "description": "Updated list of approved DEX contracts",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    "0x1111111254fb6c44bAC0beD2854e76F90643097d"
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Updated name |
| `description` | string | No | Updated description |
| `values` | array | No | Complete replacement of values |

**Note**: When updating `values`, you must provide the complete list. This is a full replacement, not a merge.

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Updated DEX Contracts",
  "description": "Updated list of approved DEX contracts",
  "values": [
    "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
    "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F",
    "0xE592427A0AEce92De3Edee1F18E0157C05861564",
    "0x1111111254fb6c44bAC0beD2854e76F90643097d"
  ],
  "value_count": 4,
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2025-01-15T12:00:00Z"
}
```

### Example

```bash
curl -X PATCH "http://localhost:8080/v1/condition-sets/$CONDITION_SET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "values": [
      "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D",
      "0x1111111254fb6c44bAC0beD2854e76F90643097d"
    ]
  }'
```

---

## Delete Condition Set

Delete a condition set.

### Request

```
DELETE /v1/condition-sets/{id}
```

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/condition-sets/$CONDITION_SET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

**Note**: Deleting a condition set that is referenced by policies will cause those policy rules to fail evaluation. Ensure no policies reference the set before deletion.

---

## Using Condition Sets in Policies

Reference condition sets in policy rules using the `in_condition_set` operator.

### Example Policy

```json
{
  "name": "Allow approved DEX only",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow approved DEX contracts",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "to",
            "operator": "in_condition_set",
            "value": "550e8400-e29b-41d4-a716-446655440000"
          }
        ],
        "action": "ALLOW"
      },
      {
        "name": "Deny all other transactions",
        "method": "*",
        "conditions": [],
        "action": "DENY"
      }
    ]
  }
}
```

### Negation Pattern

To deny transactions to addresses in a condition set (blocklist):

```json
{
  "rules": [
    {
      "name": "Block known malicious addresses",
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
```

---

## Common Patterns

### Token Whitelist

```bash
# Create condition set of approved tokens
curl -X POST "http://localhost:8080/v1/condition-sets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Approved ERC-20 Tokens",
    "values": [
      "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
      "0xdAC17F958D2ee523a2206206994597C13D831ec7",
      "0x6B175474E89094C44Da98b954EescdeCB5BE3830"
    ]
  }'
```

### Chain Restriction

```bash
# Create condition set of allowed chains
curl -X POST "http://localhost:8080/v1/condition-sets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Production Chains",
    "values": ["1", "137", "42161"]
  }'
```

### Function Selector Filter

```bash
# Create condition set of allowed function selectors
curl -X POST "http://localhost:8080/v1/condition-sets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Allowed Functions",
    "description": "transfer, approve, and transferFrom",
    "values": [
      "0xa9059cbb",
      "0x095ea7b3",
      "0x23b872dd"
    ]
  }'
```

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 400 | `empty_values` | Values array is empty |
| 401 | `invalid_token` | JWT validation failed |
| 404 | `condition_set_not_found` | Condition set doesn't exist |
| 409 | `condition_set_in_use` | Set is referenced by policies |

### Example Error

```json
{
  "error": {
    "code": "condition_set_in_use",
    "message": "Condition set is referenced by policies",
    "details": {
      "referencing_policies": [
        "policy-uuid-1",
        "policy-uuid-2"
      ]
    }
  }
}
```
