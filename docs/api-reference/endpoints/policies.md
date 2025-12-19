# Policies API

Complete reference for policy management endpoints.

## Endpoints Overview

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/policies` | Create a policy |
| GET | `/v1/policies` | List policies |
| GET | `/v1/policies/{id}` | Get policy details |
| PATCH | `/v1/policies/{id}` | Update a policy |
| DELETE | `/v1/policies/{id}` | Delete a policy |
| POST | `/v1/policies/validate` | Validate policy rules |

---

## Create Policy

Create a new access control policy.

### Request

```
POST /v1/policies
```

### Headers

| Header | Required | Description |
|--------|----------|-------------|
| `X-App-Id` | Yes | Application ID |
| `X-App-Secret` | Yes | Application secret |
| `Authorization` | Optional | Bearer JWT token (optional for app-managed policies) |
| `X-Idempotency-Key` | Recommended | Unique request identifier |

> **Note:** Policies can be created without a user JWT for app-managed scenarios. The policy's `owner_id` field determines ownership regardless of how it was created.

### Body

```json
{
  "name": "Trading policy",
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow small transfers",
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
  },
  "owner_id": "auth-key-uuid"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Human-readable policy name |
| `chain_type` | string | Yes | Blockchain type (`ethereum`) |
| `rules` | object | Yes | Policy rules object |
| `owner_id` | UUID | No | Authorization key for owned policies |

### Rules Object

```json
{
  "version": "1.0",
  "rules": [
    {
      "name": "Rule description",
      "method": "*",
      "conditions": [...],
      "action": "ALLOW"
    }
  ]
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `version` | string | Yes | Always `"1.0"` |
| `rules` | array | Yes | Ordered list of rules |

### Rule Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Rule description |
| `method` | string | Yes | RPC method (`*` for any) |
| `conditions` | array | Yes | Conditions (AND logic) |
| `action` | string | Yes | `ALLOW` or `DENY` |

### Condition Object

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `field_source` | string | Yes | Data source |
| `field` | string | Yes | Field name |
| `operator` | string | Yes | Comparison operator |
| `value` | any | Yes | Expected value |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Trading policy",
  "chain_type": "ethereum",
  "version": "1.0",
  "rules": {...},
  "owner_id": "auth-key-uuid",
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/policies" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Max 1 ETH transfers",
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [
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
      ]
    }
  }'
```

---

## List Policies

List all policies for the application.

### Request

```
GET /v1/policies
```

### Query Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `chain_type` | string | - | Filter by chain type |
| `limit` | integer | 20 | Items per page (max 100) |
| `offset` | integer | 0 | Items to skip |

### Response

```json
{
  "policies": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "name": "Trading policy",
      "chain_type": "ethereum",
      "version": "1.0",
      "owner_id": null,
      "created_at": "2025-01-15T10:00:00Z"
    }
  ],
  "pagination": {
    "total": 1,
    "limit": 20,
    "offset": 0,
    "has_more": false
  }
}
```

### Example

```bash
curl "http://localhost:8080/v1/policies?chain_type=ethereum" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Get Policy

Get details of a specific policy including full rules.

### Request

```
GET /v1/policies/{id}
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Trading policy",
  "chain_type": "ethereum",
  "version": "1.0",
  "rules": {
    "version": "1.0",
    "rules": [
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
    ]
  },
  "owner_id": null,
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Example

```bash
curl "http://localhost:8080/v1/policies/$POLICY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

---

## Update Policy

Update an existing policy. Requires authorization signature if policy has an owner.

### Request

```
PATCH /v1/policies/{id}
```

### Headers (Additional for Owned Policies)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signature` | If owned | Owner's signature |
| `X-Authorization-Key-Id` | If owned | Owner's key ID |

### Body

```json
{
  "name": "Updated trading policy",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Allow transfers up to 0.5 ETH",
        "method": "*",
        "conditions": [
          {
            "field_source": "ethereum_transaction",
            "field": "value",
            "operator": "lte",
            "value": "500000000000000000"
          }
        ],
        "action": "ALLOW"
      }
    ]
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | No | Updated name |
| `rules` | object | No | Updated rules |

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "Updated trading policy",
  "chain_type": "ethereum",
  "version": "1.0",
  "rules": {...},
  "owner_id": "auth-key-uuid",
  "created_at": "2025-01-15T10:00:00Z",
  "updated_at": "2025-01-15T12:00:00Z"
}
```

### Example (Owned Policy)

```bash
curl -X PATCH "http://localhost:8080/v1/policies/$POLICY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "More restrictive policy",
    "rules": {...}
  }'
```

---

## Delete Policy

Delete a policy. Requires authorization signature if policy has an owner.

### Request

```
DELETE /v1/policies/{id}
```

### Headers (Additional for Owned Policies)

| Header | Required | Description |
|--------|----------|-------------|
| `X-Authorization-Signature` | If owned | Owner's signature |
| `X-Authorization-Key-Id` | If owned | Owner's key ID |

### Response

```
204 No Content
```

### Example

```bash
curl -X DELETE "http://localhost:8080/v1/policies/$POLICY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "X-Authorization-Signature: $SIGNATURE" \
  -H "X-Authorization-Key-Id: $OWNER_KEY_ID"
```

---

## Validate Policy

Validate policy rules without creating. Useful for testing policies before deployment.

### Request

```
POST /v1/policies/validate
```

### Body

```json
{
  "chain_type": "ethereum",
  "rules": {
    "version": "1.0",
    "rules": [
      {
        "name": "Test rule",
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

### Response (Valid)

```json
{
  "valid": true,
  "errors": []
}
```

### Response (Invalid)

```json
{
  "valid": false,
  "errors": [
    {
      "rule_index": 0,
      "field": "conditions[0].operator",
      "message": "Unknown operator: 'equals'. Use 'eq' instead."
    }
  ]
}
```

### Example

```bash
curl -X POST "http://localhost:8080/v1/policies/validate" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "rules": {
      "version": "1.0",
      "rules": [...]
    }
  }'
```

---

## Field Sources Reference

| Field Source | Description |
|--------------|-------------|
| `ethereum_transaction` | Raw transaction fields |
| `ethereum_calldata` | Decoded contract calls |
| `ethereum_typed_data_domain` | EIP-712 domain |
| `ethereum_typed_data_message` | EIP-712 message |
| `ethereum_7702_authorization` | EIP-7702 delegations |
| `ethereum_message` | Personal messages |
| `system` | System data |

## Operators Reference

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

---

## Error Responses

| Status | Code | Description |
|--------|------|-------------|
| 400 | `invalid_request` | Invalid request body |
| 400 | `invalid_policy` | Policy validation failed |
| 401 | `invalid_token` | JWT validation failed |
| 403 | `not_authorized` | Not authorized to modify |
| 403 | `invalid_signature` | Authorization signature invalid |
| 404 | `policy_not_found` | Policy doesn't exist |
| 409 | `policy_in_use` | Policy attached to wallets |

### Example Error

```json
{
  "error": {
    "code": "invalid_policy",
    "message": "Policy validation failed",
    "details": {
      "errors": [
        {
          "rule_index": 0,
          "field": "conditions[0].field_source",
          "message": "Unknown field source: 'invalid_source'"
        }
      ]
    }
  }
}
```
