# Managing Wallets

Guide to listing, retrieving, updating, and managing wallet lifecycle.

## Listing Wallets

### List All User Wallets

```bash
curl "http://localhost:8080/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "wallets": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "chain_type": "ethereum",
      "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "exec_backend": "kms",
      "created_at": "2025-01-15T10:00:00Z"
    },
    {
      "id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
      "chain_type": "ethereum",
      "address": "0x123456789abcdef123456789abcdef12345678",
      "exec_backend": "kms",
      "created_at": "2025-01-14T10:00:00Z"
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

### Filtering

```bash
# By chain type
curl "http://localhost:8080/v1/wallets?chain_type=ethereum"

# With pagination
curl "http://localhost:8080/v1/wallets?limit=10&offset=0"

# Combined
curl "http://localhost:8080/v1/wallets?chain_type=ethereum&limit=50"
```

### Pagination Parameters

| Parameter | Type | Default | Max | Description |
|-----------|------|---------|-----|-------------|
| `limit` | integer | 20 | 100 | Items per page |
| `offset` | integer | 0 | - | Items to skip |
| `chain_type` | string | - | - | Filter by chain |

---

## Getting Wallet Details

### Basic Request

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "user_id": "user-uuid",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "owner_id": "auth-key-uuid",
  "policies": [
    {
      "id": "policy-uuid-1",
      "name": "Trading Policy"
    },
    {
      "id": "policy-uuid-2",
      "name": "Value Limits"
    }
  ],
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Response Fields

| Field | Description |
|-------|-------------|
| `id` | Unique wallet identifier |
| `user_id` | Associated user (from JWT sub) |
| `chain_type` | Blockchain type |
| `exec_backend` | Execution backend (kms/tee) |
| `address` | On-chain wallet address |
| `owner_id` | Authorization key or quorum ID |
| `policies` | Attached policies (summary) |
| `created_at` | Creation timestamp |

---

## Attaching Policies

### Single Policy

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

### Multiple Policies

Attach policies one at a time:

```bash
for POLICY_ID in "policy-1" "policy-2" "policy-3"; do
  curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/policies" \
    -H "..." \
    -d "{\"policy_id\": \"$POLICY_ID\"}"
done
```

### Policy Evaluation Order

When multiple policies are attached:

1. **All policies must ALLOW** for the operation to proceed
2. If **any policy DENYs**, the operation is denied
3. Order of attachment doesn't matter

```
Transaction Request
     │
     ├─▶ Policy A: ALLOW
     ├─▶ Policy B: ALLOW
     ├─▶ Policy C: DENY  ──▶ DENIED
     │
     └─▶ Result: DENIED (Policy C rejected)
```

---

## Detaching Policies

```bash
curl -X DELETE "http://localhost:8080/v1/wallets/$WALLET_ID/policies/$POLICY_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT"
```

### Response

```
204 No Content
```

### Warning

Detaching all policies leaves the wallet with no access control beyond authentication. Consider always having at least one restrictive policy.

---

## Viewing Attached Policies

Policies are included in wallet details:

```bash
curl "http://localhost:8080/v1/wallets/$WALLET_ID" | jq '.policies'
```

```json
[
  {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "name": "Max 1 ETH transfers"
  },
  {
    "id": "660f9511-f39c-4b8a-9e1f-1a2b3c4d5e6f",
    "name": "Approved contracts only"
  }
]
```

---

## Wallet Status Monitoring

### Check Wallet Exists

```bash
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
  "http://localhost:8080/v1/wallets/$WALLET_ID" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT")

if [ "$HTTP_CODE" == "200" ]; then
  echo "Wallet exists"
elif [ "$HTTP_CODE" == "404" ]; then
  echo "Wallet not found"
fi
```

### Monitor Multiple Wallets

```javascript
async function getWalletStatuses(walletIds) {
  const statuses = await Promise.all(
    walletIds.map(async (id) => {
      try {
        const wallet = await getWallet(id);
        return { id, status: 'active', address: wallet.address };
      } catch (error) {
        return { id, status: 'error', error: error.message };
      }
    })
  );
  return statuses;
}
```

---

## Bulk Operations

### Export Wallet List

```bash
# Export all wallet addresses to CSV
curl "http://localhost:8080/v1/wallets?limit=100" \
  -H "..." | \
  jq -r '.wallets[] | [.id, .address, .chain_type] | @csv' > wallets.csv
```

### Batch Policy Attachment

```javascript
async function attachPolicyToAllWallets(policyId) {
  const { wallets } = await listWallets();

  for (const wallet of wallets) {
    await attachPolicy(wallet.id, policyId);
    console.log(`Attached policy to ${wallet.address}`);
  }
}
```

---

## Audit Trail

All wallet operations are logged:

```sql
-- View recent wallet operations
SELECT * FROM audit_logs
WHERE resource_type = 'wallet'
AND resource_id = 'wallet-uuid'
ORDER BY created_at DESC
LIMIT 20;
```

### Audit Events

| Event | Description |
|-------|-------------|
| `wallet.created` | Wallet was created |
| `wallet.deleted` | Wallet was deleted |
| `wallet.policy_attached` | Policy attached |
| `wallet.policy_detached` | Policy detached |
| `wallet.ownership_transferred` | Owner changed |

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `wallet_not_found` | Invalid wallet ID | Verify wallet exists |
| `not_authorized` | User doesn't own wallet | Check JWT sub |
| `policy_not_found` | Invalid policy ID | Verify policy exists |
| `policy_already_attached` | Duplicate attachment | Policy already linked |

---

## Best Practices

1. **Use pagination** for listing wallets in production
2. **Cache wallet details** client-side when appropriate
3. **Monitor policy attachments** to ensure security
4. **Review audit logs** regularly for unusual activity
5. **Document wallet purposes** for operational clarity
