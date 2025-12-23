# Transaction Signing

Detailed guide to signing Ethereum transactions with Better Wallet.

## Transaction Types

All signing operations use the unified `/rpc` endpoint with JSON-RPC 2.0 format.

### EIP-1559 Transactions (Recommended)

Modern transaction format with dynamic fee market:

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "value": "0xde0b6b3a7640000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x5208",
      "max_fee_per_gas": "0x6fc23ac00",
      "max_priority_fee_per_gas": "0x77359400"
    }],
    "id": 1
  }'
```

### Legacy Transactions

For networks without EIP-1559 support:

```bash
curl -X POST "http://localhost:8080/v1/wallets/$WALLET_ID/rpc" \
  -H "..." \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_sendTransaction",
    "params": [{
      "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
      "value": "0xde0b6b3a7640000",
      "chain_id": 1,
      "nonce": "0x0",
      "gas_limit": "0x5208",
      "gas_price": "0x4a817c800"
    }],
    "id": 1
  }'
```

---

## Request Parameters

### Required Fields

| Parameter | Type | Description |
|-----------|------|-------------|
| `to` | string | Recipient address (checksummed hex) |
| `value` | string | Transfer amount in wei |
| `chain_id` | integer | Network chain ID |
| `nonce` | integer | Transaction sequence number |
| `gas_limit` | integer | Maximum gas units |

### Gas Parameters (EIP-1559)

| Parameter | Type | Description |
|-----------|------|-------------|
| `gas_fee_cap` | string | Maximum total fee per gas (wei) |
| `gas_tip_cap` | string | Maximum priority fee per gas (wei) |

### Gas Parameters (Legacy)

| Parameter | Type | Description |
|-----------|------|-------------|
| `gas_price` | string | Gas price in wei |

### Optional Fields

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `data` | string | `""` | Contract call data (hex) |

---

## Response Format

```json
{
  "signed_transaction": "0x02f87001808477359400850708d7c00082520894742d35cc6634c0532925a3b844bc9e7595f0beb88de0b6b3a764000080c001a0...",
  "tx_hash": "0xabc123def456789..."
}
```

| Field | Description |
|-------|-------------|
| `signed_transaction` | RLP-encoded signed transaction (hex) |
| `tx_hash` | Transaction hash for tracking |

---

## Common Transaction Types

### ETH Transfer

```json
{
  "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "value": "1000000000000000000",
  "chain_id": 1,
  "nonce": 0,
  "gas_limit": 21000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": ""
}
```

### ERC-20 Transfer

```json
{
  "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "value": "0",
  "chain_id": 1,
  "nonce": 1,
  "gas_limit": 65000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": "0xa9059cbb000000000000000000000000RECIPIENT_ADDRESS_PADDED000000000000000000000000000000000000000000000000000000000000AMOUNT_PADDED"
}
```

### ERC-20 Approve

```json
{
  "to": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
  "value": "0",
  "chain_id": 1,
  "nonce": 2,
  "gas_limit": 50000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": "0x095ea7b3000000000000000000000000SPENDER_ADDRESS_PADDED000000000000000000000000000000000000000000000000000000000000AMOUNT_PADDED"
}
```

### Contract Deployment

```json
{
  "to": "",
  "value": "0",
  "chain_id": 1,
  "nonce": 3,
  "gas_limit": 2000000,
  "gas_fee_cap": "30000000000",
  "gas_tip_cap": "2000000000",
  "data": "0x608060405234801561001057600080fd5b50..."
}
```

---

## Building Transaction Data

### Using ethers.js

```javascript
const { ethers } = require('ethers');

// ERC-20 transfer
const iface = new ethers.Interface([
  'function transfer(address to, uint256 amount)'
]);

const data = iface.encodeFunctionData('transfer', [
  '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
  ethers.parseUnits('100', 6) // 100 USDC
]);

// Sign with Better Wallet
const signedTx = await fetch('/v1/wallets/' + walletId + '/rpc', {
  method: 'POST',
  headers: { ... },
  body: JSON.stringify({
    jsonrpc: '2.0',
    method: 'eth_sendTransaction',
    params: [{
      to: USDC_ADDRESS,
      value: '0x0',
      chain_id: 1,
      nonce: '0x' + (await getNonce(walletAddress)).toString(16),
      gas_limit: '0xfde8',
      max_fee_per_gas: '0x6fc23ac00',
      max_priority_fee_per_gas: '0x77359400',
      data: data
    }],
    id: 1
  })
});
```

### Using web3.js

```javascript
const Web3 = require('web3');

const contract = new web3.eth.Contract(ERC20_ABI, USDC_ADDRESS);
const data = contract.methods.transfer(recipient, amount).encodeABI();
```

---

## Gas Estimation

### Get Current Gas Prices

```javascript
const provider = new ethers.JsonRpcProvider(RPC_URL);

// EIP-1559
const feeData = await provider.getFeeData();
const gasFeeСap = feeData.maxFeePerGas;
const gasTipCap = feeData.maxPriorityFeePerGas;

// Legacy
const gasPrice = await provider.getGasPrice();
```

### Estimate Gas Limit

```javascript
const gasLimit = await provider.estimateGas({
  from: walletAddress,
  to: recipient,
  value: ethers.parseEther('1.0'),
  data: callData
});

// Add 20% buffer
const safeGasLimit = gasLimit * 120n / 100n;
```

---

## Nonce Management

### Get Current Nonce

```javascript
const nonce = await provider.getTransactionCount(walletAddress);
```

### Handling Pending Transactions

```javascript
// Get nonce including pending transactions
const pendingNonce = await provider.getTransactionCount(
  walletAddress,
  'pending'
);
```

### Sequential Transactions

```javascript
async function signMultipleTransactions(walletId, transactions) {
  let nonce = await provider.getTransactionCount(walletAddress);
  const signed = [];

  for (const tx of transactions) {
    const result = await signTransaction(walletId, {
      ...tx,
      nonce: nonce++
    });
    signed.push(result);
  }

  return signed;
}
```

---

## Chain ID Reference

| Network | Chain ID | Type |
|---------|----------|------|
| Ethereum Mainnet | 1 | Production |
| Sepolia | 11155111 | Testnet |
| Polygon | 137 | Production |
| Arbitrum One | 42161 | Production |
| Optimism | 10 | Production |
| Base | 8453 | Production |

---

## Broadcasting Transactions

After signing, broadcast to the network:

```javascript
const { signed_transaction, tx_hash } = await signTransaction(walletId, tx);

// Broadcast using ethers.js
const provider = new ethers.JsonRpcProvider(RPC_URL);
const receipt = await provider.broadcastTransaction(signed_transaction);

console.log('Transaction hash:', receipt.hash);

// Wait for confirmation
const confirmed = await receipt.wait(1);
console.log('Confirmed in block:', confirmed.blockNumber);
```

---

## Policy Considerations

Transaction signing passes through the policy engine:

```json
{
  "rules": [
    {
      "name": "Limit ETH transfers",
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

### Available Policy Fields

| Field | Description |
|-------|-------------|
| `to` | Recipient address |
| `value` | Transfer value (wei) |
| `from` | Sender address (wallet) |
| `data` | Call data |
| `chain_id` | Network chain ID |
| `gas_limit` | Gas limit |

---

## Error Handling

| Error Code | Cause | Solution |
|------------|-------|----------|
| `policy_denied` | Policy rejected transaction | Check policy rules |
| `invalid_nonce` | Nonce mismatch | Get current nonce |
| `invalid_chain_id` | Unsupported network | Check supported chains |
| `invalid_address` | Malformed address | Verify checksum |
| `gas_too_low` | Gas limit insufficient | Estimate gas properly |

### Error Response

```json
{
  "error": {
    "code": "policy_denied",
    "message": "Transaction denied by policy",
    "details": {
      "policy_id": "policy-uuid",
      "rule_name": "Value limit",
      "reason": "value 2000000000000000000 exceeds limit 1000000000000000000"
    }
  }
}
```

---

## Best Practices

1. **Always estimate gas** before signing
2. **Use EIP-1559** for better fee predictability
3. **Handle nonce carefully** for sequential transactions
4. **Simulate transactions** before signing to catch errors
5. **Set appropriate gas buffers** (10-20% over estimate)
6. **Verify chain ID** matches intended network
