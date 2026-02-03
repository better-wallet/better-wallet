# Quick Start

Get Better Wallet running in under 5 minutes.

## Prerequisites

- Go 1.21+
- PostgreSQL 15+
- Node.js 18+ (for database schema management)

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet
```

### 2. Set Up the Database

```bash
# Create database
createdb better_wallet

# Install dashboard dependencies and push schema
cd dashboard
bun install
bun run db:push
cd ..
```

### 3. Configure Environment

```bash
cat > .env << 'EOF'
# Database
POSTGRES_DSN=postgres://user:pass@localhost:5432/better_wallet?sslmode=disable

# Key execution backend
EXECUTION_BACKEND=kms
KMS_PROVIDER=local
KMS_MASTER_KEY=$(openssl rand -hex 32)

# Optional: EVM RPC for chain operations
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# Server
PORT=8080
EOF
```

### 4. Build and Run

```bash
go build -o bin/server ./cmd/server
./bin/server
```

You should see:
```
INFO connected to database
INFO initialized key executor backend=kms
INFO server started port=8080
```

## First Steps

### 1. Create a Principal

First, you need a Principal (human/org) account. This is typically done through the dashboard or a bootstrap script.

For development, you can use the dashboard at `http://localhost:3000` or create directly in the database.

### 2. Get Your Principal API Key

After creating a Principal, you'll receive an API key:
```
aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy
```

Save this securely - the secret part is only shown once.

### 3. Create an Agent Wallet

```bash
curl -X POST http://localhost:8080/v1/wallets \
  -H "Authorization: Bearer aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My First Agent Wallet",
    "chain_type": "evm"
  }'
```

Response:
```json
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "name": "My First Agent Wallet",
  "chain_type": "evm",
  "address": "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
  "status": "active",
  "created_at": "2026-02-02T10:00:00Z"
}
```

### 4. Create an Agent Credential

```bash
curl -X POST http://localhost:8080/v1/wallets/550e8400-e29b-41d4-a716-446655440000/credentials \
  -H "Authorization: Bearer aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Agent",
    "capabilities": {
      "operations": ["transfer", "sign_message"]
    },
    "limits": {
      "max_value_per_tx": "1000000000000000000",
      "max_tx_per_hour": 10
    }
  }'
```

Response:
```json
{
  "id": "660e8400-e29b-41d4-a716-446655440001",
  "credential": "aw_ag_xxxxxxxxxxxx.zzzzzzzzzzzzzzzzzzzzzzzz",
  "name": "Test Agent",
  "capabilities": {
    "operations": ["transfer", "sign_message"]
  },
  "limits": {
    "max_value_per_tx": "1000000000000000000",
    "max_tx_per_hour": 10
  },
  "status": "active",
  "created_at": "2026-02-02T10:01:00Z"
}
```

**Important**: Save the `credential` value - the secret part is only shown once!

### 5. Use the Agent Credential

Now your AI agent can use this credential to sign transactions:

```bash
# Get wallet address
curl -X POST http://localhost:8080/v1/agent/rpc \
  -H "Authorization: Bearer aw_ag_xxxxxxxxxxxx.zzzzzzzzzzzzzzzzzzzzzzzz" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "eth_accounts",
    "params": [],
    "id": 1
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": ["0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
  "id": 1
}
```

```bash
# Sign a message
curl -X POST http://localhost:8080/v1/agent/rpc \
  -H "Authorization: Bearer aw_ag_xxxxxxxxxxxx.zzzzzzzzzzzzzzzzzzzzzzzz" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "personal_sign",
    "params": ["0x48656c6c6f20576f726c64", "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"],
    "id": 2
  }'
```

Response:
```json
{
  "jsonrpc": "2.0",
  "result": "0x...(signature)",
  "id": 2
}
```

### 6. Revoke Access (When Needed)

If you need to stop an agent:

```bash
# Pause (can resume later)
curl -X POST http://localhost:8080/v1/credentials/660e8400-e29b-41d4-a716-446655440001/pause \
  -H "Authorization: Bearer aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy"

# Or revoke permanently
curl -X POST http://localhost:8080/v1/credentials/660e8400-e29b-41d4-a716-446655440001/revoke \
  -H "Authorization: Bearer aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy"

# Emergency: Kill the entire wallet (blocks ALL credentials)
curl -X POST http://localhost:8080/v1/wallets/550e8400-e29b-41d4-a716-446655440000/kill \
  -H "Authorization: Bearer aw_pk_xxxxxxxxxxxx.yyyyyyyyyyyyyyyyyyyyyyyy"
```

## Docker Setup

For production, use Docker:

```bash
# Build
docker build -t better-wallet .

# Run
docker run -d \
  -p 8080:8080 \
  -e POSTGRES_DSN="postgres://..." \
  -e EXECUTION_BACKEND=kms \
  -e KMS_PROVIDER=aws \
  -e AWS_KMS_KEY_ID="arn:aws:kms:..." \
  -e RPC_URL="https://..." \
  better-wallet
```

Or use docker-compose:

```bash
docker-compose up -d
```

## Next Steps

- [API Reference](./api-reference.md) - Complete API documentation
- [Overview](./overview.md) - Understand the architecture
- [Deployment Guide](../deployment/overview.md) - Production deployment
