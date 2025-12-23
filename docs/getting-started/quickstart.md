# Quick Start Guide

Get Better Wallet up and running in under 5 minutes.

## Prerequisites

Choose your deployment method:

| Method | Requirements |
|--------|--------------|
| **Docker** (recommended) | Docker & Docker Compose |
| **Local Development** | Go 1.21+, PostgreSQL 15+ |

## Option 1: Docker Compose (Recommended)

### Step 1: Clone and Configure

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Create environment file with a development master key
cat > .env << 'EOF'
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
EOF
```

### Step 2: Start Services

```bash
docker-compose up -d
```

This starts:
- Better Wallet API on port 8080
- PostgreSQL database on port 5432

### Step 3: Verify Installation

```bash
curl http://localhost:8080/health
```

Expected response:
```json
{"status":"ok"}
```

## Option 2: Local Development

### Step 1: Set Up Database

Start PostgreSQL (or use an existing instance):

```bash
# Using Docker for just the database
docker run -d \
  --name better-wallet-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=better_wallet \
  -p 5432:5432 \
  postgres:15

# Push schema using Drizzle (from dashboard directory)
cd dashboard
bun install
bun run db:push
cd ..
```

### Step 2: Configure Environment

```bash
# Copy example environment
cp .env.example .env
```

Edit `.env` with your settings:

```bash
# Required
POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/better_wallet?sslmode=disable
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012

# Optional
PORT=8080
EXECUTION_BACKEND=kms
```

### Step 3: Build and Run

```bash
# Install dependencies
go mod download

# Build
make build

# Run
./bin/better-wallet
```

Or use hot-reload during development:

```bash
make dev  # Requires 'air' installed
```

## Your First API Call

### Step 1: Set Up Authentication

Better Wallet requires:
1. **App credentials** (App ID + Secret) - Created via Dashboard
2. **User JWT** - From your OIDC provider

For testing, start the dashboard to create an app:

```bash
cd dashboard
bun run dev
# Open http://localhost:3000
```

Create an app and note the `APP_ID` and `APP_SECRET`.

### Step 2: Create a Wallet

```bash
curl -X POST http://localhost:8080/v1/wallets \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "chain_type": "ethereum",
    "exec_backend": "kms"
  }'
```

Response:
```json
{
  "id": "123e4567-e89b-12d3-a456-426614174000",
  "address": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
  "chain_type": "ethereum",
  "exec_backend": "kms",
  "created_at": "2025-01-01T00:00:00Z"
}
```

### Step 3: List Wallets

```bash
curl http://localhost:8080/v1/wallets \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### Step 4: Sign a Transaction

```bash
curl -X POST http://localhost:8080/v1/wallets/{WALLET_ID}/rpc \
  -H "X-App-Id: YOUR_APP_ID" \
  -H "X-App-Secret: YOUR_APP_SECRET" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
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

Response:
```json
{
  "jsonrpc": "2.0",
  "result": {
    "signed_transaction": "0xf86c...",
    "tx_hash": "0xabc123..."
  },
  "id": 1
}
```

## Common Development Commands

```bash
# Build
make build

# Run tests
make test

# Format code
make fmt

# Database operations (in dashboard/)
cd dashboard
bun run db:push      # Push schema changes
bun run db:studio    # Open Drizzle Studio

# Clean artifacts
make clean

# View all targets
make help
```

## Troubleshooting

### "Database connection failed"

```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Test connection
psql $POSTGRES_DSN -c "SELECT 1"

# Check connection string format
echo $POSTGRES_DSN
# Should be: postgres://user:pass@host:5432/dbname?sslmode=disable
```

### "Authentication required"

- Verify `Authorization: Bearer TOKEN` header is present
- Check token validity at [jwt.io](https://jwt.io)
- Ensure issuer and audience match your app configuration

### "Port already in use"

```bash
# Find process using port 8080
lsof -i :8080

# Kill the process
kill -9 <PID>

# Or change port in .env
PORT=8081
```

### "KMS key not found"

```bash
# For local development, set a 32-byte hex key
export KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
```

## Next Steps

Now that Better Wallet is running:

1. **[Core Concepts](./core-concepts.md)** - Understand wallets, policies, and keys
2. **[Authentication Setup](../authentication/overview.md)** - Configure your OIDC provider
3. **[Policy Engine](../policies/overview.md)** - Set up access control rules
4. **[API Reference](../api-reference/overview.md)** - Explore all endpoints

## Production Deployment

For production deployments, see the [Deployment Guide](../deployment/):

- [ ] Use proper KMS/HSM (AWS KMS, HashiCorp Vault)
- [ ] Enable TLS/HTTPS
- [ ] Configure secure database credentials
- [ ] Set up monitoring and alerting
- [ ] Enable audit logging
- [ ] Configure rate limiting
- [ ] Plan backup and recovery
