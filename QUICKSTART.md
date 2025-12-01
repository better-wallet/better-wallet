# Better Wallet Quick Start Guide

Get Better Wallet up and running in under 5 minutes!

## Prerequisites

- Docker & Docker Compose installed
- Or: Go 1.21+ and PostgreSQL 15+ installed

## Option 1: Docker Compose (Recommended)

### 1. Clone and Configure

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Create environment file
cat > .env << 'EOF'
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
EOF
```

### 2. Start Services

```bash
docker-compose up -d
```

That's it! The API is now running at `http://localhost:8080`

### 3. Test the API

```bash
# Health check
curl http://localhost:8080/health

# Response: {"status":"ok"}
```

## Option 2: Local Development

### 1. Set Up Database

```bash
# Start PostgreSQL (or use existing instance)
# Database schema is managed by Drizzle in dashboard/

cd dashboard
bun install
bun run db:push  # Push schema to database
```

### 2. Configure Environment

```bash
cp .env.example .env
# Edit .env with your settings (POSTGRES_DSN, KMS_KEY_ID, etc.)

# Configure dashboard environment
cd dashboard
cp .env.example .env
# Edit dashboard/.env with app settings (auth, RPC, etc.)
```

### 3. Run the Application

```bash
# Install dependencies
go mod download

# Run
go run ./cmd/server

# Or build and run
make build
./bin/better-wallet
```

## Making Your First API Call

### 1. Get an Authentication Token

You'll need a JWT token from your OIDC provider (Auth0, Better Auth, etc.)

For testing, you can use a service like https://jwt.io or your auth provider's dashboard to generate a token.

### 2. Create a Wallet

```bash
curl -X POST http://localhost:8080/v1/wallets \
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
  "created_at": "2025-01-01T00:00:00Z"
}
```

### 3. List Your Wallets

```bash
curl http://localhost:8080/v1/wallets \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 4. Sign a Transaction

```bash
curl -X POST http://localhost:8080/v1/wallets/WALLET_ID/sign \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb",
    "value": "1000000000000000000",
    "chain_id": 1,
    "nonce": 0,
    "gas_limit": 21000,
    "gas_fee_cap": "30000000000",
    "gas_tip_cap": "2000000000"
  }'
```

## Setting Up Authentication

Authentication is configured through the Dashboard, not environment variables.

### Using the Dashboard

1. Start the dashboard: `cd dashboard && bun run dev`
2. Create an app in the dashboard
3. Configure authentication settings (OIDC issuer, audience, JWKS URI) in the app settings
4. Use the app credentials (APP_ID, APP_SECRET) in your client application

## Troubleshooting

### "Database connection failed"
```bash
# Check if PostgreSQL is running
docker ps | grep postgres

# Check connection string
echo $POSTGRES_DSN
```

### "Authentication required"
- Ensure you're sending the `Authorization: Bearer TOKEN` header
- Verify token is valid at https://jwt.io
- Check issuer and audience match your configuration

### "Port already in use"
```bash
# Change port in .env
PORT=8081

# Or kill process using port 8080
lsof -i :8080
kill -9 PID
```

## Next Steps

- Read the [README](README.md) for detailed API documentation
- Check [DEVELOPMENT.md](docs/DEVELOPMENT.md) for development setup
- Review [CONTRIBUTING.md](CONTRIBUTING.md) to contribute
- Join our Discord for support

## Common Development Commands

```bash
# Build the project
make build

# Run tests
make test

# Format code
make fmt

# Database operations (in dashboard/)
cd dashboard
bun run db:push      # Push schema changes
bun run db:studio    # Open Drizzle Studio

# Clean build artifacts
make clean

# View all make targets
make help
```

## Production Deployment

For production deployment:

1. Use proper KMS/HSM for key management
2. Enable SSL/TLS
3. Configure proper database credentials
4. Set up monitoring and logging
5. Review security best practices in docs
6. Enable rate limiting
7. Set up backup and recovery

See [docs/DEPLOYMENT.md](docs/design/07-DEPLOYMENT.md) for detailed deployment guides.

## Support

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Discord**: Real-time help
- **Email**: contact@better-wallet.com

Happy building! 🚀
