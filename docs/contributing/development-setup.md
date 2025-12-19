# Development Setup

This guide walks you through setting up a local development environment for Better Wallet.

## Prerequisites

| Requirement | Version | Check Command |
|-------------|---------|---------------|
| Go | 1.21+ | `go version` |
| PostgreSQL | 15+ | `psql --version` |
| Node.js | 18+ | `node --version` |
| Bun | Latest | `bun --version` |
| Docker | Latest | `docker --version` |

## Quick Setup

### 1. Clone the Repository

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet
```

### 2. Start PostgreSQL

Using Docker:
```bash
docker run -d \
  --name better-wallet-db \
  -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=better_wallet \
  -p 5432:5432 \
  postgres:15
```

Or use an existing PostgreSQL instance.

### 3. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```bash
POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/better_wallet?sslmode=disable
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
PORT=8080
```

### 4. Initialize Database Schema

The database schema is managed by Drizzle in the dashboard:

```bash
cd dashboard
bun install
bun run db:push
cd ..
```

### 5. Install Go Dependencies

```bash
go mod download
```

### 6. Run the Server

```bash
# Standard run
go run ./cmd/server

# Or with hot-reload (requires air)
make dev
```

### 7. Verify Installation

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

## Project Structure

```
better-wallet/
├── cmd/
│   ├── server/          # Main application entry point
│   └── enclave/         # TEE enclave server
├── internal/
│   ├── api/             # HTTP handlers
│   ├── app/             # Business logic
│   ├── config/          # Configuration
│   ├── crypto/          # Cryptographic utilities
│   ├── keyexec/         # Key execution backends
│   ├── middleware/      # HTTP middleware
│   ├── policy/          # Policy engine
│   ├── storage/         # Database repositories
│   └── validation/      # Input validation
├── pkg/
│   ├── auth/            # Authorization utilities
│   ├── crypto/          # Shared crypto utilities
│   ├── errors/          # Error definitions
│   └── types/           # Shared types
├── dashboard/           # Next.js dashboard
│   └── src/server/db/   # Drizzle schema
├── docs/                # Documentation
└── tests/               # Test suites
```

## Development Commands

### Building

```bash
# Build binary
make build

# Build with version info
go build -ldflags "-X main.version=$(git describe --tags)" -o bin/better-wallet ./cmd/server
```

### Running

```bash
# Standard run
make run

# Hot-reload (requires air)
make dev

# With debug logging
LOG_LEVEL=debug go run ./cmd/server
```

### Testing

```bash
# Run all tests
make test

# Run with coverage
go test -cover ./...

# Run specific package
go test -v ./internal/policy

# Run specific test
go test -v ./internal/policy -run TestEvaluate

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Code Quality

```bash
# Format code
make fmt

# Run linter
make lint

# Run both
make check
```

## Database Management

### Push Schema Changes

```bash
cd dashboard
bun run db:push
```

### Open Drizzle Studio

```bash
cd dashboard
bun run db:studio
# Opens at http://localhost:4983
```

### Generate Migration (if needed)

```bash
cd dashboard
bun run db:generate
```

## Working with the Dashboard

### Start Dashboard

```bash
cd dashboard
bun install
bun run dev
# Opens at http://localhost:3000
```

### Build Dashboard

```bash
cd dashboard
bun run build
```

## IDE Setup

### VS Code

Recommended extensions:
- Go (official Go extension)
- ESLint
- Prettier
- Tailwind CSS IntelliSense

`.vscode/settings.json`:
```json
{
  "go.formatTool": "gofmt",
  "go.lintTool": "golangci-lint",
  "go.lintOnSave": "package",
  "editor.formatOnSave": true
}
```

### GoLand / IntelliJ

- Enable "Run gofmt on save"
- Configure golangci-lint as external tool

## Testing Locally

### Create Test Data

```bash
# Start the server
make run

# Create an app via dashboard
cd dashboard && bun run dev
# Navigate to http://localhost:3000 and create an app

# Note the App ID and Secret
```

### Test API Calls

```bash
# Set environment variables
export API=http://localhost:8080
export APP_ID=your-app-id
export APP_SECRET=your-app-secret

# Get a JWT from your OIDC provider
export JWT=your-jwt-token

# Create a wallet
curl -X POST "$API/v1/wallets" \
  -H "X-App-Id: $APP_ID" \
  -H "X-App-Secret: $APP_SECRET" \
  -H "Authorization: Bearer $JWT" \
  -H "Content-Type: application/json" \
  -d '{"chain_type": "ethereum", "exec_backend": "kms"}'
```

### Using Test Fixtures

```bash
# Run tests with fixtures
go test -v ./tests/integration/...
```

## Debugging

### Enable Debug Logging

```bash
LOG_LEVEL=debug go run ./cmd/server
```

### Using Delve

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug
dlv debug ./cmd/server
```

### Database Queries

```bash
# Connect to database
psql postgres://postgres:postgres@localhost:5432/better_wallet

# View recent audit logs
SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 10;

# View wallets
SELECT * FROM wallets;
```

## Common Issues

### "Database connection failed"

```bash
# Check PostgreSQL is running
docker ps | grep postgres

# Test connection
psql $POSTGRES_DSN -c "SELECT 1"
```

### "Port already in use"

```bash
# Find process
lsof -i :8080

# Kill it
kill -9 <PID>
```

### "Module not found"

```bash
# Tidy modules
go mod tidy

# Download dependencies
go mod download
```

### "Schema out of sync"

```bash
cd dashboard
bun run db:push
```

## Next Steps

- [CLAUDE.md](../../CLAUDE.md) - Project coding guidelines and architecture
- [API Reference](../api-reference/overview.md) - API documentation
- [Architecture Overview](../getting-started/architecture-overview.md) - System design
