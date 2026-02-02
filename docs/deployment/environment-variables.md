# Environment Variables Reference

This document provides a complete reference for all environment variables used to configure Better Wallet.

## Core Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `PORT` | No | `8080` | HTTP server port |
| `POSTGRES_DSN` | Yes | - | PostgreSQL connection string |
| `EXECUTION_BACKEND` | No | `kms` | Execution backend (`kms` or `tee`) |
| `RPC_URL` | No | - | EVM RPC URL for chain operations |
| `LOG_LEVEL` | No | `info` | Logging level (`debug`, `info`, `warn`, `error`) |

### Example

```bash
PORT=8080
POSTGRES_DSN=postgres://user:password@localhost:5432/better_wallet?sslmode=require
EXECUTION_BACKEND=kms
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
LOG_LEVEL=info
```

### RPC URL

The `RPC_URL` is optional but enables:
- Auto-fetching nonce, gas price, gas limit
- `eth_chainId` and `eth_getBalance` methods
- Transaction broadcasting via `eth_sendTransaction`

If not configured:
- Agents must provide `nonce`, `gas`, `gasPrice` in transaction params
- `eth_chainId` and `eth_getBalance` will return errors
- `eth_signTransaction` still works (returns signed tx without broadcasting)

## KMS Backend Configuration

### Provider Selection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMS_PROVIDER` | No | `local` | KMS provider (`local`, `aws-kms`, `vault`) |

### Local Provider

For development and simple deployments:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMS_KEY_ID` | Yes | - | 32-byte hex master key |
| `KMS_LOCAL_MASTER_KEY` | Yes | - | Alias for `KMS_KEY_ID` |

```bash
KMS_PROVIDER=local
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
```

### AWS KMS Provider

For production deployments with AWS:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMS_AWS_KEY_ID` | Yes | - | KMS key ID, ARN, or alias |
| `KMS_AWS_REGION` | Yes | - | AWS region |

```bash
KMS_PROVIDER=aws-kms
KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/12345678-1234-1234-1234-123456789012
KMS_AWS_REGION=us-east-1
```

AWS credentials are loaded from the default credential chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`)
2. Shared credentials file (`~/.aws/credentials`)
3. IAM instance role

### HashiCorp Vault Provider

For production deployments with Vault:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KMS_VAULT_ADDRESS` | Yes | - | Vault server URL |
| `KMS_VAULT_TOKEN` | Yes | - | Vault authentication token |
| `KMS_VAULT_TRANSIT_KEY` | Yes | - | Transit engine key name |

```bash
KMS_PROVIDER=vault
KMS_VAULT_ADDRESS=https://vault.example.com:8200
KMS_VAULT_TOKEN=hvs.xxxxxxxxxxxxx
KMS_VAULT_TRANSIT_KEY=better-wallet-key
```

## TEE Backend Configuration

### Platform Selection

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TEE_PLATFORM` | No | `dev` | TEE platform (`dev`, `aws-nitro`) |

### Development Mode

For local development (no actual TEE):

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TEE_MASTER_KEY_HEX` | Yes | - | 32-byte hex master key |

```bash
EXECUTION_BACKEND=tee
TEE_PLATFORM=dev
TEE_MASTER_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

### AWS Nitro Enclave

For production TEE deployments:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `TEE_VSOCK_CID` | Yes | - | Enclave CID assigned by Nitro |
| `TEE_VSOCK_PORT` | No | `5000` | Enclave vsock port |
| `TEE_MASTER_KEY_HEX` | Yes | - | Master key for auth share encryption |
| `TEE_ATTESTATION_REQUIRED` | No | `true` | Require attestation verification |

```bash
EXECUTION_BACKEND=tee
TEE_PLATFORM=aws-nitro
TEE_VSOCK_CID=16
TEE_VSOCK_PORT=5000
TEE_MASTER_KEY_HEX=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
TEE_ATTESTATION_REQUIRED=true
```

## Database Configuration

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `POSTGRES_DSN` | Yes | - | Full connection string |
| `DB_MAX_CONNECTIONS` | No | `25` | Maximum connection pool size |
| `DB_MIN_CONNECTIONS` | No | `5` | Minimum connection pool size |
| `DB_MAX_CONN_LIFETIME` | No | `1h` | Maximum connection lifetime |

### Connection String Format

```
postgres://user:password@host:port/database?sslmode=require
```

### SSL Modes

| Mode | Description |
|------|-------------|
| `disable` | No SSL (development only) |
| `require` | Use SSL, don't verify certificate |
| `verify-ca` | Verify server certificate |
| `verify-full` | Verify server certificate and hostname |

### Example

```bash
POSTGRES_DSN=postgres://bw_user:secretpassword@db.example.com:5432/better_wallet?sslmode=verify-full
DB_MAX_CONNECTIONS=50
DB_MIN_CONNECTIONS=10
DB_MAX_CONN_LIFETIME=30m
```

## Security Configuration

Note: Agent Wallet uses API Key authentication (not JWT). Rate limits are configured per-credential, not globally.

## Logging

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `LOG_LEVEL` | No | `info` | Log level |
| `LOG_FORMAT` | No | `json` | Log format (`json`, `text`) |

## Complete Production Example

```bash
# Core
PORT=8080
POSTGRES_DSN=postgres://bw_prod:${DB_PASSWORD}@db.internal:5432/better_wallet?sslmode=verify-full
EXECUTION_BACKEND=kms
RPC_URL=https://eth-mainnet.g.alchemy.com/v2/${ALCHEMY_KEY}
LOG_LEVEL=info
LOG_FORMAT=json

# AWS KMS
KMS_PROVIDER=aws-kms
KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/better-wallet-prod
KMS_AWS_REGION=us-east-1

# Database tuning
DB_MAX_CONNECTIONS=100
DB_MIN_CONNECTIONS=20
DB_MAX_CONN_LIFETIME=30m
```

## Development Example

```bash
# Core
PORT=8080
POSTGRES_DSN=postgres://postgres:postgres@localhost:5432/better_wallet?sslmode=disable
EXECUTION_BACKEND=kms
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
LOG_LEVEL=debug
LOG_FORMAT=text

# Local KMS
KMS_PROVIDER=local
KMS_MASTER_KEY=$(openssl rand -hex 32)
```

## Docker Compose Environment

```yaml
services:
  better-wallet:
    environment:
      - PORT=8080
      - POSTGRES_DSN=postgres://postgres:postgres@db:5432/better_wallet?sslmode=disable
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=local
      - KMS_MASTER_KEY=${KMS_MASTER_KEY}
      - RPC_URL=${RPC_URL}
```

## Kubernetes ConfigMap/Secret

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: better-wallet-config
data:
  PORT: "8080"
  EXECUTION_BACKEND: "kms"
  KMS_PROVIDER: "aws-kms"
  KMS_AWS_REGION: "us-east-1"
---
apiVersion: v1
kind: Secret
metadata:
  name: better-wallet-secrets
stringData:
  POSTGRES_DSN: "postgres://user:pass@host:5432/db"
  KMS_AWS_KEY_ID: "arn:aws:kms:..."
  RPC_URL: "https://eth-mainnet.g.alchemy.com/v2/..."
```

## Validation

Better Wallet validates configuration at startup. Invalid configuration causes immediate exit with an error message:

```
Error: invalid configuration: POSTGRES_DSN is required
Error: invalid configuration: KMS_MASTER_KEY is required for local provider
```
