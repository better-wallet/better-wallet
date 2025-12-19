# Deployment Overview

Better Wallet is designed for self-hosted deployment with minimal dependencies. This guide covers deployment options, infrastructure requirements, and best practices.

## Deployment Options

| Option | Best For | Complexity |
|--------|----------|------------|
| [Docker Compose](./docker-compose.md) | Development, small production | Low |
| [Kubernetes](./kubernetes.md) | Production, high availability | Medium |
| [Bare Metal](./bare-metal.md) | Maximum control | Medium |

## Infrastructure Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | 2 cores |
| Memory | 4 GB RAM |
| Storage | 20 GB SSD |
| Database | PostgreSQL 15+ |
| Network | Outbound HTTPS for RPC endpoints |

### Recommended Production

| Component | Requirement |
|-----------|-------------|
| CPU | 4+ cores |
| Memory | 8+ GB RAM |
| Storage | 100 GB SSD |
| Database | PostgreSQL 15+ (dedicated) |
| Network | VPC with private subnets |

### High Availability

| Component | Configuration |
|-----------|---------------|
| Application | 3+ instances behind load balancer |
| Database | Primary + replica(s) |
| Load Balancer | Layer 7 with health checks |
| Storage | Persistent volumes or cloud storage |

## Architecture Patterns

### Single Node

```
┌─────────────────────────────────────┐
│            Single Server            │
│  ┌───────────────────────────────┐  │
│  │     Better Wallet Process     │  │
│  └───────────────────────────────┘  │
│  ┌───────────────────────────────┐  │
│  │         PostgreSQL            │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

**Pros**: Simple, low cost
**Cons**: Single point of failure
**Use for**: Development, testing, small workloads

### Horizontal Scaling

```
┌─────────────────────────────────────────────────────────────┐
│                      Load Balancer                          │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  BW Node 1    │ │  BW Node 2    │ │  BW Node 3    │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        └─────────────────┼─────────────────┘
                          │
                ┌─────────▼─────────┐
                │    PostgreSQL     │
                │    (Primary)      │
                └─────────┬─────────┘
                          │
                ┌─────────▼─────────┐
                │    PostgreSQL     │
                │    (Replica)      │
                └───────────────────┘
```

**Pros**: High availability, horizontal scaling
**Cons**: More complex
**Use for**: Production workloads

### TEE Deployment (AWS Nitro)

```
┌─────────────────────────────────────────────────────────────┐
│                     EC2 Instance                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │           Better Wallet (Parent Process)               │  │
│  │   Interface → Application → Policy → [TEE Client]     │  │
│  └───────────────────────────────┬───────────────────────┘  │
│                                  │ vsock                    │
│  ┌───────────────────────────────▼───────────────────────┐  │
│  │                  Nitro Enclave                         │  │
│  │   • Sealed key storage                                │  │
│  │   • Key reconstruction                                │  │
│  │   • Transaction signing                               │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Pros**: Maximum security, hardware isolation
**Cons**: AWS-specific, more complex
**Use for**: High-security requirements

## Configuration Overview

### Environment Variables

Core configuration is via environment variables:

```bash
# Required
POSTGRES_DSN=postgres://user:pass@localhost:5432/better_wallet?sslmode=require
PORT=8080

# Execution Backend
EXECUTION_BACKEND=kms  # or tee

# KMS Provider (when EXECUTION_BACKEND=kms)
KMS_PROVIDER=aws-kms   # local, aws-kms, vault
KMS_AWS_KEY_ID=arn:aws:kms:region:account:key/key-id
KMS_AWS_REGION=us-east-1

# TEE (when EXECUTION_BACKEND=tee)
TEE_PLATFORM=aws-nitro
TEE_VSOCK_CID=16
TEE_VSOCK_PORT=5000
TEE_MASTER_KEY_HEX=<32-byte-hex>
```

See [Environment Variables](./environment-variables.md) for complete reference.

### Per-App Configuration

Application-specific settings are stored in the database and managed via the Dashboard:

- Authentication (OIDC issuer, audience, JWKS)
- RPC endpoints per chain
- Rate limits

## Quick Start Deployments

### Docker Compose (Development)

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

cat > .env << 'EOF'
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
EOF

docker-compose up -d
curl http://localhost:8080/health
```

### Docker Compose (Production)

```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  better-wallet:
    image: ghcr.io/better-wallet/better-wallet:latest
    ports:
      - "8080:8080"
    environment:
      - POSTGRES_DSN=${POSTGRES_DSN}
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=aws-kms
      - KMS_AWS_KEY_ID=${KMS_AWS_KEY_ID}
      - KMS_AWS_REGION=${AWS_REGION}
    deploy:
      replicas: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3

  postgres:
    image: postgres:15
    volumes:
      - pgdata:/var/lib/postgresql/data
    environment:
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=better_wallet

volumes:
  pgdata:
```

### Kubernetes (Helm)

```bash
helm repo add better-wallet https://charts.better-wallet.com
helm install better-wallet better-wallet/better-wallet \
  --set postgresql.enabled=true \
  --set kms.provider=aws-kms \
  --set kms.awsKeyId=$KMS_KEY_ID
```

## Security Checklist

### Pre-Deployment

- [ ] Use strong KMS provider (AWS KMS, Vault) in production
- [ ] Enable TLS/HTTPS
- [ ] Configure secure database credentials
- [ ] Set up network isolation (VPC/private subnets)
- [ ] Review and customize default policies

### Post-Deployment

- [ ] Enable monitoring and alerting
- [ ] Configure log aggregation
- [ ] Set up database backups
- [ ] Test disaster recovery procedures
- [ ] Document operational runbooks

### Ongoing

- [ ] Rotate secrets regularly
- [ ] Apply security patches promptly
- [ ] Review audit logs
- [ ] Conduct periodic security assessments

## Monitoring

### Health Check

```bash
curl http://localhost:8080/health
# {"status":"ok"}
```

### Key Metrics to Monitor

| Metric | Description | Alert Threshold |
|--------|-------------|-----------------|
| Request latency | P99 response time | > 500ms |
| Error rate | 4xx/5xx responses | > 1% |
| Database connections | Active connections | > 80% pool |
| Signing latency | Key reconstruction + sign | > 200ms |
| Memory usage | Process memory | > 80% available |

### Logging

Better Wallet outputs structured JSON logs:

```json
{
  "level": "info",
  "msg": "Request completed",
  "method": "POST",
  "path": "/v1/wallets",
  "status": 201,
  "duration_ms": 45,
  "trace_id": "abc123"
}
```

See [Monitoring](./monitoring.md) for detailed setup.

## Backup and Recovery

### Database Backup

```bash
# Daily backup
pg_dump -h localhost -U postgres better_wallet > backup-$(date +%Y%m%d).sql

# Restore
psql -h localhost -U postgres better_wallet < backup-20250115.sql
```

### Key Material

Key shares are encrypted and stored in:
1. PostgreSQL (auth_share)
2. KMS/TEE (exec_share)

Backup both:
- Database: Regular pg_dump backups
- KMS: Managed by provider (AWS KMS has automatic replication)

See [Backup and Recovery](./backup-recovery.md) for detailed procedures.

## Upgrade Process

### Rolling Update

```bash
# Pull latest image
docker pull ghcr.io/better-wallet/better-wallet:latest

# Rolling restart (zero downtime with 3+ replicas)
docker-compose up -d --no-deps better-wallet
```

### Database Migrations

Schema changes are managed by Drizzle in the dashboard:

```bash
cd dashboard
bun run db:push
```

## Troubleshooting

### Common Issues

| Symptom | Likely Cause | Solution |
|---------|--------------|----------|
| Connection refused | Service not running | Check docker/systemd status |
| 401 Unauthorized | Invalid credentials | Verify app ID/secret |
| 500 Internal Error | KMS/DB issue | Check logs, connectivity |
| High latency | Database contention | Check indexes, connections |

### Debug Mode

```bash
# Enable verbose logging
export LOG_LEVEL=debug
./better-wallet
```

### Health Check Details

```bash
# Detailed health check (if implemented)
curl http://localhost:8080/health?verbose=true
```

## Next Steps

Choose your deployment method:

- [Docker Compose](./docker-compose.md) - Quick setup
- [Kubernetes](./kubernetes.md) - Production orchestration
- [Bare Metal](./bare-metal.md) - Systemd services
- [Environment Variables](./environment-variables.md) - Configuration reference
- [TLS Configuration](./tls-configuration.md) - HTTPS setup
