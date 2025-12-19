# Docker Compose Deployment

This guide covers deploying Better Wallet using Docker Compose for development and production environments.

## Prerequisites

- Docker 24.0+
- Docker Compose v2.0+
- Git

## Development Setup

### Quick Start

```bash
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Create environment file
cat > .env << 'EOF'
KMS_KEY_ID=dev-master-key-12345678901234567890123456789012
EOF

# Start services
docker-compose up -d

# Verify
curl http://localhost:8080/health
```

### Development Configuration

The default `docker-compose.yml` is optimized for development:

```yaml
version: '3.8'

services:
  better-wallet:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8080:8080"
    environment:
      - POSTGRES_DSN=postgres://postgres:postgres@postgres:5432/better_wallet?sslmode=disable
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=local
      - KMS_LOCAL_MASTER_KEY=${KMS_KEY_ID}
      - LOG_LEVEL=debug
    depends_on:
      postgres:
        condition: service_healthy
    volumes:
      - ./:/app  # Mount source for hot reload

  postgres:
    image: postgres:15-alpine
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=better_wallet
    volumes:
      - pgdata:/var/lib/postgresql/data
    ports:
      - "5432:5432"
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  pgdata:
```

### Hot Reload Development

For development with hot reload:

```bash
# Start only postgres
docker-compose up -d postgres

# Run the app locally with air
make dev
```

## Production Setup

### Production Docker Compose

Create `docker-compose.prod.yml`:

```yaml
version: '3.8'

services:
  better-wallet:
    image: ghcr.io/better-wallet/better-wallet:latest
    ports:
      - "8080:8080"
    environment:
      - POSTGRES_DSN=${POSTGRES_DSN}
      - PORT=8080
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=aws-kms
      - KMS_AWS_KEY_ID=${KMS_AWS_KEY_ID}
      - KMS_AWS_REGION=${AWS_REGION}
      - LOG_LEVEL=info
    deploy:
      replicas: 3
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
      interval: 10s
      timeout: 5s
      retries: 3
      start_period: 30s
    logging:
      driver: "json-file"
      options:
        max-size: "100m"
        max-file: "5"
    networks:
      - internal

  postgres:
    image: postgres:15
    environment:
      - POSTGRES_USER=${POSTGRES_USER}
      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
      - POSTGRES_DB=better_wallet
    volumes:
      - pgdata:/var/lib/postgresql/data
      - ./postgres/init.sql:/docker-entrypoint-initdb.d/init.sql:ro
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U ${POSTGRES_USER}"]
      interval: 10s
      timeout: 5s
      retries: 5
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
    networks:
      - internal
    # Don't expose postgres in production
    # Use internal network only

  # Optional: nginx reverse proxy
  nginx:
    image: nginx:alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
      - ./nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - better-wallet
    networks:
      - internal
      - external

networks:
  internal:
    internal: true
  external:

volumes:
  pgdata:
```

### Production Environment Variables

Create `.env.prod`:

```bash
# Database
POSTGRES_DSN=postgres://bw_user:STRONG_PASSWORD@postgres:5432/better_wallet?sslmode=require
POSTGRES_USER=bw_user
POSTGRES_PASSWORD=STRONG_PASSWORD

# AWS KMS
KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc-def-123
AWS_REGION=us-east-1

# AWS Credentials (use IAM roles in production)
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...

# Optional
LOG_LEVEL=info
```

### Deployment Commands

```bash
# Start production stack
docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d

# Scale application
docker-compose -f docker-compose.prod.yml up -d --scale better-wallet=5

# View logs
docker-compose -f docker-compose.prod.yml logs -f better-wallet

# Rolling update
docker-compose -f docker-compose.prod.yml pull better-wallet
docker-compose -f docker-compose.prod.yml up -d --no-deps better-wallet

# Stop services
docker-compose -f docker-compose.prod.yml down
```

## Nginx Configuration

Example `nginx/nginx.conf` for production:

```nginx
events {
    worker_connections 1024;
}

http {
    upstream better_wallet {
        server better-wallet:8080;
        keepalive 32;
    }

    server {
        listen 80;
        server_name _;
        return 301 https://$host$request_uri;
    }

    server {
        listen 443 ssl http2;
        server_name wallet.example.com;

        ssl_certificate /etc/nginx/certs/fullchain.pem;
        ssl_certificate_key /etc/nginx/certs/privkey.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
        ssl_prefer_server_ciphers off;

        # Security headers
        add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
        add_header X-Content-Type-Options nosniff always;
        add_header X-Frame-Options DENY always;

        location /health {
            proxy_pass http://better_wallet;
            proxy_http_version 1.1;
            access_log off;
        }

        location / {
            proxy_pass http://better_wallet;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
            proxy_set_header Connection "";
            proxy_connect_timeout 60s;
            proxy_send_timeout 60s;
            proxy_read_timeout 60s;
        }
    }
}
```

## HashiCorp Vault Integration

For Vault-based KMS:

```yaml
# docker-compose.vault.yml
version: '3.8'

services:
  better-wallet:
    image: ghcr.io/better-wallet/better-wallet:latest
    environment:
      - POSTGRES_DSN=${POSTGRES_DSN}
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=vault
      - KMS_VAULT_ADDRESS=http://vault:8200
      - KMS_VAULT_TOKEN=${VAULT_TOKEN}
      - KMS_VAULT_TRANSIT_KEY=better-wallet
    depends_on:
      - vault
      - postgres

  vault:
    image: hashicorp/vault:1.15
    cap_add:
      - IPC_LOCK
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=${VAULT_TOKEN}
    ports:
      - "8200:8200"
    volumes:
      - vault-data:/vault/data
    command: server -dev

volumes:
  vault-data:
```

Initialize Vault transit:

```bash
# Enable transit secrets engine
docker exec -it vault vault secrets enable transit

# Create encryption key
docker exec -it vault vault write -f transit/keys/better-wallet
```

## Health Checks and Monitoring

### Container Health

```bash
# Check container health
docker-compose ps

# Inspect health status
docker inspect --format='{{json .State.Health}}' better-wallet_1

# View health check logs
docker inspect --format='{{range .State.Health.Log}}{{.Output}}{{end}}' better-wallet_1
```

### Prometheus Metrics

Add a metrics sidecar:

```yaml
services:
  prometheus:
    image: prom/prometheus:latest
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"
    networks:
      - internal

  grafana:
    image: grafana/grafana:latest
    ports:
      - "3000:3000"
    volumes:
      - grafana-data:/var/lib/grafana
    networks:
      - internal

volumes:
  grafana-data:
```

## Database Management

### Schema Migrations

```bash
# Run migrations via dashboard
cd dashboard
bun run db:push

# Or connect to the database
docker-compose exec postgres psql -U postgres -d better_wallet
```

### Backups

```bash
# Create backup
docker-compose exec postgres pg_dump -U postgres better_wallet > backup-$(date +%Y%m%d).sql

# Automated backup with cron
# Add to crontab: 0 2 * * * /path/to/backup.sh
```

### Restore

```bash
# Stop application
docker-compose stop better-wallet

# Restore database
docker-compose exec -T postgres psql -U postgres better_wallet < backup-20250115.sql

# Restart application
docker-compose start better-wallet
```

## Troubleshooting

### Container Won't Start

```bash
# Check logs
docker-compose logs better-wallet

# Check environment
docker-compose config

# Verify network connectivity
docker-compose exec better-wallet ping postgres
```

### Database Connection Issues

```bash
# Test database connection
docker-compose exec better-wallet sh -c 'nc -z postgres 5432 && echo "OK"'

# Check postgres logs
docker-compose logs postgres
```

### Memory Issues

```bash
# Check container stats
docker stats

# Increase memory limits in docker-compose.yml
deploy:
  resources:
    limits:
      memory: 8G
```

### Disk Space

```bash
# Clean up unused resources
docker system prune -a

# Check volume usage
docker system df -v
```

## Next Steps

- [Environment Variables](./environment-variables.md) - Complete configuration reference
- [Monitoring](./monitoring.md) - Detailed monitoring setup
- [TLS Configuration](./tls-configuration.md) - HTTPS setup
- [Backup & Recovery](./backup-recovery.md) - Data protection
