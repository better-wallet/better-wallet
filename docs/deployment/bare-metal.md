# Bare Metal Deployment

This guide covers deploying Better Wallet on bare metal servers or VMs using systemd for process management.

## Prerequisites

- Linux server (Ubuntu 22.04+, Debian 12+, or RHEL 9+)
- Go 1.21+ (for building from source)
- PostgreSQL 15+
- Root or sudo access
- Network access to KMS/Vault (if using external KMS)

## System Preparation

### Create Service User

```bash
# Create dedicated user
sudo useradd --system --shell /sbin/nologin --home-dir /opt/better-wallet better-wallet

# Create directories
sudo mkdir -p /opt/better-wallet/{bin,config}
sudo chown -R better-wallet:better-wallet /opt/better-wallet
```

### Install Dependencies

```bash
# Ubuntu/Debian
sudo apt update
sudo apt install -y curl wget git build-essential

# Install Go (if building from source)
wget https://go.dev/dl/go1.21.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
```

## Build from Source

```bash
# Clone repository
git clone https://github.com/better-wallet/better-wallet.git
cd better-wallet

# Build binary
make build

# Copy binary to installation directory
sudo cp bin/better-wallet /opt/better-wallet/bin/
sudo chown better-wallet:better-wallet /opt/better-wallet/bin/better-wallet
sudo chmod 755 /opt/better-wallet/bin/better-wallet
```

Or download pre-built binary:

```bash
# Download latest release
VERSION="v1.0.0"
curl -LO "https://github.com/better-wallet/better-wallet/releases/download/${VERSION}/better-wallet-linux-amd64"
sudo mv better-wallet-linux-amd64 /opt/better-wallet/bin/better-wallet
sudo chown better-wallet:better-wallet /opt/better-wallet/bin/better-wallet
sudo chmod 755 /opt/better-wallet/bin/better-wallet
```

## PostgreSQL Setup

### Install PostgreSQL

```bash
# Ubuntu/Debian
sudo apt install -y postgresql-15

# Start and enable
sudo systemctl enable postgresql
sudo systemctl start postgresql
```

### Create Database and User

```bash
sudo -u postgres psql << 'EOF'
CREATE USER bw_user WITH PASSWORD 'STRONG_PASSWORD_HERE';
CREATE DATABASE better_wallet OWNER bw_user;
GRANT ALL PRIVILEGES ON DATABASE better_wallet TO bw_user;

-- Enable required extensions
\c better_wallet
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
EOF
```

### Configure PostgreSQL for TLS

```bash
# Generate self-signed certificates (for internal use)
sudo -u postgres openssl req -new -x509 -days 365 -nodes \
  -out /var/lib/postgresql/15/main/server.crt \
  -keyout /var/lib/postgresql/15/main/server.key \
  -subj "/CN=postgres"

sudo chmod 600 /var/lib/postgresql/15/main/server.key
sudo chown postgres:postgres /var/lib/postgresql/15/main/server.*
```

Edit `/etc/postgresql/15/main/postgresql.conf`:

```ini
ssl = on
ssl_cert_file = '/var/lib/postgresql/15/main/server.crt'
ssl_key_file = '/var/lib/postgresql/15/main/server.key'
```

Edit `/etc/postgresql/15/main/pg_hba.conf`:

```
# Require SSL for better-wallet connections
hostssl better_wallet bw_user 127.0.0.1/32 scram-sha-256
hostssl better_wallet bw_user ::1/128 scram-sha-256
```

Restart PostgreSQL:

```bash
sudo systemctl restart postgresql
```

## Configuration

### Environment File

Create `/opt/better-wallet/config/better-wallet.env`:

```bash
# Database
POSTGRES_DSN=postgres://bw_user:STRONG_PASSWORD_HERE@localhost:5432/better_wallet?sslmode=require

# Server
PORT=8080
LOG_LEVEL=info

# Execution Backend
EXECUTION_BACKEND=kms

# KMS Configuration (choose one provider)

# Option 1: Local KMS (development/testing only)
KMS_PROVIDER=local
KMS_LOCAL_MASTER_KEY=your-32-byte-master-key-in-hex-format

# Option 2: AWS KMS
# KMS_PROVIDER=aws-kms
# KMS_AWS_KEY_ID=arn:aws:kms:us-east-1:123456789:key/abc-def-123
# KMS_AWS_REGION=us-east-1
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...

# Option 3: HashiCorp Vault
# KMS_PROVIDER=vault
# KMS_VAULT_ADDRESS=https://vault.example.com:8200
# KMS_VAULT_TOKEN=hvs.xxxxx
# KMS_VAULT_TRANSIT_KEY=better-wallet
```

Set permissions:

```bash
sudo chmod 600 /opt/better-wallet/config/better-wallet.env
sudo chown better-wallet:better-wallet /opt/better-wallet/config/better-wallet.env
```

## Systemd Service

Create `/etc/systemd/system/better-wallet.service`:

```ini
[Unit]
Description=Better Wallet Key Management Service
Documentation=https://github.com/better-wallet/better-wallet
After=network-online.target postgresql.service
Wants=network-online.target
Requires=postgresql.service

[Service]
Type=simple
User=better-wallet
Group=better-wallet
WorkingDirectory=/opt/better-wallet

EnvironmentFile=/opt/better-wallet/config/better-wallet.env
ExecStart=/opt/better-wallet/bin/better-wallet
ExecReload=/bin/kill -HUP $MAINPID

Restart=on-failure
RestartSec=5
StartLimitBurst=3
StartLimitInterval=60

# Security hardening
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ReadOnlyPaths=/
ReadWritePaths=/opt/better-wallet
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

# Capabilities
CapabilityBoundingSet=
AmbientCapabilities=

# Resource limits
LimitNOFILE=65535
LimitNPROC=4096

[Install]
WantedBy=multi-user.target
```

Enable and start the service:

```bash
sudo systemctl daemon-reload
sudo systemctl enable better-wallet
sudo systemctl start better-wallet

# Check status
sudo systemctl status better-wallet
```

## Nginx Reverse Proxy

### Install Nginx

```bash
sudo apt install -y nginx certbot python3-certbot-nginx
```

### Configure Nginx

Create `/etc/nginx/sites-available/better-wallet`:

```nginx
upstream better_wallet {
    server 127.0.0.1:8080;
    keepalive 32;
}

server {
    listen 80;
    server_name wallet.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name wallet.example.com;

    ssl_certificate /etc/letsencrypt/live/wallet.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wallet.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/s;

    location /health {
        proxy_pass http://better_wallet;
        proxy_http_version 1.1;
        access_log off;
    }

    location / {
        limit_req zone=api burst=50 nodelay;

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

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }
}
```

Enable and start:

```bash
sudo ln -s /etc/nginx/sites-available/better-wallet /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Get SSL certificate
sudo certbot --nginx -d wallet.example.com
```

## Firewall Configuration

### UFW (Ubuntu)

```bash
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### firewalld (RHEL/CentOS)

```bash
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

## Logging

### Configure Log Rotation

Create `/etc/logrotate.d/better-wallet`:

```
/var/log/better-wallet/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0640 better-wallet better-wallet
    sharedscripts
    postrotate
        systemctl reload better-wallet > /dev/null 2>&1 || true
    endscript
}
```

### Journald Logs

```bash
# View logs
sudo journalctl -u better-wallet -f

# View logs since boot
sudo journalctl -u better-wallet -b

# Export logs
sudo journalctl -u better-wallet --since "2025-01-01" --until "2025-01-15" > /tmp/logs.txt
```

## Backup Configuration

### Automated Backups

Create `/opt/better-wallet/scripts/backup.sh`:

```bash
#!/bin/bash
set -e

BACKUP_DIR="/var/backups/better-wallet"
DATE=$(date +%Y%m%d_%H%M%S)
RETENTION_DAYS=30

mkdir -p "$BACKUP_DIR"

# Database backup
pg_dump -h localhost -U bw_user better_wallet | gzip > "$BACKUP_DIR/db_$DATE.sql.gz"

# Config backup
tar -czf "$BACKUP_DIR/config_$DATE.tar.gz" /opt/better-wallet/config/

# Cleanup old backups
find "$BACKUP_DIR" -name "*.gz" -mtime +$RETENTION_DAYS -delete

echo "Backup completed: $DATE"
```

Add to crontab:

```bash
sudo crontab -e
# Add line:
0 2 * * * /opt/better-wallet/scripts/backup.sh >> /var/log/better-wallet/backup.log 2>&1
```

## Health Monitoring

### Simple Health Check Script

Create `/opt/better-wallet/scripts/healthcheck.sh`:

```bash
#!/bin/bash

ENDPOINT="http://127.0.0.1:8080/health"
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"

check_health() {
    response=$(curl -s -o /dev/null -w "%{http_code}" "$ENDPOINT" --max-time 10)
    if [ "$response" != "200" ]; then
        echo "Health check failed: HTTP $response"
        if [ -n "$SLACK_WEBHOOK" ]; then
            curl -s -X POST -H 'Content-type: application/json' \
                --data '{"text":"Better Wallet health check failed on '"$(hostname)"'"}' \
                "$SLACK_WEBHOOK"
        fi
        return 1
    fi
    return 0
}

check_health
```

Add to crontab:

```bash
* * * * * /opt/better-wallet/scripts/healthcheck.sh >> /var/log/better-wallet/healthcheck.log 2>&1
```

## Upgrading

### Upgrade Process

```bash
# Download new version
VERSION="v1.1.0"
curl -LO "https://github.com/better-wallet/better-wallet/releases/download/${VERSION}/better-wallet-linux-amd64"

# Stop service
sudo systemctl stop better-wallet

# Backup current binary
sudo mv /opt/better-wallet/bin/better-wallet /opt/better-wallet/bin/better-wallet.bak

# Install new binary
sudo mv better-wallet-linux-amd64 /opt/better-wallet/bin/better-wallet
sudo chown better-wallet:better-wallet /opt/better-wallet/bin/better-wallet
sudo chmod 755 /opt/better-wallet/bin/better-wallet

# Run migrations (if any)
cd /path/to/dashboard && bun run db:push

# Start service
sudo systemctl start better-wallet

# Verify
curl http://localhost:8080/health
```

### Rollback

```bash
sudo systemctl stop better-wallet
sudo mv /opt/better-wallet/bin/better-wallet.bak /opt/better-wallet/bin/better-wallet
sudo systemctl start better-wallet
```

## High Availability Setup

### Multiple Servers with HAProxy

Install HAProxy on a separate load balancer node:

```bash
sudo apt install -y haproxy
```

Configure `/etc/haproxy/haproxy.cfg`:

```
global
    daemon
    maxconn 4096

defaults
    mode http
    timeout connect 5s
    timeout client 30s
    timeout server 30s
    option httplog
    option dontlognull

frontend http_front
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/wallet.pem
    redirect scheme https if !{ ssl_fc }
    default_backend better_wallet_backend

backend better_wallet_backend
    balance roundrobin
    option httpchk GET /health
    http-check expect status 200
    server node1 10.0.0.1:8080 check
    server node2 10.0.0.2:8080 check
    server node3 10.0.0.3:8080 check
```

## Troubleshooting

### Service Won't Start

```bash
# Check logs
sudo journalctl -u better-wallet -n 50 --no-pager

# Check configuration
sudo -u better-wallet /opt/better-wallet/bin/better-wallet --help

# Test database connection
PGPASSWORD=xxx psql -h localhost -U bw_user -d better_wallet -c "SELECT 1"
```

### Permission Issues

```bash
# Fix ownership
sudo chown -R better-wallet:better-wallet /opt/better-wallet

# Check SELinux (RHEL)
sudo ausearch -m avc -ts recent
sudo setsebool -P httpd_can_network_connect 1
```

### Performance Issues

```bash
# Check resource usage
top -u better-wallet

# Check open files
sudo lsof -u better-wallet | wc -l

# Check network connections
ss -tlnp | grep 8080
```

## Next Steps

- [Environment Variables](./environment-variables.md) - Configuration reference
- [Monitoring](./monitoring.md) - Metrics and alerting
- [TLS Configuration](./tls-configuration.md) - HTTPS setup
- [Backup & Recovery](./backup-recovery.md) - Data protection
