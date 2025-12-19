# TLS Configuration

This guide covers configuring TLS/HTTPS for Better Wallet deployments, including certificate management, cipher suites, and security best practices.

## Overview

Better Wallet should always be deployed behind TLS in production environments. This guide covers:

- Certificate options (Let's Encrypt, self-signed, custom CA)
- Reverse proxy configuration (Nginx, Traefik)
- Kubernetes TLS with cert-manager
- Security hardening

## Certificate Options

### Let's Encrypt (Recommended)

Free, automated certificates with 90-day validity.

**Using Certbot with Nginx:**

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain certificate
sudo certbot --nginx -d wallet.example.com

# Auto-renewal is configured automatically
sudo systemctl status certbot.timer
```

**Using Certbot Standalone:**

```bash
# Stop any service using port 80
sudo certbot certonly --standalone -d wallet.example.com

# Certificates are stored in:
# /etc/letsencrypt/live/wallet.example.com/fullchain.pem
# /etc/letsencrypt/live/wallet.example.com/privkey.pem
```

### Self-Signed Certificates

For development or internal deployments:

```bash
# Generate private key and certificate
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
  -keyout /etc/ssl/private/better-wallet.key \
  -out /etc/ssl/certs/better-wallet.crt \
  -subj "/CN=wallet.example.com/O=Better Wallet/C=US"

# Set permissions
sudo chmod 600 /etc/ssl/private/better-wallet.key
sudo chmod 644 /etc/ssl/certs/better-wallet.crt
```

### Custom CA Certificate

For enterprise deployments with internal CA:

```bash
# Generate CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /etc/ssl/private/better-wallet.key \
  -out /tmp/better-wallet.csr \
  -subj "/CN=wallet.example.com/O=Your Company/C=US"

# Submit CSR to your CA and receive signed certificate
# Place certificate in /etc/ssl/certs/better-wallet.crt

# Create certificate chain (if needed)
cat /etc/ssl/certs/better-wallet.crt intermediate.crt > /etc/ssl/certs/better-wallet-chain.crt
```

## Nginx TLS Configuration

### Basic Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name wallet.example.com;

    # Certificate files
    ssl_certificate /etc/letsencrypt/live/wallet.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/wallet.example.com/privkey.pem;

    # TLS protocols (TLS 1.2 and 1.3 only)
    ssl_protocols TLSv1.2 TLSv1.3;

    # Modern cipher suites
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
    ssl_prefer_server_ciphers off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    ssl_trusted_certificate /etc/letsencrypt/live/wallet.example.com/chain.pem;
    resolver 8.8.8.8 8.8.4.4 valid=300s;
    resolver_timeout 5s;

    # Session settings
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # DH parameters (generate with: openssl dhparam -out /etc/nginx/dhparam.pem 2048)
    ssl_dhparam /etc/nginx/dhparam.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# HTTP to HTTPS redirect
server {
    listen 80;
    server_name wallet.example.com;
    return 301 https://$host$request_uri;
}
```

### Generate DH Parameters

```bash
sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048
```

### Test Configuration

```bash
# Test nginx config
sudo nginx -t

# Reload
sudo systemctl reload nginx

# Test TLS with OpenSSL
openssl s_client -connect wallet.example.com:443 -servername wallet.example.com

# Test with SSL Labs (online)
# https://www.ssllabs.com/ssltest/
```

## Traefik TLS Configuration

### Docker Compose with Traefik

```yaml
version: '3.8'

services:
  traefik:
    image: traefik:v2.10
    command:
      - "--api.insecure=false"
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      - "--entrypoints.web.http.redirections.entryPoint.to=websecure"
      - "--entrypoints.web.http.redirections.entryPoint.scheme=https"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge=true"
      - "--certificatesresolvers.letsencrypt.acme.httpchallenge.entrypoint=web"
      - "--certificatesresolvers.letsencrypt.acme.email=admin@example.com"
      - "--certificatesresolvers.letsencrypt.acme.storage=/letsencrypt/acme.json"
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - "/var/run/docker.sock:/var/run/docker.sock:ro"
      - "letsencrypt:/letsencrypt"

  better-wallet:
    image: ghcr.io/better-wallet/better-wallet:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.better-wallet.rule=Host(`wallet.example.com`)"
      - "traefik.http.routers.better-wallet.entrypoints=websecure"
      - "traefik.http.routers.better-wallet.tls.certresolver=letsencrypt"
      - "traefik.http.services.better-wallet.loadbalancer.server.port=8080"
      # Security headers
      - "traefik.http.middlewares.secure-headers.headers.stsSeconds=31536000"
      - "traefik.http.middlewares.secure-headers.headers.stsIncludeSubdomains=true"
      - "traefik.http.middlewares.secure-headers.headers.contentTypeNosniff=true"
      - "traefik.http.middlewares.secure-headers.headers.frameDeny=true"
      - "traefik.http.routers.better-wallet.middlewares=secure-headers"
    environment:
      - POSTGRES_DSN=${POSTGRES_DSN}
      - EXECUTION_BACKEND=kms
      - KMS_PROVIDER=aws-kms
      - KMS_AWS_KEY_ID=${KMS_AWS_KEY_ID}

volumes:
  letsencrypt:
```

### Traefik Static Configuration (File)

`traefik.yml`:

```yaml
entryPoints:
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
          scheme: https

  websecure:
    address: ":443"
    http:
      tls:
        options: default

tls:
  options:
    default:
      minVersion: VersionTLS12
      cipherSuites:
        - TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        - TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305
        - TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        - TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
      sniStrict: true

certificatesResolvers:
  letsencrypt:
    acme:
      email: admin@example.com
      storage: /letsencrypt/acme.json
      httpChallenge:
        entryPoint: web
```

## Kubernetes TLS with cert-manager

### Install cert-manager

```bash
kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.13.0/cert-manager.yaml

# Verify installation
kubectl -n cert-manager get pods
```

### Create ClusterIssuer

```yaml
# cluster-issuer.yaml
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: letsencrypt-prod
spec:
  acme:
    server: https://acme-v02.api.letsencrypt.org/directory
    email: admin@example.com
    privateKeySecretRef:
      name: letsencrypt-prod
    solvers:
      - http01:
          ingress:
            class: nginx
```

```bash
kubectl apply -f cluster-issuer.yaml
```

### Configure Ingress with TLS

```yaml
# ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: better-wallet
  namespace: better-wallet
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    # Security headers
    nginx.ingress.kubernetes.io/configuration-snippet: |
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
      add_header X-Content-Type-Options nosniff always;
      add_header X-Frame-Options DENY always;
spec:
  tls:
    - hosts:
        - wallet.example.com
      secretName: better-wallet-tls
  rules:
    - host: wallet.example.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: better-wallet
                port:
                  number: 80
```

### Verify Certificate

```bash
# Check certificate status
kubectl -n better-wallet get certificate

# Check certificate details
kubectl -n better-wallet describe certificate better-wallet-tls

# View secret
kubectl -n better-wallet get secret better-wallet-tls -o yaml
```

## mTLS (Mutual TLS)

For high-security deployments requiring client certificate authentication:

### Nginx mTLS Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name wallet.example.com;

    # Server certificate
    ssl_certificate /etc/ssl/certs/server.crt;
    ssl_certificate_key /etc/ssl/private/server.key;

    # Client certificate verification
    ssl_client_certificate /etc/ssl/certs/ca.crt;
    ssl_verify_client on;
    ssl_verify_depth 2;

    # Pass client cert info to backend
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header X-Client-Cert-CN $ssl_client_s_dn_cn;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-Client-Verified $ssl_client_verify;
    }
}
```

### Generate Client Certificates

```bash
# Generate client key and CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout client.key \
  -out client.csr \
  -subj "/CN=api-client/O=Your Company"

# Sign with CA
openssl x509 -req -days 365 \
  -in client.csr \
  -CA ca.crt \
  -CAkey ca.key \
  -CAcreateserial \
  -out client.crt

# Create PKCS12 bundle (for browsers/apps)
openssl pkcs12 -export \
  -in client.crt \
  -inkey client.key \
  -out client.p12 \
  -name "API Client"
```

### Using Client Certificate

```bash
curl --cert client.crt --key client.key https://wallet.example.com/health
```

## Security Best Practices

### TLS Configuration Checklist

- [ ] Use TLS 1.2 or higher only
- [ ] Disable weak cipher suites
- [ ] Enable HSTS with preload
- [ ] Use OCSP stapling
- [ ] Generate strong DH parameters
- [ ] Disable TLS compression
- [ ] Enable certificate transparency

### Testing TLS Security

```bash
# Test with testssl.sh
git clone https://github.com/drwetter/testssl.sh.git
cd testssl.sh
./testssl.sh https://wallet.example.com

# Test specific protocols
openssl s_client -connect wallet.example.com:443 -tls1_2
openssl s_client -connect wallet.example.com:443 -tls1_3

# Check certificate chain
openssl s_client -connect wallet.example.com:443 -showcerts

# Verify HSTS
curl -I https://wallet.example.com | grep -i strict
```

### Certificate Rotation

Automate certificate renewal:

```bash
# Let's Encrypt auto-renewal (certbot)
sudo certbot renew --dry-run

# Manual renewal with reload
sudo certbot renew --post-hook "systemctl reload nginx"
```

### Monitor Certificate Expiry

```bash
#!/bin/bash
# check-cert-expiry.sh

DOMAIN="wallet.example.com"
THRESHOLD_DAYS=30

expiry_date=$(echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN:443" 2>/dev/null | openssl x509 -noout -enddate | cut -d= -f2)
expiry_epoch=$(date -d "$expiry_date" +%s)
current_epoch=$(date +%s)
days_left=$(( (expiry_epoch - current_epoch) / 86400 ))

if [ "$days_left" -lt "$THRESHOLD_DAYS" ]; then
    echo "WARNING: Certificate expires in $days_left days"
    exit 1
fi

echo "Certificate valid for $days_left days"
```

## Troubleshooting

### Common Issues

**Certificate chain incomplete:**
```bash
# Check chain
openssl s_client -connect wallet.example.com:443 -servername wallet.example.com 2>&1 | grep -i verify

# Fix: Include intermediate certificates in fullchain.pem
```

**HSTS not working:**
```bash
# Ensure header is set on HTTPS response
curl -I https://wallet.example.com | grep -i strict

# Check nginx config for add_header directive
```

**Certificate mismatch:**
```bash
# Verify certificate matches domain
openssl x509 -in /etc/ssl/certs/server.crt -noout -text | grep -A1 "Subject Alternative Name"
```

### Debug TLS Handshake

```bash
# Verbose connection test
openssl s_client -connect wallet.example.com:443 -servername wallet.example.com -debug -state

# Check supported ciphers
nmap --script ssl-enum-ciphers -p 443 wallet.example.com
```

## Next Steps

- [Environment Variables](./environment-variables.md) - Configuration reference
- [Monitoring](./monitoring.md) - Metrics and alerting
- [Security Architecture](../security/architecture.md) - Security model
