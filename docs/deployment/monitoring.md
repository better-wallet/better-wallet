# Monitoring Guide

Comprehensive guide to monitoring Better Wallet in production.

## Overview

Effective monitoring is essential for maintaining a secure and reliable wallet infrastructure. This guide covers metrics, logging, alerting, and observability best practices.

## Health Endpoints

### Basic Health Check

```bash
curl http://localhost:8080/health
```

Response:
```json
{
  "status": "ok"
}
```

### Readiness Check

```bash
curl http://localhost:8080/ready
```

Response:
```json
{
  "status": "ready",
  "checks": {
    "database": "ok",
    "kms": "ok"
  }
}
```

Use this endpoint for Kubernetes readiness probes.

### Liveness Check

```bash
curl http://localhost:8080/live
```

Response:
```json
{
  "status": "alive"
}
```

Use this endpoint for Kubernetes liveness probes.

---

## Metrics

### Prometheus Metrics

Better Wallet exposes Prometheus metrics at `/metrics`:

```bash
curl http://localhost:8080/metrics
```

### Key Metrics

#### Request Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `http_requests_total` | Counter | Total HTTP requests |
| `http_request_duration_seconds` | Histogram | Request latency |
| `http_request_size_bytes` | Histogram | Request body size |
| `http_response_size_bytes` | Histogram | Response body size |

#### Business Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `wallets_created_total` | Counter | Total wallets created |
| `transactions_signed_total` | Counter | Total transactions signed |
| `policy_evaluations_total` | Counter | Policy evaluation count |
| `policy_denials_total` | Counter | Transactions denied by policy |

#### System Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `go_goroutines` | Gauge | Current goroutine count |
| `go_memstats_alloc_bytes` | Gauge | Memory allocation |
| `db_connections_active` | Gauge | Active database connections |
| `db_connections_idle` | Gauge | Idle database connections |

### Prometheus Configuration

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'better-wallet'
    static_configs:
      - targets: ['better-wallet:8080']
    metrics_path: /metrics
    scrape_interval: 15s
```

---

## Logging

### Log Levels

| Level | Usage |
|-------|-------|
| `debug` | Development debugging |
| `info` | Normal operations |
| `warn` | Recoverable issues |
| `error` | Errors requiring attention |

### Log Format

Configure via environment:

```bash
LOG_LEVEL=info
LOG_FORMAT=json  # or "text"
```

### JSON Log Structure

```json
{
  "level": "info",
  "ts": "2025-01-15T10:00:00Z",
  "msg": "request completed",
  "request_id": "req-123",
  "method": "POST",
  "path": "/v1/wallets",
  "status": 201,
  "duration_ms": 45,
  "principal_id": "principal-uuid",
  "wallet_id": "wallet-uuid"
}
```

### Key Log Fields

| Field | Description |
|-------|-------------|
| `request_id` | Unique request identifier |
| `principal_id` | Principal ID |
| `wallet_id` | Wallet ID (when applicable) |
| `credential_id` | Agent Credential ID (for agent requests) |
| `duration_ms` | Request duration |
| `error` | Error message (if any) |

### Log Aggregation

#### Fluentd Configuration

```xml
<source>
  @type forward
  port 24224
</source>

<filter better-wallet.**>
  @type parser
  key_name log
  <parse>
    @type json
  </parse>
</filter>

<match better-wallet.**>
  @type elasticsearch
  host elasticsearch
  port 9200
  index_name better-wallet
</match>
```

#### Loki Configuration

```yaml
# promtail.yml
scrape_configs:
  - job_name: better-wallet
    static_configs:
      - targets:
          - localhost
        labels:
          job: better-wallet
          __path__: /var/log/better-wallet/*.log
```

---

## Audit Logging

### Audit Events

Security-relevant operations are logged to the `audit_logs` table:

| Event | Description |
|-------|-------------|
| `wallet.created` | New wallet created |
| `wallet.deleted` | Wallet deleted |
| `transaction.signed` | Transaction signed |
| `policy.created` | Policy created |
| `policy.updated` | Policy modified |
| `policy.denied` | Transaction denied |
| `session.created` | Session signer created |
| `auth_key.registered` | Authorization key registered |
| `auth_key.revoked` | Authorization key revoked |

### Audit Log Structure

```json
{
  "id": "audit-uuid",
  "event_type": "transaction.signed",
  "principal_id": "principal-uuid",
  "credential_id": "credential-uuid",
  "wallet_id": "wallet-uuid",
  "request_id": "req-uuid",
  "ip_address": "192.168.1.1",
  "user_agent": "MyAgent/1.0",
  "details": {
    "chain_id": 1,
    "to": "0x742d35Cc...",
    "value": "1000000000000000000"
  },
  "created_at": "2025-01-15T10:00:00Z"
}
```

### Querying Audit Logs

```sql
-- Recent failed policy evaluations
SELECT * FROM audit_logs
WHERE event_type = 'policy.denied'
AND created_at > NOW() - INTERVAL '24 hours'
ORDER BY created_at DESC;

-- All activity for a specific wallet
SELECT * FROM audit_logs
WHERE wallet_id = 'wallet-uuid'
ORDER BY created_at DESC;
```

---

## Alerting

### Critical Alerts

Set up alerts for these conditions:

| Alert | Condition | Severity |
|-------|-----------|----------|
| Service Down | Health check fails | Critical |
| High Error Rate | 5xx errors > 1% | Critical |
| Database Down | DB connection fails | Critical |
| KMS Unavailable | KMS errors | Critical |
| High Latency | p99 > 5s | High |
| Policy Spike | Denial rate > 50% | High |

### Alert Examples (Prometheus)

```yaml
groups:
  - name: better-wallet
    rules:
      - alert: BetterWalletDown
        expr: up{job="better-wallet"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Better Wallet is down"

      - alert: HighErrorRate
        expr: |
          rate(http_requests_total{job="better-wallet",status=~"5.."}[5m])
          / rate(http_requests_total{job="better-wallet"}[5m]) > 0.01
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"

      - alert: HighLatency
        expr: |
          histogram_quantile(0.99,
            rate(http_request_duration_seconds_bucket{job="better-wallet"}[5m])
          ) > 5
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "High latency detected"

      - alert: PolicyDenialSpike
        expr: |
          rate(policy_denials_total[5m])
          / rate(policy_evaluations_total[5m]) > 0.5
        for: 5m
        labels:
          severity: high
        annotations:
          summary: "Unusual policy denial rate"
```

---

## Dashboards

### Grafana Dashboard

Key panels to include:

1. **Request Rate**: `rate(http_requests_total[5m])`
2. **Error Rate**: `rate(http_requests_total{status=~"5.."}[5m])`
3. **Latency (p50, p95, p99)**: `histogram_quantile`
4. **Wallets Created**: `increase(wallets_created_total[24h])`
5. **Transactions Signed**: `rate(transactions_signed_total[5m])`
6. **Policy Denials**: `rate(policy_denials_total[5m])`
7. **Database Connections**: `db_connections_active`
8. **Memory Usage**: `go_memstats_alloc_bytes`

### Example Dashboard JSON

```json
{
  "title": "Better Wallet Overview",
  "panels": [
    {
      "title": "Request Rate",
      "type": "graph",
      "targets": [
        {
          "expr": "rate(http_requests_total{job=\"better-wallet\"}[5m])",
          "legendFormat": "{{method}} {{path}}"
        }
      ]
    },
    {
      "title": "Error Rate",
      "type": "singlestat",
      "targets": [
        {
          "expr": "sum(rate(http_requests_total{job=\"better-wallet\",status=~\"5..\"}[5m])) / sum(rate(http_requests_total{job=\"better-wallet\"}[5m])) * 100"
        }
      ],
      "format": "percent"
    }
  ]
}
```

---

## Tracing

### Distributed Tracing

Better Wallet supports OpenTelemetry for distributed tracing.

### Configuration

```bash
OTEL_EXPORTER_OTLP_ENDPOINT=http://jaeger:4317
OTEL_SERVICE_NAME=better-wallet
```

### Trace Context

Traces include:
- HTTP request handling
- Database queries
- KMS operations
- Policy evaluation

### Jaeger Integration

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # UI
      - "4317:4317"    # OTLP gRPC
```

---

## Security Monitoring

### Suspicious Activity Patterns

Monitor for:

1. **Unusual request patterns**: Spike in requests from single IP
2. **Failed authentication**: Multiple JWT validation failures
3. **Policy denial patterns**: Repeated denied operations
4. **Geographic anomalies**: Requests from unexpected locations

### Security Alerts

```yaml
- alert: AuthenticationFailureSpike
  expr: |
    rate(http_requests_total{status="401"}[5m]) > 10
  for: 2m
  labels:
    severity: high
  annotations:
    summary: "High authentication failure rate"

- alert: UnusualRequestVolume
  expr: |
    rate(http_requests_total[5m]) >
    avg_over_time(rate(http_requests_total[5m])[24h:5m]) * 3
  for: 10m
  labels:
    severity: medium
  annotations:
    summary: "Request volume 3x normal"
```

---

## Kubernetes Monitoring

### Pod Resources

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 1000m
    memory: 512Mi
```

### Probes

```yaml
livenessProbe:
  httpGet:
    path: /live
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10

readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
```

### Pod Disruption Budget

```yaml
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: better-wallet-pdb
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: better-wallet
```

---

## Runbooks

### Service Degradation

1. Check health endpoints
2. Review recent deployments
3. Check database connectivity
4. Check KMS availability
5. Review error logs
6. Check resource usage

### High Latency

1. Check database query times
2. Review KMS latency
3. Check connection pool status
4. Look for long-running queries
5. Review recent traffic patterns

### Policy Denial Spike

1. Identify affected wallets/users
2. Review recent policy changes
3. Check for misconfigured policies
4. Review transaction patterns
5. Contact affected users if legitimate
