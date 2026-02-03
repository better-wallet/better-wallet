# Backup and Recovery Guide

Comprehensive guide to backing up and recovering Better Wallet deployments.

## Overview

Better Wallet stores critical data that must be protected:

| Data Type | Location | Criticality |
|-----------|----------|-------------|
| Wallet keys (encrypted shares) | PostgreSQL | Critical |
| User data | PostgreSQL | High |
| Policies | PostgreSQL | High |
| Configuration | Environment/Secrets | High |
| Audit logs | PostgreSQL | Medium |

## Backup Strategy

### Data Classification

```
┌─────────────────────────────────────────────────────────────┐
│  CRITICAL - Loss means permanent loss of funds              │
│  ├── wallet_shares (encrypted key material)                 │
│  ├── KMS master key (or Vault configuration)                │
│  └── TEE master key (if using TEE)                          │
├─────────────────────────────────────────────────────────────┤
│  HIGH - Loss means service disruption                       │
│  ├── users                                                  │
│  ├── wallets                                                │
│  ├── authorization_keys                                     │
│  ├── policies                                               │
│  └── session_signers                                        │
├─────────────────────────────────────────────────────────────┤
│  MEDIUM - Loss is inconvenient but recoverable              │
│  ├── audit_logs                                             │
│  ├── idempotency_keys                                       │
│  └── Application metrics                                    │
└─────────────────────────────────────────────────────────────┘
```

### Backup Frequency

| Data | Frequency | Retention |
|------|-----------|-----------|
| Database (full) | Daily | 30 days |
| Database (incremental) | Hourly | 7 days |
| Database (WAL) | Continuous | 7 days |
| KMS key backup | On creation | Indefinite |
| Configuration | On change | 90 days |

---

## PostgreSQL Backup

### Full Backup (pg_dump)

```bash
# Full database backup
pg_dump -h localhost -U postgres -d better_wallet \
  --format=custom \
  --compress=9 \
  --file=better_wallet_$(date +%Y%m%d_%H%M%S).dump

# Backup specific critical tables
pg_dump -h localhost -U postgres -d better_wallet \
  --table=wallet_shares \
  --table=wallets \
  --table=authorization_keys \
  --format=custom \
  --file=critical_$(date +%Y%m%d).dump
```

### Continuous Archiving (WAL)

Enable continuous archiving in `postgresql.conf`:

```ini
wal_level = replica
archive_mode = on
archive_command = 'cp %p /backup/wal/%f'
```

### Point-in-Time Recovery Setup

```ini
# postgresql.conf
restore_command = 'cp /backup/wal/%f %p'
recovery_target_time = '2025-01-15 10:00:00'
```

### Automated Backup Script

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/postgresql"
RETENTION_DAYS=30
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Create backup
pg_dump -h $DB_HOST -U $DB_USER -d $DB_NAME \
  --format=custom \
  --compress=9 \
  --file="${BACKUP_DIR}/better_wallet_${TIMESTAMP}.dump"

# Encrypt backup
gpg --symmetric --cipher-algo AES256 \
  --output "${BACKUP_DIR}/better_wallet_${TIMESTAMP}.dump.gpg" \
  "${BACKUP_DIR}/better_wallet_${TIMESTAMP}.dump"

# Remove unencrypted version
rm "${BACKUP_DIR}/better_wallet_${TIMESTAMP}.dump"

# Upload to S3
aws s3 cp "${BACKUP_DIR}/better_wallet_${TIMESTAMP}.dump.gpg" \
  "s3://my-backups/better-wallet/"

# Clean old backups
find $BACKUP_DIR -name "*.dump.gpg" -mtime +$RETENTION_DAYS -delete
```

---

## KMS Key Backup

### AWS KMS

AWS KMS keys are managed by AWS. For disaster recovery:

1. **Enable key rotation** (automatic annual rotation)
2. **Document key ARN** in secure location
3. **Cross-region replication** for critical keys

```bash
# Create multi-region key
aws kms create-key \
  --multi-region \
  --description "Better Wallet Master Key"

# Create replica in another region
aws kms replicate-key \
  --key-id arn:aws:kms:us-east-1:123456789:key/mrk-xxx \
  --replica-region us-west-2
```

### HashiCorp Vault

```bash
# Backup Vault data
vault operator raft snapshot save backup.snap

# Backup transit key
vault read transit/backup/better-wallet-key > key_backup.json
```

### Local KMS

For local KMS provider, back up the master key:

```bash
# Store master key securely
echo $KMS_KEY_ID | gpg --symmetric --cipher-algo AES256 > master_key.gpg

# Store in multiple secure locations:
# - Hardware security module (HSM)
# - Physical safe
# - Encrypted cloud storage (separate account)
```

> **Critical**: Never store the master key in the same location as database backups.

---

## Configuration Backup

### Environment Variables

```bash
# Export current configuration (excluding secrets)
env | grep -E "^(PORT|LOG_|POSTGRES_|KMS_PROVIDER|TEE_)" > config_backup.env

# For secrets, document in password manager or secrets manager
```

### Kubernetes Secrets

```bash
# Backup secrets (encrypted)
kubectl get secret better-wallet-secrets -o yaml | \
  kubeseal --format yaml > sealed-secrets-backup.yaml

# Or export to external secrets manager
kubectl get secret better-wallet-secrets -o json | \
  jq -r '.data | to_entries[] | "\(.key)=\(.value | @base64d)"'
```

---

## Recovery Procedures

### Full Database Recovery

```bash
# 1. Stop the application
kubectl scale deployment better-wallet --replicas=0

# 2. Create new database
createdb -h localhost -U postgres better_wallet_new

# 3. Restore from backup
pg_restore -h localhost -U postgres \
  -d better_wallet_new \
  --clean --if-exists \
  better_wallet_20250115.dump

# 4. Verify data
psql -h localhost -U postgres -d better_wallet_new \
  -c "SELECT COUNT(*) FROM wallets;"

# 5. Switch databases
psql -h localhost -U postgres -c "
  ALTER DATABASE better_wallet RENAME TO better_wallet_old;
  ALTER DATABASE better_wallet_new RENAME TO better_wallet;
"

# 6. Restart application
kubectl scale deployment better-wallet --replicas=3

# 7. Verify functionality
curl http://localhost:8080/health
```

### Point-in-Time Recovery

```bash
# 1. Stop PostgreSQL
systemctl stop postgresql

# 2. Clear data directory
rm -rf /var/lib/postgresql/15/main/*

# 3. Restore base backup
pg_restore -D /var/lib/postgresql/15/main/ base_backup.tar

# 4. Configure recovery
cat > /var/lib/postgresql/15/main/recovery.conf << EOF
restore_command = 'cp /backup/wal/%f %p'
recovery_target_time = '2025-01-15 09:59:00 UTC'
EOF

# 5. Start PostgreSQL
systemctl start postgresql

# 6. Verify recovery point
psql -c "SELECT pg_last_wal_replay_lsn();"
```

### Wallet Key Recovery

If wallet keys are lost but you have backups:

```bash
# 1. Restore wallet_shares table from backup
pg_restore -h localhost -U postgres \
  -d better_wallet \
  --table=wallet_shares \
  --data-only \
  critical_backup.dump

# 2. Verify encrypted shares exist
psql -c "SELECT wallet_id, auth_share IS NOT NULL, exec_share IS NOT NULL FROM wallet_shares;"

# 3. Test signing operation
curl -X POST "http://localhost:8080/v1/agent/rpc" \
  -H "Authorization: Bearer $AGENT_CREDENTIAL" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"personal_sign","params":["0x7465737420726563","0x..."],"id":1}'
```

---

## Disaster Recovery

### Recovery Time Objectives

| Scenario | RTO | RPO |
|----------|-----|-----|
| Database corruption | 1 hour | 1 hour |
| Region failure | 4 hours | 15 minutes |
| Complete data loss | 24 hours | 24 hours |

### Multi-Region Setup

```
┌─────────────────────────────────────────────────────────────┐
│  Primary Region (us-east-1)                                 │
│  ├── Better Wallet (active)                                 │
│  ├── PostgreSQL (primary)                                   │
│  └── AWS KMS (multi-region key)                             │
├─────────────────────────────────────────────────────────────┤
│  Secondary Region (us-west-2)                               │
│  ├── Better Wallet (standby)                                │
│  ├── PostgreSQL (replica)                                   │
│  └── AWS KMS (replica key)                                  │
└─────────────────────────────────────────────────────────────┘
```

### Failover Procedure

```bash
# 1. Promote replica to primary
psql -h replica.db.internal -c "SELECT pg_promote();"

# 2. Update DNS/load balancer
aws route53 change-resource-record-sets \
  --hosted-zone-id Z123456 \
  --change-batch file://failover-dns.json

# 3. Update KMS configuration (if needed)
kubectl set env deployment/better-wallet \
  KMS_AWS_KEY_ID=arn:aws:kms:us-west-2:123456789:key/mrk-xxx

# 4. Scale up standby
kubectl scale deployment better-wallet --replicas=3

# 5. Verify health
curl https://api.example.com/health
```

---

## Testing Backups

### Regular Testing Schedule

| Test | Frequency | Duration |
|------|-----------|----------|
| Backup verification | Weekly | 30 min |
| Restore to test env | Monthly | 2 hours |
| Full DR drill | Quarterly | 4 hours |

### Backup Verification Script

```bash
#!/bin/bash
# verify_backup.sh

BACKUP_FILE=$1
TEST_DB="better_wallet_test_$(date +%s)"

# Create test database
createdb -h localhost -U postgres $TEST_DB

# Restore backup
pg_restore -h localhost -U postgres -d $TEST_DB $BACKUP_FILE

# Run verification queries
psql -h localhost -U postgres -d $TEST_DB << EOF
-- Check critical tables have data
SELECT 'wallets' as table_name, COUNT(*) as row_count FROM wallets
UNION ALL SELECT 'wallet_shares', COUNT(*) FROM wallet_shares
UNION ALL SELECT 'authorization_keys', COUNT(*) FROM authorization_keys;

-- Check for orphaned records
SELECT COUNT(*) as orphaned_shares
FROM wallet_shares ws
LEFT JOIN wallets w ON ws.wallet_id = w.id
WHERE w.id IS NULL;
EOF

# Cleanup
dropdb -h localhost -U postgres $TEST_DB

echo "Backup verification complete"
```

---

## Security Considerations

### Backup Encryption

Always encrypt backups:

```bash
# Encrypt with GPG
gpg --symmetric --cipher-algo AES256 backup.dump

# Or use AWS S3 encryption
aws s3 cp backup.dump s3://my-bucket/ \
  --sse aws:kms \
  --sse-kms-key-id alias/backup-key
```

### Access Control

```yaml
# Backup service account (minimal permissions)
apiVersion: v1
kind: ServiceAccount
metadata:
  name: backup-sa
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789:role/BackupRole
---
# Role with read-only database access
# Plus write access to backup bucket only
```

### Audit Backup Access

Log all backup operations:

```bash
# Log backup creation
logger -t better-wallet-backup "Created backup: $BACKUP_FILE by $USER"

# Log restore operations
logger -t better-wallet-backup "Restored backup: $BACKUP_FILE to $DATABASE by $USER"
```

---

## Checklist

### Daily

- [ ] Verify automated backups completed
- [ ] Check backup sizes (detect anomalies)
- [ ] Review backup-related alerts

### Weekly

- [ ] Test random backup file integrity
- [ ] Verify offsite backup replication
- [ ] Review backup storage usage

### Monthly

- [ ] Full restore test to staging
- [ ] Verify all critical data is backed up
- [ ] Review and update backup procedures

### Quarterly

- [ ] Full disaster recovery drill
- [ ] Review backup retention policy
- [ ] Test cross-region failover
