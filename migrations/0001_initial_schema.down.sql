-- Rollback Better Wallet schema

-- Drop tables in reverse order (respecting foreign key constraints)
DROP TABLE IF EXISTS condition_sets;
DROP TABLE IF EXISTS idempotency_records;
DROP TABLE IF EXISTS recovery_info;
DROP TABLE IF EXISTS audit_logs;
DROP TABLE IF EXISTS session_signers;
DROP TABLE IF EXISTS wallet_policies;
DROP TABLE IF EXISTS policies;
DROP TABLE IF EXISTS wallet_shares;
DROP TABLE IF EXISTS wallets;
DROP TABLE IF EXISTS key_quorums;
DROP TABLE IF EXISTS authorization_keys;
DROP TABLE IF EXISTS users;

-- Drop extension
DROP EXTENSION IF EXISTS "uuid-ossp";
