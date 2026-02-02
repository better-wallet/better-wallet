-- Migration: 000001_init_schema (down)
-- Description: Rollback initial schema

DROP TABLE IF EXISTS "verification";
DROP TABLE IF EXISTS "session";
DROP TABLE IF EXISTS "account";
DROP TABLE IF EXISTS "user";

DROP TABLE IF EXISTS agent_transactions;
DROP TABLE IF EXISTS agent_audit_logs;
DROP TABLE IF EXISTS agent_rate_limits;
DROP TABLE IF EXISTS agent_policies;
DROP TABLE IF EXISTS agent_credentials;
DROP TABLE IF EXISTS wallet_keys;
DROP TABLE IF EXISTS agent_wallets;
DROP TABLE IF EXISTS principal_api_keys;
DROP TABLE IF EXISTS principals;
