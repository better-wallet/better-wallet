-- Migration: 000001_init_schema
-- Description: Initial schema for Agent Wallet system

-- ==================== Principal Tables ====================

CREATE TABLE IF NOT EXISTS principals (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS principals_email_idx ON principals(email);

CREATE TABLE IF NOT EXISTS principal_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS principal_api_keys_principal_id_idx ON principal_api_keys(principal_id);
CREATE INDEX IF NOT EXISTS principal_api_keys_key_prefix_idx ON principal_api_keys(key_prefix);

-- ==================== Agent Wallet Tables ====================

CREATE TABLE IF NOT EXISTS agent_wallets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    principal_id UUID NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    chain_type TEXT NOT NULL DEFAULT 'evm',
    address TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_wallets_principal_id_idx ON agent_wallets(principal_id);
CREATE INDEX IF NOT EXISTS agent_wallets_address_idx ON agent_wallets(address);

CREATE TABLE IF NOT EXISTS wallet_keys (
    wallet_id UUID PRIMARY KEY REFERENCES agent_wallets(id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    kms_key_id TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ==================== Agent Credential Tables ====================

CREATE TABLE IF NOT EXISTS agent_credentials (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES agent_wallets(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    capabilities JSONB NOT NULL DEFAULT '{}',
    limits JSONB NOT NULL DEFAULT '{}',
    status TEXT NOT NULL DEFAULT 'active',
    last_used_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    paused_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS agent_credentials_wallet_id_idx ON agent_credentials(wallet_id);
CREATE INDEX IF NOT EXISTS agent_credentials_key_prefix_idx ON agent_credentials(key_prefix);

CREATE TABLE IF NOT EXISTS agent_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    credential_id UUID NOT NULL REFERENCES agent_credentials(id) ON DELETE CASCADE,
    policy_type TEXT NOT NULL,
    policy_data JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_policies_credential_id_idx ON agent_policies(credential_id);

CREATE TABLE IF NOT EXISTS agent_rate_limits (
    credential_id UUID NOT NULL REFERENCES agent_credentials(id) ON DELETE CASCADE,
    window_type TEXT NOT NULL,
    window_start TIMESTAMPTZ NOT NULL,
    tx_count INTEGER NOT NULL DEFAULT 0,
    total_value TEXT NOT NULL DEFAULT '0',
    PRIMARY KEY (credential_id, window_type, window_start)
);

-- ==================== Audit Tables ====================

CREATE TABLE IF NOT EXISTS agent_audit_logs (
    id SERIAL PRIMARY KEY,
    credential_id UUID REFERENCES agent_credentials(id) ON DELETE SET NULL,
    wallet_id UUID REFERENCES agent_wallets(id) ON DELETE SET NULL,
    principal_id UUID REFERENCES principals(id) ON DELETE SET NULL,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    policy_result TEXT,
    tx_hash TEXT,
    error_message TEXT,
    metadata JSONB,
    client_ip TEXT,
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_audit_logs_principal_id_idx ON agent_audit_logs(principal_id);
CREATE INDEX IF NOT EXISTS agent_audit_logs_wallet_id_idx ON agent_audit_logs(wallet_id);
CREATE INDEX IF NOT EXISTS agent_audit_logs_credential_id_idx ON agent_audit_logs(credential_id);
CREATE INDEX IF NOT EXISTS agent_audit_logs_created_at_idx ON agent_audit_logs(created_at);

-- ==================== Transaction Tables ====================

CREATE TABLE IF NOT EXISTS agent_transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id UUID NOT NULL REFERENCES agent_wallets(id) ON DELETE CASCADE,
    credential_id UUID REFERENCES agent_credentials(id) ON DELETE SET NULL,
    tx_hash TEXT,
    method TEXT NOT NULL,
    to_address TEXT,
    value TEXT,
    data TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    error_message TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS agent_transactions_wallet_id_idx ON agent_transactions(wallet_id);
CREATE INDEX IF NOT EXISTS agent_transactions_credential_id_idx ON agent_transactions(credential_id);

-- ==================== Better Auth Tables ====================
-- These tables are managed by better-auth but we include them for completeness

CREATE TABLE IF NOT EXISTS "user" (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    "emailVerified" BOOLEAN NOT NULL DEFAULT FALSE,
    image TEXT,
    role TEXT NOT NULL DEFAULT 'user',
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "account" (
    id TEXT PRIMARY KEY,
    "accountId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE,
    "accessToken" TEXT,
    "refreshToken" TEXT,
    "idToken" TEXT,
    "accessTokenExpiresAt" TIMESTAMPTZ,
    "refreshTokenExpiresAt" TIMESTAMPTZ,
    scope TEXT,
    password TEXT,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS "session" (
    id TEXT PRIMARY KEY,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    token TEXT UNIQUE NOT NULL,
    "createdAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "updatedAt" TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    "ipAddress" TEXT,
    "userAgent" TEXT,
    "userId" TEXT NOT NULL REFERENCES "user"(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS "verification" (
    id TEXT PRIMARY KEY,
    identifier TEXT NOT NULL,
    value TEXT NOT NULL,
    "expiresAt" TIMESTAMPTZ NOT NULL,
    "createdAt" TIMESTAMPTZ,
    "updatedAt" TIMESTAMPTZ
);
