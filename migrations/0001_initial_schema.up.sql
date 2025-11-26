-- Better Wallet Initial Schema
-- Version: v0.7.0
-- Stateless signature model with P-256 default algorithm

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Users table
CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    external_sub text NOT NULL UNIQUE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_users_external_sub ON users(external_sub);

-- Authorization keys table
-- Only P-256 (NIST P-256 / prime256v1) is supported
CREATE TABLE authorization_keys (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    public_key bytea NOT NULL,
    algorithm text NOT NULL CHECK (algorithm = 'p256'),
    owner_entity text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'rotated', 'revoked')),
    created_at timestamptz NOT NULL DEFAULT now(),
    rotated_at timestamptz
);

CREATE INDEX idx_authorization_keys_status ON authorization_keys(status);
CREATE INDEX idx_authorization_keys_owner_entity ON authorization_keys(owner_entity);

-- Key quorums table
CREATE TABLE key_quorums (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    threshold int NOT NULL CHECK (threshold > 0),
    key_ids uuid[] NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'inactive')),
    created_at timestamptz NOT NULL DEFAULT now()
);

-- Wallets table
CREATE TABLE wallets (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    chain_type text NOT NULL DEFAULT 'ethereum',
    owner_id uuid NOT NULL REFERENCES authorization_keys(id) ON DELETE RESTRICT,
    exec_backend text NOT NULL DEFAULT 'kms' CHECK (exec_backend IN ('kms', 'tee')),
    address text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_wallets_user_id ON wallets(user_id);
CREATE INDEX idx_wallets_address ON wallets(address);
CREATE INDEX idx_wallets_owner_id ON wallets(owner_id);

-- Wallet shares table
CREATE TABLE wallet_shares (
    wallet_id uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    share_type text NOT NULL CHECK (share_type IN ('auth_share', 'exec_share', 'enclave_share')),
    blob_encrypted bytea NOT NULL,
    kms_key_id text,
    version int NOT NULL DEFAULT 1,
    PRIMARY KEY (wallet_id, share_type)
);

-- Policies table
CREATE TABLE policies (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    name text NOT NULL,
    chain_type text NOT NULL,
    version text NOT NULL DEFAULT '1.0',
    rules jsonb NOT NULL,
    owner_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_policies_owner_id ON policies(owner_id);
CREATE INDEX idx_policies_chain_type ON policies(chain_type);

-- Wallet policies junction table
CREATE TABLE wallet_policies (
    wallet_id uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    policy_id uuid NOT NULL REFERENCES policies(id) ON DELETE CASCADE,
    PRIMARY KEY (wallet_id, policy_id)
);

-- Session signers table
CREATE TABLE session_signers (
    id uuid PRIMARY KEY DEFAULT uuid_generate_v4(),
    wallet_id uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    signer_id text NOT NULL,
    policy_override_id uuid REFERENCES policies(id),
    allowed_methods text[],
    max_value numeric,
    max_txs int,
    ttl_expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    UNIQUE(wallet_id, signer_id)
);

CREATE INDEX idx_session_signers_wallet_id ON session_signers(wallet_id);
CREATE INDEX idx_session_signers_signer_id ON session_signers(signer_id);
CREATE INDEX idx_session_signers_ttl_expires_at ON session_signers(ttl_expires_at);

-- Audit logs table
-- request_nonce is deprecated (v0.7.0+) but kept for historical audit data
CREATE TABLE audit_logs (
    id bigserial PRIMARY KEY,
    actor text NOT NULL,
    action text NOT NULL,
    resource_type text NOT NULL,
    resource_id text NOT NULL,
    policy_result text,
    signer_id text,
    tx_hash text,
    request_digest text,
    request_nonce text,  -- Deprecated: kept for backward compatibility
    client_ip inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_logs_actor ON audit_logs(actor);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_action ON audit_logs(action);

-- Recovery info table
CREATE TABLE recovery_info (
    wallet_id uuid PRIMARY KEY REFERENCES wallets(id) ON DELETE CASCADE,
    method text NOT NULL CHECK (method IN ('auto', 'passkey', 'external_kms')),
    blob_encrypted bytea NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Transactions table for tracking RPC transaction requests
-- Stores transaction_id returned from eth_sendTransaction for later status queries
CREATE TABLE transactions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    wallet_id uuid NOT NULL REFERENCES wallets(id) ON DELETE CASCADE,
    chain_id bigint NOT NULL,
    tx_hash text,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'submitted', 'confirmed', 'failed')),
    method text NOT NULL,  -- eth_sendTransaction, eth_signTransaction, etc.
    to_address text,
    value text,
    data text,
    nonce bigint,
    gas_limit bigint,
    max_fee_per_gas text,
    max_priority_fee_per_gas text,
    signed_tx bytea,
    error_message text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX idx_transactions_wallet_id ON transactions(wallet_id);
CREATE INDEX idx_transactions_tx_hash ON transactions(tx_hash) WHERE tx_hash IS NOT NULL;
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC);

-- Idempotency records table for response caching
-- Store first response for 24 hours to prevent duplicate operations
-- Scoped by app_id, key, method, and URL to allow same key for different endpoints
CREATE TABLE idempotency_records (
    id BIGSERIAL PRIMARY KEY,
    app_id VARCHAR(256) NOT NULL,
    key VARCHAR(256) NOT NULL,
    method VARCHAR(10) NOT NULL,
    url VARCHAR(2048) NOT NULL,
    body_hash VARCHAR(64) NOT NULL,
    status_code INTEGER NOT NULL,
    headers JSONB NOT NULL DEFAULT '{}',
    body BYTEA NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(app_id, key, method, url)
);

CREATE INDEX idx_idempotency_records_expires_at ON idempotency_records(expires_at);
CREATE INDEX idx_idempotency_records_app_key_method_url ON idempotency_records(app_id, key, method, url) WHERE expires_at > NOW();

-- Comments
COMMENT ON TABLE authorization_keys IS 'Public keys for owner signature verification. Only P-256 is supported';
COMMENT ON TABLE idempotency_records IS 'Stores idempotency records with cached responses. Records expire after 24 hours. Scoped by (app_id, key, method, url)';
COMMENT ON COLUMN idempotency_records.key IS 'The idempotency key from x-idempotency-key header (max 256 chars, recommended UUIDv4)';
COMMENT ON COLUMN idempotency_records.body_hash IS 'SHA-256 hash of the request body to detect reused keys with different bodies';
COMMENT ON COLUMN audit_logs.request_nonce IS 'Deprecated in v0.7.0 - replaced with idempotency records';
