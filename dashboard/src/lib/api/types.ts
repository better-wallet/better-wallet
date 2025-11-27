// Types matching Go backend types

export interface User {
  id: string
  external_sub: string
  created_at: string
}

export interface AuthorizationKey {
  id: string
  public_key: string // base64 encoded
  algorithm: 'p256'
  owner_entity: string
  status: 'active' | 'rotated' | 'revoked'
  created_at: string
  rotated_at?: string
}

export interface KeyQuorum {
  id: string
  threshold: number
  key_ids: string[]
  status: 'active' | 'inactive'
  created_at: string
}

export interface Wallet {
  id: string
  user_id: string
  chain_type: 'ethereum' | 'solana' | 'bitcoin'
  owner_id: string
  exec_backend: 'kms' | 'tee'
  address: string
  created_at: string
}

export interface Policy {
  id: string
  name: string
  chain_type: string
  version: string
  rules: Record<string, unknown>
  owner_id: string
  created_at: string
}

export interface SessionSigner {
  id: string
  wallet_id: string
  signer_id: string
  policy_override_id?: string
  allowed_methods?: string[]
  max_value?: string
  max_txs?: number
  ttl_expires_at: string
  created_at: string
  revoked_at?: string
}

export interface AuditLog {
  id: number
  actor: string
  action: string
  resource_type: string
  resource_id: string
  policy_result?: string
  signer_id?: string
  tx_hash?: string
  request_digest?: string
  client_ip?: string
  user_agent?: string
  created_at: string
}

export interface ConditionSet {
  id: string
  name: string
  description?: string
  values: unknown[]
  owner_id: string
  created_at: string
  updated_at: string
}

export interface Transaction {
  id: string
  wallet_id: string
  chain_type: string
  tx_hash?: string
  to: string
  value: string
  data?: string
  status: 'pending' | 'submitted' | 'confirmed' | 'failed'
  created_at: string
  submitted_at?: string
  confirmed_at?: string
}

// API Response types
export interface PaginatedResponse<T> {
  items: T[]
  next_cursor?: string
  total?: number
}

export interface APIError {
  error: string
  code?: string
  details?: Record<string, unknown>
}

// Request types
export interface CreateWalletRequest {
  chain_type: string
  owner_public_key?: string
}

export interface CreatePolicyRequest {
  name: string
  chain_type: string
  rules: Record<string, unknown>
}

export interface UpdatePolicyRequest {
  name?: string
  rules?: Record<string, unknown>
}

export interface SignTransactionRequest {
  to: string
  value: string
  data?: string
  chain_id: number
}
