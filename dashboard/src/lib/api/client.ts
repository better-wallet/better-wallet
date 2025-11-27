import type {
  User,
  Wallet,
  Policy,
  AuthorizationKey,
  AuditLog,
  Transaction,
  ConditionSet,
  PaginatedResponse,
  APIError,
  CreateWalletRequest,
  CreatePolicyRequest,
  UpdatePolicyRequest,
} from './types'

const API_BASE_URL = process.env.BETTER_WALLET_API_URL || 'http://localhost:8080'
const APP_ID = process.env.BETTER_WALLET_APP_ID || ''
const APP_SECRET = process.env.BETTER_WALLET_APP_SECRET || ''

interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
  body?: unknown
  headers?: Record<string, string>
  userToken?: string
}

class BetterWalletClient {
  private baseUrl: string
  private appId: string
  private appSecret: string

  constructor(baseUrl: string, appId: string, appSecret: string) {
    this.baseUrl = baseUrl
    this.appId = appId
    this.appSecret = appSecret
  }

  private async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { method = 'GET', body, headers = {}, userToken } = options

    const requestHeaders: Record<string, string> = {
      'Content-Type': 'application/json',
      'X-App-ID': this.appId,
      'X-App-Secret': this.appSecret,
      ...headers,
    }

    if (userToken) {
      requestHeaders['Authorization'] = `Bearer ${userToken}`
    }

    const response = await fetch(`${this.baseUrl}${endpoint}`, {
      method,
      headers: requestHeaders,
      body: body ? JSON.stringify(body) : undefined,
    })

    if (!response.ok) {
      const error: APIError = await response.json().catch(() => ({
        error: `HTTP ${response.status}: ${response.statusText}`,
      }))
      throw new Error(error.error || `Request failed: ${response.status}`)
    }

    // Handle empty responses
    const text = await response.text()
    if (!text) {
      return {} as T
    }

    return JSON.parse(text)
  }

  // Health check
  async health(): Promise<{ status: string }> {
    return this.request('/health')
  }

  // Users
  async listUsers(params?: { cursor?: string; limit?: number }): Promise<PaginatedResponse<User>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    const query = searchParams.toString()
    return this.request(`/v1/users${query ? `?${query}` : ''}`)
  }

  async getUser(id: string): Promise<User> {
    return this.request(`/v1/users/${id}`)
  }

  // Wallets
  async listWallets(params?: {
    cursor?: string
    limit?: number
    chain_type?: string
    user_id?: string
  }): Promise<PaginatedResponse<Wallet>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.chain_type) searchParams.set('chain_type', params.chain_type)
    if (params?.user_id) searchParams.set('user_id', params.user_id)
    const query = searchParams.toString()
    return this.request(`/v1/wallets${query ? `?${query}` : ''}`)
  }

  async getWallet(id: string): Promise<Wallet> {
    return this.request(`/v1/wallets/${id}`)
  }

  async createWallet(data: CreateWalletRequest, userToken?: string): Promise<Wallet> {
    return this.request('/v1/wallets', {
      method: 'POST',
      body: data,
      userToken,
    })
  }

  // Policies
  async listPolicies(params?: {
    cursor?: string
    limit?: number
    chain_type?: string
  }): Promise<PaginatedResponse<Policy>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.chain_type) searchParams.set('chain_type', params.chain_type)
    const query = searchParams.toString()
    return this.request(`/v1/policies${query ? `?${query}` : ''}`)
  }

  async getPolicy(id: string): Promise<Policy> {
    return this.request(`/v1/policies/${id}`)
  }

  async createPolicy(data: CreatePolicyRequest, userToken?: string): Promise<Policy> {
    return this.request('/v1/policies', {
      method: 'POST',
      body: data,
      userToken,
    })
  }

  async updatePolicy(id: string, data: UpdatePolicyRequest, userToken?: string): Promise<Policy> {
    return this.request(`/v1/policies/${id}`, {
      method: 'PATCH',
      body: data,
      userToken,
    })
  }

  async deletePolicy(id: string, userToken?: string): Promise<void> {
    return this.request(`/v1/policies/${id}`, {
      method: 'DELETE',
      userToken,
    })
  }

  // Authorization Keys
  async listAuthorizationKeys(params?: {
    cursor?: string
    limit?: number
  }): Promise<PaginatedResponse<AuthorizationKey>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    const query = searchParams.toString()
    return this.request(`/v1/authorization-keys${query ? `?${query}` : ''}`)
  }

  async getAuthorizationKey(id: string): Promise<AuthorizationKey> {
    return this.request(`/v1/authorization-keys/${id}`)
  }

  // Transactions
  async listTransactions(params?: {
    cursor?: string
    limit?: number
    wallet_id?: string
    status?: string
  }): Promise<PaginatedResponse<Transaction>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.wallet_id) searchParams.set('wallet_id', params.wallet_id)
    if (params?.status) searchParams.set('status', params.status)
    const query = searchParams.toString()
    return this.request(`/v1/transactions${query ? `?${query}` : ''}`)
  }

  async getTransaction(id: string): Promise<Transaction> {
    return this.request(`/v1/transactions/${id}`)
  }

  // Condition Sets
  async listConditionSets(params?: {
    cursor?: string
    limit?: number
  }): Promise<PaginatedResponse<ConditionSet>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    const query = searchParams.toString()
    return this.request(`/v1/condition_sets${query ? `?${query}` : ''}`)
  }

  async getConditionSet(id: string): Promise<ConditionSet> {
    return this.request(`/v1/condition_sets/${id}`)
  }

  // Audit Logs (read-only, for dashboard)
  async listAuditLogs(params?: {
    cursor?: string
    limit?: number
    actor?: string
    action?: string
    resource_type?: string
    from?: string
    to?: string
  }): Promise<PaginatedResponse<AuditLog>> {
    const searchParams = new URLSearchParams()
    if (params?.cursor) searchParams.set('cursor', params.cursor)
    if (params?.limit) searchParams.set('limit', params.limit.toString())
    if (params?.actor) searchParams.set('actor', params.actor)
    if (params?.action) searchParams.set('action', params.action)
    if (params?.resource_type) searchParams.set('resource_type', params.resource_type)
    if (params?.from) searchParams.set('from', params.from)
    if (params?.to) searchParams.set('to', params.to)
    const query = searchParams.toString()
    // Note: This endpoint may not exist in the Go backend yet
    return this.request(`/v1/audit-logs${query ? `?${query}` : ''}`)
  }
}

// Export singleton instance
export const apiClient = new BetterWalletClient(API_BASE_URL, APP_ID, APP_SECRET)

// Export class for custom instances
export { BetterWalletClient }
