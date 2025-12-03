/**
 * Wallet Backend API Client
 *
 * This module provides functions to call the Better Wallet Go backend API.
 * Used by the dashboard for operations that require key generation (e.g., creating wallets).
 */

const WALLET_API_URL = process.env.BETTER_WALLET_API_URL || 'http://localhost:8080'

interface CreateWalletRequest {
  chain_type: string
  // No owner fields - creates an app-managed wallet
}

interface WalletResponse {
  id: string
  address: string
  public_key?: string
  chain_type: string
  policy_ids: string[]
  owner_id: string | null
  additional_signers: unknown[]
  created_at: number
  exported_at: number | null
  imported_at: number | null
}

interface ApiError {
  error: string
  detail?: string
}

/**
 * Call the wallet backend API with app credentials
 */
async function callWalletApi<T>(
  method: string,
  path: string,
  appId: string,
  appSecret: string,
  body?: unknown
): Promise<T> {
  const credentials = Buffer.from(`${appId}:${appSecret}`).toString('base64')

  const response = await fetch(`${WALLET_API_URL}${path}`, {
    method,
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Basic ${credentials}`,
      'x-app-id': appId,
    },
    body: body ? JSON.stringify(body) : undefined,
  })

  if (!response.ok) {
    const error: ApiError = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.detail || error.error || `API error: ${response.status}`)
  }

  return response.json()
}

/**
 * Create an App-Managed Wallet (no owner)
 *
 * App-managed wallets are controlled entirely by the app via API secret authentication.
 * They are ideal for:
 * - AI Agents
 * - Automated trading bots
 * - Server-side operations
 * - Gas station wallets
 *
 * No authorization signature is required for operations on these wallets.
 */
export async function createAppWallet(
  appId: string,
  appSecret: string,
  chainType: string = 'ethereum'
): Promise<WalletResponse> {
  const request: CreateWalletRequest = {
    chain_type: chainType,
    // No owner or owner_id - creates an app-managed wallet
  }

  return callWalletApi<WalletResponse>('POST', '/v1/wallets', appId, appSecret, request)
}
