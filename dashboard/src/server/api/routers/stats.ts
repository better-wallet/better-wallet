import { apiClient } from '@/lib/api/client'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const statsRouter = createTRPCRouter({
  overview: protectedProcedure.query(async () => {
    // Fetch counts from various endpoints
    // In a real implementation, you might have a dedicated stats endpoint
    try {
      const [users, wallets, policies] = await Promise.all([
        apiClient.listUsers({ limit: 1 }),
        apiClient.listWallets({ limit: 1 }),
        apiClient.listPolicies({ limit: 1 }),
      ])

      return {
        totalUsers: users.total ?? 0,
        totalWallets: wallets.total ?? 0,
        totalPolicies: policies.total ?? 0,
        totalTransactions: 0, // Would need a count endpoint
      }
    } catch (error) {
      // Return zeros if API is not available
      return {
        totalUsers: 0,
        totalWallets: 0,
        totalPolicies: 0,
        totalTransactions: 0,
      }
    }
  }),

  health: protectedProcedure.query(async () => {
    try {
      const result = await apiClient.health()
      return {
        api: result.status === 'ok',
        database: true, // Assume true if API is up
        executionBackend: true,
      }
    } catch (error) {
      return {
        api: false,
        database: false,
        executionBackend: false,
      }
    }
  }),
})
