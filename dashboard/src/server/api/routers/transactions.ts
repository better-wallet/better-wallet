import { z } from 'zod'
import { apiClient } from '@/lib/api/client'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const transactionsRouter = createTRPCRouter({
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().optional(),
        limit: z.number().min(1).max(100).default(20),
        walletId: z.string().optional(),
        status: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const result = await apiClient.listTransactions({
        cursor: input.cursor,
        limit: input.limit,
        wallet_id: input.walletId,
        status: input.status,
      })
      return {
        items: result.items,
        nextCursor: result.next_cursor,
        total: result.total,
      }
    }),

  get: protectedProcedure.input(z.object({ id: z.string() })).query(async ({ input }) => {
    return apiClient.getTransaction(input.id)
  }),
})
