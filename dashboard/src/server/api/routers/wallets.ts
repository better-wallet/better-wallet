import { z } from 'zod'
import { apiClient } from '@/lib/api/client'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const walletsRouter = createTRPCRouter({
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().optional(),
        limit: z.number().min(1).max(100).default(20),
        chainType: z.string().optional(),
        userId: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const result = await apiClient.listWallets({
        cursor: input.cursor,
        limit: input.limit,
        chain_type: input.chainType,
        user_id: input.userId,
      })
      return {
        items: result.items,
        nextCursor: result.next_cursor,
        total: result.total,
      }
    }),

  get: protectedProcedure.input(z.object({ id: z.string() })).query(async ({ input }) => {
    return apiClient.getWallet(input.id)
  }),

  create: protectedProcedure
    .input(
      z.object({
        chainType: z.string(),
        ownerPublicKey: z.string().optional(),
      })
    )
    .mutation(async ({ input }) => {
      return apiClient.createWallet({
        chain_type: input.chainType,
        owner_public_key: input.ownerPublicKey,
      })
    }),
})
