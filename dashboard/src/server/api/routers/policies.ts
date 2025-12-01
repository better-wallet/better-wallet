import { z } from 'zod'
import { apiClient } from '@/lib/api/client'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const policiesRouter = createTRPCRouter({
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().optional(),
        limit: z.number().min(1).max(100).default(20),
        chainType: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const result = await apiClient.listPolicies({
        cursor: input.cursor,
        limit: input.limit,
        chain_type: input.chainType,
      })
      return {
        items: result.items,
        nextCursor: result.next_cursor,
        total: result.total,
      }
    }),

  get: protectedProcedure.input(z.object({ id: z.string() })).query(async ({ input }) => {
    return apiClient.getPolicy(input.id)
  }),

  create: protectedProcedure
    .input(
      z.object({
        name: z.string(),
        chainType: z.string(),
        rules: z.record(z.string(), z.unknown()),
      })
    )
    .mutation(async ({ input }) => {
      return apiClient.createPolicy({
        name: input.name,
        chain_type: input.chainType,
        rules: input.rules,
      })
    }),

  update: protectedProcedure
    .input(
      z.object({
        id: z.string(),
        name: z.string().optional(),
        rules: z.record(z.string(), z.unknown()).optional(),
      })
    )
    .mutation(async ({ input }) => {
      return apiClient.updatePolicy(input.id, {
        name: input.name,
        rules: input.rules,
      })
    }),

  delete: protectedProcedure.input(z.object({ id: z.string() })).mutation(async ({ input }) => {
    await apiClient.deletePolicy(input.id)
    return { success: true }
  }),
})
