import { z } from 'zod'
import { apiClient } from '@/lib/api/client'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const auditRouter = createTRPCRouter({
  list: protectedProcedure
    .input(
      z.object({
        cursor: z.string().optional(),
        limit: z.number().min(1).max(100).default(50),
        actor: z.string().optional(),
        action: z.string().optional(),
        resourceType: z.string().optional(),
        from: z.string().optional(),
        to: z.string().optional(),
      })
    )
    .query(async ({ input }) => {
      const result = await apiClient.listAuditLogs({
        cursor: input.cursor,
        limit: input.limit,
        actor: input.actor,
        action: input.action,
        resource_type: input.resourceType,
        from: input.from,
        to: input.to,
      })
      return {
        items: result.items,
        nextCursor: result.next_cursor,
        total: result.total,
      }
    }),
})
