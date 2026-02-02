import { eq, and, desc, count } from 'drizzle-orm'
import { z } from 'zod'
import { TRPCError } from '@trpc/server'
import { db } from '@/server/db'
import { principals, agentWallets, agentAuditLogs } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

// Helper to get principal for current user
async function getPrincipalForUser(email: string) {
  const [principal] = await db
    .select()
    .from(principals)
    .where(eq(principals.email, email))
    .limit(1)
  return principal
}

export const agentAuditRouter = createTRPCRouter({
  // List all audit logs for current principal
  list: protectedProcedure
    .input(z.object({
      action: z.string().optional(),
      limit: z.number().int().min(1).max(100).default(50),
      offset: z.number().int().min(0).default(0),
    }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        return { logs: [], total: 0 }
      }

      const conditions = [eq(agentAuditLogs.principalId, principal.id)]
      if (input.action) {
        conditions.push(eq(agentAuditLogs.action, input.action))
      }

      const logs = await db
        .select()
        .from(agentAuditLogs)
        .where(and(...conditions))
        .orderBy(desc(agentAuditLogs.createdAt))
        .limit(input.limit)
        .offset(input.offset)

      // Get total count for pagination
      const [countResult] = await db
        .select({ count: count() })
        .from(agentAuditLogs)
        .where(and(...conditions))

      return { logs, total: countResult?.count ?? 0 }
    }),

  // List audit logs for a specific wallet
  listByWallet: protectedProcedure
    .input(z.object({
      walletId: z.string().uuid(),
      limit: z.number().int().min(1).max(100).default(50),
      offset: z.number().int().min(0).default(0),
    }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Verify wallet access
      const [wallet] = await db
        .select()
        .from(agentWallets)
        .where(and(
          eq(agentWallets.id, input.walletId),
          eq(agentWallets.principalId, principal.id)
        ))
        .limit(1)

      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      const logs = await db
        .select()
        .from(agentAuditLogs)
        .where(eq(agentAuditLogs.walletId, input.walletId))
        .orderBy(desc(agentAuditLogs.createdAt))
        .limit(input.limit)
        .offset(input.offset)

      // Get total count for pagination
      const [countResult] = await db
        .select({ count: count() })
        .from(agentAuditLogs)
        .where(eq(agentAuditLogs.walletId, input.walletId))

      return { logs, total: countResult?.count ?? 0 }
    }),
})
