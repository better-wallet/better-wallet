import { eq, and, desc, count } from 'drizzle-orm'
import { z } from 'zod'
import { TRPCError } from '@trpc/server'
import { db } from '@/server/db'
import { principals, agentWallets, agentTransactions } from '@/server/db/schema'
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

export const agentTransactionsRouter = createTRPCRouter({
  // List transactions for a wallet
  list: protectedProcedure
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

      const transactions = await db
        .select()
        .from(agentTransactions)
        .where(eq(agentTransactions.walletId, input.walletId))
        .orderBy(desc(agentTransactions.createdAt))
        .limit(input.limit)
        .offset(input.offset)

      // Get total count for pagination
      const [countResult] = await db
        .select({ count: count() })
        .from(agentTransactions)
        .where(eq(agentTransactions.walletId, input.walletId))

      return { transactions, total: countResult?.count ?? 0 }
    }),

  // Get single transaction
  get: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [transaction] = await db
        .select()
        .from(agentTransactions)
        .where(eq(agentTransactions.id, input.id))
        .limit(1)

      if (!transaction) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Transaction not found' })
      }

      // Verify wallet access
      const [wallet] = await db
        .select()
        .from(agentWallets)
        .where(and(
          eq(agentWallets.id, transaction.walletId),
          eq(agentWallets.principalId, principal.id)
        ))
        .limit(1)

      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Transaction not found' })
      }

      return transaction
    }),
})
