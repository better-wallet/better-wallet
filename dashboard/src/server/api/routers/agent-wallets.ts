import { eq, and, desc } from 'drizzle-orm'
import { z } from 'zod'
import { TRPCError } from '@trpc/server'
import { db } from '@/server/db'
import { principals, agentWallets, agentCredentials, agentTransactions } from '@/server/db/schema'
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

export const agentWalletsRouter = createTRPCRouter({
  // List all wallets for current principal
  list: protectedProcedure.query(async ({ ctx }) => {
    const principal = await getPrincipalForUser(ctx.user.email!)
    if (!principal) {
      return []
    }

    const wallets = await db
      .select()
      .from(agentWallets)
      .where(eq(agentWallets.principalId, principal.id))
      .orderBy(desc(agentWallets.createdAt))

    return wallets
  }),

  // Get single wallet
  get: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [wallet] = await db
        .select()
        .from(agentWallets)
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id)
        ))
        .limit(1)

      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      return wallet
    }),

  // Create new wallet
  create: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100),
      chainType: z.string().default('evm'),
    }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found. Please refresh the page.' })
      }

      // Generate a placeholder address - actual key generation happens in Go backend
      // Format: 0x + 40 hex chars (will be replaced when wallet is first used)
      const placeholderAddress = '0x' + Array.from({ length: 40 }, () =>
        Math.floor(Math.random() * 16).toString(16)
      ).join('')

      const [wallet] = await db
        .insert(agentWallets)
        .values({
          principalId: principal.id,
          name: input.name,
          chainType: input.chainType,
          address: placeholderAddress,
          execBackend: 'kms',
          status: 'active',
        })
        .returning()

      return wallet!
    }),

  // Update wallet name
  update: protectedProcedure
    .input(z.object({
      id: z.string().uuid(),
      name: z.string().min(1).max(100),
    }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [updated] = await db
        .update(agentWallets)
        .set({
          name: input.name,
          updatedAt: new Date(),
        })
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id)
        ))
        .returning()

      if (!updated) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      return updated
    }),

  // Pause wallet
  pause: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [updated] = await db
        .update(agentWallets)
        .set({
          status: 'paused',
          updatedAt: new Date(),
        })
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id),
          eq(agentWallets.status, 'active')
        ))
        .returning()

      if (!updated) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found or not active' })
      }

      return updated
    }),

  // Resume wallet
  resume: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [updated] = await db
        .update(agentWallets)
        .set({
          status: 'active',
          updatedAt: new Date(),
        })
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id),
          eq(agentWallets.status, 'paused')
        ))
        .returning()

      if (!updated) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found or not paused' })
      }

      return updated
    }),

  // Kill wallet (emergency stop - permanent)
  kill: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      const [updated] = await db
        .update(agentWallets)
        .set({
          status: 'killed',
          updatedAt: new Date(),
        })
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id)
        ))
        .returning()

      if (!updated) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      // Revoke all credentials for this wallet
      await db
        .update(agentCredentials)
        .set({
          status: 'revoked',
          revokedAt: new Date(),
        })
        .where(eq(agentCredentials.walletId, input.id))

      return updated
    }),

  // Get wallet stats
  stats: protectedProcedure
    .input(z.object({ id: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const principal = await getPrincipalForUser(ctx.user.email!)
      if (!principal) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Principal not found' })
      }

      // Verify wallet belongs to principal
      const [wallet] = await db
        .select()
        .from(agentWallets)
        .where(and(
          eq(agentWallets.id, input.id),
          eq(agentWallets.principalId, principal.id)
        ))
        .limit(1)

      if (!wallet) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Wallet not found' })
      }

      // Count credentials
      const credentials = await db
        .select()
        .from(agentCredentials)
        .where(eq(agentCredentials.walletId, input.id))

      const activeCredentials = credentials.filter(c => c.status === 'active').length
      const totalCredentials = credentials.length

      // Count transactions
      const transactions = await db
        .select()
        .from(agentTransactions)
        .where(eq(agentTransactions.walletId, input.id))

      return {
        activeCredentials,
        totalCredentials,
        totalTransactions: transactions.length,
      }
    }),
})
