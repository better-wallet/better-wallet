import { eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { principals } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

export const principalsRouter = createTRPCRouter({
  // Get or create principal for current user
  getOrCreate: protectedProcedure.mutation(async ({ ctx }) => {
    const userEmail = ctx.user.email!
    const userName = ctx.user.name || userEmail.split('@')[0] || 'User'

    // Use upsert pattern to avoid race conditions
    const [principal] = await db
      .insert(principals)
      .values({
        name: userName,
        email: userEmail,
        emailVerified: ctx.user.emailVerified ?? false,
      })
      .onConflictDoNothing({ target: principals.email })
      .returning()

    // If insert was skipped due to conflict, fetch the existing record
    if (!principal) {
      const [existing] = await db
        .select()
        .from(principals)
        .where(eq(principals.email, userEmail))
        .limit(1)
      return existing!
    }

    return principal
  }),

  // Get current principal
  get: protectedProcedure.query(async ({ ctx }) => {
    const userEmail = ctx.user.email

    const [principal] = await db
      .select()
      .from(principals)
      .where(eq(principals.email, userEmail!))
      .limit(1)

    return principal ?? null
  }),

  // Update principal
  update: protectedProcedure
    .input(z.object({
      name: z.string().min(1).max(100).optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const userEmail = ctx.user.email

      const [updated] = await db
        .update(principals)
        .set({
          name: input.name,
          updatedAt: new Date(),
        })
        .where(eq(principals.email, userEmail!))
        .returning()

      return updated
    }),
})
