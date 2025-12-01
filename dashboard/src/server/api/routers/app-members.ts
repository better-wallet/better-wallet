import { TRPCError } from '@trpc/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { appMembers, apps, walletUsers } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'

const roleSchema = z.enum(['admin', 'developer', 'viewer'])

export const appMembersRouter = createTRPCRouter({
  // List members of an app
  list: protectedProcedure.input(z.object({ appId: z.string().uuid() })).query(async ({ ctx, input }) => {
    await checkAppAccess(ctx.user.id, input.appId)

    const members = await db
      .select({
        id: appMembers.id,
        userId: appMembers.userId,
        role: appMembers.role,
        invitedBy: appMembers.invitedBy,
        createdAt: appMembers.createdAt,
        userExternalSub: walletUsers.externalSub,
      })
      .from(appMembers)
      .innerJoin(walletUsers, eq(appMembers.userId, walletUsers.id))
      .where(eq(appMembers.appId, input.appId))

    // Also get owner info
    const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)
    const owner = await db.select().from(walletUsers).where(eq(walletUsers.id, app[0].ownerUserId)).limit(1)

    return {
      owner: {
        userId: owner[0].id,
        externalSub: owner[0].externalSub,
        role: 'owner' as const,
      },
      members,
    }
  }),

  // Invite a new member (by their external_sub / email)
  invite: protectedProcedure
    .input(
      z.object({
        appId: z.string().uuid(),
        externalSub: z.string().min(1), // The auth user id or email
        role: roleSchema,
      })
    )
    .mutation(async ({ ctx, input }) => {
      const currentUser = await checkAppAccess(ctx.user.id, input.appId, ['admin'])

      // Find or create the user to invite
      let inviteeUser = await db
        .select()
        .from(walletUsers)
        .where(eq(walletUsers.externalSub, input.externalSub))
        .limit(1)

      if (!inviteeUser[0]) {
        // Create the user record
        const [newUser] = await db.insert(walletUsers).values({ externalSub: input.externalSub }).returning()
        inviteeUser = [newUser]
      }

      // Check if already a member
      const existingMember = await db
        .select()
        .from(appMembers)
        .where(and(eq(appMembers.appId, input.appId), eq(appMembers.userId, inviteeUser[0].id)))
        .limit(1)

      if (existingMember[0]) {
        throw new TRPCError({ code: 'CONFLICT', message: 'User is already a member' })
      }

      // Check if trying to add owner as member
      const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)
      if (app[0].ownerUserId === inviteeUser[0].id) {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Cannot add owner as member' })
      }

      const [newMember] = await db
        .insert(appMembers)
        .values({
          appId: input.appId,
          userId: inviteeUser[0].id,
          role: input.role,
          invitedBy: currentUser.id,
        })
        .returning()

      return newMember
    }),

  // Update a member's role
  updateRole: protectedProcedure
    .input(
      z.object({
        id: z.string().uuid(),
        role: roleSchema,
      })
    )
    .mutation(async ({ ctx, input }) => {
      const member = await db.select().from(appMembers).where(eq(appMembers.id, input.id)).limit(1)

      if (!member[0]) {
        throw new TRPCError({ code: 'NOT_FOUND', message: 'Member not found' })
      }

      await checkAppAccess(ctx.user.id, member[0].appId, ['admin'])

      const [updatedMember] = await db
        .update(appMembers)
        .set({ role: input.role })
        .where(eq(appMembers.id, input.id))
        .returning()

      return updatedMember
    }),

  // Remove a member
  remove: protectedProcedure.input(z.object({ id: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const member = await db.select().from(appMembers).where(eq(appMembers.id, input.id)).limit(1)

    if (!member[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'Member not found' })
    }

    await checkAppAccess(ctx.user.id, member[0].appId, ['admin'])

    await db.delete(appMembers).where(eq(appMembers.id, input.id))

    return { success: true }
  }),

  // Leave an app (self-remove)
  leave: protectedProcedure.input(z.object({ appId: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const walletUser = await db.select().from(walletUsers).where(eq(walletUsers.externalSub, ctx.user.id)).limit(1)

    if (!walletUser[0]) {
      throw new TRPCError({ code: 'UNAUTHORIZED', message: 'User not found' })
    }

    // Check if owner (can't leave own app)
    const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)
    if (app[0]?.ownerUserId === walletUser[0].id) {
      throw new TRPCError({
        code: 'BAD_REQUEST',
        message: 'Owner cannot leave app. Transfer ownership or delete the app.',
      })
    }

    await db.delete(appMembers).where(and(eq(appMembers.appId, input.appId), eq(appMembers.userId, walletUser[0].id)))

    return { success: true }
  }),
})

// Helper to check if user has access to an app with required role
async function checkAppAccess(authUserId: string, appId: string, requiredRoles?: string[]) {
  // Get wallet user
  const walletUser = await db.select().from(walletUsers).where(eq(walletUsers.externalSub, authUserId)).limit(1)

  if (!walletUser[0]) {
    throw new TRPCError({ code: 'UNAUTHORIZED', message: 'User not found' })
  }

  // Check if owner
  const app = await db.select().from(apps).where(eq(apps.id, appId)).limit(1)

  if (!app[0]) {
    throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
  }

  if (app[0].ownerUserId === walletUser[0].id) {
    return walletUser[0] // Owner has full access
  }

  // Check membership
  const membership = await db
    .select()
    .from(appMembers)
    .where(and(eq(appMembers.appId, appId), eq(appMembers.userId, walletUser[0].id)))
    .limit(1)

  if (!membership[0]) {
    throw new TRPCError({ code: 'FORBIDDEN', message: 'Access denied' })
  }

  if (requiredRoles && !requiredRoles.includes(membership[0].role)) {
    throw new TRPCError({ code: 'FORBIDDEN', message: `Required role: ${requiredRoles.join(' or ')}` })
  }

  return walletUser[0]
}
