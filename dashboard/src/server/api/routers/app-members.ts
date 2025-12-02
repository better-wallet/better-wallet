import { TRPCError } from '@trpc/server'
import { and, eq } from 'drizzle-orm'
import { z } from 'zod'
import { db } from '@/server/db'
import { appMembers, apps, user, walletUsers } from '@/server/db/schema'
import { createTRPCRouter, protectedProcedure } from '../trpc'
import { checkAppAccess, getOrCreateWalletUser } from './apps'

const roleSchema = z.enum(['admin', 'developer', 'viewer'])

export const appMembersRouter = createTRPCRouter({
  // List members of an app
  list: protectedProcedure.input(z.object({ appId: z.string().uuid() })).query(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(input.appId, walletUser.id)

    // Get members with their dashboard user info
    const members = await db
      .select({
        id: appMembers.id,
        userId: appMembers.userId,
        role: appMembers.role,
        invitedBy: appMembers.invitedBy,
        createdAt: appMembers.createdAt,
        dashboardUserId: walletUsers.dashboardUserId,
      })
      .from(appMembers)
      .innerJoin(walletUsers, eq(appMembers.userId, walletUsers.id))
      .where(eq(appMembers.appId, input.appId))

    // Get member emails from dashboard user table
    const membersWithEmail = await Promise.all(
      members.map(async (member) => {
        const dashboardUser = await db
          .select({ email: user.email, name: user.name })
          .from(user)
          .where(eq(user.id, member.dashboardUserId))
          .limit(1)
        return {
          ...member,
          email: dashboardUser[0]?.email,
          name: dashboardUser[0]?.name,
        }
      })
    )

    // Get owner info
    const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)
    const ownerWalletUser = await db.select().from(walletUsers).where(eq(walletUsers.id, app[0].ownerId)).limit(1)
    const ownerDashboardUser = await db
      .select({ email: user.email, name: user.name })
      .from(user)
      .where(eq(user.id, ownerWalletUser[0].dashboardUserId))
      .limit(1)

    return {
      owner: {
        userId: ownerWalletUser[0].id,
        email: ownerDashboardUser[0]?.email,
        name: ownerDashboardUser[0]?.name,
        role: 'owner' as const,
      },
      members: membersWithEmail,
    }
  }),

  // Invite a new member (by email)
  invite: protectedProcedure
    .input(
      z.object({
        appId: z.string().uuid(),
        email: z.string().email(),
        role: roleSchema,
      })
    )
    .mutation(async ({ ctx, input }) => {
      const currentWalletUser = await getOrCreateWalletUser(ctx.user.id)
      await checkAppAccess(input.appId, currentWalletUser.id, ['owner', 'admin'])

      // Find dashboard user by email
      const dashboardUser = await db.select().from(user).where(eq(user.email, input.email)).limit(1)

      if (!dashboardUser[0]) {
        throw new TRPCError({
          code: 'NOT_FOUND',
          message: 'User not found. They need to sign up first.',
        })
      }

      // Get or create wallet user for the invitee
      let inviteeWalletUser = await db
        .select()
        .from(walletUsers)
        .where(eq(walletUsers.dashboardUserId, dashboardUser[0].id))
        .limit(1)

      if (!inviteeWalletUser[0]) {
        const [newWalletUser] = await db
          .insert(walletUsers)
          .values({ dashboardUserId: dashboardUser[0].id })
          .returning()
        inviteeWalletUser = [newWalletUser]
      }

      // Check if already a member
      const existingMember = await db
        .select()
        .from(appMembers)
        .where(and(eq(appMembers.appId, input.appId), eq(appMembers.userId, inviteeWalletUser[0].id)))
        .limit(1)

      if (existingMember[0]) {
        throw new TRPCError({ code: 'CONFLICT', message: 'User is already a member' })
      }

      // Check if trying to add owner as member
      const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)
      if (app[0].ownerId === inviteeWalletUser[0].id) {
        throw new TRPCError({ code: 'BAD_REQUEST', message: 'Cannot add owner as member' })
      }

      const [newMember] = await db
        .insert(appMembers)
        .values({
          appId: input.appId,
          userId: inviteeWalletUser[0].id,
          role: input.role,
          invitedBy: currentWalletUser.id,
        })
        .returning()

      return {
        ...newMember,
        email: dashboardUser[0].email,
        name: dashboardUser[0].name,
      }
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

      const walletUser = await getOrCreateWalletUser(ctx.user.id)
      await checkAppAccess(member[0].appId, walletUser.id, ['owner', 'admin'])

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

    const walletUser = await getOrCreateWalletUser(ctx.user.id)
    await checkAppAccess(member[0].appId, walletUser.id, ['owner', 'admin'])

    await db.delete(appMembers).where(eq(appMembers.id, input.id))

    return { success: true }
  }),

  // Leave an app (self-remove)
  leave: protectedProcedure.input(z.object({ appId: z.string().uuid() })).mutation(async ({ ctx, input }) => {
    const walletUser = await getOrCreateWalletUser(ctx.user.id)

    // Check if owner (can't leave own app)
    const app = await db.select().from(apps).where(eq(apps.id, input.appId)).limit(1)

    if (!app[0]) {
      throw new TRPCError({ code: 'NOT_FOUND', message: 'App not found' })
    }

    if (app[0].ownerId === walletUser.id) {
      throw new TRPCError({
        code: 'BAD_REQUEST',
        message: 'Owner cannot leave app. Transfer ownership or delete the app.',
      })
    }

    await db.delete(appMembers).where(and(eq(appMembers.appId, input.appId), eq(appMembers.userId, walletUser.id)))

    return { success: true }
  }),
})
