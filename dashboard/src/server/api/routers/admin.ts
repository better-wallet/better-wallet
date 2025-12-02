import { count, eq } from 'drizzle-orm'
import { db } from '@/server/db'
import { apps, user, walletUsers } from '@/server/db/schema'
import { adminProcedure, createTRPCRouter } from '../trpc'

export const adminRouter = createTRPCRouter({
  // List ALL apps in the system (admin only)
  listAllApps: adminProcedure.query(async () => {
    const allApps = await db
      .select({
        id: apps.id,
        name: apps.name,
        description: apps.description,
        status: apps.status,
        ownerId: apps.ownerId,
        createdAt: apps.createdAt,
        updatedAt: apps.updatedAt,
      })
      .from(apps)
      .where(eq(apps.status, 'active'))
      .orderBy(apps.createdAt)

    return allApps
  }),

  // Get system stats (admin only)
  getSystemStats: adminProcedure.query(async () => {
    const [appsResult] = await db.select({ count: count() }).from(apps).where(eq(apps.status, 'active'))
    const [usersResult] = await db.select({ count: count() }).from(user)
    const [walletUsersResult] = await db.select({ count: count() }).from(walletUsers)

    return {
      totalApps: appsResult?.count ?? 0,
      totalDashboardUsers: usersResult?.count ?? 0,
      totalWalletUsers: walletUsersResult?.count ?? 0,
    }
  }),
})
