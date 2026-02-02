import { count, eq } from 'drizzle-orm'
import { db } from '@/server/db'
import { principals, agentWallets, agentCredentials } from '@/server/db/schema'
import { adminProcedure, createTRPCRouter } from '../trpc'

export const adminRouter = createTRPCRouter({
  // List ALL principals in the system (admin only)
  listAllPrincipals: adminProcedure.query(async () => {
    const allPrincipals = await db
      .select({
        id: principals.id,
        name: principals.name,
        email: principals.email,
        emailVerified: principals.emailVerified,
        createdAt: principals.createdAt,
        updatedAt: principals.updatedAt,
      })
      .from(principals)
      .orderBy(principals.createdAt)

    return allPrincipals
  }),

  // Get system stats (admin only)
  getSystemStats: adminProcedure.query(async () => {
    const [principalsResult] = await db.select({ count: count() }).from(principals)
    const [walletsResult] = await db.select({ count: count() }).from(agentWallets)
    const [credentialsResult] = await db.select({ count: count() }).from(agentCredentials)

    // Count active wallets
    const [activeWalletsResult] = await db
      .select({ count: count() })
      .from(agentWallets)
      .where(eq(agentWallets.status, 'active'))

    // Count active credentials
    const [activeCredentialsResult] = await db
      .select({ count: count() })
      .from(agentCredentials)
      .where(eq(agentCredentials.status, 'active'))

    return {
      totalPrincipals: principalsResult?.count ?? 0,
      totalWallets: walletsResult?.count ?? 0,
      activeWallets: activeWalletsResult?.count ?? 0,
      totalCredentials: credentialsResult?.count ?? 0,
      activeCredentials: activeCredentialsResult?.count ?? 0,
    }
  }),
})
