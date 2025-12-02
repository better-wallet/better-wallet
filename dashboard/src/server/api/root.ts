import { adminRouter } from './routers/admin'
import { appMembersRouter } from './routers/app-members'
import { appSecretsRouter } from './routers/app-secrets'
import { appsRouter } from './routers/apps'
import { backendRouter } from './routers/backend'
import { createCallerFactory, createTRPCRouter } from './trpc'

export const appRouter = createTRPCRouter({
  // Dashboard-managed resources
  apps: appsRouter,
  appSecrets: appSecretsRouter,
  appMembers: appMembersRouter,

  // Backend-managed resources (proxied to Go API)
  backend: backendRouter,

  // Admin-only operations
  admin: adminRouter,
})

export type AppRouter = typeof appRouter

export const createCaller = createCallerFactory(appRouter)
