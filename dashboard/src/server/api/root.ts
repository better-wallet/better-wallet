import { appMembersRouter } from './routers/app-members'
import { appSecretsRouter } from './routers/app-secrets'
import { appsRouter } from './routers/apps'
import { auditRouter } from './routers/audit'
import { authorizationKeysRouter } from './routers/authorization-keys'
import { policiesRouter } from './routers/policies'
import { statsRouter } from './routers/stats'
import { transactionsRouter } from './routers/transactions'
import { usersRouter } from './routers/users'
import { walletsRouter } from './routers/wallets'
import { createCallerFactory, createTRPCRouter } from './trpc'

export const appRouter = createTRPCRouter({
  apps: appsRouter,
  appSecrets: appSecretsRouter,
  appMembers: appMembersRouter,
  wallets: walletsRouter,
  users: usersRouter,
  policies: policiesRouter,
  transactions: transactionsRouter,
  authorizationKeys: authorizationKeysRouter,
  audit: auditRouter,
  stats: statsRouter,
})

export type AppRouter = typeof appRouter

export const createCaller = createCallerFactory(appRouter)
