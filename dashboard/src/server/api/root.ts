import { principalsRouter } from './routers/principals'
import { agentWalletsRouter } from './routers/agent-wallets'
import { agentCredentialsRouter } from './routers/agent-credentials'
import { principalApiKeysRouter } from './routers/principal-api-keys'
import { agentAuditRouter } from './routers/agent-audit'
import { agentTransactionsRouter } from './routers/agent-transactions'
import { adminRouter } from './routers/admin'
import { createCallerFactory, createTRPCRouter } from './trpc'

export const appRouter = createTRPCRouter({
  // Principal management
  principals: principalsRouter,

  // Agent Wallet resources
  wallets: agentWalletsRouter,
  credentials: agentCredentialsRouter,
  apiKeys: principalApiKeysRouter,
  audit: agentAuditRouter,
  transactions: agentTransactionsRouter,

  // Admin-only operations
  admin: adminRouter,
})

export type AppRouter = typeof appRouter

export const createCaller = createCallerFactory(appRouter)
