'use client'

import { useParams } from 'next/navigation'
import { createContext, useContext } from 'react'
import { trpc } from '@/lib/trpc/client'

// App context to share app data with child components
interface AppContextValue {
  appId: string
  app: {
    id: string
    name: string
    description: string | null
    role: 'owner' | 'admin' | 'developer' | 'viewer'
  } | null | undefined
  isLoading: boolean
}

const AppContext = createContext<AppContextValue | null>(null)

export function useApp() {
  const context = useContext(AppContext)
  if (!context) {
    throw new Error('useApp must be used within AppLayout')
  }
  return context
}

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const params = useParams()
  const appId = params.appId as string

  const { data: app, isLoading } = trpc.apps.get.useQuery({ id: appId }, { enabled: !!appId })

  return (
    <AppContext.Provider value={{ appId, app, isLoading }}>
      {children}
    </AppContext.Provider>
  )
}
