'use client'

import { usePathname } from 'next/navigation'
import { useEffect } from 'react'
import { AppSidebar } from '@/components/layout/app-sidebar'
import { UserNav } from '@/components/layout/user-nav'
import { Separator } from '@/components/ui/separator'
import { SidebarInset, SidebarProvider, SidebarTrigger } from '@/components/ui/sidebar'
import { isProvider, useSession } from '@/lib/auth/client'
import { trpc } from '@/lib/trpc/client'

interface DashboardShellProps {
  user: {
    id: string
    name: string
    email: string
    image?: string | null
  }
  children: React.ReactNode
}

export function DashboardShell({ user, children }: DashboardShellProps) {
  const pathname = usePathname()
  const { data: session } = useSession()

  // Ensure principal exists for current user
  const principalMutation = trpc.principals.getOrCreate.useMutation()

  useEffect(() => {
    // Create principal on first load if needed
    principalMutation.mutate()
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Check if we're in admin or wallet route
  const isAdminRoute = pathname.startsWith('/admin')
  const walletIdMatch = pathname.match(/^\/wallets\/([^/]+)/)
  const currentWalletId = walletIdMatch ? walletIdMatch[1] : undefined

  // Fetch wallet data if we're in a wallet route
  const { data: wallet } = trpc.wallets.get.useQuery(
    { id: currentWalletId! },
    { enabled: !!currentWalletId && currentWalletId !== 'new' }
  )

  // Check if user has provider/admin role
  const userRole = (session?.user as { role?: string } | undefined)?.role
  const isAdmin = isProvider(userRole)

  // Determine header title
  const headerTitle = isAdminRoute ? 'Admin Console' : wallet?.name

  return (
    <SidebarProvider>
      <AppSidebar
        currentWalletId={currentWalletId !== 'new' ? currentWalletId : undefined}
        currentWalletName={wallet?.name}
        isAdmin={isAdmin}
        isAdminRoute={isAdminRoute}
      />
      <SidebarInset>
        <header className="flex h-16 shrink-0 items-center justify-between gap-2 border-b px-4">
          <div className="flex items-center gap-2">
            <SidebarTrigger className="-ml-1" />
            <Separator orientation="vertical" className="mr-2 h-4" />
            {headerTitle && <span className="text-sm font-medium text-muted-foreground">{headerTitle}</span>}
          </div>
          <UserNav user={{ ...user, role: userRole }} isAdminRoute={isAdminRoute} />
        </header>
        <main className="flex-1 p-6">{children}</main>
      </SidebarInset>
    </SidebarProvider>
  )
}
