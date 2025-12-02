'use client'

import { usePathname } from 'next/navigation'
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

  // Check if we're in admin or app route
  const isAdminRoute = pathname.startsWith('/admin')
  const appIdMatch = pathname.match(/^\/apps\/([^/]+)/)
  const currentAppId = appIdMatch ? appIdMatch[1] : undefined

  // Fetch app data if we're in an app route
  const { data: app } = trpc.apps.get.useQuery(
    { id: currentAppId! },
    { enabled: !!currentAppId && currentAppId !== 'new' }
  )

  // Check if user has provider/admin role
  const userRole = (session?.user as { role?: string } | undefined)?.role
  const isAdmin = isProvider(userRole)

  // Determine header title
  const headerTitle = isAdminRoute ? 'Admin Console' : app?.name

  return (
    <SidebarProvider>
      <AppSidebar
        currentAppId={currentAppId !== 'new' ? currentAppId : undefined}
        currentAppName={app?.name}
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
