'use client'

import { redirect } from 'next/navigation'
import { isProvider, useSession } from '@/lib/auth/client'

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const { data: session, isPending } = useSession()

  // Check if user has provider/admin role
  const userRole = (session?.user as { role?: string } | undefined)?.role
  const isAdmin = isProvider(userRole)

  if (isPending) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (!session) {
    redirect('/login')
  }

  // Redirect non-admin users to apps page
  if (!isAdmin) {
    redirect('/apps')
  }

  return <>{children}</>
}
