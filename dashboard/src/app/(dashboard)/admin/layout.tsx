'use client'

import { useRouter } from 'next/navigation'
import { useEffect } from 'react'
import { isProvider, useSession } from '@/lib/auth/client'

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  const router = useRouter()
  const { data: session, isPending } = useSession()

  // Check if user has provider/admin role
  const userRole = (session?.user as { role?: string } | undefined)?.role
  const isAdmin = isProvider(userRole)

  useEffect(() => {
    if (!isPending) {
      if (!session) {
        router.replace('/login')
      } else if (!isAdmin) {
        router.replace('/wallets')
      }
    }
  }, [isPending, session, isAdmin, router])

  if (isPending) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-muted-foreground">Loading...</div>
      </div>
    )
  }

  if (!session || !isAdmin) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="text-muted-foreground">Redirecting...</div>
      </div>
    )
  }

  return <>{children}</>
}
