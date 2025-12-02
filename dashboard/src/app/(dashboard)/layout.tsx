import { redirect } from 'next/navigation'
import { getSession } from '@/lib/auth/server'
import { DashboardShell } from '@/components/layout/dashboard-shell'

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const session = await getSession()

  if (!session) {
    redirect('/login')
  }

  return <DashboardShell user={session.user}>{children}</DashboardShell>
}
