'use client'

import { Activity, Building2, FileText, Settings } from 'lucide-react'
import Link from 'next/link'

import { PageHeader } from '@/components/layout/page-header'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { trpc } from '@/lib/trpc/client'

export default function AdminDashboardPage() {
  const { data: health } = trpc.backend.health.useQuery()
  const { data: apps } = trpc.apps.list.useQuery()

  const totalApps = apps ? apps.owned.length + apps.member.length : 0

  return (
    <div className="space-y-6">
      <PageHeader title="Admin Dashboard" description="System-wide overview and management" />

      {/* System Status */}
      <Card
        className={
          health?.status === 'ok' ? 'border-green-500/50 bg-green-500/10' : 'border-yellow-500/50 bg-yellow-500/10'
        }
      >
        <CardContent className="pt-6">
          <div className="flex items-center gap-3">
            <Activity className={`h-5 w-5 ${health?.status === 'ok' ? 'text-green-500' : 'text-yellow-500'}`} />
            <div>
              <p
                className={`font-medium ${health?.status === 'ok' ? 'text-green-700 dark:text-green-400' : 'text-yellow-700 dark:text-yellow-400'}`}
              >
                System Status: {health?.status?.toUpperCase() || 'UNKNOWN'}
              </p>
              <p className="text-sm text-muted-foreground mt-1">
                API: {health?.api ? 'OK' : 'Down'} | Database: {health?.database ? 'OK' : 'Down'} | Execution Backend:{' '}
                {health?.execution_backend ? 'OK' : 'Down'}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Apps</CardTitle>
            <Building2 className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{totalApps}</div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Actions */}
      <div className="grid gap-4 md:grid-cols-3">
        <Link href="/admin/apps">
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Building2 className="h-5 w-5" />
                All Apps
              </CardTitle>
              <CardDescription>View and manage all registered applications</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/admin/health">
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Activity className="h-5 w-5" />
                System Health
              </CardTitle>
              <CardDescription>Monitor backend services and infrastructure</CardDescription>
            </CardHeader>
          </Card>
        </Link>
        <Link href="/admin/config">
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer h-full">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Settings className="h-5 w-5" />
                Configuration
              </CardTitle>
              <CardDescription>View system configuration and environment</CardDescription>
            </CardHeader>
          </Card>
        </Link>
      </div>
    </div>
  )
}
