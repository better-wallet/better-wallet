'use client'

import { Activity, FileText, Key, Shield, Users, Wallet } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'

import { ErrorState } from '@/components/data/error-state'
import { StatsSkeleton } from '@/components/data/loading-state'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { trpc } from '@/lib/trpc/client'

export default function AppOverviewPage() {
  const params = useParams()
  const appId = params.appId as string

  const { data: app, isLoading: appLoading, error: appError, refetch } = trpc.apps.get.useQuery({ id: appId })
  const { data: health } = trpc.backend.health.useQuery()
  const { data: stats } = trpc.backend.stats.useQuery({ appId })

  if (appLoading) {
    return (
      <div>
        <PageHeader title="Loading..." />
        <StatsSkeleton />
      </div>
    )
  }

  if (appError) {
    return (
      <div>
        <PageHeader title="Error" />
        <ErrorState message={appError.message} onRetry={() => refetch()} />
      </div>
    )
  }

  if (!app) {
    return (
      <div>
        <PageHeader title="Not Found" />
        <ErrorState message="App not found" />
      </div>
    )
  }

  const quickLinks = [
    {
      title: 'Wallets',
      description: 'Create and manage wallets',
      icon: Wallet,
      href: `/apps/${appId}/wallets`,
      count: stats?.wallets_count,
    },
    {
      title: 'Policies',
      description: 'Configure access control rules',
      icon: Shield,
      href: `/apps/${appId}/policies`,
      count: stats?.policies_count,
    },
    {
      title: 'Auth Keys',
      description: 'Manage authorization keys',
      icon: Key,
      href: `/apps/${appId}/keys`,
    },
    {
      title: 'Condition Sets',
      description: 'Reusable value sets for policies',
      icon: FileText,
      href: `/apps/${appId}/condition-sets`,
    },
  ]

  return (
    <div className="space-y-6">
      <PageHeader
        title={app.name}
        description={app.description || 'No description'}
        actions={
          <Badge variant="outline" className="capitalize">
            {app.role}
          </Badge>
        }
      />

      {/* Stats */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Wallets</CardTitle>
            <Wallet className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.wallets_count ?? '-'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Policies</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.policies_count ?? '-'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Users</CardTitle>
            <Users className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.users_count ?? '-'}</div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Transactions</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats?.transactions_count ?? '-'}</div>
          </CardContent>
        </Card>
      </div>

      {/* System Health */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">System Status</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex gap-4">
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${health?.api ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm">API</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${health?.database ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm">Database</span>
            </div>
            <div className="flex items-center gap-2">
              <div className={`h-2 w-2 rounded-full ${health?.execution_backend ? 'bg-green-500' : 'bg-red-500'}`} />
              <span className="text-sm">Execution Backend</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Links */}
      <div>
        <h2 className="text-lg font-semibold mb-4">Quick Access</h2>
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {quickLinks.map((link) => (
            <Link key={link.title} href={link.href}>
              <Card className="hover:border-primary/50 transition-colors cursor-pointer h-full">
                <CardHeader>
                  <div className="flex items-center gap-2">
                    <link.icon className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-base">{link.title}</CardTitle>
                  </div>
                  <CardDescription>{link.description}</CardDescription>
                </CardHeader>
              </Card>
            </Link>
          ))}
        </div>
      </div>
    </div>
  )
}
