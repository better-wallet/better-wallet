'use client'

import Link from 'next/link'
import { useParams } from 'next/navigation'
import { ArrowRight, Shield, ArrowLeftRight, Cog } from 'lucide-react'
import { PageHeader } from '@/components/layout/page-header'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

export default function WalletOverviewPage() {
  const params = useParams<{ walletId: string }>()
  const walletId = params.walletId
  const { data: wallet, isLoading: walletLoading } = trpc.wallets.get.useQuery({ id: walletId })
  const { data: stats, isLoading: statsLoading } = trpc.wallets.stats.useQuery({ id: walletId })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge variant="default">Active</Badge>
      case 'paused':
        return <Badge variant="secondary">Paused</Badge>
      case 'killed':
        return <Badge variant="destructive">Killed</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  if (walletLoading) {
    return (
      <div className="space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-96" />
        </div>
        <div className="grid gap-4 md:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-24" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-8 w-16" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  if (!wallet) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-muted-foreground">Wallet not found</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title={wallet.name}
        description={
          <span className="font-mono text-sm">{wallet.address}</span>
        }
      >
        {getStatusBadge(wallet.status)}
      </PageHeader>

      {/* Stats Cards */}
      <div className="grid gap-4 md:grid-cols-3">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Active Credentials</CardDescription>
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold">
                {stats?.activeCredentials ?? 0}
                <span className="text-sm font-normal text-muted-foreground ml-2">
                  / {stats?.totalCredentials ?? 0} total
                </span>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Total Transactions</CardDescription>
          </CardHeader>
          <CardContent>
            {statsLoading ? (
              <Skeleton className="h-8 w-16" />
            ) : (
              <div className="text-2xl font-bold">{stats?.totalTransactions ?? 0}</div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Chain Type</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold uppercase">{wallet.chainType}</div>
          </CardContent>
        </Card>
      </div>

      {/* Quick Links */}
      <div className="grid gap-4 md:grid-cols-3">
        <Link href={`/wallets/${walletId}/credentials`}>
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Credentials
              </CardTitle>
              <CardDescription>Manage agent credentials and permissions</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center text-sm text-primary">
                View credentials <ArrowRight className="ml-2 h-4 w-4" />
              </div>
            </CardContent>
          </Card>
        </Link>

        <Link href={`/wallets/${walletId}/transactions`}>
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <ArrowLeftRight className="h-5 w-5" />
                Transactions
              </CardTitle>
              <CardDescription>View transaction history</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center text-sm text-primary">
                View transactions <ArrowRight className="ml-2 h-4 w-4" />
              </div>
            </CardContent>
          </Card>
        </Link>

        <Link href={`/wallets/${walletId}/settings`}>
          <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
            <CardHeader>
              <CardTitle className="text-lg flex items-center gap-2">
                <Cog className="h-5 w-5" />
                Settings
              </CardTitle>
              <CardDescription>Wallet settings and controls</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center text-sm text-primary">
                Manage settings <ArrowRight className="ml-2 h-4 w-4" />
              </div>
            </CardContent>
          </Card>
        </Link>
      </div>
    </div>
  )
}
