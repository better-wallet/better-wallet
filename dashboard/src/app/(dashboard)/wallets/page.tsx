'use client'

import { Plus, Wallet } from 'lucide-react'
import Link from 'next/link'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

export default function WalletsPage() {
  const { data: wallets, isLoading } = trpc.wallets.list.useQuery()

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

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Wallets"
        description="Manage your agent wallets and credentials"
      >
        <Button asChild>
          <Link href="/wallets/new">
            <Plus className="mr-2 h-4 w-4" />
            Create Wallet
          </Link>
        </Button>
      </PageHeader>

      {isLoading ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <Card key={i}>
              <CardHeader>
                <Skeleton className="h-5 w-32" />
                <Skeleton className="h-4 w-48" />
              </CardHeader>
              <CardContent>
                <Skeleton className="h-4 w-24" />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : wallets && wallets.length > 0 ? (
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {wallets.map((wallet) => (
            <Link key={wallet.id} href={`/wallets/${wallet.id}`}>
              <Card className="hover:bg-muted/50 transition-colors cursor-pointer">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-lg flex items-center gap-2">
                      <Wallet className="h-5 w-5" />
                      {wallet.name}
                    </CardTitle>
                    {getStatusBadge(wallet.status)}
                  </div>
                  <CardDescription className="font-mono text-xs truncate">
                    {wallet.address}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center gap-4 text-sm text-muted-foreground">
                    <span>{wallet.chainType.toUpperCase()}</span>
                    <span>Created {new Date(wallet.createdAt).toLocaleDateString()}</span>
                  </div>
                </CardContent>
              </Card>
            </Link>
          ))}
        </div>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Wallet className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No wallets yet</h3>
            <p className="text-muted-foreground mb-4">Create your first agent wallet to get started</p>
            <Button asChild>
              <Link href="/wallets/new">
                <Plus className="mr-2 h-4 w-4" />
                Create Wallet
              </Link>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
