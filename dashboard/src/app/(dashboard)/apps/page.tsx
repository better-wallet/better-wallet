'use client'

import { Building2, Plus } from 'lucide-react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'

import { EmptyState } from '@/components/data/empty-state'
import { ErrorState } from '@/components/data/error-state'
import { CardSkeleton } from '@/components/data/loading-state'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { trpc } from '@/lib/trpc/client'

export default function AppsPage() {
  const router = useRouter()
  const { data, isLoading, error, refetch } = trpc.apps.list.useQuery()

  if (isLoading) {
    return (
      <div>
        <PageHeader
          title="Apps"
          description="Manage your applications"
          actions={
            <Button asChild>
              <Link href="/apps/new">
                <Plus className="h-4 w-4 mr-2" />
                Create App
              </Link>
            </Button>
          }
        />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((i) => (
            <CardSkeleton key={i} />
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div>
        <PageHeader title="Apps" description="Manage your applications" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const allApps = [...(data?.owned || []), ...(data?.member || [])]

  if (allApps.length === 0) {
    return (
      <div>
        <PageHeader title="Apps" description="Manage your applications" />
        <EmptyState
          icon={Building2}
          title="No apps yet"
          description="Create your first app to start managing wallets and policies."
          action={{
            label: 'Create App',
            onClick: () => router.push('/apps/new'),
          }}
        />
      </div>
    )
  }

  return (
    <div>
      <PageHeader
        title="Apps"
        description="Manage your applications"
        actions={
          <Button asChild>
            <Link href="/apps/new">
              <Plus className="h-4 w-4 mr-2" />
              Create App
            </Link>
          </Button>
        }
      />

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {data?.owned.map((app) => (
          <Link key={app.id} href={`/apps/${app.id}`}>
            <Card className="hover:border-primary/50 transition-colors cursor-pointer">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Building2 className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-lg">{app.name}</CardTitle>
                  </div>
                  <Badge variant="secondary">Owner</Badge>
                </div>
                <CardDescription className="line-clamp-2">{app.description || 'No description'}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}

        {data?.member.map((app) => (
          <Link key={app.id} href={`/apps/${app.id}`}>
            <Card className="hover:border-primary/50 transition-colors cursor-pointer">
              <CardHeader>
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <Building2 className="h-5 w-5 text-muted-foreground" />
                    <CardTitle className="text-lg">{app.name}</CardTitle>
                  </div>
                  <Badge variant="outline" className="capitalize">
                    {app.memberRole}
                  </Badge>
                </div>
                <CardDescription className="line-clamp-2">{app.description || 'No description'}</CardDescription>
              </CardHeader>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
