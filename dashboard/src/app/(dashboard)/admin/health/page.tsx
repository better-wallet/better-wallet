'use client'

import { Activity, CheckCircle, Database, RefreshCw, Server, XCircle } from 'lucide-react'

import { ErrorState } from '@/components/data/error-state'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

export default function SystemHealthPage() {
  const { data: health, isLoading, error, refetch } = trpc.backend.health.useQuery()

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="System Health" />
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
          {[1, 2, 3, 4].map((i) => (
            <Card key={i}>
              <CardContent className="pt-6">
                <Skeleton className="h-12 w-full" />
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="System Health" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const services = [
    {
      name: 'API Server',
      status: health?.api ? 'healthy' : 'unhealthy',
      icon: Server,
      description: 'Main API server handling requests',
    },
    {
      name: 'Database',
      status: health?.database ? 'healthy' : 'unhealthy',
      icon: Database,
      description: 'PostgreSQL database connection',
    },
    {
      name: 'Execution Backend',
      status: health?.execution_backend ? 'healthy' : 'unhealthy',
      icon: Activity,
      description: 'Key management and signing service',
    },
  ]

  const overallStatus = health?.status || 'unknown'

  return (
    <div className="space-y-6">
      <PageHeader
        title="System Health"
        description="Monitor backend services and infrastructure"
        actions={
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {/* Overall Status */}
      <Card
        className={
          overallStatus === 'ok'
            ? 'border-green-500/50 bg-green-500/10'
            : overallStatus === 'degraded'
              ? 'border-yellow-500/50 bg-yellow-500/10'
              : 'border-red-500/50 bg-red-500/10'
        }
      >
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              {overallStatus === 'ok' ? (
                <CheckCircle className="h-8 w-8 text-green-500" />
              ) : (
                <XCircle className="h-8 w-8 text-red-500" />
              )}
              <div>
                <p className="text-lg font-semibold">
                  Overall Status:{' '}
                  <span
                    className={
                      overallStatus === 'ok'
                        ? 'text-green-600 dark:text-green-400'
                        : overallStatus === 'degraded'
                          ? 'text-yellow-600 dark:text-yellow-400'
                          : 'text-red-600 dark:text-red-400'
                    }
                  >
                    {overallStatus.toUpperCase()}
                  </span>
                </p>
                <p className="text-sm text-muted-foreground">
                  {overallStatus === 'ok'
                    ? 'All systems are operational'
                    : overallStatus === 'degraded'
                      ? 'Some services may be experiencing issues'
                      : 'System is experiencing problems'}
                </p>
              </div>
            </div>
            <Badge variant={overallStatus === 'ok' ? 'default' : 'destructive'} className="text-sm px-3 py-1">
              {overallStatus === 'ok' ? 'Operational' : 'Issues Detected'}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {/* Service Status Grid */}
      <div className="grid gap-4 md:grid-cols-3">
        {services.map((service) => (
          <Card key={service.name}>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <service.icon className="h-5 w-5 text-muted-foreground" />
                  <CardTitle className="text-base">{service.name}</CardTitle>
                </div>
                {service.status === 'healthy' ? (
                  <CheckCircle className="h-5 w-5 text-green-500" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-500" />
                )}
              </div>
              <CardDescription>{service.description}</CardDescription>
            </CardHeader>
            <CardContent>
              <Badge variant={service.status === 'healthy' ? 'default' : 'destructive'}>
                {service.status === 'healthy' ? 'Healthy' : 'Unhealthy'}
              </Badge>
            </CardContent>
          </Card>
        ))}
      </div>

    </div>
  )
}
