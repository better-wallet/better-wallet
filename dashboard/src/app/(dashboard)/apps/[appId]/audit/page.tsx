'use client'

import { ClipboardList, ExternalLink, Filter, RefreshCw } from 'lucide-react'
import { useParams } from 'next/navigation'
import { useState } from 'react'

import { EmptyState } from '@/components/data/empty-state'
import { ErrorState } from '@/components/data/error-state'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

interface AuditLogData {
  id: number
  actor: string
  action: string
  resource_type: string
  resource_id: string
  policy_result: string | null
  signer_id: string | null
  tx_hash: string | null
  client_ip: string | null
  created_at: number
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

const actionBadgeVariant: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  create: 'default',
  update: 'secondary',
  delete: 'destructive',
  sign: 'default',
  approve: 'default',
  deny: 'destructive',
  revoke: 'destructive',
  rotate: 'secondary',
}

const resourceTypeLabels: Record<string, string> = {
  wallet: 'Wallet',
  policy: 'Policy',
  authorization_key: 'Auth Key',
  session_signer: 'Session Signer',
  condition_set: 'Condition Set',
  transaction: 'Transaction',
  user: 'User',
}

export default function AuditLogPage() {
  const params = useParams()
  const appId = params.appId as string

  const [actor, setActor] = useState('')
  const [action, setAction] = useState<string>('')
  const [resourceType, setResourceType] = useState<string>('')

  const { data, isLoading, error, refetch } = trpc.backend.auditLogs.list.useQuery({
    appId,
    actor: actor || undefined,
    action: action || undefined,
    resourceType: resourceType || undefined,
    limit: 50,
  })

  const clearFilters = () => {
    setActor('')
    setAction('')
    setResourceType('')
  }

  const hasFilters = actor || action || resourceType

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Audit Log" />
        <Card>
          <CardContent className="pt-6">
            {[1, 2, 3, 4, 5].map((i) => (
              <div key={i} className="flex items-center gap-4 py-4">
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-20" />
                <Skeleton className="h-4 w-40" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Audit Log" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const logs = data?.data || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="View all security events and actions for this app"
        actions={
          <Button variant="outline" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        }
      />

      {/* Filters */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Filter className="h-4 w-4" />
              <CardTitle className="text-base">Filters</CardTitle>
            </div>
            {hasFilters && (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                Clear All
              </Button>
            )}
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid gap-4 md:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="actor">Actor</Label>
              <Input
                id="actor"
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                placeholder="Filter by actor ID..."
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="action">Action</Label>
              <Select value={action || '__all__'} onValueChange={(v) => setAction(v === '__all__' ? '' : v)}>
                <SelectTrigger id="action">
                  <SelectValue placeholder="All actions" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">All actions</SelectItem>
                  <SelectItem value="create">Create</SelectItem>
                  <SelectItem value="update">Update</SelectItem>
                  <SelectItem value="delete">Delete</SelectItem>
                  <SelectItem value="sign">Sign</SelectItem>
                  <SelectItem value="approve">Approve</SelectItem>
                  <SelectItem value="deny">Deny</SelectItem>
                  <SelectItem value="revoke">Revoke</SelectItem>
                  <SelectItem value="rotate">Rotate</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="resource-type">Resource Type</Label>
              <Select value={resourceType || '__all__'} onValueChange={(v) => setResourceType(v === '__all__' ? '' : v)}>
                <SelectTrigger id="resource-type">
                  <SelectValue placeholder="All types" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__all__">All types</SelectItem>
                  <SelectItem value="wallet">Wallet</SelectItem>
                  <SelectItem value="policy">Policy</SelectItem>
                  <SelectItem value="authorization_key">Auth Key</SelectItem>
                  <SelectItem value="session_signer">Session Signer</SelectItem>
                  <SelectItem value="condition_set">Condition Set</SelectItem>
                  <SelectItem value="transaction">Transaction</SelectItem>
                  <SelectItem value="user">User</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Log Table */}
      {logs.length === 0 ? (
        <EmptyState
          icon={ClipboardList}
          title={hasFilters ? 'No matching events' : 'No audit events'}
          description={
            hasFilters
              ? 'Try adjusting your filters to find events.'
              : 'Security events will appear here as actions are performed.'
          }
          action={hasFilters ? { label: 'Clear Filters', onClick: clearFilters } : undefined}
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Events</CardTitle>
            <CardDescription>
              Showing {logs.length} event{logs.length !== 1 ? 's' : ''}
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Timestamp</TableHead>
                  <TableHead>Actor</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Resource</TableHead>
                  <TableHead>Result</TableHead>
                  <TableHead>Details</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.map((log: AuditLogData) => (
                  <TableRow key={log.id}>
                    <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                      {formatDate(log.created_at)}
                    </TableCell>
                    <TableCell>
                      <code className="text-xs bg-muted px-1 py-0.5 rounded">
                        {log.actor.length > 20 ? `${log.actor.slice(0, 8)}...` : log.actor}
                      </code>
                    </TableCell>
                    <TableCell>
                      <Badge variant={actionBadgeVariant[log.action] || 'outline'}>{log.action}</Badge>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-xs">
                          {resourceTypeLabels[log.resource_type] || log.resource_type}
                        </Badge>
                        <code className="text-xs text-muted-foreground">
                          {log.resource_id.length > 12 ? `${log.resource_id.slice(0, 8)}...` : log.resource_id}
                        </code>
                      </div>
                    </TableCell>
                    <TableCell>
                      {log.policy_result && (
                        <Badge variant={log.policy_result === 'allow' ? 'default' : 'destructive'}>
                          {log.policy_result}
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        {log.tx_hash && (
                          <a
                            href={`https://etherscan.io/tx/${log.tx_hash}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-xs text-primary hover:underline flex items-center gap-1"
                          >
                            <ExternalLink className="h-3 w-3" />
                            Tx
                          </a>
                        )}
                        {log.signer_id && (
                          <span className="text-xs text-muted-foreground">Signer: {log.signer_id.slice(0, 8)}...</span>
                        )}
                        {log.client_ip && <span className="text-xs text-muted-foreground">{log.client_ip}</span>}
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
