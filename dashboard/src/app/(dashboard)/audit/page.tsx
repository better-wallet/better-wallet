'use client'

import { useState } from 'react'
import { FileText, Filter } from 'lucide-react'
import { PageHeader } from '@/components/layout/page-header'
import { Card, CardContent } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { trpc } from '@/lib/trpc/client'

const ACTION_TYPES = [
  { value: 'all', label: 'All Actions' },
  { value: 'wallet_created', label: 'Wallet Created' },
  { value: 'wallet_paused', label: 'Wallet Paused' },
  { value: 'wallet_resumed', label: 'Wallet Resumed' },
  { value: 'wallet_killed', label: 'Wallet Killed' },
  { value: 'credential_created', label: 'Credential Created' },
  { value: 'credential_paused', label: 'Credential Paused' },
  { value: 'credential_resumed', label: 'Credential Resumed' },
  { value: 'credential_revoked', label: 'Credential Revoked' },
  { value: 'transaction_submitted', label: 'Transaction Submitted' },
  { value: 'transaction_confirmed', label: 'Transaction Confirmed' },
  { value: 'transaction_failed', label: 'Transaction Failed' },
]

export default function AuditPage() {
  const [actionFilter, setActionFilter] = useState('all')
  const { data, isLoading } = trpc.audit.list.useQuery({
    action: actionFilter === 'all' ? undefined : actionFilter,
    limit: 100,
  })

  const getActionBadge = (action: string) => {
    if (action.includes('created')) {
      return <Badge variant="default">{action}</Badge>
    }
    if (action.includes('paused')) {
      return <Badge variant="secondary">{action}</Badge>
    }
    if (action.includes('killed') || action.includes('revoked') || action.includes('failed')) {
      return <Badge variant="destructive">{action}</Badge>
    }
    if (action.includes('resumed') || action.includes('confirmed')) {
      return <Badge variant="outline" className="border-green-500 text-green-600">{action}</Badge>
    }
    return <Badge variant="outline">{action}</Badge>
  }

  const formatDetails = (metadata: Record<string, unknown> | null) => {
    if (!metadata) return '-'
    const entries = Object.entries(metadata)
    if (entries.length === 0) return '-'
    return entries
      .slice(0, 3)
      .map(([key, value]) => `${key}: ${String(value)}`)
      .join(', ')
  }

  const getActorDisplay = (log: { credentialId: string | null; principalId: string | null }) => {
    if (log.credentialId) {
      return <span className="text-blue-600">Credential</span>
    }
    if (log.principalId) {
      return <span className="text-muted-foreground">Principal</span>
    }
    return <span className="text-orange-600">System</span>
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Audit Log"
        description="View all actions performed across your wallets"
      >
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <Select value={actionFilter} onValueChange={setActionFilter}>
            <SelectTrigger className="w-[200px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {ACTION_TYPES.map((type) => (
                <SelectItem key={type.value} value={type.value}>
                  {type.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
      </PageHeader>

      {isLoading ? (
        <Card>
          <CardContent className="p-6">
            <div className="space-y-4">
              {[1, 2, 3, 4, 5].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : data?.logs && data.logs.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Timestamp</TableHead>
                <TableHead>Action</TableHead>
                <TableHead>Actor</TableHead>
                <TableHead>Wallet</TableHead>
                <TableHead>Details</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.logs.map((log) => (
                <TableRow key={log.id}>
                  <TableCell className="text-sm text-muted-foreground whitespace-nowrap">
                    {new Date(log.createdAt).toLocaleString()}
                  </TableCell>
                  <TableCell>{getActionBadge(log.action)}</TableCell>
                  <TableCell className="text-sm">
                    {getActorDisplay(log)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {log.walletId ? (
                      <a
                        href={`/wallets/${log.walletId}`}
                        className="text-primary hover:underline"
                      >
                        {log.walletId.slice(0, 8)}...
                      </a>
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground max-w-xs truncate">
                    {formatDetails(log.metadata)}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <FileText className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No audit logs yet</h3>
            <p className="text-muted-foreground">
              Actions will be logged here as you use your wallets
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
