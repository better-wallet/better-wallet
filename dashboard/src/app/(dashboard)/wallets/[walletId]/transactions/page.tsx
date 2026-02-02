'use client'

import { useParams } from 'next/navigation'
import { ArrowLeftRight } from 'lucide-react'
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
import { trpc } from '@/lib/trpc/client'

export default function TransactionsPage() {
  const params = useParams<{ walletId: string }>()
  const walletId = params.walletId
  const { data, isLoading } = trpc.transactions.list.useQuery({ walletId })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <Badge variant="secondary">Pending</Badge>
      case 'confirmed':
        return <Badge variant="default">Confirmed</Badge>
      case 'failed':
        return <Badge variant="destructive">Failed</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  const truncateHash = (hash: string | null) => {
    if (!hash) return '-'
    return `${hash.slice(0, 10)}...${hash.slice(-8)}`
  }

  const truncateAddress = (address: string | null) => {
    if (!address) return '-'
    return `${address.slice(0, 10)}...${address.slice(-8)}`
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Transactions"
        description="View transaction history for this wallet"
      />

      {isLoading ? (
        <Card>
          <CardContent className="p-6">
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : data?.transactions && data.transactions.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>TX Hash</TableHead>
                <TableHead>Method</TableHead>
                <TableHead>To</TableHead>
                <TableHead>Value</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {data.transactions.map((tx) => (
                <TableRow key={tx.id}>
                  <TableCell className="font-mono text-xs">
                    {tx.txHash ? (
                      <a
                        href={`https://etherscan.io/tx/${tx.txHash}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        {truncateHash(tx.txHash)}
                      </a>
                    ) : (
                      '-'
                    )}
                  </TableCell>
                  <TableCell>
                    <code className="text-xs bg-muted px-2 py-1 rounded">
                      {tx.method}
                    </code>
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {truncateAddress(tx.toAddress)}
                  </TableCell>
                  <TableCell className="font-mono text-xs">
                    {tx.value || '0'}
                  </TableCell>
                  <TableCell>{getStatusBadge(tx.status)}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {new Date(tx.createdAt).toLocaleString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <ArrowLeftRight className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No transactions yet</h3>
            <p className="text-muted-foreground">
              Transactions will appear here when agents use this wallet
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
