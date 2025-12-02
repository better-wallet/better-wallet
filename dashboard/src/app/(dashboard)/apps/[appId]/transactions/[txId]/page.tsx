'use client'

import { ArrowLeft, ArrowUpRight, Copy, FileCode, Fuel, Hash, Wallet } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'

import { ErrorState } from '@/components/data/error-state'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

const CHAIN_NAMES: Record<number, string> = {
  1: 'Ethereum',
  5: 'Goerli',
  11155111: 'Sepolia',
  137: 'Polygon',
  80001: 'Mumbai',
  42161: 'Arbitrum',
  10: 'Optimism',
  8453: 'Base',
}

const CHAIN_EXPLORERS: Record<number, string> = {
  1: 'https://etherscan.io',
  5: 'https://goerli.etherscan.io',
  11155111: 'https://sepolia.etherscan.io',
  137: 'https://polygonscan.com',
  80001: 'https://mumbai.polygonscan.com',
  42161: 'https://arbiscan.io',
  10: 'https://optimistic.etherscan.io',
  8453: 'https://basescan.org',
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleString('en-US', {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

function copyToClipboard(text: string) {
  navigator.clipboard.writeText(text)
}

function formatValue(value: string | null) {
  if (!value || value === '0') return '0 ETH'
  const eth = Number(value) / 1e18
  return `${eth.toFixed(18).replace(/\.?0+$/, '')} ETH`
}

function formatGwei(value: string | null) {
  if (!value) return '-'
  const gwei = Number(value) / 1e9
  return `${gwei.toFixed(2)} Gwei`
}

const statusVariant: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  pending: 'secondary',
  submitted: 'outline',
  confirmed: 'default',
  failed: 'destructive',
}

export default function TransactionDetailPage() {
  const params = useParams()
  const appId = params.appId as string
  const txId = params.txId as string

  const { data: tx, isLoading, error, refetch } = trpc.backend.transactions.get.useQuery({
    appId,
    id: txId,
  })

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Transaction Details" />
        <div className="grid gap-6 md:grid-cols-2">
          <Card>
            <CardHeader>
              <Skeleton className="h-6 w-32" />
            </CardHeader>
            <CardContent className="space-y-4">
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-full" />
              <Skeleton className="h-4 w-3/4" />
            </CardContent>
          </Card>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Transaction Details" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  if (!tx) {
    return (
      <div className="space-y-6">
        <PageHeader title="Transaction Details" />
        <ErrorState message="Transaction not found" />
      </div>
    )
  }

  const explorer = CHAIN_EXPLORERS[tx.chain_id]

  return (
    <div className="space-y-6">
      <PageHeader
        title="Transaction Details"
        description={tx.tx_hash ? `Hash: ${tx.tx_hash.slice(0, 20)}...` : `ID: ${tx.id.slice(0, 20)}...`}
        actions={
          <div className="flex gap-2">
            {tx.tx_hash && explorer && (
              <Button variant="outline" asChild>
                <a href={`${explorer}/tx/${tx.tx_hash}`} target="_blank" rel="noopener noreferrer">
                  <ArrowUpRight className="h-4 w-4 mr-2" />
                  View on Explorer
                </a>
              </Button>
            )}
            <Button variant="outline" asChild>
              <Link href={`/apps/${appId}/transactions`}>
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back
              </Link>
            </Button>
          </div>
        }
      />

      {/* Status Banner */}
      <Card className={tx.status === 'failed' ? 'border-red-200 bg-red-50' : undefined}>
        <CardContent className="pt-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <Badge variant={statusVariant[tx.status]} className="text-sm px-3 py-1">
                {tx.status.toUpperCase()}
              </Badge>
              <span className="text-sm text-muted-foreground">{formatDate(tx.created_at)}</span>
            </div>
            <Badge variant="outline">{CHAIN_NAMES[tx.chain_id] || `Chain ${tx.chain_id}`}</Badge>
          </div>
          {tx.error_message && (
            <div className="mt-4 p-3 bg-red-100 rounded-md text-red-700 text-sm">{tx.error_message}</div>
          )}
        </CardContent>
      </Card>

      <div className="grid gap-6 md:grid-cols-2">
        {/* Transaction Info */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Hash className="h-5 w-5" />
              <CardTitle>Transaction Info</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            {tx.tx_hash && (
              <div>
                <label className="text-sm font-medium text-muted-foreground">Transaction Hash</label>
                <div className="flex items-center gap-2 mt-1">
                  <code className="text-sm bg-muted px-2 py-1 rounded font-mono flex-1 break-all">{tx.tx_hash}</code>
                  <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => copyToClipboard(tx.tx_hash!)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>
            )}

            <div>
              <label className="text-sm font-medium text-muted-foreground">Internal ID</label>
              <div className="flex items-center gap-2 mt-1">
                <code className="text-sm bg-muted px-2 py-1 rounded font-mono flex-1 break-all">{tx.id}</code>
                <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => copyToClipboard(tx.id)}>
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">Method</label>
              <div className="mt-1">
                <Badge variant="outline">{tx.method}</Badge>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Nonce</label>
                <p className="mt-1 font-mono">{tx.nonce ?? '-'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Block</label>
                <p className="mt-1 font-mono">-</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Addresses */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Wallet className="h-5 w-5" />
              <CardTitle>Addresses</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <label className="text-sm font-medium text-muted-foreground">From (Wallet)</label>
              <div className="flex items-center gap-2 mt-1">
                <code className="text-sm bg-muted px-2 py-1 rounded font-mono flex-1 break-all">
                  {tx.wallet_address}
                </code>
                <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => copyToClipboard(tx.wallet_address)}>
                  <Copy className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" asChild>
                  <Link href={`/apps/${appId}/wallets/${tx.wallet_id}`}>
                    <ArrowUpRight className="h-4 w-4" />
                  </Link>
                </Button>
              </div>
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">To</label>
              {tx.to_address ? (
                <div className="flex items-center gap-2 mt-1">
                  <code className="text-sm bg-muted px-2 py-1 rounded font-mono flex-1 break-all">
                    {tx.to_address}
                  </code>
                  <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => copyToClipboard(tx.to_address!)}>
                    <Copy className="h-4 w-4" />
                  </Button>
                  {explorer && (
                    <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" asChild>
                      <a href={`${explorer}/address/${tx.to_address}`} target="_blank" rel="noopener noreferrer">
                        <ArrowUpRight className="h-4 w-4" />
                      </a>
                    </Button>
                  )}
                </div>
              ) : (
                <p className="mt-1 text-muted-foreground">Contract Creation</p>
              )}
            </div>

            <div>
              <label className="text-sm font-medium text-muted-foreground">Value</label>
              <p className="mt-1 font-mono text-lg">{formatValue(tx.value)}</p>
              {tx.value && tx.value !== '0' && (
                <p className="text-xs text-muted-foreground font-mono">{tx.value} wei</p>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Gas Info */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <Fuel className="h-5 w-5" />
              <CardTitle>Gas</CardTitle>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Gas Limit</label>
                <p className="mt-1 font-mono">{tx.gas_limit?.toLocaleString() ?? '-'}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Gas Used</label>
                <p className="mt-1 font-mono">-</p>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm font-medium text-muted-foreground">Max Fee</label>
                <p className="mt-1 font-mono">{formatGwei(tx.max_fee_per_gas)}</p>
              </div>
              <div>
                <label className="text-sm font-medium text-muted-foreground">Max Priority Fee</label>
                <p className="mt-1 font-mono">{formatGwei(tx.max_priority_fee_per_gas)}</p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Input Data */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-2">
              <FileCode className="h-5 w-5" />
              <CardTitle>Input Data</CardTitle>
            </div>
            <CardDescription>Raw calldata sent with the transaction</CardDescription>
          </CardHeader>
          <CardContent>
            {tx.data ? (
              <div className="relative">
                <pre className="text-xs bg-muted p-3 rounded-md overflow-x-auto max-h-48 font-mono">
                  {tx.data}
                </pre>
                <Button
                  variant="ghost"
                  size="sm"
                  className="absolute top-2 right-2"
                  onClick={() => copyToClipboard(tx.data!)}
                >
                  <Copy className="h-3 w-3" />
                </Button>
              </div>
            ) : (
              <p className="text-muted-foreground text-sm">No input data (simple transfer)</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Signed Transaction (if available) */}
      {tx.signed_tx && (
        <Card>
          <CardHeader>
            <CardTitle>Signed Transaction</CardTitle>
            <CardDescription>Raw signed transaction data</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="relative">
              <pre className="text-xs bg-muted p-3 rounded-md overflow-x-auto max-h-32 font-mono break-all">
                {tx.signed_tx}
              </pre>
              <Button
                variant="ghost"
                size="sm"
                className="absolute top-2 right-2"
                onClick={() => copyToClipboard(tx.signed_tx!)}
              >
                <Copy className="h-3 w-3" />
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
