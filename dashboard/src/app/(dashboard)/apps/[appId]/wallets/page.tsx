'use client'

import { Copy, MoreHorizontal, Wallet as WalletIcon } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'

import { EmptyState } from '@/components/data/empty-state'
import { ErrorState } from '@/components/data/error-state'
import { ConfirmDialog } from '@/components/forms/confirm-dialog'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

interface WalletData {
  id: string
  address: string
  chainType: string
  policy_ids: string[]
  created_at: number
}

function formatAddress(address: string) {
  if (address.length <= 13) return address
  return `${address.slice(0, 6)}...${address.slice(-4)}`
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

const chainTypeBadgeVariant = {
  ethereum: 'default' as const,
  solana: 'secondary' as const,
  bitcoin: 'outline' as const,
}

export default function WalletsPage() {
  const params = useParams()
  const appId = params.appId as string
  const [walletToDelete, setWalletToDelete] = useState<{ id: string; address: string } | null>(null)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.backend.wallets.list.useQuery({ appId })

  const deleteWallet = trpc.backend.wallets.delete.useMutation({
    onSuccess: () => {
      toast.success('Wallet deleted')
      utils.backend.wallets.list.invalidate()
      utils.backend.stats.invalidate()
      setWalletToDelete(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleDelete = async () => {
    if (walletToDelete) {
      await deleteWallet.mutateAsync({ appId, id: walletToDelete.id })
    }
  }

  const handleCopyAddress = async (address: string) => {
    await navigator.clipboard.writeText(address)
    toast.success('Address copied to clipboard')
  }

  const canManage = app?.role === 'owner' || app?.role === 'admin' || app?.role === 'developer'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Wallets" />
        <Card>
          <CardContent className="pt-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-4 py-4">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-20" />
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
        <PageHeader title="Wallets" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const wallets = data?.data || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Wallets"
        description="View and manage blockchain wallets for this app"
      />

      {wallets.length === 0 ? (
        <EmptyState
          icon={WalletIcon}
          title="No wallets"
          description="Wallets are created via the API by your application users."
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>All Wallets</CardTitle>
            <CardDescription>
              {wallets.length} wallet{wallets.length !== 1 ? 's' : ''} in this app
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead>Chain</TableHead>
                  <TableHead>Policies</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[100px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {wallets.map((wallet: WalletData) => (
                  <TableRow key={wallet.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <code className="text-sm font-mono">{formatAddress(wallet.address)}</code>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6"
                          onClick={() => handleCopyAddress(wallet.address)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={chainTypeBadgeVariant[wallet.chainType as keyof typeof chainTypeBadgeVariant] ?? 'outline'}>
                        {wallet.chainType}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">{wallet.policy_ids?.length || 0} policies</span>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(wallet.created_at)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem asChild>
                            <Link href={`/apps/${appId}/wallets/${wallet.id}`}>View Details</Link>
                          </DropdownMenuItem>
                          <DropdownMenuItem onClick={() => handleCopyAddress(wallet.address)}>
                            Copy Address
                          </DropdownMenuItem>
                          {canManage && (
                            <>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                className="text-destructive"
                                onClick={() => setWalletToDelete({ id: wallet.id, address: wallet.address })}
                              >
                                Delete
                              </DropdownMenuItem>
                            </>
                          )}
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={!!walletToDelete}
        onOpenChange={() => setWalletToDelete(null)}
        title="Delete Wallet"
        description={`Are you sure you want to delete wallet ${walletToDelete?.address ? formatAddress(walletToDelete.address) : ''}? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />
    </div>
  )
}
