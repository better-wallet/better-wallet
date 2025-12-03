'use client'

import { Bot, Copy, MoreHorizontal, Plus, Wallet as WalletIcon } from 'lucide-react'
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
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
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
  const [showCreateDialog, setShowCreateDialog] = useState(false)
  const [chainType, setChainType] = useState<'ethereum' | 'solana'>('ethereum')

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.backend.wallets.list.useQuery({ appId })

  const createWallet = trpc.backend.wallets.create.useMutation({
    onSuccess: (data) => {
      toast.success(`App wallet created: ${data.address.slice(0, 10)}...`)
      utils.backend.wallets.list.invalidate()
      utils.backend.stats.invalidate()
      setShowCreateDialog(false)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

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

  const handleCreateWallet = async () => {
    await createWallet.mutateAsync({ appId, chainType })
  }

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
        actions={
          canManage && (
            <Button onClick={() => setShowCreateDialog(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create App Wallet
            </Button>
          )
        }
      />

      {wallets.length === 0 ? (
        <EmptyState
          icon={WalletIcon}
          title="No wallets"
          description="Create an App Wallet for server-side operations, or wallets will appear here when users create them via API."
          action={
            canManage
              ? {
                  label: 'Create App Wallet',
                  onClick: () => setShowCreateDialog(true),
                }
              : undefined
          }
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

      {/* Create App Wallet Dialog */}
      <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
        <DialogContent className="sm:max-w-[500px]">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Bot className="h-5 w-5" />
              Create App Wallet
            </DialogTitle>
            <DialogDescription className="text-left">
              Create a server-controlled wallet for automated operations.
            </DialogDescription>
          </DialogHeader>

          <div className="space-y-4 py-4">
            {/* Explanation Card */}
            <Card className="bg-muted/50">
              <CardContent className="pt-4 text-sm space-y-2">
                <p className="font-medium">What is an App Wallet?</p>
                <p className="text-muted-foreground">
                  An App Wallet is a <strong>server-controlled</strong> wallet without a user owner.
                  It is authenticated using your app&apos;s API secret only.
                </p>
                <p className="font-medium mt-3">Use cases:</p>
                <ul className="text-muted-foreground list-disc list-inside space-y-1">
                  <li>AI Agents &amp; Trading Bots</li>
                  <li>Gas Station (paying gas for users)</li>
                  <li>Treasury &amp; Fund Management</li>
                  <li>Automated DeFi Operations</li>
                </ul>
                <p className="text-muted-foreground mt-3">
                  <strong>Note:</strong> No authorization signature is required for operations.
                  Anyone with your API secret can control this wallet.
                </p>
              </CardContent>
            </Card>

            {/* Chain Type Selection */}
            <div className="space-y-2">
              <Label htmlFor="chain-type">Blockchain</Label>
              <Select value={chainType} onValueChange={(v) => setChainType(v as 'ethereum' | 'solana')}>
                <SelectTrigger id="chain-type">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="ethereum">Ethereum (EVM)</SelectItem>
                  <SelectItem value="solana">Solana</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {chainType === 'ethereum'
                  ? 'Works on Ethereum, Polygon, Arbitrum, Base, and other EVM chains.'
                  : 'Native Solana wallet for SPL tokens and programs.'}
              </p>
            </div>
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateDialog(false)}>
              Cancel
            </Button>
            <Button onClick={handleCreateWallet} disabled={createWallet.isPending}>
              {createWallet.isPending ? 'Creating...' : 'Create Wallet'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
