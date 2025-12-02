'use client'

import { ArrowLeft, Check, Clock, Copy, ExternalLink, Key, Plus, Shield, Trash2, X } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'

import { ErrorState } from '@/components/data/error-state'
import { ConfirmDialog } from '@/components/forms/confirm-dialog'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Checkbox } from '@/components/ui/checkbox'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

interface SessionSignerData {
  id: string
  signer_public_key: string
  policy_override_id: string | null
  allowed_methods: string[] | null
  max_value: string | null
  max_txs: number | null
  ttl_expires_at: string
  created_at: string
  revoked_at?: string
}

function formatDate(timestamp: number | string) {
  const date = typeof timestamp === 'string' ? new Date(timestamp) : new Date(timestamp)
  return date.toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function isExpired(expiresAt: string) {
  return new Date(expiresAt) < new Date()
}

const chainTypeBadgeVariant = {
  ethereum: 'default' as const,
  solana: 'secondary' as const,
  bitcoin: 'outline' as const,
}

export default function WalletDetailPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string
  const walletId = params.walletId as string
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)
  const [showDeleteSignerDialog, setShowDeleteSignerDialog] = useState<string | null>(null)
  const [showPolicyDialog, setShowPolicyDialog] = useState(false)
  const [selectedPolicies, setSelectedPolicies] = useState<string[]>([])

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data: wallet, isLoading, error, refetch } = trpc.backend.wallets.get.useQuery({ appId, id: walletId })
  const { data: sessionSigners, refetch: refetchSigners } = trpc.backend.sessionSigners.list.useQuery({
    appId,
    walletId,
  })
  const { data: allPolicies } = trpc.backend.policies.list.useQuery({ appId, limit: 100 })

  // Initialize selected policies when wallet data loads
  useEffect(() => {
    if (wallet?.policy_ids) {
      setSelectedPolicies(wallet.policy_ids)
    }
  }, [wallet?.policy_ids])

  const deleteWallet = trpc.backend.wallets.delete.useMutation({
    onSuccess: () => {
      toast.success('Wallet deleted')
      utils.backend.wallets.list.invalidate()
      utils.backend.stats.invalidate()
      router.push(`/apps/${appId}/wallets`)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const deleteSessionSigner = trpc.backend.sessionSigners.delete.useMutation({
    onSuccess: () => {
      toast.success('Session signer revoked')
      refetchSigners()
      setShowDeleteSignerDialog(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const updatePolicies = trpc.backend.wallets.updatePolicies.useMutation({
    onSuccess: () => {
      toast.success('Policies updated successfully')
      refetch()
      setShowPolicyDialog(false)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleCopyAddress = async () => {
    if (wallet) {
      await navigator.clipboard.writeText(wallet.address)
      toast.success('Address copied to clipboard')
    }
  }

  const handleDelete = async () => {
    await deleteWallet.mutateAsync({ appId, id: walletId })
  }

  const handleDeleteSessionSigner = async (signerId: string) => {
    await deleteSessionSigner.mutateAsync({ appId, walletId, signerId })
  }

  const handleOpenPolicyDialog = () => {
    // Reset selected policies to current wallet policies when opening dialog
    setSelectedPolicies(wallet?.policy_ids || [])
    setShowPolicyDialog(true)
  }

  const handleTogglePolicy = (policyId: string) => {
    setSelectedPolicies((prev) =>
      prev.includes(policyId) ? prev.filter((id) => id !== policyId) : [...prev, policyId]
    )
  }

  const handleSavePolicies = async () => {
    await updatePolicies.mutateAsync({
      appId,
      walletId,
      policyIds: selectedPolicies,
    })
  }

  const canManage = app?.role === 'owner' || app?.role === 'admin' || app?.role === 'developer'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Loading..." />
        <Card>
          <CardContent className="pt-6 space-y-4">
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-96" />
            <Skeleton className="h-4 w-32" />
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Error" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  if (!wallet) {
    return (
      <div className="space-y-6">
        <PageHeader title="Not Found" />
        <ErrorState message="Wallet not found" />
      </div>
    )
  }


  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href={`/apps/${appId}/wallets`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <PageHeader
          title="Wallet Details"
          description={wallet.address}
          actions={
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={handleCopyAddress}>
                <Copy className="h-4 w-4 mr-2" />
                Copy Address
              </Button>
              {wallet.chainType === 'ethereum' && (
                <Button variant="outline" size="sm" asChild>
                  <a href={`https://etherscan.io/address/${wallet.address}`} target="_blank" rel="noopener noreferrer">
                    <ExternalLink className="h-4 w-4 mr-2" />
                    Etherscan
                  </a>
                </Button>
              )}
            </div>
          }
        />
      </div>

      {/* Wallet Info */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Chain</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge variant={chainTypeBadgeVariant[wallet.chainType as keyof typeof chainTypeBadgeVariant] ?? 'outline'}>
              {wallet.chainType}
            </Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Created</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{formatDate(wallet.created_at)}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Policies</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{wallet.policy_ids?.length || 0}</p>
          </CardContent>
        </Card>
      </div>

      {/* Policies */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle>Attached Policies</CardTitle>
              <CardDescription>Policies that control what transactions this wallet can sign</CardDescription>
            </div>
            {canManage && (
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={handleOpenPolicyDialog}>
                  <Plus className="h-4 w-4 mr-2" />
                  Edit Policies
                </Button>
                <Button variant="outline" size="sm" asChild>
                  <Link href={`/apps/${appId}/policies`}>
                    <Shield className="h-4 w-4 mr-2" />
                    Manage Policies
                  </Link>
                </Button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardContent>
          {wallet.policy_ids && wallet.policy_ids.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {wallet.policy_ids.map((policyId) => {
                const policy = allPolicies?.data.find((p) => p.id === policyId)
                return (
                  <Link key={policyId} href={`/apps/${appId}/policies/${policyId}`}>
                    <Badge variant="outline" className="cursor-pointer hover:bg-accent">
                      {policy?.name || `${policyId.slice(0, 8)}...`}
                    </Badge>
                  </Link>
                )
              })}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">
              No policies attached. This wallet will deny all transactions by default.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Session Signers */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="flex items-center gap-2">
                <Key className="h-5 w-5" />
                Session Signers
              </CardTitle>
              <CardDescription>Temporary delegated signers with limited permissions and TTL</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          {sessionSigners && sessionSigners.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Signer ID</TableHead>
                  <TableHead>Public Key</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Limits</TableHead>
                  <TableHead>Status</TableHead>
                  {canManage && <TableHead className="w-[80px]" />}
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessionSigners.map((signer: SessionSignerData) => {
                  const expired = isExpired(signer.ttl_expires_at)
                  const revoked = !!signer.revoked_at
                  return (
                    <TableRow key={signer.id} className={expired || revoked ? 'opacity-50' : ''}>
                      <TableCell>
                        <code className="text-sm">{signer.id.slice(0, 8)}...</code>
                      </TableCell>
                      <TableCell>
                        <code className="text-sm">{signer.signer_public_key.slice(0, 16)}...</code>
                      </TableCell>
                      <TableCell>
                        <div className="flex items-center gap-1 text-sm">
                          <Clock className="h-3 w-3" />
                          {formatDate(signer.ttl_expires_at)}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex flex-wrap gap-1">
                          {signer.max_value && (
                            <Badge variant="outline" className="text-xs">
                              Max: {signer.max_value} wei
                            </Badge>
                          )}
                          {signer.max_txs && (
                            <Badge variant="outline" className="text-xs">
                              {signer.max_txs} txs
                            </Badge>
                          )}
                          {!signer.max_value && !signer.max_txs && (
                            <span className="text-muted-foreground text-xs">No limits</span>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        {revoked ? (
                          <Badge variant="destructive">Revoked</Badge>
                        ) : expired ? (
                          <Badge variant="secondary">Expired</Badge>
                        ) : (
                          <Badge variant="default">Active</Badge>
                        )}
                      </TableCell>
                      {canManage && (
                        <TableCell>
                          {!revoked && !expired && (
                            <Button variant="ghost" size="icon" onClick={() => setShowDeleteSignerDialog(signer.id)}>
                              <Trash2 className="h-4 w-4 text-destructive" />
                            </Button>
                          )}
                        </TableCell>
                      )}
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">
              No session signers. Session signers allow temporary delegated signing with limited permissions.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Revoke Session Signer Dialog */}
      <ConfirmDialog
        open={!!showDeleteSignerDialog}
        onOpenChange={(open) => !open && setShowDeleteSignerDialog(null)}
        title="Revoke Session Signer"
        description="Are you sure you want to revoke this session signer? They will no longer be able to sign transactions for this wallet."
        confirmLabel="Revoke"
        variant="destructive"
        onConfirm={() => {
          if (showDeleteSignerDialog) {
            handleDeleteSessionSigner(showDeleteSignerDialog)
          }
        }}
      />

      {/* Danger Zone */}
      {canManage && (
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
            <CardDescription>Irreversible and destructive actions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Delete this wallet</p>
                <p className="text-sm text-muted-foreground">
                  The wallet and its key material will be permanently deleted. Any funds remaining will be inaccessible.
                </p>
              </div>
              <Button variant="destructive" onClick={() => setShowDeleteDialog(true)}>
                Delete Wallet
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        title="Delete Wallet"
        description={`Are you sure you want to delete this wallet? This action cannot be undone and any remaining funds will be permanently inaccessible.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />

      {/* Edit Policies Dialog */}
      <Dialog open={showPolicyDialog} onOpenChange={setShowPolicyDialog}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Assign Policies to Wallet</DialogTitle>
            <DialogDescription>
              Select the policies you want to attach to this wallet. Policies control what transactions the wallet can sign.
            </DialogDescription>
          </DialogHeader>
          <div className="py-4">
            {allPolicies?.data && allPolicies.data.length > 0 ? (
              <div className="space-y-3 max-h-[300px] overflow-y-auto">
                {allPolicies.data.map((policy) => (
                  <div
                    key={policy.id}
                    className="flex items-center space-x-3 p-3 border rounded-lg hover:bg-accent/50 cursor-pointer"
                    onClick={() => handleTogglePolicy(policy.id)}
                  >
                    <Checkbox
                      checked={selectedPolicies.includes(policy.id)}
                      onCheckedChange={() => handleTogglePolicy(policy.id)}
                    />
                    <div className="flex-1">
                      <div className="font-medium">{policy.name}</div>
                      <div className="text-sm text-muted-foreground">
                        {policy.chainType} • {(policy.rules as { name: string }[])?.length || 0} rule(s)
                      </div>
                    </div>
                    {selectedPolicies.includes(policy.id) && (
                      <Check className="h-4 w-4 text-primary" />
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-center py-8">
                <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-3" />
                <p className="text-muted-foreground">No policies available</p>
                <p className="text-sm text-muted-foreground mt-1">
                  Create a policy first in the Policies section.
                </p>
                <Button variant="outline" size="sm" className="mt-4" asChild>
                  <Link href={`/apps/${appId}/policies/new`}>Create Policy</Link>
                </Button>
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowPolicyDialog(false)}>
              Cancel
            </Button>
            <Button
              onClick={handleSavePolicies}
              disabled={updatePolicies.isPending}
            >
              {updatePolicies.isPending ? 'Saving...' : `Save (${selectedPolicies.length} selected)`}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  )
}
