'use client'

import { Copy, Key, MoreHorizontal, Plus, XCircle } from 'lucide-react'
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
  DialogTrigger,
} from '@/components/ui/dialog'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

interface KeyData {
  id: string
  public_key: string
  owner_entity: string
  status: string
  created_at: number
}

function formatPublicKey(key: string) {
  if (key.length <= 20) return key
  return `${key.slice(0, 10)}...${key.slice(-8)}`
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

const statusBadgeVariant: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  active: 'default',
  rotated: 'secondary',
  revoked: 'destructive',
}

export default function AuthKeysPage() {
  const params = useParams()
  const appId = params.appId as string
  const [createOpen, setCreateOpen] = useState(false)
  const [publicKey, setPublicKey] = useState('')
  const [ownerEntity, setOwnerEntity] = useState('')
  const [keyToRevoke, setKeyToRevoke] = useState<{ id: string; publicKey: string } | null>(null)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.backend.authorizationKeys.list.useQuery({ appId })

  const createKey = trpc.backend.authorizationKeys.create.useMutation({
    onSuccess: () => {
      toast.success('Authorization key registered')
      utils.backend.authorizationKeys.list.invalidate()
      setCreateOpen(false)
      setPublicKey('')
      setOwnerEntity('')
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const revokeKey = trpc.backend.authorizationKeys.revoke.useMutation({
    onSuccess: () => {
      toast.success('Key revoked')
      utils.backend.authorizationKeys.list.invalidate()
      setKeyToRevoke(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleCreate = () => {
    if (!publicKey.trim()) {
      toast.error('Public key is required')
      return
    }
    createKey.mutate({
      appId,
      publicKey: publicKey.trim(),
      ownerEntity: ownerEntity.trim() || undefined,
    })
  }

  const handleRevoke = async () => {
    if (keyToRevoke) {
      await revokeKey.mutateAsync({ appId, id: keyToRevoke.id })
    }
  }

  const handleCopyKey = async (key: string) => {
    await navigator.clipboard.writeText(key)
    toast.success('Public key copied to clipboard')
  }

  const canManage = app?.role === 'owner' || app?.role === 'admin' || app?.role === 'developer'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Authorization Keys" />
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
        <PageHeader title="Authorization Keys" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const keys = data?.data || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Authorization Keys"
        description="Manage P-256 public keys for signing authorization requests"
        actions={
          canManage && (
            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Register Key
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Register Authorization Key</DialogTitle>
                  <DialogDescription>
                    Register a P-256 public key that can sign authorization requests for wallets.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="public-key">Public Key (hex)</Label>
                    <Input
                      id="public-key"
                      value={publicKey}
                      onChange={(e) => setPublicKey(e.target.value)}
                      placeholder="0x04..."
                      className="font-mono text-sm"
                    />
                    <p className="text-xs text-muted-foreground">
                      P-256 public key in uncompressed format (0x-prefixed hex)
                    </p>
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="owner-entity">Owner Entity (optional)</Label>
                    <Input
                      id="owner-entity"
                      value={ownerEntity}
                      onChange={(e) => setOwnerEntity(e.target.value)}
                      placeholder="e.g., user:123 or service:api"
                    />
                    <p className="text-xs text-muted-foreground">
                      Identifier for the key owner (user ID, service name, etc.)
                    </p>
                  </div>
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setCreateOpen(false)}>
                    Cancel
                  </Button>
                  <Button onClick={handleCreate} disabled={createKey.isPending}>
                    {createKey.isPending ? 'Registering...' : 'Register'}
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )
        }
      />

      {/* Info Card */}
      <Card className="border-blue-500/50 bg-blue-500/10">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Key className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-blue-700 dark:text-blue-400">Authorization Signatures</p>
              <p className="text-sm text-muted-foreground mt-1">
                Authorization keys are used to sign requests for high-risk operations like transaction signing and
                policy updates. Each wallet has an owner key that must authorize operations.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {keys.length === 0 ? (
        <EmptyState
          icon={Key}
          title="No authorization keys"
          description="Register your first authorization key to enable wallet operations."
          action={
            canManage
              ? {
                  label: 'Register Key',
                  onClick: () => setCreateOpen(true),
                }
              : undefined
          }
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>All Authorization Keys</CardTitle>
            <CardDescription>
              {keys.length} key{keys.length !== 1 ? 's' : ''} registered
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Public Key</TableHead>
                  <TableHead>Owner</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[100px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {keys.map((key: KeyData) => (
                  <TableRow key={key.id}>
                    <TableCell>
                      <div className="flex items-center gap-2">
                        <code className="text-sm font-mono">{formatPublicKey(key.public_key)}</code>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6"
                          onClick={() => handleCopyKey(key.public_key)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">{key.owner_entity || '-'}</span>
                    </TableCell>
                    <TableCell>
                      <Badge variant={statusBadgeVariant[key.status]}>{key.status}</Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(key.created_at)}</TableCell>
                    <TableCell>
                      {canManage && key.status === 'active' && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleCopyKey(key.public_key)}>
                              <Copy className="h-4 w-4 mr-2" />
                              Copy Key
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => setKeyToRevoke({ id: key.id, publicKey: key.public_key })}
                            >
                              <XCircle className="h-4 w-4 mr-2" />
                              Revoke
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      {/* Revoke Dialog */}
      <ConfirmDialog
        open={!!keyToRevoke}
        onOpenChange={() => setKeyToRevoke(null)}
        title="Revoke Key"
        description={`Are you sure you want to revoke key ${keyToRevoke?.publicKey ? formatPublicKey(keyToRevoke.publicKey) : ''}? This action cannot be undone and any wallets using this key will lose authorization.`}
        confirmLabel="Revoke"
        variant="destructive"
        onConfirm={handleRevoke}
      />
    </div>
  )
}
