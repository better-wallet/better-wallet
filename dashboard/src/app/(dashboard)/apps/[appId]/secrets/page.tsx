'use client'

import { Check, Copy, Eye, EyeOff, Key, MoreHorizontal, Plus, RefreshCw } from 'lucide-react'
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
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

function formatDate(date: Date | string | null) {
  if (!date) return 'Never'
  return new Date(date).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

const statusBadgeVariant = {
  active: 'default' as const,
  rotated: 'secondary' as const,
  revoked: 'destructive' as const,
}

export default function AppSecretsPage() {
  const params = useParams()
  const appId = params.appId as string
  const [showNewSecret, setShowNewSecret] = useState<string | null>(null)
  const [secretToRevoke, setSecretToRevoke] = useState<string | null>(null)
  const [secretToRotate, setSecretToRotate] = useState<string | null>(null)
  const [copiedSecret, setCopiedSecret] = useState(false)
  const [showSecret, setShowSecret] = useState(false)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data: secrets, isLoading, error, refetch } = trpc.appSecrets.list.useQuery({ appId })

  const createSecret = trpc.appSecrets.create.useMutation({
    onSuccess: (data) => {
      toast.success('Secret created successfully')
      utils.appSecrets.list.invalidate({ appId })
      setShowNewSecret(data.secret)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const rotateSecret = trpc.appSecrets.rotate.useMutation({
    onSuccess: (data) => {
      toast.success('Secret rotated successfully')
      utils.appSecrets.list.invalidate({ appId })
      setSecretToRotate(null)
      setShowNewSecret(data.secret)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const revokeSecret = trpc.appSecrets.revoke.useMutation({
    onSuccess: () => {
      toast.success('Secret revoked')
      utils.appSecrets.list.invalidate({ appId })
      setSecretToRevoke(null)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const handleCreate = () => {
    createSecret.mutate({ appId })
  }

  const handleRotate = async () => {
    if (secretToRotate) {
      await rotateSecret.mutateAsync({ id: secretToRotate })
    }
  }

  const handleRevoke = async () => {
    if (secretToRevoke) {
      await revokeSecret.mutateAsync({ id: secretToRevoke })
    }
  }

  const handleCopySecret = async () => {
    if (showNewSecret) {
      await navigator.clipboard.writeText(showNewSecret)
      setCopiedSecret(true)
      setTimeout(() => setCopiedSecret(false), 2000)
    }
  }

  const canManageSecrets = app?.role === 'owner' || app?.role === 'admin'
  const activeSecrets = secrets?.filter((s) => s.status === 'active') || []
  const inactiveSecrets = secrets?.filter((s) => s.status !== 'active') || []

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="API Secrets" />
        <Card>
          <CardContent className="pt-6">
            {[1, 2].map((i) => (
              <div key={i} className="flex items-center gap-4 py-4">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-24" />
                <Skeleton className="h-4 w-48" />
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
        <PageHeader title="API Secrets" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="API Secrets"
        description="Manage API secrets for authenticating requests to the wallet backend"
        actions={
          canManageSecrets && (
            <Button onClick={handleCreate} disabled={createSecret.isPending}>
              <Plus className="h-4 w-4 mr-2" />
              Create Secret
            </Button>
          )
        }
      />

      {/* Important Warning */}
      <Card className="border-yellow-500/50 bg-yellow-500/10">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Key className="h-5 w-5 text-yellow-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-yellow-700 dark:text-yellow-400">Keep your secrets safe</p>
              <p className="text-sm text-muted-foreground mt-1">
                API secrets are only shown once when created. Store them securely and never commit them to version
                control. If a secret is compromised, rotate it immediately.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {secrets?.length === 0 ? (
        <EmptyState
          icon={Key}
          title="No API secrets"
          description="Create an API secret to authenticate requests to the wallet backend."
          action={
            canManageSecrets
              ? {
                  label: 'Create Secret',
                  onClick: handleCreate,
                }
              : undefined
          }
        />
      ) : (
        <>
          {/* Active Secrets */}
          <Card>
            <CardHeader>
              <CardTitle>Active Secrets</CardTitle>
              <CardDescription>
                {activeSecrets.length} active secret{activeSecrets.length !== 1 ? 's' : ''}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {activeSecrets.length === 0 ? (
                <p className="text-sm text-muted-foreground text-center py-4">
                  No active secrets. Create one to authenticate API requests.
                </p>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Secret</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Last Used</TableHead>
                      <TableHead className="w-[100px]" />
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {activeSecrets.map((secret) => (
                      <TableRow key={secret.id}>
                        <TableCell>
                          <code className="text-sm bg-muted px-2 py-1 rounded">{secret.secretPrefix}</code>
                        </TableCell>
                        <TableCell>
                          <Badge variant={statusBadgeVariant[secret.status as keyof typeof statusBadgeVariant]}>
                            {secret.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(secret.createdAt)}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(secret.lastUsedAt)}</TableCell>
                        <TableCell>
                          {canManageSecrets && (
                            <DropdownMenu>
                              <DropdownMenuTrigger asChild>
                                <Button variant="ghost" size="icon">
                                  <MoreHorizontal className="h-4 w-4" />
                                </Button>
                              </DropdownMenuTrigger>
                              <DropdownMenuContent align="end">
                                <DropdownMenuItem onClick={() => setSecretToRotate(secret.id)}>
                                  <RefreshCw className="h-4 w-4 mr-2" />
                                  Rotate
                                </DropdownMenuItem>
                                <DropdownMenuSeparator />
                                <DropdownMenuItem
                                  className="text-destructive"
                                  onClick={() => setSecretToRevoke(secret.id)}
                                >
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
              )}
            </CardContent>
          </Card>

          {/* Inactive Secrets */}
          {inactiveSecrets.length > 0 && (
            <Card>
              <CardHeader>
                <CardTitle>Inactive Secrets</CardTitle>
                <CardDescription>Rotated or revoked secrets that are no longer valid</CardDescription>
              </CardHeader>
              <CardContent>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Secret</TableHead>
                      <TableHead>Status</TableHead>
                      <TableHead>Created</TableHead>
                      <TableHead>Rotated/Revoked</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {inactiveSecrets.map((secret) => (
                      <TableRow key={secret.id} className="opacity-60">
                        <TableCell>
                          <code className="text-sm bg-muted px-2 py-1 rounded">{secret.secretPrefix}</code>
                        </TableCell>
                        <TableCell>
                          <Badge variant={statusBadgeVariant[secret.status as keyof typeof statusBadgeVariant]}>
                            {secret.status}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(secret.createdAt)}</TableCell>
                        <TableCell className="text-sm text-muted-foreground">{formatDate(secret.rotatedAt)}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          )}
        </>
      )}

      {/* New Secret Dialog */}
      <Dialog
        open={!!showNewSecret}
        onOpenChange={() => {
          setShowNewSecret(null)
          setShowSecret(false)
          setCopiedSecret(false)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Your new API secret</DialogTitle>
            <DialogDescription>Copy this secret now. You will not be able to see it again.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Input
                  value={showNewSecret || ''}
                  readOnly
                  type={showSecret ? 'text' : 'password'}
                  className="pr-20 font-mono text-sm"
                />
                <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => setShowSecret(!showSecret)}
                  >
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                  <Button type="button" variant="ghost" size="icon" className="h-7 w-7" onClick={handleCopySecret}>
                    {copiedSecret ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                  </Button>
                </div>
              </div>
            </div>
            <p className="text-sm text-destructive">This secret will not be shown again. Make sure to copy it now.</p>
          </div>
          <DialogFooter>
            <Button
              onClick={() => {
                setShowNewSecret(null)
                setShowSecret(false)
                setCopiedSecret(false)
              }}
            >
              Done
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rotate Confirmation */}
      <ConfirmDialog
        open={!!secretToRotate}
        onOpenChange={() => setSecretToRotate(null)}
        title="Rotate Secret"
        description="This will create a new secret and mark the old one as rotated. The old secret will immediately stop working. Are you sure?"
        confirmLabel="Rotate"
        onConfirm={handleRotate}
      />

      {/* Revoke Confirmation */}
      <ConfirmDialog
        open={!!secretToRevoke}
        onOpenChange={() => setSecretToRevoke(null)}
        title="Revoke Secret"
        description="This secret will be permanently revoked and cannot be used again. This action cannot be undone."
        confirmLabel="Revoke"
        variant="destructive"
        onConfirm={handleRevoke}
      />
    </div>
  )
}
