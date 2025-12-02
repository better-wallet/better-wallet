'use client'

import { MoreHorizontal, Plus, Shield } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
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

interface PolicyData {
  id: string
  name: string
  chainType: string
  rules: Array<{ name: string; method: string; conditions: unknown[]; action: string }>
  created_at: number
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

export default function PoliciesPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string
  const [policyToDelete, setPolicyToDelete] = useState<{ id: string; name: string } | null>(null)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.backend.policies.list.useQuery({ appId })

  const deletePolicy = trpc.backend.policies.delete.useMutation({
    onSuccess: () => {
      toast.success('Policy deleted')
      utils.backend.policies.list.invalidate()
      utils.backend.stats.invalidate()
      setPolicyToDelete(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleDelete = async () => {
    if (policyToDelete) {
      await deletePolicy.mutateAsync({ appId, id: policyToDelete.id })
    }
  }

  const canManage = app?.role === 'owner' || app?.role === 'admin' || app?.role === 'developer'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Policies" />
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
        <PageHeader title="Policies" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const policies = data?.data || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policies"
        description="Define access control rules for wallet operations"
        actions={
          canManage && (
            <Button asChild>
              <Link href={`/apps/${appId}/policies/new`}>
                <Plus className="h-4 w-4 mr-2" />
                Create Policy
              </Link>
            </Button>
          )
        }
      />

      {/* Info Card */}
      <Card className="border-blue-500/50 bg-blue-500/10">
        <CardContent className="pt-6">
          <div className="flex gap-3">
            <Shield className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-blue-700 dark:text-blue-400">Default-Deny Security</p>
              <p className="text-sm text-muted-foreground mt-1">
                Wallets deny all transactions by default. Create policies with explicit ALLOW rules to permit specific
                operations. Rules are evaluated in order - the first matching rule determines the outcome.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {policies.length === 0 ? (
        <EmptyState
          icon={Shield}
          title="No policies"
          description="Create your first policy to define access control rules for wallets."
          action={
            canManage
              ? {
                  label: 'Create Policy',
                  onClick: () => router.push(`/apps/${appId}/policies/new`),
                }
              : undefined
          }
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>All Policies</CardTitle>
            <CardDescription>
              {policies.length} polic{policies.length !== 1 ? 'ies' : 'y'} defined
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Chain</TableHead>
                  <TableHead>Rules</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[100px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.map((policy: PolicyData) => (
                  <TableRow key={policy.id}>
                    <TableCell>
                      <Link href={`/apps/${appId}/policies/${policy.id}`} className="font-medium hover:underline">
                        {policy.name}
                      </Link>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline">{policy.chainType || 'ethereum'}</Badge>
                    </TableCell>
                    <TableCell>
                      <span className="text-sm text-muted-foreground">
                        {policy.rules?.length || 0} rule{(policy.rules?.length || 0) !== 1 ? 's' : ''}
                      </span>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(policy.created_at)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem asChild>
                            <Link href={`/apps/${appId}/policies/${policy.id}`}>View Details</Link>
                          </DropdownMenuItem>
                          {canManage && (
                            <>
                              <DropdownMenuItem asChild>
                                <Link href={`/apps/${appId}/policies/${policy.id}/edit`}>Edit</Link>
                              </DropdownMenuItem>
                              <DropdownMenuSeparator />
                              <DropdownMenuItem
                                className="text-destructive"
                                onClick={() => setPolicyToDelete({ id: policy.id, name: policy.name })}
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
        open={!!policyToDelete}
        onOpenChange={() => setPolicyToDelete(null)}
        title="Delete Policy"
        description={`Are you sure you want to delete "${policyToDelete?.name}"? Wallets using this policy will lose access to the rules defined in it.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />
    </div>
  )
}
