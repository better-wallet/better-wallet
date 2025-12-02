'use client'

import { ArrowLeft, Check, Edit2, X } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'

import { ErrorState } from '@/components/data/error-state'
import { ConfirmDialog } from '@/components/forms/confirm-dialog'
import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

interface PolicyConditionData {
  field_source: string
  field: string
  operator: string
  value: unknown
}

interface PolicyRuleData {
  name: string
  method: string
  conditions: PolicyConditionData[]
  action: 'ALLOW' | 'DENY'
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

function formatOperator(op: string) {
  const operators: Record<string, string> = {
    eq: '=',
    neq: '!=',
    lt: '<',
    lte: '<=',
    gt: '>',
    gte: '>=',
    in: 'in',
    in_condition_set: 'in set',
  }
  return operators[op] || op
}

function formatFieldSource(source: string) {
  const sources: Record<string, string> = {
    ethereum_transaction: 'Transaction',
    ethereum_calldata: 'Calldata',
    ethereum_typed_data_domain: 'Typed Data Domain',
    ethereum_typed_data_message: 'Typed Data Message',
    ethereum_7702_authorization: '7702 Authorization',
    ethereum_message: 'Message',
    system: 'System',
  }
  return sources[source] || source
}

function formatValue(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  if (Array.isArray(value)) return `[${value.map(formatValue).join(', ')}]`
  return JSON.stringify(value)
}

export default function PolicyDetailPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string
  const policyId = params.policyId as string
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data: policy, isLoading, error, refetch } = trpc.backend.policies.get.useQuery({ appId, id: policyId })

  const deletePolicy = trpc.backend.policies.delete.useMutation({
    onSuccess: () => {
      toast.success('Policy deleted')
      utils.backend.policies.list.invalidate()
      utils.backend.stats.invalidate()
      router.push(`/apps/${appId}/policies`)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleDelete = async () => {
    await deletePolicy.mutateAsync({ appId, id: policyId })
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

  if (!policy) {
    return (
      <div className="space-y-6">
        <PageHeader title="Not Found" />
        <ErrorState message="Policy not found" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href={`/apps/${appId}/policies`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <PageHeader
          title={policy.name}
          description={`Policy for ${policy.chainType || 'ethereum'} wallets`}
          actions={
            canManage && (
              <Button variant="outline" asChild>
                <Link href={`/apps/${appId}/policies/${policyId}/edit`}>
                  <Edit2 className="h-4 w-4 mr-2" />
                  Edit Policy
                </Link>
              </Button>
            )
          }
        />
      </div>

      {/* Policy Info */}
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Version</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm font-mono">{policy.version || '1.0'}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Chain</CardTitle>
          </CardHeader>
          <CardContent>
            <Badge variant="outline">{policy.chainType || 'ethereum'}</Badge>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-2xl font-bold">{policy.rules?.length || 0}</p>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium">Created</CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-sm">{formatDate(policy.created_at)}</p>
          </CardContent>
        </Card>
      </div>

      {/* Rules */}
      <Card>
        <CardHeader>
          <CardTitle>Policy Rules</CardTitle>
          <CardDescription>
            Rules are evaluated in order. The first matching rule determines the outcome.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {policy.rules && policy.rules.length > 0 ? (
            <div className="space-y-4">
              {policy.rules.map((rule: PolicyRuleData, index: number) => (
                <Card key={index} className="border-l-4 border-l-primary">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Badge variant="secondary">#{index + 1}</Badge>
                        <CardTitle className="text-base">{rule.name}</CardTitle>
                      </div>
                      <Badge variant={rule.action === 'ALLOW' ? 'default' : 'destructive'}>
                        {rule.action === 'ALLOW' ? (
                          <>
                            <Check className="h-3 w-3 mr-1" /> ALLOW
                          </>
                        ) : (
                          <>
                            <X className="h-3 w-3 mr-1" /> DENY
                          </>
                        )}
                      </Badge>
                    </div>
                    <CardDescription>
                      Method: <code className="bg-muted px-1 rounded">{rule.method}</code>
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {rule.conditions && rule.conditions.length > 0 ? (
                      <div className="space-y-2">
                        <p className="text-sm font-medium">Conditions (all must match):</p>
                        <div className="space-y-1">
                          {rule.conditions.map((condition: PolicyConditionData, condIndex: number) => (
                            <div
                              key={condIndex}
                              className="flex items-center gap-2 text-sm bg-muted/50 px-3 py-2 rounded"
                            >
                              <Badge variant="outline" className="text-xs">
                                {formatFieldSource(condition.field_source)}
                              </Badge>
                              <code className="font-mono">{condition.field}</code>
                              <span className="font-bold">{formatOperator(condition.operator)}</span>
                              <code className="font-mono text-primary">{formatValue(condition.value)}</code>
                            </div>
                          ))}
                        </div>
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground">
                        No conditions - this rule matches all {rule.method} requests
                      </p>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground text-center py-4">
              No rules defined. This policy will not match any transactions.
            </p>
          )}
        </CardContent>
      </Card>

      {/* Raw JSON */}
      <Card>
        <CardHeader>
          <CardTitle>Raw Policy JSON</CardTitle>
          <CardDescription>The complete policy definition in JSON format</CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="bg-muted p-4 rounded-lg overflow-auto text-xs">{JSON.stringify(policy, null, 2)}</pre>
        </CardContent>
      </Card>

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
                <p className="font-medium">Delete this policy</p>
                <p className="text-sm text-muted-foreground">
                  Wallets using this policy will lose the access rules defined here.
                </p>
              </div>
              <Button variant="destructive" onClick={() => setShowDeleteDialog(true)}>
                Delete Policy
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        title="Delete Policy"
        description={`Are you sure you want to delete "${policy.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />
    </div>
  )
}
