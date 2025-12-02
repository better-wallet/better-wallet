'use client'

import { ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useEffect, useState } from 'react'
import { toast } from 'sonner'

import { ErrorState } from '@/components/data/error-state'
import { PolicyBuilder } from '@/components/forms/policy-builder'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { trpc } from '@/lib/trpc/client'

interface PolicyRuleData {
  name: string
  method: string
  conditions: Array<{
    field_source: string
    field: string
    operator: string
    value: unknown
  }>
  action: 'ALLOW' | 'DENY'
}

export default function EditPolicyPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string
  const policyId = params.policyId as string

  const [name, setName] = useState('')
  const [rules, setRules] = useState<PolicyRuleData[]>([])
  const [initialized, setInitialized] = useState(false)

  const utils = trpc.useUtils()
  const { data: policy, isLoading, error, refetch } = trpc.backend.policies.get.useQuery({ appId, id: policyId })

  useEffect(() => {
    if (policy && !initialized) {
      setName(policy.name)
      setRules((policy.rules || []) as PolicyRuleData[])
      setInitialized(true)
    }
  }, [policy, initialized])

  const updatePolicy = trpc.backend.policies.update.useMutation({
    onSuccess: () => {
      toast.success('Policy updated successfully')
      utils.backend.policies.list.invalidate()
      utils.backend.policies.get.invalidate({ appId, id: policyId })
      router.push(`/apps/${appId}/policies/${policyId}`)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()

    if (!name.trim()) {
      toast.error('Policy name is required')
      return
    }

    if (rules.length === 0) {
      toast.error('At least one rule is required')
      return
    }

    // Validate all rules have names
    const invalidRules = rules.filter((rule) => !rule.name.trim())
    if (invalidRules.length > 0) {
      toast.error('All rules must have a name')
      return
    }

    updatePolicy.mutate({
      appId,
      id: policyId,
      name: name.trim(),
      rules,
    })
  }

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
          <Link href={`/apps/${appId}/policies/${policyId}`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <PageHeader title={`Edit: ${policy.name}`} description="Modify policy rules and configuration" />
      </div>

      <form onSubmit={handleSubmit} className="space-y-6">
        <Card>
          <CardHeader>
            <CardTitle>Policy Details</CardTitle>
            <CardDescription>Basic information about your policy</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="name">Policy Name</Label>
                <Input
                  id="name"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="e.g., Allow ERC20 Transfers"
                  required
                />
              </div>
              <div className="space-y-2">
                <Label>Chain Type</Label>
                <Input value={policy.chainType || 'ethereum'} disabled className="bg-muted" />
                <p className="text-xs text-muted-foreground">Chain type cannot be changed after creation</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Policy Rules</CardTitle>
            <CardDescription>
              Rules are evaluated in order. The first matching rule determines the outcome. If no rules match, the
              transaction is denied by default.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <PolicyBuilder rules={rules} onChange={setRules} />
          </CardContent>
        </Card>

        <div className="flex justify-end gap-4">
          <Button type="button" variant="outline" asChild>
            <Link href={`/apps/${appId}/policies/${policyId}`}>Cancel</Link>
          </Button>
          <Button type="submit" disabled={updatePolicy.isPending}>
            {updatePolicy.isPending ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </form>
    </div>
  )
}
