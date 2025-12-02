'use client'

import { ArrowLeft } from 'lucide-react'
import Link from 'next/link'
import { useParams, useRouter } from 'next/navigation'
import { useState } from 'react'
import { toast } from 'sonner'

import { PolicyBuilder } from '@/components/forms/policy-builder'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
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

export default function NewPolicyPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string

  const [name, setName] = useState('')
  const [chainType, setChainType] = useState('ethereum')
  const [rules, setRules] = useState<PolicyRuleData[]>([])

  const utils = trpc.useUtils()

  const createPolicy = trpc.backend.policies.create.useMutation({
    onSuccess: () => {
      toast.success('Policy created successfully')
      utils.backend.policies.list.invalidate()
      utils.backend.stats.invalidate()
      router.push(`/apps/${appId}/policies`)
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

    createPolicy.mutate({
      appId,
      name: name.trim(),
      chainType,
      rules,
    })
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" asChild>
          <Link href={`/apps/${appId}/policies`}>
            <ArrowLeft className="h-4 w-4" />
          </Link>
        </Button>
        <PageHeader title="Create Policy" description="Define access control rules for wallet operations" />
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
                <Label htmlFor="chain">Chain Type</Label>
                <Select value={chainType} onValueChange={setChainType}>
                  <SelectTrigger id="chain">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ethereum">Ethereum</SelectItem>
                    <SelectItem value="solana">Solana</SelectItem>
                    <SelectItem value="bitcoin">Bitcoin</SelectItem>
                  </SelectContent>
                </Select>
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
            <Link href={`/apps/${appId}/policies`}>Cancel</Link>
          </Button>
          <Button type="submit" disabled={createPolicy.isPending}>
            {createPolicy.isPending ? 'Creating...' : 'Create Policy'}
          </Button>
        </div>
      </form>
    </div>
  )
}
