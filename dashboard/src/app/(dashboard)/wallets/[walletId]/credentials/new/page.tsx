'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { Copy, Check } from 'lucide-react'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Checkbox } from '@/components/ui/checkbox'
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert'
import { trpc } from '@/lib/trpc/client'
import { toast } from 'sonner'

const OPERATIONS = [
  { id: 'transfer', label: 'Transfer', description: 'Send transactions (eth_sendTransaction)' },
  { id: 'sign_message', label: 'Sign Message', description: 'Sign messages (personal_sign)' },
  { id: 'sign_typed_data', label: 'Sign Typed Data', description: 'Sign EIP-712 typed data' },
  { id: 'contract_deploy', label: 'Contract Deploy', description: 'Deploy smart contracts' },
]

export default function NewCredentialPage() {
  const params = useParams<{ walletId: string }>()
  const walletId = params.walletId
  const router = useRouter()
  const [name, setName] = useState('')
  const [operations, setOperations] = useState<string[]>([])
  const [allowedContracts, setAllowedContracts] = useState('')
  const [maxValuePerTx, setMaxValuePerTx] = useState('')
  const [maxTxPerHour, setMaxTxPerHour] = useState('')
  const [maxTxPerDay, setMaxTxPerDay] = useState('')
  const [createdCredential, setCreatedCredential] = useState<string | null>(null)
  const [copied, setCopied] = useState(false)

  const createCredential = trpc.credentials.create.useMutation({
    onSuccess: (data) => {
      toast.success('Credential created successfully')
      setCreatedCredential(data.credential)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) {
      toast.error('Please enter a credential name')
      return
    }

    const contracts = allowedContracts
      .split('\n')
      .map((c) => c.trim())
      .filter((c) => c.length > 0)

    createCredential.mutate({
      walletId,
      name: name.trim(),
      capabilities: {
        chains: [],
        operations: operations.length > 0 ? operations : [],
        allowedContracts: contracts,
        allowedMethods: [],
      },
      limits: {
        maxValuePerTx: maxValuePerTx || '',
        maxValuePerHour: '',
        maxValuePerDay: '',
        maxTxPerHour: maxTxPerHour ? parseInt(maxTxPerHour) : 0,
        maxTxPerDay: maxTxPerDay ? parseInt(maxTxPerDay) : 0,
      },
    })
  }

  const copyToClipboard = () => {
    if (createdCredential) {
      navigator.clipboard.writeText(createdCredential)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    }
  }

  const toggleOperation = (op: string) => {
    setOperations((prev) =>
      prev.includes(op) ? prev.filter((o) => o !== op) : [...prev, op]
    )
  }

  // Show success screen with credential
  if (createdCredential) {
    return (
      <div className="space-y-6">
        <PageHeader
          title="Credential Created"
          description="Save your credential key - it won't be shown again"
        />

        <Alert>
          <AlertTitle>Important: Save your credential key</AlertTitle>
          <AlertDescription>
            This is the only time you will see the full credential key. Store it securely.
          </AlertDescription>
        </Alert>

        <Card className="max-w-2xl">
          <CardHeader>
            <CardTitle>Your Agent Credential</CardTitle>
            <CardDescription>
              Use this credential in your agent's Authorization header
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex items-center gap-2">
              <code className="flex-1 bg-muted p-3 rounded text-sm font-mono break-all">
                {createdCredential}
              </code>
              <Button variant="outline" size="icon" onClick={copyToClipboard}>
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>

            <div className="bg-muted p-4 rounded text-sm">
              <p className="font-medium mb-2">Usage:</p>
              <code className="text-xs">
                Authorization: Bearer {createdCredential}
              </code>
            </div>

            <div className="flex gap-2 pt-4">
              <Button onClick={() => router.push(`/wallets/${walletId}/credentials`)}>
                Done
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Create Credential"
        description="Create a new agent credential with specific capabilities and limits"
      />

      <form onSubmit={handleSubmit} className="space-y-6 max-w-2xl">
        <Card>
          <CardHeader>
            <CardTitle>Basic Info</CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Credential Name</Label>
              <Input
                id="name"
                placeholder="e.g., DeFi Trading Agent"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={createCredential.isPending}
              />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Capabilities</CardTitle>
            <CardDescription>
              Select which operations this credential can perform. Leave empty to allow all.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {OPERATIONS.map((op) => (
              <div key={op.id} className="flex items-start space-x-3">
                <Checkbox
                  id={op.id}
                  checked={operations.includes(op.id)}
                  onCheckedChange={() => toggleOperation(op.id)}
                  disabled={createCredential.isPending}
                />
                <div className="space-y-1">
                  <Label htmlFor={op.id} className="cursor-pointer">
                    {op.label}
                  </Label>
                  <p className="text-sm text-muted-foreground">{op.description}</p>
                </div>
              </div>
            ))}

            <div className="space-y-2 pt-4">
              <Label htmlFor="contracts">Allowed Contracts (optional)</Label>
              <textarea
                id="contracts"
                className="w-full min-h-[100px] p-3 rounded-md border bg-background text-sm font-mono"
                placeholder="0x... (one address per line)"
                value={allowedContracts}
                onChange={(e) => setAllowedContracts(e.target.value)}
                disabled={createCredential.isPending}
              />
              <p className="text-sm text-muted-foreground">
                Leave empty to allow all contracts
              </p>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Rate Limits</CardTitle>
            <CardDescription>
              Set limits to prevent runaway agents. Leave empty for no limit.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="space-y-2">
                <Label htmlFor="maxValuePerTx">Max Value per TX (wei)</Label>
                <Input
                  id="maxValuePerTx"
                  placeholder="e.g., 1000000000000000000"
                  value={maxValuePerTx}
                  onChange={(e) => setMaxValuePerTx(e.target.value)}
                  disabled={createCredential.isPending}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maxTxPerHour">Max TX per Hour</Label>
                <Input
                  id="maxTxPerHour"
                  type="number"
                  placeholder="e.g., 100"
                  value={maxTxPerHour}
                  onChange={(e) => setMaxTxPerHour(e.target.value)}
                  disabled={createCredential.isPending}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="maxTxPerDay">Max TX per Day</Label>
                <Input
                  id="maxTxPerDay"
                  type="number"
                  placeholder="e.g., 1000"
                  value={maxTxPerDay}
                  onChange={(e) => setMaxTxPerDay(e.target.value)}
                  disabled={createCredential.isPending}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="flex gap-2">
          <Button
            type="button"
            variant="outline"
            onClick={() => router.back()}
            disabled={createCredential.isPending}
          >
            Cancel
          </Button>
          <Button type="submit" disabled={createCredential.isPending}>
            {createCredential.isPending ? 'Creating...' : 'Create Credential'}
          </Button>
        </div>
      </form>
    </div>
  )
}
