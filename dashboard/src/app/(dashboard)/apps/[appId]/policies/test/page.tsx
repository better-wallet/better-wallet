'use client'

import { AlertCircle, ArrowLeft, CheckCircle2, ChevronDown, ChevronRight, Play, XCircle } from 'lucide-react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { useState } from 'react'

import { PageHeader } from '@/components/layout/page-header'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'
import { trpc } from '@/lib/trpc/client'

interface PolicyRule {
  name: string
  method: string
  conditions: {
    field_source: string
    field: string
    operator: string
    value: unknown
  }[]
  action: 'ALLOW' | 'DENY'
}

const METHODS = [
  { value: 'eth_sendTransaction', label: 'Send Transaction' },
  { value: 'eth_signTransaction', label: 'Sign Transaction' },
  { value: 'eth_signTypedData_v4', label: 'Sign Typed Data (EIP-712)' },
  { value: 'personal_sign', label: 'Personal Sign' },
]

const PRESET_SCENARIOS = [
  {
    name: 'Simple ETH Transfer',
    context: {
      method: 'eth_sendTransaction',
      to: '0x742d35Cc6634C0532925a3b844Bc9e7595f5EACB',
      value: '1000000000000000000', // 1 ETH
      chainId: 1,
    },
  },
  {
    name: 'USDC Transfer (ERC-20)',
    context: {
      method: 'eth_sendTransaction',
      to: '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', // USDC contract
      value: '0',
      data: '0xa9059cbb000000000000000000000000742d35cc6634c0532925a3b844bc9e7595f5eacb0000000000000000000000000000000000000000000000000000000005f5e100',
      chainId: 1,
    },
  },
  {
    name: 'Uniswap Swap',
    context: {
      method: 'eth_sendTransaction',
      to: '0x68b3465833fb72A70ecDF485E0e4C7bD8665Fc45', // Uniswap Router
      value: '500000000000000000', // 0.5 ETH
      chainId: 1,
    },
  },
  {
    name: 'NFT Marketplace Approval',
    context: {
      method: 'eth_signTypedData_v4',
      typedDataDomain: {
        name: 'Seaport',
        version: '1.5',
        chainId: 1,
        verifyingContract: '0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC',
      },
      typedDataMessage: {
        offerer: '0x742d35Cc6634C0532925a3b844Bc9e7595f5EACB',
        zone: '0x0000000000000000000000000000000000000000',
      },
    },
  },
]

export default function PolicyTestPage() {
  const params = useParams()
  const appId = params.appId as string

  // Policy rules state
  const [rules, setRules] = useState<PolicyRule[]>([
    {
      name: 'Allow transfers under 1 ETH',
      method: 'eth_sendTransaction',
      conditions: [
        { field_source: 'ethereum_transaction', field: 'value', operator: 'lte', value: '1000000000000000000' },
      ],
      action: 'ALLOW',
    },
  ])

  // Test context state
  const [testContext, setTestContext] = useState({
    method: 'eth_sendTransaction',
    chainType: 'ethereum',
    to: '',
    value: '',
    data: '',
    chainId: 1,
    decodedCalldata: {} as Record<string, unknown>,
    typedDataDomain: {} as Record<string, unknown>,
    typedDataMessage: {} as Record<string, unknown>,
    personalMessage: '',
  })

  // UI state
  const [showRulesEditor, setShowRulesEditor] = useState(false)
  const [rulesJson, setRulesJson] = useState('')
  const [result, setResult] = useState<{
    decision: 'ALLOW' | 'DENY'
    reason: string
    matchedRule: { ruleIndex: number; ruleName: string; action: string; matchedConditions: string[] } | null
    evaluationTrace: { rule: string; matched: boolean; reason: string }[]
  } | null>(null)

  const simulateMutation = trpc.backend.policyTest.simulate.useMutation({
    onSuccess: (data) => {
      setResult(data)
    },
  })

  const loadPreset = (preset: (typeof PRESET_SCENARIOS)[0]) => {
    setTestContext({
      ...testContext,
      ...preset.context,
      decodedCalldata: {},
      typedDataDomain: preset.context.typedDataDomain || {},
      typedDataMessage: preset.context.typedDataMessage || {},
    })
  }

  const loadRulesFromJson = () => {
    try {
      const parsed = JSON.parse(rulesJson)
      if (Array.isArray(parsed)) {
        setRules(parsed)
        setShowRulesEditor(false)
      } else if (parsed.rules && Array.isArray(parsed.rules)) {
        setRules(parsed.rules)
        setShowRulesEditor(false)
      }
    } catch {
      // Invalid JSON
    }
  }

  const runSimulation = () => {
    simulateMutation.mutate({
      appId,
      rules,
      testContext: {
        method: testContext.method,
        chainType: testContext.chainType,
        to: testContext.to || undefined,
        value: testContext.value || undefined,
        data: testContext.data || undefined,
        chainId: testContext.chainId,
        decodedCalldata: Object.keys(testContext.decodedCalldata).length > 0 ? testContext.decodedCalldata : undefined,
        typedDataDomain: Object.keys(testContext.typedDataDomain).length > 0 ? testContext.typedDataDomain : undefined,
        typedDataMessage:
          Object.keys(testContext.typedDataMessage).length > 0 ? testContext.typedDataMessage : undefined,
        personalMessage: testContext.personalMessage || undefined,
      },
    })
  }

  // Load existing policy
  const { data: policies } = trpc.backend.policies.list.useQuery({ appId, limit: 100 })

  const loadExistingPolicy = (policyId: string) => {
    const policy = policies?.data.find((p) => p.id === policyId)
    if (policy && policy.rules) {
      setRules(policy.rules as PolicyRule[])
    }
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Policy Tester"
        description="Test and simulate policy rules before deployment"
        actions={
          <Button variant="outline" asChild>
            <Link href={`/apps/${appId}/policies`}>
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Policies
            </Link>
          </Button>
        }
      />

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Left Column - Policy Rules */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle>Policy Rules</CardTitle>
                  <CardDescription>Define the rules to test</CardDescription>
                </div>
                <div className="flex gap-2">
                  {policies && policies.data.length > 0 && (
                    <Select onValueChange={loadExistingPolicy}>
                      <SelectTrigger className="w-[180px]">
                        <SelectValue placeholder="Load existing..." />
                      </SelectTrigger>
                      <SelectContent>
                        {policies.data.map((p) => (
                          <SelectItem key={p.id} value={p.id}>
                            {p.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  )}
                  <Button variant="outline" size="sm" onClick={() => setShowRulesEditor(!showRulesEditor)}>
                    {showRulesEditor ? 'Hide JSON' : 'Edit JSON'}
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {showRulesEditor ? (
                <div className="space-y-4">
                  <Textarea
                    value={rulesJson || JSON.stringify(rules, null, 2)}
                    onChange={(e) => setRulesJson(e.target.value)}
                    className="font-mono text-sm min-h-[300px]"
                    placeholder="Paste policy rules JSON here..."
                  />
                  <Button onClick={loadRulesFromJson}>Apply JSON</Button>
                </div>
              ) : (
                <div className="space-y-4">
                  {rules.map((rule, idx) => (
                    <div key={idx} className="border rounded-lg p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="font-medium">{rule.name}</span>
                        <Badge variant={rule.action === 'ALLOW' ? 'default' : 'destructive'}>{rule.action}</Badge>
                      </div>
                      <div className="text-sm text-muted-foreground">
                        Method: <code className="bg-muted px-1 rounded">{rule.method}</code>
                      </div>
                      <div className="text-sm">
                        <span className="text-muted-foreground">Conditions:</span>
                        <ul className="mt-1 space-y-1">
                          {rule.conditions.map((cond, cidx) => (
                            <li key={cidx} className="text-xs bg-muted px-2 py-1 rounded font-mono">
                              {cond.field_source}.{cond.field} {cond.operator} {JSON.stringify(cond.value)}
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  ))}
                  {rules.length === 0 && (
                    <p className="text-center text-muted-foreground py-8">
                      No rules defined. Click "Edit JSON" to add rules.
                    </p>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Column - Test Context */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Test Scenario</CardTitle>
              <CardDescription>Configure the request to test against the rules</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Presets */}
              <div>
                <Label className="text-xs text-muted-foreground">Quick Presets</Label>
                <div className="flex flex-wrap gap-2 mt-1">
                  {PRESET_SCENARIOS.map((preset) => (
                    <Button key={preset.name} variant="outline" size="sm" onClick={() => loadPreset(preset)}>
                      {preset.name}
                    </Button>
                  ))}
                </div>
              </div>

              {/* Method */}
              <div className="space-y-2">
                <Label htmlFor="method">Method</Label>
                <Select value={testContext.method} onValueChange={(v) => setTestContext({ ...testContext, method: v })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {METHODS.map((m) => (
                      <SelectItem key={m.value} value={m.value}>
                        {m.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {/* Transaction Fields */}
              {(testContext.method === 'eth_sendTransaction' || testContext.method === 'eth_signTransaction') && (
                <>
                  <div className="space-y-2">
                    <Label htmlFor="to">To Address</Label>
                    <Input
                      id="to"
                      value={testContext.to}
                      onChange={(e) => setTestContext({ ...testContext, to: e.target.value })}
                      placeholder="0x..."
                      className="font-mono"
                    />
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <Label htmlFor="value">Value (wei)</Label>
                      <Input
                        id="value"
                        value={testContext.value}
                        onChange={(e) => setTestContext({ ...testContext, value: e.target.value })}
                        placeholder="0"
                        className="font-mono"
                      />
                      {testContext.value && (
                        <p className="text-xs text-muted-foreground">
                          ≈ {(Number(testContext.value) / 1e18).toFixed(6)} ETH
                        </p>
                      )}
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="chainId">Chain ID</Label>
                      <Input
                        id="chainId"
                        type="number"
                        value={testContext.chainId}
                        onChange={(e) => setTestContext({ ...testContext, chainId: Number(e.target.value) })}
                      />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="data">Calldata (hex)</Label>
                    <Textarea
                      id="data"
                      value={testContext.data}
                      onChange={(e) => setTestContext({ ...testContext, data: e.target.value })}
                      placeholder="0x..."
                      className="font-mono text-xs"
                    />
                  </div>
                </>
              )}

              {/* Typed Data Fields */}
              {testContext.method === 'eth_signTypedData_v4' && (
                <>
                  <div className="space-y-2">
                    <Label>Typed Data Domain (JSON)</Label>
                    <Textarea
                      value={JSON.stringify(testContext.typedDataDomain, null, 2)}
                      onChange={(e) => {
                        try {
                          setTestContext({ ...testContext, typedDataDomain: JSON.parse(e.target.value) })
                        } catch {
                          // Invalid JSON, keep current
                        }
                      }}
                      className="font-mono text-xs min-h-[100px]"
                      placeholder='{"name": "...", "version": "1", "chainId": 1}'
                    />
                  </div>
                  <div className="space-y-2">
                    <Label>Typed Data Message (JSON)</Label>
                    <Textarea
                      value={JSON.stringify(testContext.typedDataMessage, null, 2)}
                      onChange={(e) => {
                        try {
                          setTestContext({ ...testContext, typedDataMessage: JSON.parse(e.target.value) })
                        } catch {
                          // Invalid JSON
                        }
                      }}
                      className="font-mono text-xs min-h-[100px]"
                      placeholder='{"from": "0x...", "to": "0x..."}'
                    />
                  </div>
                </>
              )}

              {/* Personal Sign */}
              {testContext.method === 'personal_sign' && (
                <div className="space-y-2">
                  <Label htmlFor="message">Message</Label>
                  <Textarea
                    id="message"
                    value={testContext.personalMessage}
                    onChange={(e) => setTestContext({ ...testContext, personalMessage: e.target.value })}
                    placeholder="Message to sign..."
                  />
                </div>
              )}

              <Button onClick={runSimulation} disabled={simulateMutation.isPending} className="w-full">
                <Play className="h-4 w-4 mr-2" />
                {simulateMutation.isPending ? 'Running...' : 'Run Simulation'}
              </Button>
            </CardContent>
          </Card>

          {/* Results */}
          {result && (
            <Card className={result.decision === 'ALLOW' ? 'border-green-200' : 'border-red-200'}>
              <CardHeader>
                <div className="flex items-center gap-2">
                  {result.decision === 'ALLOW' ? (
                    <CheckCircle2 className="h-5 w-5 text-green-600" />
                  ) : (
                    <XCircle className="h-5 w-5 text-red-600" />
                  )}
                  <CardTitle className={result.decision === 'ALLOW' ? 'text-green-600' : 'text-red-600'}>
                    {result.decision}
                  </CardTitle>
                </div>
                <CardDescription>{result.reason}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {result.matchedRule && (
                  <div className="p-3 bg-muted rounded-lg">
                    <p className="font-medium text-sm">Matched Rule: {result.matchedRule.ruleName}</p>
                    <ul className="mt-2 space-y-1">
                      {result.matchedRule.matchedConditions.map((cond, idx) => (
                        <li key={idx} className="text-xs text-green-600 flex items-center gap-1">
                          <CheckCircle2 className="h-3 w-3" />
                          {cond}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Evaluation Trace */}
                <div>
                  <button
                    className="flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground"
                    onClick={() => {
                      const el = document.getElementById('trace')
                      if (el) el.classList.toggle('hidden')
                    }}
                  >
                    <ChevronRight className="h-4 w-4" />
                    Evaluation Trace ({result.evaluationTrace.length} rules)
                  </button>
                  <div id="trace" className="hidden mt-2 space-y-2">
                    {result.evaluationTrace.map((trace, idx) => (
                      <div
                        key={idx}
                        className={`p-2 rounded text-xs ${trace.matched ? 'bg-green-50 border border-green-200' : 'bg-gray-50 border border-gray-200'}`}
                      >
                        <div className="flex items-center gap-2">
                          {trace.matched ? (
                            <CheckCircle2 className="h-3 w-3 text-green-600" />
                          ) : (
                            <AlertCircle className="h-3 w-3 text-gray-400" />
                          )}
                          <span className="font-medium">{trace.rule}</span>
                        </div>
                        <p className="mt-1 text-muted-foreground">{trace.reason}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
