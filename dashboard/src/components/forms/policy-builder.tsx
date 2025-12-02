'use client'

import { GripVertical, Plus, Trash2 } from 'lucide-react'
import { useCallback } from 'react'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
// Using flexible string types to be compatible with both API types and local types
interface PolicyCondition {
  field_source: string
  field: string
  operator: string
  value: unknown
}

interface PolicyRule {
  name: string
  method: string
  conditions: PolicyCondition[]
  action: 'ALLOW' | 'DENY'
}

interface PolicyBuilderProps {
  rules: PolicyRule[]
  onChange: (rules: PolicyRule[]) => void
}

const FIELD_SOURCES: { value: string; label: string }[] = [
  { value: 'ethereum_transaction', label: 'Transaction' },
  { value: 'ethereum_calldata', label: 'Calldata' },
  { value: 'ethereum_typed_data_domain', label: 'Typed Data Domain' },
  { value: 'ethereum_typed_data_message', label: 'Typed Data Message' },
  { value: 'ethereum_7702_authorization', label: '7702 Authorization' },
  { value: 'ethereum_message', label: 'Message' },
  { value: 'system', label: 'System' },
]

const OPERATORS: { value: string; label: string }[] = [
  { value: 'eq', label: '= (equals)' },
  { value: 'neq', label: '!= (not equals)' },
  { value: 'lt', label: '< (less than)' },
  { value: 'lte', label: '<= (less or equal)' },
  { value: 'gt', label: '> (greater than)' },
  { value: 'gte', label: '>= (greater or equal)' },
  { value: 'in', label: 'in (in array)' },
  { value: 'in_condition_set', label: 'in set (condition set)' },
]

const METHODS = ['eth_signTransaction', 'eth_sendTransaction', 'eth_signTypedData_v4', 'personal_sign', 'eth_sign', '*']

const COMMON_FIELDS: Record<string, string[]> = {
  ethereum_transaction: ['to', 'value', 'from', 'data', 'chain_id', 'gas', 'nonce'],
  ethereum_calldata: ['function_name', 'param_0', 'param_1', 'param_2'],
  ethereum_typed_data_domain: ['name', 'version', 'chainId', 'verifyingContract'],
  ethereum_typed_data_message: [],
  ethereum_7702_authorization: ['address', 'chain_id', 'nonce'],
  ethereum_message: ['message', 'message_hash'],
  system: ['current_unix_timestamp'],
}

function createEmptyCondition(): PolicyCondition {
  return {
    field_source: 'ethereum_transaction',
    field: '',
    operator: 'eq',
    value: '',
  }
}

function createEmptyRule(): PolicyRule {
  return {
    name: '',
    method: 'eth_signTransaction',
    conditions: [],
    action: 'ALLOW',
  }
}

export function PolicyBuilder({ rules, onChange }: PolicyBuilderProps) {
  const addRule = useCallback(() => {
    onChange([...rules, createEmptyRule()])
  }, [rules, onChange])

  const removeRule = useCallback(
    (index: number) => {
      onChange(rules.filter((_, i) => i !== index))
    },
    [rules, onChange]
  )

  const updateRule = useCallback(
    (index: number, updates: Partial<PolicyRule>) => {
      onChange(rules.map((rule, i) => (i === index ? { ...rule, ...updates } : rule)))
    },
    [rules, onChange]
  )

  const addCondition = useCallback(
    (ruleIndex: number) => {
      const rule = rules[ruleIndex]
      updateRule(ruleIndex, {
        conditions: [...rule.conditions, createEmptyCondition()],
      })
    },
    [rules, updateRule]
  )

  const removeCondition = useCallback(
    (ruleIndex: number, conditionIndex: number) => {
      const rule = rules[ruleIndex]
      updateRule(ruleIndex, {
        conditions: rule.conditions.filter((_, i) => i !== conditionIndex),
      })
    },
    [rules, updateRule]
  )

  const updateCondition = useCallback(
    (ruleIndex: number, conditionIndex: number, updates: Partial<PolicyCondition>) => {
      const rule = rules[ruleIndex]
      updateRule(ruleIndex, {
        conditions: rule.conditions.map((cond, i) => (i === conditionIndex ? { ...cond, ...updates } : cond)),
      })
    },
    [rules, updateRule]
  )

  const moveRule = useCallback(
    (fromIndex: number, toIndex: number) => {
      if (toIndex < 0 || toIndex >= rules.length) return
      const newRules = [...rules]
      const [removed] = newRules.splice(fromIndex, 1)
      newRules.splice(toIndex, 0, removed)
      onChange(newRules)
    },
    [rules, onChange]
  )

  return (
    <div className="space-y-4">
      {rules.map((rule, ruleIndex) => (
        <Card key={ruleIndex} className="border-l-4 border-l-primary">
          <CardHeader className="pb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="flex flex-col gap-1">
                  <Button
                    type="button"
                    variant="ghost"
                    size="icon"
                    className="h-4 w-4 cursor-grab"
                    onClick={() => moveRule(ruleIndex, ruleIndex - 1)}
                    disabled={ruleIndex === 0}
                  >
                    <GripVertical className="h-3 w-3" />
                  </Button>
                </div>
                <Badge variant="secondary">#{ruleIndex + 1}</Badge>
                <CardTitle className="text-base">
                  <Input
                    value={rule.name}
                    onChange={(e) => updateRule(ruleIndex, { name: e.target.value })}
                    placeholder="Rule name"
                    className="h-8 w-48"
                  />
                </CardTitle>
              </div>
              <div className="flex items-center gap-2">
                <Select
                  value={rule.action}
                  onValueChange={(value: 'ALLOW' | 'DENY') => updateRule(ruleIndex, { action: value })}
                >
                  <SelectTrigger className="w-28">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ALLOW">ALLOW</SelectItem>
                    <SelectItem value="DENY">DENY</SelectItem>
                  </SelectContent>
                </Select>
                <Button type="button" variant="ghost" size="icon" onClick={() => removeRule(ruleIndex)}>
                  <Trash2 className="h-4 w-4 text-destructive" />
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Method</Label>
                <Select value={rule.method} onValueChange={(value) => updateRule(ruleIndex, { method: value })}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {METHODS.map((method) => (
                      <SelectItem key={method} value={method}>
                        {method === '*' ? 'All methods (*)' : method}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label>Conditions (all must match)</Label>
                <Button type="button" variant="outline" size="sm" onClick={() => addCondition(ruleIndex)}>
                  <Plus className="h-3 w-3 mr-1" />
                  Add Condition
                </Button>
              </div>

              {rule.conditions.length === 0 ? (
                <p className="text-sm text-muted-foreground py-2">
                  No conditions - this rule matches all {rule.method} requests
                </p>
              ) : (
                <div className="space-y-2">
                  {rule.conditions.map((condition, condIndex) => (
                    <ConditionRow
                      key={condIndex}
                      condition={condition}
                      onChange={(updates) => updateCondition(ruleIndex, condIndex, updates)}
                      onRemove={() => removeCondition(ruleIndex, condIndex)}
                    />
                  ))}
                </div>
              )}
            </div>
          </CardContent>
        </Card>
      ))}

      <Button type="button" variant="outline" onClick={addRule} className="w-full">
        <Plus className="h-4 w-4 mr-2" />
        Add Rule
      </Button>

      {rules.length === 0 && (
        <p className="text-sm text-muted-foreground text-center py-4">
          No rules defined. Add at least one rule to create a policy.
        </p>
      )}
    </div>
  )
}

interface ConditionRowProps {
  condition: PolicyCondition
  onChange: (updates: Partial<PolicyCondition>) => void
  onRemove: () => void
}

function ConditionRow({ condition, onChange, onRemove }: ConditionRowProps) {
  const suggestedFields = COMMON_FIELDS[condition.field_source] || []

  const handleValueChange = (value: string) => {
    // Try to parse as JSON for arrays, objects, numbers, booleans
    try {
      if (value.startsWith('[') || value.startsWith('{')) {
        onChange({ value: JSON.parse(value) })
        return
      }
      if (value === 'true' || value === 'false') {
        onChange({ value: value === 'true' })
        return
      }
      if (/^\d+$/.test(value)) {
        onChange({ value: Number.parseInt(value, 10) })
        return
      }
    } catch {
      // Fall through to string
    }
    onChange({ value })
  }

  const formatValue = (value: unknown): string => {
    if (typeof value === 'string') return value
    if (value === null || value === undefined) return ''
    return JSON.stringify(value)
  }

  return (
    <div className="flex items-center gap-2 bg-muted/50 p-3 rounded-lg">
      <Select value={condition.field_source} onValueChange={(value: string) => onChange({ field_source: value })}>
        <SelectTrigger className="w-40">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {FIELD_SOURCES.map((source) => (
            <SelectItem key={source.value} value={source.value}>
              {source.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <div className="relative flex-1">
        <Input
          value={condition.field}
          onChange={(e) => onChange({ field: e.target.value })}
          placeholder="Field name"
          list={`fields-${condition.field_source}`}
        />
        {suggestedFields.length > 0 && (
          <datalist id={`fields-${condition.field_source}`}>
            {suggestedFields.map((field) => (
              <option key={field} value={field} />
            ))}
          </datalist>
        )}
      </div>

      <Select value={condition.operator} onValueChange={(value: string) => onChange({ operator: value })}>
        <SelectTrigger className="w-36">
          <SelectValue />
        </SelectTrigger>
        <SelectContent>
          {OPERATORS.map((op) => (
            <SelectItem key={op.value} value={op.value}>
              {op.label}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      <Input
        value={formatValue(condition.value)}
        onChange={(e) => handleValueChange(e.target.value)}
        placeholder="Value"
        className="flex-1"
      />

      <Button type="button" variant="ghost" size="icon" onClick={onRemove}>
        <Trash2 className="h-4 w-4 text-destructive" />
      </Button>
    </div>
  )
}
