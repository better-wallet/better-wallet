'use client'

import { Edit2, FileText, MoreHorizontal, Plus, Trash2 } from 'lucide-react'
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
import { Textarea } from '@/components/ui/textarea'
import { trpc } from '@/lib/trpc/client'

interface ConditionSetData {
  id: string
  name: string
  description: string | null
  values: unknown[]
  created_at: number
  updated_at: number
}

function formatDate(timestamp: number) {
  return new Date(timestamp).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  })
}

function formatValues(values: unknown[]): string {
  if (values.length === 0) return 'Empty'
  if (values.length <= 3) {
    return values.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join(', ')
  }
  const firstThree = values.slice(0, 3).map((v) => (typeof v === 'string' ? v : JSON.stringify(v)))
  return `${firstThree.join(', ')} +${values.length - 3} more`
}

export default function ConditionSetsPage() {
  const params = useParams()
  const appId = params.appId as string

  const [createOpen, setCreateOpen] = useState(false)
  const [editOpen, setEditOpen] = useState(false)
  const [editingSet, setEditingSet] = useState<ConditionSetData | null>(null)

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [valuesText, setValuesText] = useState('')

  const [setToDelete, setSetToDelete] = useState<{ id: string; name: string } | null>(null)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.backend.conditionSets.list.useQuery({ appId })

  const createSet = trpc.backend.conditionSets.create.useMutation({
    onSuccess: () => {
      toast.success('Condition set created')
      utils.backend.conditionSets.list.invalidate()
      resetForm()
      setCreateOpen(false)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const updateSet = trpc.backend.conditionSets.update.useMutation({
    onSuccess: () => {
      toast.success('Condition set updated')
      utils.backend.conditionSets.list.invalidate()
      resetForm()
      setEditOpen(false)
      setEditingSet(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const deleteSet = trpc.backend.conditionSets.delete.useMutation({
    onSuccess: () => {
      toast.success('Condition set deleted')
      utils.backend.conditionSets.list.invalidate()
      setSetToDelete(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const resetForm = () => {
    setName('')
    setDescription('')
    setValuesText('')
  }

  const parseValues = (text: string): unknown[] => {
    if (!text.trim()) return []

    // Try parsing as JSON array first
    try {
      const parsed = JSON.parse(text)
      if (Array.isArray(parsed)) return parsed
    } catch {
      // Not JSON
    }

    // Fall back to line-separated values
    return text
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line.length > 0)
  }

  const handleCreate = () => {
    if (!name.trim()) {
      toast.error('Name is required')
      return
    }

    const values = parseValues(valuesText)

    createSet.mutate({
      appId,
      name: name.trim(),
      description: description.trim() || undefined,
      values,
    })
  }

  const handleUpdate = () => {
    if (!editingSet) return

    if (!name.trim()) {
      toast.error('Name is required')
      return
    }

    const values = parseValues(valuesText)

    updateSet.mutate({
      appId,
      id: editingSet.id,
      name: name.trim(),
      description: description.trim() || undefined,
      values,
    })
  }

  const handleEdit = (set: ConditionSetData) => {
    setEditingSet(set)
    setName(set.name)
    setDescription(set.description || '')
    setValuesText(set.values.map((v) => (typeof v === 'string' ? v : JSON.stringify(v))).join('\n'))
    setEditOpen(true)
  }

  const handleDelete = async () => {
    if (setToDelete) {
      await deleteSet.mutateAsync({ appId, id: setToDelete.id })
    }
  }

  const canManage = app?.role === 'owner' || app?.role === 'admin' || app?.role === 'developer'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Condition Sets" />
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
        <PageHeader title="Condition Sets" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  const sets = data?.data || []

  return (
    <div className="space-y-6">
      <PageHeader
        title="Condition Sets"
        description="Reusable value sets for policy conditions"
        actions={
          canManage && (
            <Dialog open={createOpen} onOpenChange={setCreateOpen}>
              <DialogTrigger asChild>
                <Button>
                  <Plus className="h-4 w-4 mr-2" />
                  Create Set
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Create Condition Set</DialogTitle>
                  <DialogDescription>
                    Create a reusable set of values that can be referenced in policy conditions using the
                    "in_condition_set" operator.
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4 py-4">
                  <div className="space-y-2">
                    <Label htmlFor="name">Name</Label>
                    <Input
                      id="name"
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      placeholder="e.g., Allowed Addresses"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="description">Description (optional)</Label>
                    <Input
                      id="description"
                      value={description}
                      onChange={(e) => setDescription(e.target.value)}
                      placeholder="e.g., List of approved contract addresses"
                    />
                  </div>
                  <div className="space-y-2">
                    <Label htmlFor="values">Values</Label>
                    <Textarea
                      id="values"
                      value={valuesText}
                      onChange={(e) => setValuesText(e.target.value)}
                      placeholder="Enter values, one per line:&#10;0x1234...&#10;0x5678...&#10;&#10;Or paste a JSON array: [&quot;value1&quot;, &quot;value2&quot;]"
                      rows={6}
                      className="font-mono text-sm"
                    />
                    <p className="text-xs text-muted-foreground">Enter one value per line, or paste a JSON array</p>
                  </div>
                </div>
                <DialogFooter>
                  <Button
                    variant="outline"
                    onClick={() => {
                      resetForm()
                      setCreateOpen(false)
                    }}
                  >
                    Cancel
                  </Button>
                  <Button onClick={handleCreate} disabled={createSet.isPending}>
                    {createSet.isPending ? 'Creating...' : 'Create'}
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
            <FileText className="h-5 w-5 text-blue-500 shrink-0 mt-0.5" />
            <div>
              <p className="font-medium text-blue-700 dark:text-blue-400">Policy Integration</p>
              <p className="text-sm text-muted-foreground mt-1">
                Condition sets can be referenced in policy rules using the "in_condition_set" operator. This allows you
                to maintain lists of addresses, chain IDs, or other values without modifying the policy itself.
              </p>
            </div>
          </div>
        </CardContent>
      </Card>

      {sets.length === 0 ? (
        <EmptyState
          icon={FileText}
          title="No condition sets"
          description="Create your first condition set to use in policy conditions."
          action={
            canManage
              ? {
                  label: 'Create Set',
                  onClick: () => setCreateOpen(true),
                }
              : undefined
          }
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>All Condition Sets</CardTitle>
            <CardDescription>
              {sets.length} set{sets.length !== 1 ? 's' : ''} defined
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Values</TableHead>
                  <TableHead>Updated</TableHead>
                  <TableHead className="w-[100px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {sets.map((set: ConditionSetData) => (
                  <TableRow key={set.id}>
                    <TableCell>
                      <div>
                        <p className="font-medium">{set.name}</p>
                        {set.description && <p className="text-sm text-muted-foreground">{set.description}</p>}
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="font-mono text-xs">
                        {formatValues(set.values)}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm text-muted-foreground">{formatDate(set.updated_at)}</TableCell>
                    <TableCell>
                      {canManage && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleEdit(set)}>
                              <Edit2 className="h-4 w-4 mr-2" />
                              Edit
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => setSetToDelete({ id: set.id, name: set.name })}
                            >
                              <Trash2 className="h-4 w-4 mr-2" />
                              Delete
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

      {/* Edit Dialog */}
      <Dialog
        open={editOpen}
        onOpenChange={(open) => {
          if (!open) {
            resetForm()
            setEditingSet(null)
          }
          setEditOpen(open)
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Edit Condition Set</DialogTitle>
            <DialogDescription>Update the values in this condition set.</DialogDescription>
          </DialogHeader>
          <div className="space-y-4 py-4">
            <div className="space-y-2">
              <Label htmlFor="edit-name">Name</Label>
              <Input
                id="edit-name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g., Allowed Addresses"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-description">Description (optional)</Label>
              <Input
                id="edit-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="e.g., List of approved contract addresses"
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="edit-values">Values</Label>
              <Textarea
                id="edit-values"
                value={valuesText}
                onChange={(e) => setValuesText(e.target.value)}
                placeholder="Enter values, one per line"
                rows={6}
                className="font-mono text-sm"
              />
            </div>
          </div>
          <DialogFooter>
            <Button
              variant="outline"
              onClick={() => {
                resetForm()
                setEditingSet(null)
                setEditOpen(false)
              }}
            >
              Cancel
            </Button>
            <Button onClick={handleUpdate} disabled={updateSet.isPending}>
              {updateSet.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete Dialog */}
      <ConfirmDialog
        open={!!setToDelete}
        onOpenChange={() => setSetToDelete(null)}
        title="Delete Condition Set"
        description={`Are you sure you want to delete "${setToDelete?.name}"? Policies using this set may stop working correctly.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />
    </div>
  )
}
