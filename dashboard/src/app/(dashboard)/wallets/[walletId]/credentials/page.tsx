'use client'

import { useState } from 'react'
import Link from 'next/link'
import { useParams } from 'next/navigation'
import { Plus, Shield, Copy, Check } from 'lucide-react'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { trpc } from '@/lib/trpc/client'
import { toast } from 'sonner'

export default function CredentialsPage() {
  const params = useParams<{ walletId: string }>()
  const walletId = params.walletId
  const utils = trpc.useUtils()
  const { data: credentials, isLoading } = trpc.credentials.list.useQuery({ walletId })
  const [copiedId, setCopiedId] = useState<string | null>(null)

  const pauseCredential = trpc.credentials.pause.useMutation({
    onSuccess: () => {
      toast.success('Credential paused')
      utils.credentials.list.invalidate({ walletId })
    },
    onError: (error) => toast.error(error.message),
  })

  const resumeCredential = trpc.credentials.resume.useMutation({
    onSuccess: () => {
      toast.success('Credential resumed')
      utils.credentials.list.invalidate({ walletId })
    },
    onError: (error) => toast.error(error.message),
  })

  const revokeCredential = trpc.credentials.revoke.useMutation({
    onSuccess: () => {
      toast.success('Credential revoked')
      utils.credentials.list.invalidate({ walletId })
    },
    onError: (error) => toast.error(error.message),
  })

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge variant="default">Active</Badge>
      case 'paused':
        return <Badge variant="secondary">Paused</Badge>
      case 'revoked':
        return <Badge variant="destructive">Revoked</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  const formatOperations = (operations: string[]) => {
    if (!operations || operations.length === 0) return 'All'
    if (operations.includes('*')) return 'All'
    return operations.join(', ')
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Agent Credentials"
        description="Manage credentials for AI agents to access this wallet"
      >
        <Button asChild>
          <Link href={`/wallets/${walletId}/credentials/new`}>
            <Plus className="mr-2 h-4 w-4" />
            Create Credential
          </Link>
        </Button>
      </PageHeader>

      {isLoading ? (
        <Card>
          <CardContent className="p-6">
            <div className="space-y-4">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          </CardContent>
        </Card>
      ) : credentials && credentials.length > 0 ? (
        <Card>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Key Prefix</TableHead>
                <TableHead>Operations</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Last Used</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {credentials.map((credential) => (
                <TableRow key={credential.id}>
                  <TableCell className="font-medium">{credential.name}</TableCell>
                  <TableCell>
                    <div className="flex items-center gap-2">
                      <code className="text-xs bg-muted px-2 py-1 rounded">
                        {credential.keyPrefix}
                      </code>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6"
                        onClick={() => copyToClipboard(credential.keyPrefix, credential.id)}
                      >
                        {copiedId === credential.id ? (
                          <Check className="h-3 w-3" />
                        ) : (
                          <Copy className="h-3 w-3" />
                        )}
                      </Button>
                    </div>
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatOperations(credential.capabilities?.operations ?? [])}
                  </TableCell>
                  <TableCell>{getStatusBadge(credential.status)}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {credential.lastUsedAt
                      ? new Date(credential.lastUsedAt).toLocaleDateString()
                      : 'Never'}
                  </TableCell>
                  <TableCell className="text-right">
                    <DropdownMenu>
                      <DropdownMenuTrigger asChild>
                        <Button variant="ghost" size="sm">
                          Actions
                        </Button>
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        {credential.status === 'active' && (
                          <DropdownMenuItem
                            onClick={() => pauseCredential.mutate({ id: credential.id })}
                          >
                            Pause
                          </DropdownMenuItem>
                        )}
                        {credential.status === 'paused' && (
                          <DropdownMenuItem
                            onClick={() => resumeCredential.mutate({ id: credential.id })}
                          >
                            Resume
                          </DropdownMenuItem>
                        )}
                        {credential.status !== 'revoked' && (
                          <DropdownMenuItem
                            className="text-destructive"
                            onClick={() => revokeCredential.mutate({ id: credential.id })}
                          >
                            Revoke
                          </DropdownMenuItem>
                        )}
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </Card>
      ) : (
        <Card>
          <CardContent className="flex flex-col items-center justify-center py-12">
            <Shield className="h-12 w-12 text-muted-foreground mb-4" />
            <h3 className="text-lg font-medium mb-2">No credentials yet</h3>
            <p className="text-muted-foreground mb-4">Create a credential to allow agents to use this wallet</p>
            <Button asChild>
              <Link href={`/wallets/${walletId}/credentials/new`}>
                <Plus className="mr-2 h-4 w-4" />
                Create Credential
              </Link>
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
