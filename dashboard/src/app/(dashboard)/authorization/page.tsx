'use client'

import { Key, MoreHorizontal, Plus } from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { api } from '@/trpc/react'

export default function AuthorizationPage() {
  const { data, isLoading, error } = api.authorizationKeys.list.useQuery({ limit: 50 })

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const truncateKey = (key: string) => {
    if (key.length <= 20) return key
    return `${key.slice(0, 10)}...${key.slice(-10)}`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Authorization Keys</h1>
          <p className="text-muted-foreground">Manage P-256 keys used for signing authorization requests</p>
        </div>
        <Button>
          <Plus className="mr-2 h-4 w-4" />
          Register Key
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Authorization Keys</CardTitle>
          <CardDescription>Keys are used to authorize wallet operations and policy changes</CardDescription>
        </CardHeader>
        <CardContent>
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(5)].map((_, i) => (
                <Skeleton key={i} className="h-12 w-full" />
              ))}
            </div>
          ) : error ? (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Failed to load authorization keys</p>
              <p className="text-sm">{error.message}</p>
            </div>
          ) : data?.items.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Key className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No authorization keys found</p>
              <p className="text-sm">Register a key to get started</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>ID</TableHead>
                  <TableHead>Public Key</TableHead>
                  <TableHead>Algorithm</TableHead>
                  <TableHead>Owner Entity</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((key) => (
                  <TableRow key={key.id}>
                    <TableCell className="font-mono text-sm">{key.id.slice(0, 8)}...</TableCell>
                    <TableCell className="font-mono text-sm">{truncateKey(key.public_key)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{key.algorithm.toUpperCase()}</Badge>
                    </TableCell>
                    <TableCell>{key.owner_entity}</TableCell>
                    <TableCell>
                      <Badge
                        variant={
                          key.status === 'active' ? 'default' : key.status === 'rotated' ? 'secondary' : 'destructive'
                        }
                      >
                        {key.status}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatDate(key.created_at)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem>View Details</DropdownMenuItem>
                          <DropdownMenuItem>Rotate Key</DropdownMenuItem>
                          <DropdownMenuItem className="text-destructive">Revoke Key</DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
