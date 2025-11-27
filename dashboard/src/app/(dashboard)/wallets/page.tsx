'use client'

import { Plus, Wallet, MoreHorizontal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { api } from '@/trpc/react'

export default function WalletsPage() {
  const { data, isLoading, error } = api.wallets.list.useQuery({ limit: 50 })

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
    })
  }

  const truncateAddress = (address: string) => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold tracking-tight">Wallets</h1>
          <p className="text-muted-foreground">Manage blockchain wallets</p>
        </div>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          Create Wallet
        </Button>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>All Wallets</CardTitle>
          <CardDescription>A list of all wallets in your system</CardDescription>
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
              <Wallet className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>Failed to load wallets</p>
              <p className="text-sm">{error.message}</p>
            </div>
          ) : data?.items.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Wallet className="h-12 w-12 mx-auto mb-4 opacity-50" />
              <p>No wallets found</p>
              <p className="text-sm">Create a wallet to get started</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Address</TableHead>
                  <TableHead>Chain</TableHead>
                  <TableHead>Owner ID</TableHead>
                  <TableHead>Backend</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="w-[50px]"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {data?.items.map((wallet) => (
                  <TableRow key={wallet.id}>
                    <TableCell className="font-mono">{truncateAddress(wallet.address)}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{wallet.chain_type}</Badge>
                    </TableCell>
                    <TableCell className="font-mono text-sm">
                      {wallet.owner_id.slice(0, 8)}...
                    </TableCell>
                    <TableCell>
                      <Badge variant={wallet.exec_backend === 'kms' ? 'default' : 'secondary'}>
                        {wallet.exec_backend.toUpperCase()}
                      </Badge>
                    </TableCell>
                    <TableCell>{formatDate(wallet.created_at)}</TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button variant="ghost" size="icon">
                            <MoreHorizontal className="h-4 w-4" />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem>View Details</DropdownMenuItem>
                          <DropdownMenuItem>Manage Policies</DropdownMenuItem>
                          <DropdownMenuItem>View Transactions</DropdownMenuItem>
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
