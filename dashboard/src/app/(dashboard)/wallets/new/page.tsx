'use client'

import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { trpc } from '@/lib/trpc/client'
import { toast } from 'sonner'

export default function NewWalletPage() {
  const router = useRouter()
  const [name, setName] = useState('')
  const [chainType, setChainType] = useState('evm')

  const createWallet = trpc.wallets.create.useMutation({
    onSuccess: (wallet) => {
      toast.success('Wallet created successfully')
      router.push(`/wallets/${wallet.id}`)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (!name.trim()) {
      toast.error('Please enter a wallet name')
      return
    }
    createWallet.mutate({ name: name.trim(), chainType })
  }

  return (
    <div className="space-y-6">
      <PageHeader
        title="Create Wallet"
        description="Create a new agent wallet"
      />

      <Card className="max-w-lg">
        <CardHeader>
          <CardTitle>Wallet Details</CardTitle>
          <CardDescription>
            Enter the details for your new agent wallet
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="name">Wallet Name</Label>
              <Input
                id="name"
                placeholder="e.g., Trading Bot Wallet"
                value={name}
                onChange={(e) => setName(e.target.value)}
                disabled={createWallet.isPending}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="chainType">Chain Type</Label>
              <Select value={chainType} onValueChange={setChainType} disabled={createWallet.isPending}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="evm">EVM (Ethereum, Polygon, etc.)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex gap-2 pt-4">
              <Button
                type="button"
                variant="outline"
                onClick={() => router.back()}
                disabled={createWallet.isPending}
              >
                Cancel
              </Button>
              <Button type="submit" disabled={createWallet.isPending}>
                {createWallet.isPending ? 'Creating...' : 'Create Wallet'}
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
