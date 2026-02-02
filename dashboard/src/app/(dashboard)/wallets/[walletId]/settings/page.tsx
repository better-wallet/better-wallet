'use client'

import { useState } from 'react'
import { useParams, useRouter } from 'next/navigation'
import { AlertTriangle, Pause, Play, Skull } from 'lucide-react'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Skeleton } from '@/components/ui/skeleton'
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from '@/components/ui/alert-dialog'
import { trpc } from '@/lib/trpc/client'
import { toast } from 'sonner'

export default function WalletSettingsPage() {
  const params = useParams<{ walletId: string }>()
  const walletId = params.walletId
  const router = useRouter()
  const utils = trpc.useUtils()
  const { data: wallet, isLoading } = trpc.wallets.get.useQuery({ id: walletId })
  const [killDialogOpen, setKillDialogOpen] = useState(false)

  const pauseWallet = trpc.wallets.pause.useMutation({
    onSuccess: () => {
      toast.success('Wallet paused')
      utils.wallets.get.invalidate({ id: walletId })
    },
    onError: (error) => toast.error(error.message),
  })

  const resumeWallet = trpc.wallets.resume.useMutation({
    onSuccess: () => {
      toast.success('Wallet resumed')
      utils.wallets.get.invalidate({ id: walletId })
    },
    onError: (error) => toast.error(error.message),
  })

  const killWallet = trpc.wallets.kill.useMutation({
    onSuccess: () => {
      toast.success('Wallet killed permanently')
      setKillDialogOpen(false)
      router.push('/wallets')
    },
    onError: (error) => toast.error(error.message),
  })

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'active':
        return <Badge variant="default">Active</Badge>
      case 'paused':
        return <Badge variant="secondary">Paused</Badge>
      case 'killed':
        return <Badge variant="destructive">Killed</Badge>
      default:
        return <Badge variant="outline">{status}</Badge>
    }
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="space-y-2">
          <Skeleton className="h-8 w-48" />
          <Skeleton className="h-4 w-96" />
        </div>
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-32" />
          </CardHeader>
          <CardContent>
            <Skeleton className="h-24 w-full" />
          </CardContent>
        </Card>
      </div>
    )
  }

  if (!wallet) {
    return (
      <div className="flex items-center justify-center h-64">
        <p className="text-muted-foreground">Wallet not found</p>
      </div>
    )
  }

  const isKilled = wallet.status === 'killed'
  const isPaused = wallet.status === 'paused'
  const isActive = wallet.status === 'active'

  return (
    <div className="space-y-6">
      <PageHeader
        title="Wallet Settings"
        description="Manage wallet status and controls"
      />

      {/* Current Status */}
      <Card>
        <CardHeader>
          <CardTitle>Current Status</CardTitle>
          <CardDescription>
            The current operational status of this wallet
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-4">
            <span className="text-sm text-muted-foreground">Status:</span>
            {getStatusBadge(wallet.status)}
          </div>
          {isKilled && (
            <div className="flex items-center gap-2 text-destructive">
              <AlertTriangle className="h-4 w-4" />
              <span className="text-sm">This wallet has been permanently killed and cannot be reactivated.</span>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Pause/Resume Control */}
      {!isKilled && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {isPaused ? <Play className="h-5 w-5" /> : <Pause className="h-5 w-5" />}
              {isPaused ? 'Resume Wallet' : 'Pause Wallet'}
            </CardTitle>
            <CardDescription>
              {isPaused
                ? 'Resume this wallet to allow agents to perform transactions again.'
                : 'Temporarily pause this wallet. All agent transactions will be blocked until resumed.'}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {isPaused ? (
              <Button
                onClick={() => resumeWallet.mutate({ id: walletId })}
                disabled={resumeWallet.isPending}
              >
                {resumeWallet.isPending ? 'Resuming...' : 'Resume Wallet'}
              </Button>
            ) : (
              <Button
                variant="secondary"
                onClick={() => pauseWallet.mutate({ id: walletId })}
                disabled={pauseWallet.isPending}
              >
                {pauseWallet.isPending ? 'Pausing...' : 'Pause Wallet'}
              </Button>
            )}
          </CardContent>
        </Card>
      )}

      {/* Kill Switch */}
      {!isKilled && (
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-destructive">
              <Skull className="h-5 w-5" />
              Kill Wallet
            </CardTitle>
            <CardDescription>
              Permanently disable this wallet. This action cannot be undone.
              All credentials will be revoked and no further transactions will be possible.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <AlertDialog open={killDialogOpen} onOpenChange={setKillDialogOpen}>
              <AlertDialogTrigger asChild>
                <Button variant="destructive">
                  Kill Wallet Permanently
                </Button>
              </AlertDialogTrigger>
              <AlertDialogContent>
                <AlertDialogHeader>
                  <AlertDialogTitle>Are you absolutely sure?</AlertDialogTitle>
                  <AlertDialogDescription>
                    This action cannot be undone. This will permanently disable the wallet
                    &quot;{wallet.name}&quot; and revoke all associated credentials.
                    No further transactions will be possible.
                  </AlertDialogDescription>
                </AlertDialogHeader>
                <AlertDialogFooter>
                  <AlertDialogCancel>Cancel</AlertDialogCancel>
                  <AlertDialogAction
                    onClick={() => killWallet.mutate({ id: walletId })}
                    className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
                  >
                    {killWallet.isPending ? 'Killing...' : 'Yes, kill this wallet'}
                  </AlertDialogAction>
                </AlertDialogFooter>
              </AlertDialogContent>
            </AlertDialog>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
