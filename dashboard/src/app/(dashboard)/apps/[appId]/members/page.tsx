'use client'

import { zodResolver } from '@hookform/resolvers/zod'
import { MoreHorizontal, UserPlus, Users } from 'lucide-react'
import { useParams } from 'next/navigation'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'

import { EmptyState } from '@/components/data/empty-state'
import { ErrorState } from '@/components/data/error-state'
import { ConfirmDialog } from '@/components/forms/confirm-dialog'
import { SubmitButton } from '@/components/forms/submit-button'
import { PageHeader } from '@/components/layout/page-header'
import { Avatar, AvatarFallback } from '@/components/ui/avatar'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import {
  Dialog,
  DialogContent,
  DialogDescription,
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
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select'
import { Skeleton } from '@/components/ui/skeleton'
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table'
import { trpc } from '@/lib/trpc/client'

const inviteSchema = z.object({
  email: z.string().email('Valid email is required'),
  role: z.enum(['admin', 'developer', 'viewer']),
})

type InviteValues = z.infer<typeof inviteSchema>

const roleDescriptions = {
  owner: 'Full control over the app',
  admin: 'Can manage members, settings, and all resources',
  developer: 'Can manage wallets, policies, and keys',
  viewer: 'Read-only access to all resources',
}

const roleBadgeVariant = {
  owner: 'default' as const,
  admin: 'secondary' as const,
  developer: 'outline' as const,
  viewer: 'outline' as const,
}

export default function AppMembersPage() {
  const params = useParams()
  const appId = params.appId as string
  const [inviteOpen, setInviteOpen] = useState(false)
  const [memberToRemove, setMemberToRemove] = useState<{ id: string; name: string } | null>(null)
  const [roleChangeDialog, setRoleChangeDialog] = useState<{
    memberId: string
    currentRole: string
    newRole: string
  } | null>(null)

  const utils = trpc.useUtils()
  const { data: app } = trpc.apps.get.useQuery({ id: appId })
  const { data, isLoading, error, refetch } = trpc.appMembers.list.useQuery({ appId })

  const invite = trpc.appMembers.invite.useMutation({
    onSuccess: () => {
      toast.success('Member invited successfully')
      utils.appMembers.list.invalidate({ appId })
      setInviteOpen(false)
      form.reset()
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const updateRole = trpc.appMembers.updateRole.useMutation({
    onSuccess: () => {
      toast.success('Role updated successfully')
      utils.appMembers.list.invalidate({ appId })
      setRoleChangeDialog(null)
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const removeMember = trpc.appMembers.remove.useMutation({
    onSuccess: () => {
      toast.success('Member removed')
      utils.appMembers.list.invalidate({ appId })
    },
    onError: (error: { message: string }) => {
      toast.error(error.message)
    },
  })

  const form = useForm<InviteValues>({
    resolver: zodResolver(inviteSchema),
    defaultValues: {
      email: '',
      role: 'developer',
    },
  })

  const onInviteSubmit = (values: InviteValues) => {
    invite.mutate({
      appId,
      ...values,
    })
  }

  const handleRoleChange = (memberId: string, currentRole: string, newRole: string) => {
    setRoleChangeDialog({ memberId, currentRole, newRole })
  }

  const confirmRoleChange = async () => {
    if (roleChangeDialog) {
      await updateRole.mutateAsync({
        id: roleChangeDialog.memberId,
        role: roleChangeDialog.newRole as 'admin' | 'developer' | 'viewer',
      })
    }
  }

  const handleRemove = async () => {
    if (memberToRemove) {
      await removeMember.mutateAsync({ id: memberToRemove.id })
      setMemberToRemove(null)
    }
  }

  const canManageMembers = app?.role === 'owner' || app?.role === 'admin'

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Members" />
        <Card>
          <CardContent className="pt-6">
            {[1, 2, 3].map((i) => (
              <div key={i} className="flex items-center gap-4 py-4">
                <Skeleton className="h-10 w-10 rounded-full" />
                <div className="space-y-2">
                  <Skeleton className="h-4 w-32" />
                  <Skeleton className="h-3 w-48" />
                </div>
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
        <PageHeader title="Members" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  // Separate owner and regular members for type safety
  const owner = data?.owner ? { ...data.owner, role: 'owner' as const, isOwner: true as const } : null
  const regularMembers = (data?.members || []).map((m) => ({ ...m, isOwner: false as const }))

  return (
    <div className="space-y-6">
      <PageHeader
        title="Members"
        description="Manage who has access to this app"
        actions={
          canManageMembers && (
            <Dialog open={inviteOpen} onOpenChange={setInviteOpen}>
              <DialogTrigger asChild>
                <Button>
                  <UserPlus className="h-4 w-4 mr-2" />
                  Invite Member
                </Button>
              </DialogTrigger>
              <DialogContent>
                <DialogHeader>
                  <DialogTitle>Invite Member</DialogTitle>
                  <DialogDescription>
                    Send an invitation to a team member. They must have an account to be added.
                  </DialogDescription>
                </DialogHeader>
                <Form {...form}>
                  <form onSubmit={form.handleSubmit(onInviteSubmit)} className="space-y-4">
                    <FormField
                      control={form.control}
                      name="email"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Email</FormLabel>
                          <FormControl>
                            <Input placeholder="team@example.com" {...field} />
                          </FormControl>
                          <FormDescription>The email address of the person you want to invite</FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <FormField
                      control={form.control}
                      name="role"
                      render={({ field }) => (
                        <FormItem>
                          <FormLabel>Role</FormLabel>
                          <Select onValueChange={field.onChange} defaultValue={field.value}>
                            <FormControl>
                              <SelectTrigger>
                                <SelectValue placeholder="Select a role" />
                              </SelectTrigger>
                            </FormControl>
                            <SelectContent>
                              <SelectItem value="admin">Admin</SelectItem>
                              <SelectItem value="developer">Developer</SelectItem>
                              <SelectItem value="viewer">Viewer</SelectItem>
                            </SelectContent>
                          </Select>
                          <FormDescription>
                            {roleDescriptions[field.value as keyof typeof roleDescriptions]}
                          </FormDescription>
                          <FormMessage />
                        </FormItem>
                      )}
                    />

                    <div className="flex justify-end gap-2">
                      <Button type="button" variant="outline" onClick={() => setInviteOpen(false)}>
                        Cancel
                      </Button>
                      <SubmitButton type="submit" isLoading={invite.isPending} loadingText="Inviting...">
                        Invite
                      </SubmitButton>
                    </div>
                  </form>
                </Form>
              </DialogContent>
            </Dialog>
          )
        }
      />

      {!owner && regularMembers.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No members"
          description="Add team members to collaborate on this app."
          action={
            canManageMembers
              ? {
                  label: 'Invite Member',
                  onClick: () => setInviteOpen(true),
                }
              : undefined
          }
        />
      ) : (
        <Card>
          <CardHeader>
            <CardTitle>Team Members</CardTitle>
            <CardDescription>
              {(owner ? 1 : 0) + regularMembers.length} member{(owner ? 1 : 0) + regularMembers.length !== 1 ? 's' : ''}{' '}
              with access to this app
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Member</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead className="w-[100px]" />
                </TableRow>
              </TableHeader>
              <TableBody>
                {/* Owner row */}
                {owner && (
                  <TableRow key="owner">
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <Avatar className="h-8 w-8">
                          <AvatarFallback>
                            {owner.name?.[0]?.toUpperCase() || owner.email?.[0]?.toUpperCase() || '?'}
                          </AvatarFallback>
                        </Avatar>
                        <div>
                          <p className="font-medium">{owner.name || 'Unknown'}</p>
                          <p className="text-sm text-muted-foreground">{owner.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={roleBadgeVariant.owner}>owner</Badge>
                    </TableCell>
                    <TableCell />
                  </TableRow>
                )}
                {/* Regular member rows */}
                {regularMembers.map((member) => (
                  <TableRow key={member.id}>
                    <TableCell>
                      <div className="flex items-center gap-3">
                        <Avatar className="h-8 w-8">
                          <AvatarFallback>
                            {member.name?.[0]?.toUpperCase() || member.email?.[0]?.toUpperCase() || '?'}
                          </AvatarFallback>
                        </Avatar>
                        <div>
                          <p className="font-medium">{member.name || 'Unknown'}</p>
                          <p className="text-sm text-muted-foreground">{member.email}</p>
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge variant={roleBadgeVariant[member.role as keyof typeof roleBadgeVariant]}>
                        {member.role}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      {canManageMembers && (
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon">
                              <MoreHorizontal className="h-4 w-4" />
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => handleRoleChange(member.id, member.role, 'admin')}
                              disabled={member.role === 'admin'}
                            >
                              Make Admin
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => handleRoleChange(member.id, member.role, 'developer')}
                              disabled={member.role === 'developer'}
                            >
                              Make Developer
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              onClick={() => handleRoleChange(member.id, member.role, 'viewer')}
                              disabled={member.role === 'viewer'}
                            >
                              Make Viewer
                            </DropdownMenuItem>
                            <DropdownMenuSeparator />
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() =>
                                setMemberToRemove({ id: member.id, name: member.name || member.email || 'Unknown' })
                              }
                            >
                              Remove
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

      {/* Role Change Confirmation */}
      <ConfirmDialog
        open={!!roleChangeDialog}
        onOpenChange={() => setRoleChangeDialog(null)}
        title="Change Role"
        description={`Are you sure you want to change this member's role from ${roleChangeDialog?.currentRole} to ${roleChangeDialog?.newRole}?`}
        confirmLabel="Change Role"
        onConfirm={confirmRoleChange}
      />

      {/* Remove Member Confirmation */}
      <ConfirmDialog
        open={!!memberToRemove}
        onOpenChange={() => setMemberToRemove(null)}
        title="Remove Member"
        description={`Are you sure you want to remove ${memberToRemove?.name} from this app? They will lose all access.`}
        confirmLabel="Remove"
        variant="destructive"
        onConfirm={handleRemove}
      />
    </div>
  )
}
