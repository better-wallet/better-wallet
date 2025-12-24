'use client'

import { Camera, Loader2, Mail, Save, User } from 'lucide-react'
import { useState } from 'react'
import { toast } from 'sonner'

import { PageHeader } from '@/components/layout/page-header'
import { Avatar, AvatarFallback, AvatarImage } from '@/components/ui/avatar'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { Skeleton } from '@/components/ui/skeleton'
import { authClient, useSession } from '@/lib/auth/client'

export default function SettingsPage() {
  const { data: session, isPending: sessionLoading } = useSession()
  const [name, setName] = useState('')
  const [isEditing, setIsEditing] = useState(false)
  const [isSaving, setIsSaving] = useState(false)

  // Initialize name from session
  if (session?.user && !name && !isEditing) {
    setName(session.user.name)
  }

  const handleSave = async () => {
    if (!name.trim()) {
      toast.error('Name cannot be empty')
      return
    }

    setIsSaving(true)
    try {
      // Update user name using Better Auth client API
      const { error } = await authClient.updateUser({
        name: name.trim(),
      })

      if (error) {
        throw new Error(error.message || 'Failed to update profile')
      }

      toast.success('Profile updated')
      setIsEditing(false)
    } catch {
      toast.error('Failed to update profile')
    } finally {
      setIsSaving(false)
    }
  }

  if (sessionLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Settings" />
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-32" />
            <Skeleton className="h-4 w-48" />
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-20 w-20 rounded-full" />
            <Skeleton className="h-10 w-full max-w-md" />
            <Skeleton className="h-10 w-full max-w-md" />
          </CardContent>
        </Card>
      </div>
    )
  }

  const user = session?.user
  if (!user) {
    return null
  }

  const initials = user.name
    .split(' ')
    .map((n) => n[0])
    .join('')
    .toUpperCase()
    .slice(0, 2)

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Manage your account settings and preferences" />

      {/* Profile Section */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <User className="h-5 w-5" />
            Profile
          </CardTitle>
          <CardDescription>Your personal information</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {/* Avatar */}
          <div className="flex items-center gap-4">
            <Avatar className="h-20 w-20">
              <AvatarImage src={user.image || undefined} alt={user.name} />
              <AvatarFallback className="text-xl">{initials}</AvatarFallback>
            </Avatar>
            <div>
              <Button variant="outline" size="sm" disabled>
                <Camera className="h-4 w-4 mr-2" />
                Change Avatar
              </Button>
              <p className="text-xs text-muted-foreground mt-1">Coming soon</p>
            </div>
          </div>

          {/* Name */}
          <div className="space-y-2 max-w-md">
            <Label htmlFor="name">Name</Label>
            <div className="flex gap-2">
              <Input
                id="name"
                value={name}
                onChange={(e) => {
                  setName(e.target.value)
                  setIsEditing(true)
                }}
                placeholder="Your name"
              />
              {isEditing && (
                <Button onClick={handleSave} disabled={isSaving}>
                  {isSaving ? <Loader2 className="h-4 w-4 animate-spin" /> : <Save className="h-4 w-4" />}
                </Button>
              )}
            </div>
          </div>

          {/* Email (read-only) */}
          <div className="space-y-2 max-w-md">
            <Label htmlFor="email">Email</Label>
            <div className="flex items-center gap-2">
              <Mail className="h-4 w-4 text-muted-foreground" />
              <Input id="email" value={user.email} disabled className="bg-muted" />
            </div>
            <p className="text-xs text-muted-foreground">Email cannot be changed</p>
          </div>

          {/* User ID */}
          <div className="space-y-2 max-w-md">
            <Label>User ID</Label>
            <code className="block text-sm bg-muted px-3 py-2 rounded font-mono">{user.id}</code>
          </div>
        </CardContent>
      </Card>

      {/* Account Section */}
      <Card>
        <CardHeader>
          <CardTitle>Account</CardTitle>
          <CardDescription>Account management options</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center justify-between p-4 border rounded-lg">
            <div>
              <p className="font-medium">Role</p>
              <p className="text-sm text-muted-foreground">Your account type</p>
            </div>
            <code className="px-2 py-1 bg-muted rounded text-sm">{(user as { role?: string }).role || 'user'}</code>
          </div>

          <div className="flex items-center justify-between p-4 border rounded-lg border-destructive/20">
            <div>
              <p className="font-medium text-destructive">Delete Account</p>
              <p className="text-sm text-muted-foreground">Permanently delete your account and all data</p>
            </div>
            <Button variant="destructive" size="sm" disabled>
              Delete
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
