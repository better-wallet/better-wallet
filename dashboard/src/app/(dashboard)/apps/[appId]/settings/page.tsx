'use client'

import { zodResolver } from '@hookform/resolvers/zod'
import { useParams, useRouter } from 'next/navigation'
import { useState } from 'react'
import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'
import { ErrorState } from '@/components/data/error-state'
import { ConfirmDialog } from '@/components/forms/confirm-dialog'
import { SubmitButton } from '@/components/forms/submit-button'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Skeleton } from '@/components/ui/skeleton'
import { Textarea } from '@/components/ui/textarea'
import { trpc } from '@/lib/trpc/client'
import type { AppSettings } from '@/server/db/schema'

const basicInfoSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name is too long'),
  description: z.string().max(500, 'Description is too long').optional(),
})

const authSettingsSchema = z.object({
  kind: z.enum(['oidc', 'jwt']),
  issuer: z.string().url('Must be a valid URL'),
  audience: z.string().min(1, 'Audience is required'),
  jwks_uri: z.string().url('Must be a valid URL'),
})

const rpcSettingsSchema = z.object({
  endpoints: z.string(), // JSON string for simplicity
})

type BasicInfoValues = z.infer<typeof basicInfoSchema>
type AuthSettingsValues = z.infer<typeof authSettingsSchema>

export default function AppSettingsPage() {
  const params = useParams()
  const router = useRouter()
  const appId = params.appId as string
  const [showDeleteDialog, setShowDeleteDialog] = useState(false)

  const utils = trpc.useUtils()
  const { data: app, isLoading, error, refetch } = trpc.apps.get.useQuery({ id: appId })

  const updateApp = trpc.apps.update.useMutation({
    onSuccess: () => {
      toast.success('App updated successfully')
      utils.apps.get.invalidate({ id: appId })
      utils.apps.list.invalidate()
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const updateSettings = trpc.apps.updateSettings.useMutation({
    onSuccess: () => {
      toast.success('Settings updated successfully')
      utils.apps.get.invalidate({ id: appId })
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const deleteApp = trpc.apps.delete.useMutation({
    onSuccess: () => {
      toast.success('App deleted successfully')
      utils.apps.list.invalidate()
      router.push('/apps')
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const basicInfoForm = useForm<BasicInfoValues>({
    resolver: zodResolver(basicInfoSchema),
    values: app
      ? {
          name: app.name,
          description: app.description || '',
        }
      : undefined,
  })

  // Cast settings to proper type
  const appSettings = app?.settings as AppSettings | undefined

  const authSettingsForm = useForm<AuthSettingsValues>({
    resolver: zodResolver(authSettingsSchema),
    values: appSettings?.auth
      ? {
          kind: appSettings.auth.kind,
          issuer: appSettings.auth.issuer,
          audience: appSettings.auth.audience,
          jwks_uri: appSettings.auth.jwks_uri,
        }
      : {
          kind: 'oidc',
          issuer: '',
          audience: '',
          jwks_uri: '',
        },
  })

  const onBasicInfoSubmit = (values: BasicInfoValues) => {
    updateApp.mutate({
      id: appId,
      ...values,
    })
  }

  const onAuthSettingsSubmit = (values: AuthSettingsValues) => {
    updateSettings.mutate({
      id: appId,
      settings: {
        ...(appSettings || {}),
        auth: values,
      },
    })
  }

  const handleDelete = async () => {
    await deleteApp.mutateAsync({ id: appId })
  }

  if (isLoading) {
    return (
      <div className="space-y-6">
        <PageHeader title="Settings" />
        <Card>
          <CardHeader>
            <Skeleton className="h-6 w-48" />
            <Skeleton className="h-4 w-64" />
          </CardHeader>
          <CardContent className="space-y-4">
            <Skeleton className="h-10 w-full" />
            <Skeleton className="h-20 w-full" />
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <PageHeader title="Settings" />
        <ErrorState message={error.message} onRetry={() => refetch()} />
      </div>
    )
  }

  if (!app) {
    return (
      <div className="space-y-6">
        <PageHeader title="Settings" />
        <ErrorState message="App not found" />
      </div>
    )
  }

  const isOwner = app.role === 'owner'

  return (
    <div className="space-y-6">
      <PageHeader title="Settings" description="Manage your app configuration" />

      {/* Basic Info */}
      <Card>
        <CardHeader>
          <CardTitle>Basic Information</CardTitle>
          <CardDescription>Update your app's name and description</CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...basicInfoForm}>
            <form onSubmit={basicInfoForm.handleSubmit(onBasicInfoSubmit)} className="space-y-4">
              <FormField
                control={basicInfoForm.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name</FormLabel>
                    <FormControl>
                      <Input {...field} disabled={!isOwner && app.role !== 'admin'} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={basicInfoForm.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea {...field} className="resize-none" disabled={!isOwner && app.role !== 'admin'} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              {(isOwner || app.role === 'admin') && (
                <SubmitButton type="submit" isLoading={updateApp.isPending} loadingText="Saving...">
                  Save Changes
                </SubmitButton>
              )}
            </form>
          </Form>
        </CardContent>
      </Card>

      {/* Auth Settings */}
      {(isOwner || app.role === 'admin') && (
        <Card>
          <CardHeader>
            <CardTitle>Authentication Settings</CardTitle>
            <CardDescription>Configure OIDC/JWT authentication for API access</CardDescription>
          </CardHeader>
          <CardContent>
            <Form {...authSettingsForm}>
              <form onSubmit={authSettingsForm.handleSubmit(onAuthSettingsSubmit)} className="space-y-4">
                <FormField
                  control={authSettingsForm.control}
                  name="kind"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Auth Type</FormLabel>
                      <FormControl>
                        <select
                          {...field}
                          className="flex h-10 w-full rounded-md border border-input bg-background px-3 py-2 text-sm ring-offset-background focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                        >
                          <option value="oidc">OIDC</option>
                          <option value="jwt">JWT</option>
                        </select>
                      </FormControl>
                      <FormDescription>Choose between OIDC discovery or manual JWT configuration</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={authSettingsForm.control}
                  name="issuer"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Issuer URL</FormLabel>
                      <FormControl>
                        <Input placeholder="https://auth.example.com" {...field} />
                      </FormControl>
                      <FormDescription>The issuer URL of your authentication provider</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={authSettingsForm.control}
                  name="audience"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>Audience</FormLabel>
                      <FormControl>
                        <Input placeholder="https://api.example.com" {...field} />
                      </FormControl>
                      <FormDescription>The expected audience claim in JWT tokens</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <FormField
                  control={authSettingsForm.control}
                  name="jwks_uri"
                  render={({ field }) => (
                    <FormItem>
                      <FormLabel>JWKS URI</FormLabel>
                      <FormControl>
                        <Input placeholder="https://auth.example.com/.well-known/jwks.json" {...field} />
                      </FormControl>
                      <FormDescription>URL to fetch JSON Web Key Set for token verification</FormDescription>
                      <FormMessage />
                    </FormItem>
                  )}
                />

                <SubmitButton type="submit" isLoading={updateSettings.isPending} loadingText="Saving...">
                  Save Auth Settings
                </SubmitButton>
              </form>
            </Form>
          </CardContent>
        </Card>
      )}

      {/* Danger Zone */}
      {isOwner && (
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive">Danger Zone</CardTitle>
            <CardDescription>Irreversible and destructive actions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium">Delete this app</p>
                <p className="text-sm text-muted-foreground">
                  Once deleted, all data associated with this app will be permanently removed.
                </p>
              </div>
              <Button variant="destructive" onClick={() => setShowDeleteDialog(true)}>
                Delete App
              </Button>
            </div>
          </CardContent>
        </Card>
      )}

      <ConfirmDialog
        open={showDeleteDialog}
        onOpenChange={setShowDeleteDialog}
        title="Delete App"
        description={`Are you sure you want to delete "${app.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="destructive"
        onConfirm={handleDelete}
      />
    </div>
  )
}
