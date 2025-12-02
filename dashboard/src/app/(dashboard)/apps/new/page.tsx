'use client'

import { zodResolver } from '@hookform/resolvers/zod'
import { useRouter } from 'next/navigation'
import { useForm } from 'react-hook-form'
import { toast } from 'sonner'
import { z } from 'zod'

import { SubmitButton } from '@/components/forms/submit-button'
import { PageHeader } from '@/components/layout/page-header'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { trpc } from '@/lib/trpc/client'

const formSchema = z.object({
  name: z.string().min(1, 'Name is required').max(100, 'Name is too long'),
  description: z.string().max(500, 'Description is too long').optional(),
})

type FormValues = z.infer<typeof formSchema>

export default function NewAppPage() {
  const router = useRouter()
  const utils = trpc.useUtils()

  const createApp = trpc.apps.create.useMutation({
    onSuccess: (app) => {
      toast.success('App created successfully')
      utils.apps.list.invalidate()
      router.push(`/apps/${app.id}`)
    },
    onError: (error) => {
      toast.error(error.message)
    },
  })

  const form = useForm<FormValues>({
    resolver: zodResolver(formSchema),
    defaultValues: {
      name: '',
      description: '',
    },
  })

  const onSubmit = (values: FormValues) => {
    createApp.mutate(values)
  }

  return (
    <div>
      <PageHeader title="Create App" description="Create a new application to manage wallets and policies" />

      <Card className="max-w-2xl">
        <CardHeader>
          <CardTitle>App Details</CardTitle>
          <CardDescription>Enter the basic information for your new app.</CardDescription>
        </CardHeader>
        <CardContent>
          <Form {...form}>
            <form onSubmit={form.handleSubmit(onSubmit)} className="space-y-6">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Name</FormLabel>
                    <FormControl>
                      <Input placeholder="My App" {...field} />
                    </FormControl>
                    <FormDescription>A unique name for your application.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="description"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Description</FormLabel>
                    <FormControl>
                      <Textarea placeholder="Describe what this app is for..." className="resize-none" {...field} />
                    </FormControl>
                    <FormDescription>Optional description to help identify this app.</FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <div className="flex gap-4">
                <SubmitButton type="submit" isLoading={createApp.isPending} loadingText="Creating...">
                  Create App
                </SubmitButton>
                <Button type="button" variant="outline" onClick={() => router.back()}>
                  Cancel
                </Button>
              </div>
            </form>
          </Form>
        </CardContent>
      </Card>
    </div>
  )
}
