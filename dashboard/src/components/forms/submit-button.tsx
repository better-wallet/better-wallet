'use client'

import type { VariantProps } from 'class-variance-authority'
import { Loader2 } from 'lucide-react'
import { Button, type buttonVariants } from '@/components/ui/button'

interface SubmitButtonProps extends React.ComponentProps<'button'>, VariantProps<typeof buttonVariants> {
  isLoading?: boolean
  loadingText?: string
  asChild?: boolean
}

export function SubmitButton({ children, isLoading, loadingText, disabled, ...props }: SubmitButtonProps) {
  return (
    <Button disabled={disabled || isLoading} {...props}>
      {isLoading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
      {isLoading && loadingText ? loadingText : children}
    </Button>
  )
}
