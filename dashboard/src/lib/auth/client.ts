import { createAuthClient } from 'better-auth/react'

export const authClient = createAuthClient({
  baseURL: process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000',
})

export const { signIn, signUp, signOut, useSession } = authClient

// User role type
export type UserRole = 'user' | 'provider'

// Helper to check if user is a provider/admin
export function isProvider(role?: string): boolean {
  return role === 'provider'
}
