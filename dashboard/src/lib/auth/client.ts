import { createAuthClient } from 'better-auth/react'

function resolveAuthBaseURL(): string {
  // In dev, Next may auto-pick another port (3001, 3002, ...) if 3000 is busy.
  // Using the runtime origin avoids CORS/session issues when that happens.
  if (process.env.NODE_ENV === 'development' && typeof window !== 'undefined') {
    return window.location.origin
  }

  if (process.env.NEXT_PUBLIC_APP_URL) {
    return process.env.NEXT_PUBLIC_APP_URL
  }

  if (typeof window !== 'undefined') {
    return window.location.origin
  }

  return 'http://localhost:3000'
}

export const authClient = createAuthClient({
  baseURL: resolveAuthBaseURL(),
})

export const { signIn, signUp, signOut, useSession } = authClient

// User role type
export type UserRole = 'user' | 'provider'

// Helper to check if user is a provider/admin
export function isProvider(role?: string): boolean {
  return role === 'provider'
}
