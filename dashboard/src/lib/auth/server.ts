import { headers } from 'next/headers'
import { auth } from './index'

export async function getSession() {
  const headersList = await headers()
  const session = await auth.api.getSession({
    headers: headersList,
  })
  return session
}

export async function requireAuth() {
  const session = await getSession()
  if (!session) {
    throw new Error('Unauthorized')
  }
  return session
}
