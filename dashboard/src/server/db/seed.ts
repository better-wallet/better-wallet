/**
 * Database seed script for development
 *
 * Creates dev users with pre-set roles:
 * - dev@example.com (password: devpassword123) - regular user
 * - admin@example.com (password: adminpassword123) - admin/provider user
 *
 * Run with: bun run db:seed
 */

import { eq } from 'drizzle-orm'
import { db } from './index'
import { account, user } from './schema'

// Use scrypt for password hashing (same as better-auth default)
async function hashPassword(password: string): Promise<string> {
  const { scrypt, randomBytes } = await import('node:crypto')
  const { promisify } = await import('node:util')
  const scryptAsync = promisify(scrypt)

  const salt = randomBytes(16).toString('hex')
  const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer
  return `${salt}:${derivedKey.toString('hex')}`
}

function generateId(): string {
  const { randomBytes } = require('node:crypto')
  return randomBytes(16).toString('hex')
}

interface DevUser {
  name: string
  email: string
  password: string
  role: 'user' | 'provider'
}

const devUsers: DevUser[] = [
  {
    name: 'Dev User',
    email: 'dev@example.com',
    password: 'devpassword123',
    role: 'user',
  },
  {
    name: 'Admin User',
    email: 'admin@example.com',
    password: 'adminpassword123',
    role: 'provider',
  },
]

async function seed() {
  console.log('Seeding development users...')

  for (const devUser of devUsers) {
    // Check if user already exists
    const existing = await db.select().from(user).where(eq(user.email, devUser.email)).limit(1)

    if (existing.length > 0) {
      // Update role if needed
      if (existing[0].role !== devUser.role) {
        await db.update(user).set({ role: devUser.role }).where(eq(user.email, devUser.email))
        console.log(`  Updated ${devUser.email} role to ${devUser.role}`)
      } else {
        console.log(`  ${devUser.email} already exists with correct role`)
      }
      continue
    }

    // Create new user
    const userId = generateId()
    const hashedPassword = await hashPassword(devUser.password)

    await db.insert(user).values({
      id: userId,
      name: devUser.name,
      email: devUser.email,
      emailVerified: true,
      role: devUser.role,
    })

    // Create account with password (for email/password login)
    await db.insert(account).values({
      id: generateId(),
      accountId: userId,
      providerId: 'credential',
      userId: userId,
      password: hashedPassword,
    })

    console.log(`  Created ${devUser.email} (${devUser.role})`)
  }

  console.log('Done!')
}

seed()
  .catch((err) => {
    console.error('Seed failed:', err)
    process.exit(1)
  })
  .finally(() => {
    process.exit(0)
  })
