/**
 * Database seed script for development
 *
 * Creates dev users and principals with pre-set data:
 * - dev@example.com (password: devpassword123) - regular user
 * - admin@example.com (password: adminpassword123) - admin user
 *
 * Run with: bun run db:seed
 */

import { eq } from 'drizzle-orm'
import { scrypt, randomBytes, randomUUID } from 'node:crypto'
import { promisify } from 'node:util'
import postgres from 'postgres'
import { drizzle } from 'drizzle-orm/postgres-js'
import { principals, agentWallets } from './schema'

const scryptAsync = promisify(scrypt)

// Hash password using scrypt (same as better-auth default)
async function hashPassword(password: string): Promise<string> {
  const salt = randomBytes(16).toString('hex')
  const derivedKey = (await scryptAsync(password, salt, 64)) as Buffer
  return `${salt}:${derivedKey.toString('hex')}`
}

function generateId(): string {
  return randomBytes(16).toString('hex')
}

// Generate a valid 40-character hex address (20 bytes)
function generateAddress(): string {
  return `0x${randomBytes(20).toString('hex')}`
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
  const connectionString = process.env.DATABASE_URL!
  const sql = postgres(connectionString)
  const db = drizzle(sql)

  console.log('Seeding development users...')

  // Better-auth creates its own user/account tables
  // We need to insert directly into those tables
  for (const devUser of devUsers) {
    // Check if user already exists in better-auth's user table
    const existingUsers = await sql`SELECT id, role FROM "user" WHERE email = ${devUser.email} LIMIT 1`

    let userId: string

    if (existingUsers.length > 0) {
      userId = existingUsers[0].id as string
      // Update role if needed
      if (existingUsers[0].role !== devUser.role) {
        await sql`UPDATE "user" SET role = ${devUser.role} WHERE id = ${userId}`
        console.log(`  Updated ${devUser.email} role to ${devUser.role}`)
      } else {
        console.log(`  ${devUser.email} already exists with correct role`)
      }
    } else {
      // Create new user in better-auth's user table
      userId = generateId()
      const hashedPassword = await hashPassword(devUser.password)

      await sql`
        INSERT INTO "user" (id, name, email, "emailVerified", role, "createdAt", "updatedAt")
        VALUES (${userId}, ${devUser.name}, ${devUser.email}, ${true}, ${devUser.role}, NOW(), NOW())
      `

      // Create account with password (for email/password login)
      await sql`
        INSERT INTO "account" (id, "accountId", "providerId", "userId", password, "createdAt", "updatedAt")
        VALUES (${generateId()}, ${userId}, ${'credential'}, ${userId}, ${hashedPassword}, NOW(), NOW())
      `

      console.log(`  Created auth user ${devUser.email} (${devUser.role})`)
    }

    // Now create/update principal for this user
    const existingPrincipal = await db
      .select()
      .from(principals)
      .where(eq(principals.email, devUser.email))
      .limit(1)

    if (existingPrincipal.length === 0) {
      const principalId = randomUUID()

      await db.insert(principals).values({
        id: principalId,
        name: devUser.name,
        email: devUser.email,
        emailVerified: true,
      })

      // Create a sample wallet for the principal
      await db.insert(agentWallets).values({
        id: randomUUID(),
        principalId: principalId,
        name: `${devUser.name}'s Wallet`,
        chainType: 'evm',
        address: generateAddress(),
        status: 'active',
      })

      console.log(`  Created principal and wallet for ${devUser.email}`)
    } else {
      console.log(`  Principal for ${devUser.email} already exists`)
    }
  }

  console.log('Done!')
  await sql.end()
}

seed()
  .catch((err) => {
    console.error('Seed failed:', err)
    process.exit(1)
  })
