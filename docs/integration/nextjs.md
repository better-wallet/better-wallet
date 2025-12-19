# Next.js Integration Guide

Complete guide to integrating Better Wallet with Next.js applications.

## Overview

This guide covers integrating Better Wallet with Next.js using:
- Server-side API routes (App Router)
- Client-side wallet management
- Authentication with popular providers

## Prerequisites

- Next.js 14+ with App Router
- An authentication provider (Auth0, Clerk, etc.)
- Better Wallet instance running

## Project Setup

### Installation

```bash
# Create new Next.js project
npx create-next-app@latest my-wallet-app
cd my-wallet-app

# Install dependencies
npm install @auth0/nextjs-auth0  # or your auth provider
```

### Environment Variables

```bash
# .env.local
BETTER_WALLET_URL=http://localhost:8080
BETTER_WALLET_APP_ID=your-app-id
BETTER_WALLET_APP_SECRET=your-app-secret

# Auth0 (example)
AUTH0_SECRET=your-auth0-secret
AUTH0_BASE_URL=http://localhost:3000
AUTH0_ISSUER_BASE_URL=https://your-domain.auth0.com
AUTH0_CLIENT_ID=your-client-id
AUTH0_CLIENT_SECRET=your-client-secret
AUTH0_AUDIENCE=https://api.yourapp.com
```

---

## Server-Side Integration

### API Client

Create a Better Wallet client for server-side use:

```typescript
// lib/better-wallet.ts
import { getAccessToken } from '@auth0/nextjs-auth0';

const BETTER_WALLET_URL = process.env.BETTER_WALLET_URL!;
const APP_ID = process.env.BETTER_WALLET_APP_ID!;
const APP_SECRET = process.env.BETTER_WALLET_APP_SECRET!;

export class BetterWalletClient {
  private baseUrl: string;
  private appId: string;
  private appSecret: string;

  constructor() {
    this.baseUrl = BETTER_WALLET_URL;
    this.appId = APP_ID;
    this.appSecret = APP_SECRET;
  }

  async request<T>(
    path: string,
    options: RequestInit & { userToken: string }
  ): Promise<T> {
    const { userToken, ...fetchOptions } = options;

    const response = await fetch(`${this.baseUrl}${path}`, {
      ...fetchOptions,
      headers: {
        ...fetchOptions.headers,
        'X-App-Id': this.appId,
        'X-App-Secret': this.appSecret,
        'Authorization': `Bearer ${userToken}`,
        'Content-Type': 'application/json',
      },
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error?.message || 'API request failed');
    }

    return response.json();
  }

  // Wallet operations
  async createWallet(userToken: string, chainType: string = 'ethereum') {
    return this.request('/v1/wallets', {
      method: 'POST',
      body: JSON.stringify({ chain_type: chainType, exec_backend: 'kms' }),
      userToken,
    });
  }

  async listWallets(userToken: string) {
    return this.request('/v1/wallets', {
      method: 'GET',
      userToken,
    });
  }

  async signTransaction(
    userToken: string,
    walletId: string,
    transaction: {
      to: string;
      value: string;
      chainId: number;
      nonce: number;
      gasLimit: number;
      gasFeeСap: string;
      gasTipCap: string;
      data?: string;
    }
  ) {
    return this.request(`/v1/wallets/${walletId}/sign`, {
      method: 'POST',
      body: JSON.stringify({
        to: transaction.to,
        value: transaction.value,
        chain_id: transaction.chainId,
        nonce: transaction.nonce,
        gas_limit: transaction.gasLimit,
        gas_fee_cap: transaction.gasFeeСap,
        gas_tip_cap: transaction.gasTipCap,
        data: transaction.data || '',
      }),
      userToken,
    });
  }

  async signMessage(userToken: string, walletId: string, message: string) {
    return this.request(`/v1/wallets/${walletId}/sign-message`, {
      method: 'POST',
      body: JSON.stringify({ message }),
      userToken,
    });
  }
}

export const betterWallet = new BetterWalletClient();
```

### API Routes (App Router)

Create API routes to proxy requests:

```typescript
// app/api/wallets/route.ts
import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';
import { NextResponse } from 'next/server';
import { betterWallet } from '@/lib/better-wallet';

export const GET = withApiAuthRequired(async function handler(req) {
  try {
    const { accessToken } = await getAccessToken();
    const wallets = await betterWallet.listWallets(accessToken!);
    return NextResponse.json(wallets);
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message },
      { status: 500 }
    );
  }
});

export const POST = withApiAuthRequired(async function handler(req) {
  try {
    const { accessToken } = await getAccessToken();
    const body = await req.json();
    const wallet = await betterWallet.createWallet(
      accessToken!,
      body.chainType
    );
    return NextResponse.json(wallet, { status: 201 });
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message },
      { status: 500 }
    );
  }
});
```

```typescript
// app/api/wallets/[id]/sign/route.ts
import { getAccessToken, withApiAuthRequired } from '@auth0/nextjs-auth0';
import { NextResponse } from 'next/server';
import { betterWallet } from '@/lib/better-wallet';

export const POST = withApiAuthRequired(async function handler(
  req,
  { params }
) {
  try {
    const { accessToken } = await getAccessToken();
    const body = await req.json();
    const { id } = params;

    const result = await betterWallet.signTransaction(
      accessToken!,
      id,
      body
    );
    return NextResponse.json(result);
  } catch (error: any) {
    return NextResponse.json(
      { error: error.message },
      { status: 500 }
    );
  }
});
```

---

## Client-Side Integration

### React Hooks

Create custom hooks for wallet operations:

```typescript
// hooks/useWallets.ts
'use client';

import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then(res => res.json());

export function useWallets() {
  const { data, error, isLoading, mutate } = useSWR('/api/wallets', fetcher);

  const createWallet = async (chainType: string = 'ethereum') => {
    const response = await fetch('/api/wallets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chainType }),
    });

    if (!response.ok) {
      throw new Error('Failed to create wallet');
    }

    const wallet = await response.json();
    mutate(); // Refresh wallet list
    return wallet;
  };

  return {
    wallets: data?.wallets || [],
    isLoading,
    error,
    createWallet,
    refresh: mutate,
  };
}
```

```typescript
// hooks/useWallet.ts
'use client';

import useSWR from 'swr';

const fetcher = (url: string) => fetch(url).then(res => res.json());

export function useWallet(walletId: string) {
  const { data, error, isLoading } = useSWR(
    walletId ? `/api/wallets/${walletId}` : null,
    fetcher
  );

  const signTransaction = async (transaction: {
    to: string;
    value: string;
    chainId: number;
    nonce: number;
    gasLimit: number;
    gasFeeСap: string;
    gasTipCap: string;
  }) => {
    const response = await fetch(`/api/wallets/${walletId}/sign`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(transaction),
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.error || 'Failed to sign transaction');
    }

    return response.json();
  };

  const signMessage = async (message: string) => {
    const response = await fetch(`/api/wallets/${walletId}/sign-message`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message }),
    });

    if (!response.ok) {
      throw new Error('Failed to sign message');
    }

    return response.json();
  };

  return {
    wallet: data,
    isLoading,
    error,
    signTransaction,
    signMessage,
  };
}
```

### Components

```tsx
// components/WalletList.tsx
'use client';

import { useWallets } from '@/hooks/useWallets';
import { useState } from 'react';

export function WalletList() {
  const { wallets, isLoading, createWallet } = useWallets();
  const [creating, setCreating] = useState(false);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await createWallet('ethereum');
    } catch (error) {
      console.error('Failed to create wallet:', error);
    } finally {
      setCreating(false);
    }
  };

  if (isLoading) {
    return <div>Loading wallets...</div>;
  }

  return (
    <div>
      <h2>Your Wallets</h2>

      <button onClick={handleCreate} disabled={creating}>
        {creating ? 'Creating...' : 'Create Wallet'}
      </button>

      <ul>
        {wallets.map((wallet: any) => (
          <li key={wallet.id}>
            <code>{wallet.address}</code>
            <span>{wallet.chain_type}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
```

```tsx
// components/SignTransaction.tsx
'use client';

import { useWallet } from '@/hooks/useWallet';
import { useState } from 'react';

interface Props {
  walletId: string;
}

export function SignTransaction({ walletId }: Props) {
  const { wallet, signTransaction } = useWallet(walletId);
  const [to, setTo] = useState('');
  const [value, setValue] = useState('');
  const [signing, setSigning] = useState(false);
  const [result, setResult] = useState<any>(null);

  const handleSign = async (e: React.FormEvent) => {
    e.preventDefault();
    setSigning(true);

    try {
      const signed = await signTransaction({
        to,
        value,
        chainId: 1,
        nonce: 0, // Should fetch actual nonce
        gasLimit: 21000,
        gasFeeСap: '30000000000',
        gasTipCap: '2000000000',
      });
      setResult(signed);
    } catch (error) {
      console.error('Signing failed:', error);
    } finally {
      setSigning(false);
    }
  };

  return (
    <form onSubmit={handleSign}>
      <h3>Sign Transaction</h3>

      <div>
        <label>To Address</label>
        <input
          type="text"
          value={to}
          onChange={(e) => setTo(e.target.value)}
          placeholder="0x..."
        />
      </div>

      <div>
        <label>Value (wei)</label>
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          placeholder="1000000000000000000"
        />
      </div>

      <button type="submit" disabled={signing}>
        {signing ? 'Signing...' : 'Sign Transaction'}
      </button>

      {result && (
        <div>
          <h4>Signed Transaction</h4>
          <pre>{JSON.stringify(result, null, 2)}</pre>
        </div>
      )}
    </form>
  );
}
```

---

## Page Examples

### Dashboard Page

```tsx
// app/dashboard/page.tsx
import { getSession } from '@auth0/nextjs-auth0';
import { redirect } from 'next/navigation';
import { WalletList } from '@/components/WalletList';

export default async function DashboardPage() {
  const session = await getSession();

  if (!session) {
    redirect('/api/auth/login');
  }

  return (
    <main>
      <h1>Dashboard</h1>
      <p>Welcome, {session.user.email}</p>
      <WalletList />
    </main>
  );
}
```

### Wallet Detail Page

```tsx
// app/wallets/[id]/page.tsx
import { getSession, getAccessToken } from '@auth0/nextjs-auth0';
import { redirect, notFound } from 'next/navigation';
import { betterWallet } from '@/lib/better-wallet';
import { SignTransaction } from '@/components/SignTransaction';

interface Props {
  params: { id: string };
}

export default async function WalletPage({ params }: Props) {
  const session = await getSession();

  if (!session) {
    redirect('/api/auth/login');
  }

  const { accessToken } = await getAccessToken();

  try {
    const wallet = await betterWallet.request(`/v1/wallets/${params.id}`, {
      method: 'GET',
      userToken: accessToken!,
    });

    return (
      <main>
        <h1>Wallet Details</h1>
        <dl>
          <dt>Address</dt>
          <dd><code>{wallet.address}</code></dd>
          <dt>Chain</dt>
          <dd>{wallet.chain_type}</dd>
          <dt>Created</dt>
          <dd>{new Date(wallet.created_at).toLocaleString()}</dd>
        </dl>

        <SignTransaction walletId={params.id} />
      </main>
    );
  } catch (error) {
    notFound();
  }
}
```

---

## Error Handling

### Global Error Handler

```tsx
// app/error.tsx
'use client';

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <div>
      <h2>Something went wrong!</h2>
      <p>{error.message}</p>
      <button onClick={() => reset()}>Try again</button>
    </div>
  );
}
```

### API Error Handling

```typescript
// lib/api-error.ts
export class ApiError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code?: string
  ) {
    super(message);
    this.name = 'ApiError';
  }
}

export function handleApiError(error: unknown) {
  if (error instanceof ApiError) {
    return { error: error.message, code: error.code };
  }

  return { error: 'An unexpected error occurred' };
}
```

---

## TypeScript Types

```typescript
// types/better-wallet.ts
export interface Wallet {
  id: string;
  user_id: string;
  chain_type: 'ethereum';
  exec_backend: 'kms' | 'tee';
  address: string;
  owner_id: string | null;
  created_at: string;
}

export interface SignedTransaction {
  signed_transaction: string;
  tx_hash: string;
}

export interface SignedMessage {
  signature: string;
}

export interface WalletListResponse {
  wallets: Wallet[];
  pagination: {
    total: number;
    limit: number;
    offset: number;
    has_more: boolean;
  };
}
```

---

## Best Practices

1. **Never expose app secrets** in client-side code
2. **Use API routes** as a proxy layer
3. **Implement proper error handling** with user-friendly messages
4. **Cache wallet data** with SWR or React Query
5. **Validate inputs** before sending to Better Wallet
6. **Log errors** server-side for debugging
7. **Use TypeScript** for type safety
