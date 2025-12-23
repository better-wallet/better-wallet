# Node.js Integration Guide

Complete guide to integrating Better Wallet with Node.js applications.

## Overview

This guide covers integrating Better Wallet with Node.js backends using:
- Express.js API server
- Authorization signature generation
- Webhook handling

## Prerequisites

- Node.js 18+
- Better Wallet instance running
- JWT tokens from your auth provider

## Installation

```bash
npm install express jsonwebtoken crypto
# or
yarn add express jsonwebtoken crypto
```

---

## Client Library

### Basic Client

```typescript
// lib/better-wallet-client.ts
import crypto from 'crypto';

interface BetterWalletConfig {
  baseUrl: string;
  appId: string;
  appSecret: string;
}

interface RequestOptions {
  method: string;
  body?: any;
  userToken: string;
  idempotencyKey?: string;
  authSignature?: {
    signature: string;
    keyId: string;
  };
}

export class BetterWalletClient {
  private config: BetterWalletConfig;

  constructor(config: BetterWalletConfig) {
    this.config = config;
  }

  async request<T>(path: string, options: RequestOptions): Promise<T> {
    const headers: Record<string, string> = {
      'X-App-Id': this.config.appId,
      'X-App-Secret': this.config.appSecret,
      'Authorization': `Bearer ${options.userToken}`,
      'Content-Type': 'application/json',
    };

    if (options.idempotencyKey) {
      headers['X-Idempotency-Key'] = options.idempotencyKey;
    }

    if (options.authSignature) {
      headers['X-Authorization-Signature'] = options.authSignature.signature;
      headers['X-Authorization-Key-Id'] = options.authSignature.keyId;
    }

    const response = await fetch(`${this.config.baseUrl}${path}`, {
      method: options.method,
      headers,
      body: options.body ? JSON.stringify(options.body) : undefined,
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({}));
      throw new BetterWalletError(
        error.error?.message || 'Request failed',
        response.status,
        error.error?.code
      );
    }

    if (response.status === 204) {
      return {} as T;
    }

    return response.json();
  }

  // Wallet operations
  async createWallet(userToken: string, options: {
    chainType?: string;
    execBackend?: string;
    ownerId?: string;
  } = {}) {
    return this.request('/v1/wallets', {
      method: 'POST',
      userToken,
      idempotencyKey: crypto.randomUUID(),
      body: {
        chain_type: options.chainType || 'ethereum',
        exec_backend: options.execBackend || 'kms',
        owner_id: options.ownerId,
      },
    });
  }

  async getWallet(userToken: string, walletId: string) {
    return this.request(`/v1/wallets/${walletId}`, {
      method: 'GET',
      userToken,
    });
  }

  async listWallets(userToken: string, params?: {
    chainType?: string;
    limit?: number;
    offset?: number;
  }) {
    const query = new URLSearchParams();
    if (params?.chainType) query.set('chain_type', params.chainType);
    if (params?.limit) query.set('limit', String(params.limit));
    if (params?.offset) query.set('offset', String(params.offset));

    const path = `/v1/wallets${query.toString() ? '?' + query : ''}`;
    return this.request(path, { method: 'GET', userToken });
  }

  async signTransaction(
    userToken: string,
    walletId: string,
    tx: {
      to: string;
      value: string;
      chainId: number;
      nonce: number;
      gasLimit: number;
      gasFeeСap: string;
      gasTipCap: string;
      data?: string;
    },
    authSignature?: { signature: string; keyId: string }
  ) {
    return this.request(`/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      userToken,
      idempotencyKey: crypto.randomUUID(),
      body: {
        jsonrpc: '2.0',
        method: 'eth_sendTransaction',
        params: [{
          to: tx.to,
          value: tx.value,
          chain_id: tx.chainId,
          nonce: tx.nonce,
          gas_limit: tx.gasLimit,
          max_fee_per_gas: tx.gasFeeСap,
          max_priority_fee_per_gas: tx.gasTipCap,
          data: tx.data || '',
        }],
        id: 1,
      },
      authSignature,
    });
  }

  async signMessage(
    userToken: string,
    walletId: string,
    message: string,
    authSignature?: { signature: string; keyId: string }
  ) {
    return this.request(`/v1/wallets/${walletId}/rpc`, {
      method: 'POST',
      userToken,
      body: {
        jsonrpc: '2.0',
        method: 'personal_sign',
        params: [{ message }],
        id: 1,
      },
      authSignature,
    });
  }

  // Policy operations
  async createPolicy(userToken: string, policy: {
    name: string;
    chainType: string;
    rules: any;
    ownerId?: string;
  }) {
    return this.request('/v1/policies', {
      method: 'POST',
      userToken,
      idempotencyKey: crypto.randomUUID(),
      body: {
        name: policy.name,
        chain_type: policy.chainType,
        rules: policy.rules,
        owner_id: policy.ownerId,
      },
    });
  }

  // Authorization key operations
  async registerAuthorizationKey(userToken: string, key: {
    publicKey: string;
    algorithm: string;
    ownerEntity?: string;
  }) {
    return this.request('/v1/authorization-keys', {
      method: 'POST',
      userToken,
      idempotencyKey: crypto.randomUUID(),
      body: {
        public_key: key.publicKey,
        algorithm: key.algorithm,
        owner_entity: key.ownerEntity,
      },
    });
  }
}

export class BetterWalletError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public code?: string
  ) {
    super(message);
    this.name = 'BetterWalletError';
  }
}
```

---

## Authorization Signatures

### Signature Generation

```typescript
// lib/auth-signature.ts
import crypto from 'crypto';

interface SignaturePayload {
  version: string;
  method: string;
  path: string;
  body: object;
  appId: string;
  idempotencyKey: string;
}

/**
 * Create canonical JSON following RFC 8785
 */
function canonicalizeJson(obj: object): string {
  return JSON.stringify(obj, Object.keys(obj).sort());
}

/**
 * Build the canonical payload for signing
 */
export function buildCanonicalPayload(payload: SignaturePayload): string {
  const canonicalBody = canonicalizeJson(payload.body);
  return `${payload.version}${payload.method}${payload.path}${canonicalBody}${payload.appId}${payload.idempotencyKey}`;
}

/**
 * Sign a payload with a P-256 private key
 */
export function signPayload(
  payload: string,
  privateKeyPem: string
): string {
  const sign = crypto.createSign('SHA256');
  sign.update(payload);
  sign.end();

  const signature = sign.sign(privateKeyPem);
  return signature.toString('base64');
}

/**
 * Generate a P-256 key pair
 */
export function generateKeyPair(): {
  privateKey: string;
  publicKey: string;
  publicKeyBase64: string;
} {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: 'prime256v1',
  });

  const privateKeyPem = privateKey.export({
    type: 'sec1',
    format: 'pem',
  }) as string;

  const publicKeyPem = publicKey.export({
    type: 'spki',
    format: 'pem',
  }) as string;

  // Export raw public key bytes for registration
  const publicKeyDer = publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const publicKeyBytes = publicKeyDer.slice(-65); // Last 65 bytes
  const publicKeyBase64 = publicKeyBytes.toString('base64');

  return {
    privateKey: privateKeyPem,
    publicKey: publicKeyPem,
    publicKeyBase64,
  };
}

/**
 * Create authorization signature for a request
 */
export function createAuthSignature(
  method: string,
  path: string,
  body: object,
  appId: string,
  idempotencyKey: string,
  privateKeyPem: string
): string {
  const payload = buildCanonicalPayload({
    version: '1.0',
    method,
    path,
    body,
    appId,
    idempotencyKey,
  });

  return signPayload(payload, privateKeyPem);
}
```

### Using Authorization Signatures

```typescript
// Example: Sign a high-risk operation
import { createAuthSignature, generateKeyPair } from './lib/auth-signature';

// Generate a key pair (do this once, store securely)
const keyPair = generateKeyPair();
console.log('Public Key (for registration):', keyPair.publicKeyBase64);
// Store privateKey securely

// Register the public key with Better Wallet
const authKey = await client.registerAuthorizationKey(userToken, {
  publicKey: keyPair.publicKeyBase64,
  algorithm: 'p256',
  ownerEntity: 'my-backend-server',
});

// Later: Sign a transaction with authorization
const idempotencyKey = crypto.randomUUID();
const rpcBody = {
  jsonrpc: '2.0',
  method: 'eth_sendTransaction',
  params: [{
    to: '0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb',
    value: '0xde0b6b3a7640000', // 1 ETH in hex
    chain_id: 1,
    nonce: '0x0',
    gas_limit: '0x5208',
    max_fee_per_gas: '0x6fc23ac00',
    max_priority_fee_per_gas: '0x77359400',
  }],
  id: 1,
};

const signature = createAuthSignature(
  'POST',
  `/v1/wallets/${walletId}/rpc`,
  rpcBody,
  APP_ID,
  idempotencyKey,
  keyPair.privateKey
);

const result = await client.signTransaction(
  userToken,
  walletId,
  rpcBody.params[0],
  { signature, keyId: authKey.id }
);
```

---

## Express.js Integration

### Server Setup

```typescript
// server.ts
import express from 'express';
import { BetterWalletClient } from './lib/better-wallet-client';
import { verifyJwt } from './lib/jwt';

const app = express();
app.use(express.json());

const betterWallet = new BetterWalletClient({
  baseUrl: process.env.BETTER_WALLET_URL!,
  appId: process.env.BETTER_WALLET_APP_ID!,
  appSecret: process.env.BETTER_WALLET_APP_SECRET!,
});

// JWT middleware
async function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ error: 'Missing authorization token' });
  }

  try {
    const decoded = await verifyJwt(token);
    req.user = decoded;
    req.userToken = token;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
}

// Wallet routes
app.get('/api/wallets', authMiddleware, async (req, res) => {
  try {
    const wallets = await betterWallet.listWallets(req.userToken);
    res.json(wallets);
  } catch (error) {
    console.error('Failed to list wallets:', error);
    res.status(error.statusCode || 500).json({
      error: error.message,
    });
  }
});

app.post('/api/wallets', authMiddleware, async (req, res) => {
  try {
    const wallet = await betterWallet.createWallet(req.userToken, {
      chainType: req.body.chainType,
    });
    res.status(201).json(wallet);
  } catch (error) {
    console.error('Failed to create wallet:', error);
    res.status(error.statusCode || 500).json({
      error: error.message,
    });
  }
});

app.get('/api/wallets/:id', authMiddleware, async (req, res) => {
  try {
    const wallet = await betterWallet.getWallet(
      req.userToken,
      req.params.id
    );
    res.json(wallet);
  } catch (error) {
    console.error('Failed to get wallet:', error);
    res.status(error.statusCode || 500).json({
      error: error.message,
    });
  }
});

// JSON-RPC endpoint for all signing operations
app.post('/api/wallets/:id/rpc', authMiddleware, async (req, res) => {
  try {
    // Proxy the JSON-RPC request to Better Wallet
    const result = await betterWallet.request(`/v1/wallets/${req.params.id}/rpc`, {
      method: 'POST',
      userToken: req.userToken,
      body: req.body, // JSON-RPC format: { jsonrpc, method, params, id }
    });
    res.json(result);
  } catch (error) {
    console.error('RPC request failed:', error);
    res.status(error.statusCode || 500).json({
      error: error.message,
    });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

---

## Error Handling

### Retry Logic

```typescript
// lib/retry.ts
interface RetryOptions {
  maxRetries: number;
  baseDelay: number;
  maxDelay: number;
}

const defaultOptions: RetryOptions = {
  maxRetries: 3,
  baseDelay: 1000,
  maxDelay: 10000,
};

export async function withRetry<T>(
  fn: () => Promise<T>,
  options: Partial<RetryOptions> = {}
): Promise<T> {
  const { maxRetries, baseDelay, maxDelay } = { ...defaultOptions, ...options };

  let lastError: Error;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error as Error;

      // Don't retry client errors (4xx)
      if (error instanceof BetterWalletError && error.statusCode < 500) {
        throw error;
      }

      if (attempt < maxRetries) {
        const delay = Math.min(
          baseDelay * Math.pow(2, attempt),
          maxDelay
        );
        await sleep(delay);
      }
    }
  }

  throw lastError!;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Usage
const wallet = await withRetry(
  () => betterWallet.createWallet(userToken),
  { maxRetries: 3 }
);
```

---

## Testing

### Unit Tests

```typescript
// __tests__/better-wallet-client.test.ts
import { BetterWalletClient } from '../lib/better-wallet-client';

// Mock fetch
global.fetch = jest.fn();

describe('BetterWalletClient', () => {
  let client: BetterWalletClient;

  beforeEach(() => {
    client = new BetterWalletClient({
      baseUrl: 'http://localhost:8080',
      appId: 'test-app-id',
      appSecret: 'test-app-secret',
    });
    (fetch as jest.Mock).mockClear();
  });

  describe('createWallet', () => {
    it('should create a wallet', async () => {
      const mockWallet = {
        id: 'wallet-id',
        address: '0x123...',
        chain_type: 'ethereum',
      };

      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: true,
        json: () => Promise.resolve(mockWallet),
      });

      const result = await client.createWallet('user-token');

      expect(result).toEqual(mockWallet);
      expect(fetch).toHaveBeenCalledWith(
        'http://localhost:8080/v1/wallets',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            'X-App-Id': 'test-app-id',
            'Authorization': 'Bearer user-token',
          }),
        })
      );
    });

    it('should throw on error', async () => {
      (fetch as jest.Mock).mockResolvedValueOnce({
        ok: false,
        status: 400,
        json: () => Promise.resolve({
          error: { message: 'Invalid request', code: 'invalid_request' },
        }),
      });

      await expect(client.createWallet('user-token'))
        .rejects
        .toThrow('Invalid request');
    });
  });
});
```

### Integration Tests

```typescript
// __tests__/integration/wallets.test.ts
import { BetterWalletClient } from '../../lib/better-wallet-client';

describe('Wallet Integration', () => {
  let client: BetterWalletClient;
  let testUserToken: string;

  beforeAll(async () => {
    client = new BetterWalletClient({
      baseUrl: process.env.BETTER_WALLET_URL!,
      appId: process.env.BETTER_WALLET_APP_ID!,
      appSecret: process.env.BETTER_WALLET_APP_SECRET!,
    });

    // Get a test token from your auth provider
    testUserToken = await getTestUserToken();
  });

  it('should create and list wallets', async () => {
    // Create a wallet
    const created = await client.createWallet(testUserToken);
    expect(created.address).toMatch(/^0x/);

    // List wallets
    const list = await client.listWallets(testUserToken);
    expect(list.wallets.some(w => w.id === created.id)).toBe(true);
  });

  it('should sign a message', async () => {
    const wallets = await client.listWallets(testUserToken);
    const wallet = wallets.wallets[0];

    const result = await client.signMessage(
      testUserToken,
      wallet.id,
      'Hello, World!'
    );

    expect(result.signature).toMatch(/^0x/);
  });
});
```

---

## Production Considerations

### Environment Variables

```bash
# .env.production
BETTER_WALLET_URL=https://better-wallet.internal:8080
BETTER_WALLET_APP_ID=prod-app-id
BETTER_WALLET_APP_SECRET=prod-app-secret
NODE_ENV=production
```

### Logging

```typescript
// lib/logger.ts
import pino from 'pino';

export const logger = pino({
  level: process.env.LOG_LEVEL || 'info',
  transport: process.env.NODE_ENV !== 'production'
    ? { target: 'pino-pretty' }
    : undefined,
});

// Usage in client
logger.info({ walletId }, 'Creating wallet');
logger.error({ error, walletId }, 'Failed to sign transaction');
```

### Health Checks

```typescript
app.get('/health', async (req, res) => {
  try {
    // Check Better Wallet connectivity
    const response = await fetch(`${process.env.BETTER_WALLET_URL}/health`);
    const healthy = response.ok;

    res.status(healthy ? 200 : 503).json({
      status: healthy ? 'ok' : 'unhealthy',
      betterWallet: healthy,
    });
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      betterWallet: false,
    });
  }
});
```
