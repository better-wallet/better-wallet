# Architecture Overview

This document provides a deep dive into Better Wallet's system architecture, data flow, and design decisions.

## System Architecture

Better Wallet uses a **layered monolithic architecture** optimized for self-hosted deployments.

```
┌─────────────────────────────────────────────────────────────────────┐
│                        Client Applications                           │
│                    (Web, Mobile, Server, Bots)                       │
└─────────────────────────────────────────┬───────────────────────────┘
                                          │ HTTPS
┌─────────────────────────────────────────▼───────────────────────────┐
│                         Interface Layer                              │
│  ┌────────────┐  ┌────────────┐  ┌────────────┐  ┌────────────┐    │
│  │ App Auth   │  │ User Auth  │  │ Idempotency│  │  Logging   │    │
│  │ Middleware │  │ Middleware │  │ Middleware │  │            │    │
│  └────────────┘  └────────────┘  └────────────┘  └────────────┘    │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    HTTP Handlers                             │   │
│  │  /v1/wallets  /v1/policies  /v1/authorization-keys  ...     │   │
│  └─────────────────────────────────────────────────────────────┘   │
├─────────────────────────────────────────────────────────────────────┤
│                       Application Layer                              │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    Wallet Service                            │   │
│  │  • Wallet lifecycle management                               │   │
│  │  • Transaction orchestration                                 │   │
│  │  • Authorization verification                                │   │
│  │  • Session signer management                                 │   │
│  └─────────────────────────────────────────────────────────────┘   │
├───────────────────────────┬─────────────────────────────────────────┤
│      Policy Engine        │         Key Execution Layer             │
│  ┌───────────────────┐   │   ┌───────────────────────────────────┐ │
│  │ Rule Evaluator    │   │   │        Executor Interface         │ │
│  │ • Parse rules     │   │   │  ┌─────────────┐ ┌─────────────┐  │ │
│  │ • Match conditions│   │   │  │KMS Executor │ │TEE Executor │  │ │
│  │ • Return decision │   │   │  └─────────────┘ └─────────────┘  │ │
│  └───────────────────┘   │   │  ┌─────────────┐                  │ │
│  ┌───────────────────┐   │   │  │KMS Providers│                  │ │
│  │ Field Sources     │   │   │  │ • Local     │                  │ │
│  │ • Transaction     │   │   │  │ • AWS KMS   │                  │ │
│  │ • Calldata        │   │   │  │ • Vault     │                  │ │
│  │ • Typed Data      │   │   │  └─────────────┘                  │ │
│  │ • System          │   │   └───────────────────────────────────┘ │
│  └───────────────────┘   │                                         │
├───────────────────────────┴─────────────────────────────────────────┤
│                         Storage Layer                                │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │                    PostgreSQL Database                       │   │
│  │  users | wallets | wallet_shares | policies | audit_logs    │   │
│  │  authorization_keys | key_quorums | session_signers | ...   │   │
│  └─────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────┘
```

## Layer Responsibilities

### Interface Layer

**Purpose**: Handle incoming HTTP requests, authentication, and validation.

| Component | Responsibility |
|-----------|----------------|
| App Auth Middleware | Verify X-App-Id and X-App-Secret |
| User Auth Middleware | Validate JWT bearer tokens |
| Idempotency Middleware | Prevent duplicate write operations |
| Logging | Request/response logging with trace IDs |
| HTTP Handlers | Route requests to service methods |

**Does NOT**:
- Execute business logic
- Access keys or perform signing
- Evaluate policies

### Application Layer

**Purpose**: Orchestrate business operations and manage state.

| Component | Responsibility |
|-----------|----------------|
| Wallet Service | Wallet CRUD, signing orchestration |
| Authorization Verifier | Validate authorization signatures |
| Session Manager | Create, validate, revoke sessions |
| Audit Logger | Record all operations |

**Does NOT**:
- Hold or reconstruct private keys
- Parse policy rules (delegates to Policy Engine)
- Manage encryption (delegates to Key Execution)

### Policy Engine

**Purpose**: Evaluate access control rules and return decisions.

| Component | Responsibility |
|-----------|----------------|
| Rule Evaluator | Parse and match policy rules |
| Field Sources | Extract data from transactions |
| Operators | Compare values (eq, lt, in, etc.) |
| Condition Sets | Load reusable value sets |

**Does NOT**:
- Persist any state
- Perform signing operations
- Modify data

### Key Execution Layer

**Purpose**: Securely manage key material and perform cryptographic operations.

| Component | Responsibility |
|-----------|----------------|
| Executor Interface | Unified API for key operations |
| KMS Executor | Key operations via KMS providers |
| TEE Executor | Key operations via TEE enclaves |
| KMS Providers | Local, AWS KMS, Vault integration |

**Does NOT**:
- Contain business logic
- Access the database directly (uses Storage Layer)
- Evaluate policies

### Storage Layer

**Purpose**: Persist data to PostgreSQL using the repository pattern.

| Repository | Manages |
|------------|---------|
| UserRepo | User records |
| WalletRepo | Wallets and shares |
| PolicyRepo | Policies and wallet-policy links |
| AuthKeyRepo | Authorization keys |
| QuorumRepo | Key quorums |
| SessionRepo | Session signers |
| AuditRepo | Audit logs |

## Request Flow

### Transaction Signing Flow

```
1. Client Request
   │
   ▼
2. Interface Layer
   ├─ App Auth Middleware: Verify app credentials
   ├─ User Auth Middleware: Validate JWT
   ├─ Idempotency: Check for duplicate request
   │
   ▼
3. Application Layer (Wallet Service)
   ├─ Load wallet from database
   ├─ Verify user owns wallet OR has session signer
   ├─ Load applicable policies
   │
   ▼
4. Policy Engine
   ├─ Load condition sets (if referenced)
   ├─ Evaluate rules against transaction
   ├─ Return ALLOW or DENY with reason
   │
   ▼ (if ALLOW)
   │
5. Key Execution Layer
   ├─ Retrieve auth share (decrypt with KMS)
   ├─ Retrieve exec share from backend
   ├─ Reconstruct private key
   ├─ Sign transaction
   ├─ Clear key from memory
   │
   ▼
6. Application Layer
   ├─ Write audit log
   ├─ Return signed transaction
   │
   ▼
7. Interface Layer
   └─ Return HTTP response
```

### Wallet Creation Flow

```
1. Client Request
   │
   ▼
2. Interface Layer
   ├─ Authenticate app and user
   │
   ▼
3. Application Layer
   ├─ Validate chain_type and exec_backend
   │
   ▼
4. Key Execution Layer
   ├─ Generate keypair using CSPRNG
   ├─ Split key into shares (Shamir 2-of-2)
   ├─ Encrypt auth share with KMS
   ├─ Store exec share in backend
   │
   ▼
5. Storage Layer
   ├─ Create wallet record
   ├─ Store encrypted shares
   │
   ▼
6. Application Layer
   ├─ Write audit log
   │
   ▼
7. Interface Layer
   └─ Return wallet with address
```

## Data Model

### Entity Relationships

```
┌──────────────┐
│     App      │ (multi-tenant)
└──────┬───────┘
       │ 1:N
       ▼
┌──────────────┐      ┌──────────────────┐
│    User      │◀────▶│      Wallet      │
└──────────────┘      └────────┬─────────┘
                               │
       ┌───────────────┬───────┴───────┬───────────────┐
       ▼               ▼               ▼               ▼
┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
│WalletShare   │ │WalletPolicy  │ │SessionSigner │ │OwnerID ref   │
│(auth/exec)   │ │   (link)     │ │              │ │(AuthKey/     │
└──────────────┘ └──────┬───────┘ └──────────────┘ │Quorum)       │
                        │                          └──────────────┘
                        ▼
                 ┌──────────────┐
                 │    Policy    │
                 └──────┬───────┘
                        │
                        ▼
                 ┌──────────────┐
                 │ConditionSet │
                 └──────────────┘
```

### Core Tables

| Table | Purpose |
|-------|---------|
| `apps` | Multi-tenant application records |
| `app_secrets` | API secrets (hashed) for app auth |
| `users` | User records (JWT sub mapping) |
| `authorization_keys` | P-256 public keys for auth signatures |
| `key_quorums` | M-of-N signature thresholds |
| `wallets` | Blockchain wallet records |
| `wallet_shares` | Encrypted key shares |
| `policies` | Access control policy definitions |
| `wallet_policies` | Wallet-to-policy links |
| `session_signers` | Temporary signing delegations |
| `condition_sets` | Reusable policy value sets |
| `audit_logs` | Complete operation audit trail |
| `idempotency_keys` | Duplicate request prevention |

## Security Architecture

### Key Protection

```
┌─────────────────────────────────────────────────────────────┐
│                     Private Key                              │
│                    (ephemeral)                               │
└─────────────────────────────────────────────────────────────┘
                          │
                   Shamir Split
                          │
        ┌─────────────────┼─────────────────┐
        ▼                                   ▼
┌───────────────────┐             ┌───────────────────┐
│    Auth Share     │             │    Exec Share     │
│                   │             │                   │
│  ┌─────────────┐  │             │  ┌─────────────┐  │
│  │ KMS Encrypt │  │             │  │ KMS Backend │  │
│  └──────┬──────┘  │             │  │   or TEE    │  │
│         │         │             │  └──────┬──────┘  │
│         ▼         │             │         │         │
│  ┌─────────────┐  │             │  ┌──────▼──────┐  │
│  │ PostgreSQL  │  │             │  │ KMS/Enclave │  │
│  └─────────────┘  │             │  └─────────────┘  │
└───────────────────┘             └───────────────────┘
```

### Authentication Layers

| Layer | Mechanism | Protects Against |
|-------|-----------|------------------|
| **App Auth** | X-App-Id + X-App-Secret | Unauthorized app access |
| **User Auth** | JWT (OIDC/custom) | Unauthorized user access |
| **Auth Signature** | P-256 signature | Unauthorized high-risk ops |
| **Policy Engine** | Rule evaluation | Unauthorized operations |

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Database compromise | Shares encrypted, need KMS to decrypt |
| KMS compromise | Only get exec share, need auth share too |
| Server memory dump | Keys cleared after signing |
| Replay attacks | Idempotency keys, timestamp validation |
| Unauthorized signing | Policy engine default-deny |
| Session hijacking | TTL expiration, revocation |

## Deployment Architecture

### Single-Node Deployment

```
┌─────────────────────────────────────┐
│           Single Server             │
│  ┌───────────────────────────────┐  │
│  │     Better Wallet Process     │  │
│  │  (all layers in one process)  │  │
│  └───────────────────────────────┘  │
│                 │                   │
│  ┌──────────────▼────────────────┐  │
│  │         PostgreSQL            │  │
│  └───────────────────────────────┘  │
└─────────────────────────────────────┘
```

### High-Availability Deployment

```
┌─────────────────────────────────────────────────────────────┐
│                     Load Balancer                            │
└─────────────────────────┬───────────────────────────────────┘
                          │
        ┌─────────────────┼─────────────────┐
        ▼                 ▼                 ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  BW Node 1    │ │  BW Node 2    │ │  BW Node 3    │
└───────┬───────┘ └───────┬───────┘ └───────┬───────┘
        │                 │                 │
        └────────────────┬┴─────────────────┘
                         │
                ┌────────▼────────┐
                │   PostgreSQL    │
                │   (Primary)     │
                └────────┬────────┘
                         │
                ┌────────▼────────┐
                │   PostgreSQL    │
                │   (Replica)     │
                └─────────────────┘
```

### TEE Deployment (AWS Nitro)

```
┌─────────────────────────────────────────────────────────────┐
│                     EC2 Instance                             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │              Better Wallet (Parent)                    │  │
│  │   Interface → Application → Policy → [TEE Client]     │  │
│  └───────────────────────────────┬───────────────────────┘  │
│                                  │ vsock                    │
│  ┌───────────────────────────────▼───────────────────────┐  │
│  │              Nitro Enclave                             │  │
│  │   ┌─────────────────────────────────────────────┐     │  │
│  │   │            Enclave Server                    │     │  │
│  │   │  • Sealed exec shares                        │     │  │
│  │   │  • Key reconstruction                        │     │  │
│  │   │  • Transaction signing                       │     │  │
│  │   └─────────────────────────────────────────────┘     │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## Design Decisions

### Why Monolithic?

| Factor | Decision Rationale |
|--------|---------------------|
| **Operational simplicity** | One binary, minimal dependencies |
| **Latency** | No network hops between services |
| **Consistency** | Single transaction boundary |
| **Self-hosted focus** | Easier for small teams to deploy |

### Why PostgreSQL Only?

| Factor | Decision Rationale |
|--------|---------------------|
| **Simplicity** | One database to manage |
| **ACID guarantees** | Critical for financial operations |
| **Row-level locking** | Can replace Redis for many patterns |
| **Proven reliability** | Battle-tested in production |

### Why No ORM?

| Factor | Decision Rationale |
|--------|---------------------|
| **Performance** | Hand-optimized SQL queries |
| **Auditability** | Clear SQL for security review |
| **Control** | Explicit transaction management |
| **Simplicity** | pgx provides clean API |

## Performance Characteristics

### Typical Latencies

| Operation | Latency (KMS) | Latency (TEE) |
|-----------|---------------|---------------|
| Create wallet | 50-100ms | 100-200ms |
| Sign transaction | 20-50ms | 50-100ms |
| Policy evaluation | 1-5ms | 1-5ms |
| List wallets | 5-20ms | 5-20ms |

### Scaling Guidelines

| Metric | Single Node | Clustered |
|--------|-------------|-----------|
| Requests/sec | 500-1000 | 2000-5000 |
| Concurrent users | 1000 | 10000+ |
| Wallets | 100K | 1M+ |

## Next Steps

- [First Integration](./first-integration.md) - Build your first app
- [Security Architecture](../security/architecture.md) - Deep dive into security
- [Deployment Guide](../deployment/overview.md) - Production deployment
