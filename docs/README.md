# Better Wallet Documentation

Welcome to the Better Wallet documentation. Better Wallet is a self-hosted wallet infrastructure designed specifically for **AI Agents**.

## What is Better Wallet?

Better Wallet provides secure, controlled on-chain execution for AI Agents:

- **Agent-First Design**: Built specifically for AI agent scenarios, not end-user wallets
- **Principal Control**: Humans/organizations maintain ultimate control over agent wallets
- **Capability-Based Security**: Fine-grained permissions with operations, contract allowlists, and rate limits
- **Kill Switch**: Instantly revoke agent access when needed
- **Self-Hosted**: Complete control over your infrastructure and data
- **EVM Compatible**: Supports all EVM-compatible chains

## Documentation

### Agent Wallet

| Document | Description |
|----------|-------------|
| [Overview](./agent-wallet/overview.md) | Core concepts, security model, capabilities |
| [Quick Start](./agent-wallet/quickstart.md) | Get running in 5 minutes |
| [API Reference](./agent-wallet/api-reference.md) | Complete API documentation |

### Deployment

| Document | Description |
|----------|-------------|
| [Overview](./deployment/overview.md) | Deployment options and requirements |
| [Environment Variables](./deployment/environment-variables.md) | Configuration reference |
| [Docker Compose](./deployment/docker-compose.md) | Docker deployment guide |
| [Kubernetes](./deployment/kubernetes.md) | Kubernetes deployment guide |
| [Bare Metal](./deployment/bare-metal.md) | Direct installation guide |
| [TLS Configuration](./deployment/tls-configuration.md) | HTTPS setup |
| [Monitoring](./deployment/monitoring.md) | Metrics and logging |
| [Backup & Recovery](./deployment/backup-recovery.md) | Data protection |

### Security

| Document | Description |
|----------|-------------|
| [Architecture](./security/architecture.md) | Security model, key protection, threat model |

### Contributing

| Document | Description |
|----------|-------------|
| [Development Setup](./contributing/development-setup.md) | Local development guide |

## Quick Navigation

### Core Concepts

| Concept | Description |
|---------|-------------|
| **Principal** | Human or organization that owns wallets. Authenticates with API Key (`aw_pk_xxx.secret`). |
| **Agent Wallet** | Blockchain wallet owned by a Principal. Private key protected by KMS/TEE. |
| **Agent Credential** | Capability token granted to an AI agent (`aw_ag_xxx.secret`) with specific permissions and limits. |

### Security Model

1. **Separation** — Agent runtime and signing service are completely isolated
2. **Least Privilege** — Agent Credential grants only necessary capabilities
3. **Default Deny** — Any operation not explicitly allowed is denied
4. **Auditable** — All operations recorded with full context
5. **Revocable** — Principal can revoke agent permissions instantly

### API Overview

| Context | Authentication | Use Case |
|---------|----------------|----------|
| **Principal API** | `Bearer aw_pk_xxx.secret` | Wallet management, credential creation |
| **Agent API** | `Bearer aw_ag_xxx.secret` | JSON-RPC signing operations |

## Support

- **GitHub Issues**: [Bug reports and feature requests](https://github.com/better-wallet/better-wallet/issues)
- **GitHub Discussions**: [Questions and community support](https://github.com/better-wallet/better-wallet/discussions)

## License

Better Wallet is open source under the [MIT License](https://github.com/better-wallet/better-wallet/blob/main/LICENSE).
