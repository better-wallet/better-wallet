# Frequently Asked Questions

## General

### What is Better Wallet?

Better Wallet is a self-hosted, modular key management and wallet infrastructure for blockchain applications. It handles wallet creation, transaction signing, and access control while you maintain complete control over deployment and data.

### How is Better Wallet different from Privy?

| Aspect | Privy | Better Wallet |
|--------|-------|---------------|
| Deployment | SaaS only | Self-hosted first |
| Authentication | Built-in (15+ methods) | Bring your own (OIDC/JWT) |
| Source Code | Closed source | MIT open source |
| Data Location | Privy's infrastructure | Your infrastructure |
| Pricing | Per-user fees | Free (self-hosted) |

### What blockchains are supported?

Currently, Ethereum and EVM-compatible chains are supported in production. Solana and Bitcoin support are planned for future releases.

### Is Better Wallet production-ready?

Better Wallet is actively developed and suitable for production use. However, review the [Security Architecture](../security/architecture.md) and conduct your own security assessment before deploying with real funds.

## Security

### How are private keys protected?

Private keys are never stored whole. They're split into two shares using Shamir's Secret Sharing:
- **Auth share**: Encrypted with KMS, stored in PostgreSQL
- **Exec share**: Managed by the execution backend (KMS or TEE)

Both shares are required to reconstruct the key, which only happens briefly during signing.

### What happens if the database is compromised?

An attacker with database access would only obtain encrypted auth shares. Without KMS access to decrypt them AND the exec shares, they cannot reconstruct private keys.

### What happens if KMS is compromised?

An attacker with KMS access could decrypt shares but would still need database access to obtain auth shares. Both are required to reconstruct keys.

### Why should I use TEE instead of KMS?

TEE (AWS Nitro Enclaves) provides hardware-level isolation:
- Private keys never exist in main server memory
- Even with root access to the EC2 instance, enclave memory cannot be read
- Attestation proves the enclave is running expected code

Use TEE for high-value wallets or when you need the highest security guarantees.

### Can Better Wallet access my private keys?

No. Better Wallet's architecture ensures that:
- Keys are split before storage
- Reconstruction happens only during signing
- With TEE, reconstruction happens inside a hardware-isolated enclave
- The open-source code is auditable

## Authentication

### What authentication providers are supported?

Better Wallet works with any OIDC/JWT provider:
- Auth0
- Clerk
- Okta
- Better Auth
- Firebase Auth
- Custom implementations

### Do I need to migrate my existing users?

No. Better Wallet maps JWT `sub` claims to internal users automatically. Your existing authentication infrastructure remains unchanged.

### How do authorization signatures work?

For high-risk operations (deleting wallets, transferring ownership), you sign a canonical payload with a P-256 private key. The signature proves the request is authorized by the key owner.

## Wallets

### Can a user have multiple wallets?

Yes. A user can have any number of wallets across different chains.

### Can I create wallets without a user?

Yes. App-managed wallets have no `user_id` and are controlled entirely by your application credentials.

### What is wallet ownership?

Wallet ownership determines who can perform high-risk operations. The `owner_id` references an authorization key or key quorum. Operations like transferring ownership require the owner's signature.

### Can I import existing wallets?

Currently, Better Wallet generates new keypairs. Importing existing private keys is not supported for security reasons (imported keys may be compromised).

### Can I export private keys?

Better Wallet does not support exporting private keys. This is intentional to prevent key extraction attacks.

## Policies

### What is default-deny?

All operations are denied unless explicitly allowed by a policy rule. If no rule matches a transaction, it is denied.

### Can I have multiple policies on a wallet?

Yes. A wallet can have multiple policies attached. All policies must allow an operation for it to proceed.

### How do I debug policy denials?

The error response includes which policy denied the operation and why:

```json
{
  "error": {
    "code": "policy_denied",
    "details": {
      "policy_name": "Value limit",
      "rule_name": "Max 1 ETH",
      "reason": "value 2000000000000000000 > 1000000000000000000"
    }
  }
}
```

### Can policies access smart contract data?

Yes. The `ethereum_calldata` field source allows policies to evaluate decoded function call parameters.

## Session Signers

### What are session signers for?

Session signers enable delegated signing for:
- Trading bots
- Telegram/Discord bots
- Automated systems
- Game sessions
- Any scenario needing temporary, limited signing authority

### How do session signers relate to policies?

Session signers can have a `policy_override_id` that replaces the wallet's default policies. This allows more restrictive policies for automated systems.

### What happens when a session expires?

Expired sessions cannot sign. Create a new session signer when needed.

### Can I revoke a session signer immediately?

Yes. Revoking a session signer invalidates it immediately, regardless of TTL.

## Deployment

### What infrastructure do I need?

Minimum requirements:
- Go 1.21+ runtime
- PostgreSQL 15+
- Network access to your OIDC provider

### Can I run Better Wallet in Docker?

Yes. Docker and Docker Compose are the recommended deployment methods:

```bash
docker-compose up -d
```

### Does Better Wallet support Kubernetes?

Yes. Helm charts and Kubernetes manifests are available. See [Kubernetes Deployment](../deployment/kubernetes.md).

### How do I scale Better Wallet?

Better Wallet is stateless and horizontally scalable:
1. Deploy multiple instances behind a load balancer
2. All instances share the same PostgreSQL database
3. No session affinity required

### What about database backups?

Use standard PostgreSQL backup procedures:
- `pg_dump` for logical backups
- Continuous archiving for point-in-time recovery
- Your cloud provider's managed backup solutions

## Troubleshooting

### "Invalid JWT token"

- Verify `iss` matches your configured issuer
- Check `aud` matches your configured audience
- Ensure the token hasn't expired
- Verify the JWKS endpoint is accessible

### "Policy denied"

- Check which policy denied in the error response
- Verify your transaction parameters
- Review the policy rules for matches
- Remember: default is DENY if no rules match

### "Connection refused"

- Verify Better Wallet is running
- Check the port configuration
- Ensure network/firewall allows connections

### "KMS error"

- Verify KMS credentials and permissions
- Check network connectivity to KMS
- Review KMS provider configuration

### "TEE attestation failed"

- Ensure running on Nitro-enabled EC2 instance
- Verify enclave is properly configured
- Check attestation document validity

## Costs

### Is Better Wallet free?

Yes. Better Wallet is MIT licensed and free to use. Costs are only:
- Your infrastructure (servers, database)
- KMS usage (AWS KMS, Vault, etc.)
- TEE instances (if using Nitro Enclaves)

### What are the ongoing infrastructure costs?

Typical monthly costs for a small deployment:
- EC2 t3.medium: ~$30
- RDS PostgreSQL db.t3.micro: ~$15
- AWS KMS: ~$1/key + $0.03/10,000 requests
- Total: ~$50-100/month (varies by region and usage)

## Support

### Where can I get help?

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support

### How do I report security issues?

Please report security vulnerabilities privately via GitHub Security Advisories or email security@better-wallet.com. Do not open public issues for security concerns.

### Can I contribute?

Yes! Better Wallet is open source. See [Contributing Guide](../contributing/development-setup.md) to get started.
