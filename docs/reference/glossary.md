# Glossary

This glossary defines key terms used throughout the Better Wallet documentation.

## A

### App (Application)
A multi-tenant entity in Better Wallet that represents your application. Each app has its own credentials (App ID and App Secret), users, wallets, and configuration.

### App-Managed Wallet
A wallet without a `user_id`, controlled entirely by the application's credentials. Used for treasury, fee payers, or system operations.

### Auth Share
One half of a split private key, encrypted with KMS and stored in PostgreSQL. Cannot reconstruct the private key without the corresponding exec share.

### Authorization Key
A P-256 public/private key pair used to sign requests for high-risk operations. The public key is registered with Better Wallet; the private key is kept secure by the owner.

### Authorization Signature
A cryptographic signature over a canonical representation of an API request, proving the request is authorized by the owner of an authorization key.

## C

### Canonical Payload
A deterministic representation of an API request used for signing, following RFC 8785 (JSON Canonicalization Scheme). Ensures signatures are consistent regardless of JSON formatting.

### Chain Type
The blockchain network a wallet operates on (e.g., `ethereum`, `solana`). Currently, only Ethereum is supported in production.

### Condition Set
A reusable collection of values (addresses, chain IDs, etc.) that can be referenced in policy conditions using the `in_condition_set` operator.

## D

### Default-Deny
Security model where all operations are denied unless explicitly allowed by a policy rule. This is Better Wallet's security posture.

## E

### EIP-712
Ethereum Improvement Proposal for typed structured data signing. Provides better security and UX than raw message signing by displaying human-readable data.

### EIP-1559
Ethereum transaction type with separate base fee and priority fee. The default transaction format for post-London fork Ethereum.

### Exec Share
One half of a split private key, managed by the execution backend (KMS or TEE). Cannot reconstruct the private key without the corresponding auth share.

### Execution Backend
The system responsible for managing exec shares and performing signing operations. Options are `kms` (default) or `tee` (AWS Nitro Enclaves).

## F

### Field Source
In the policy engine, the data source from which a condition's field value is extracted. Examples: `ethereum_transaction`, `ethereum_calldata`, `system`.

## H

### HPKE (Hybrid Public Key Encryption)
Encryption scheme used for secure communication. Used in key share exchange.

## I

### Idempotency Key
A unique identifier included with write requests to prevent duplicate operations. If the same idempotency key is used twice, the second request returns the cached response.

## J

### JWT (JSON Web Token)
A signed token containing user claims (issuer, audience, subject, expiration). Used for user authentication in Better Wallet.

### JWKS (JSON Web Key Set)
A set of public keys used to verify JWT signatures. Better Wallet fetches JWKS from your OIDC provider's published endpoint.

## K

### Key Quorum
A multi-signature configuration requiring M-of-N authorization keys to approve high-risk operations. Used for enterprise or shared wallet control.

### KMS (Key Management Service)
A service for managing cryptographic keys. Better Wallet supports local encryption, AWS KMS, and HashiCorp Vault as KMS providers.

### KMS Provider
An implementation of the KMS interface for encrypting/decrypting key shares. Options: `local`, `aws-kms`, `vault`.

## M

### Multi-Tenant
Architecture where a single Better Wallet deployment serves multiple applications, each with isolated data and configuration.

## N

### Nitro Enclave
AWS's Trusted Execution Environment (TEE) for isolating and processing sensitive data. When using the `tee` backend, signing operations occur inside the enclave.

## O

### OIDC (OpenID Connect)
Authentication protocol built on OAuth 2.0. Better Wallet validates JWTs from any OIDC-compliant provider.

### Operator
In the policy engine, the comparison function used in a condition (e.g., `eq`, `lt`, `in`, `in_condition_set`).

### Owner
An authorization key or key quorum that controls a wallet or policy. Required for high-risk operations like ownership transfer or deletion.

## P

### P-256
NIST P-256 elliptic curve (also known as prime256v1 or secp256r1). Used for authorization key signatures in Better Wallet.

### Policy
A set of rules that control what operations a wallet can perform. Policies use field_source/operator conditions with ALLOW or DENY actions.

### Policy Override
A policy attached to a session signer that replaces the wallet's default policies for that session.

## R

### RFC 8785
JSON Canonicalization Scheme (JCS). Defines a deterministic serialization of JSON objects, used for creating canonical payloads for signatures.

### Rule
A single entry in a policy containing a method filter, conditions, and an action (ALLOW or DENY).

## S

### Session Signer
A temporary, scoped authorization allowing a specific identifier to sign transactions on behalf of a wallet, subject to time, value, and transaction count limits.

### Shamir's Secret Sharing
Cryptographic algorithm that splits a secret into multiple shares, requiring a threshold number of shares to reconstruct the original. Better Wallet uses 2-of-2 splitting.

### Share
A fragment of a split private key. Better Wallet creates an auth share and an exec share for each wallet.

## T

### TEE (Trusted Execution Environment)
Hardware-based isolation for processing sensitive data. AWS Nitro Enclaves are the supported TEE platform.

### TTL (Time-To-Live)
Expiration time for a session signer, specified in seconds from creation.

### Typed Data
Structured data with type information, as defined in EIP-712. Enables signing of complex data structures with human-readable display.

## U

### User
An entity mapped from a JWT `sub` claim to an internal Better Wallet user ID. Users can own wallets.

## V

### Vsock
Virtual socket communication used between an EC2 instance and its Nitro Enclave. More secure than network sockets as it's isolated from the network stack.

## W

### Wallet
A blockchain account managed by Better Wallet, consisting of an address, encrypted key shares, and associated policies.

### Wallet Share
See "Share". The encrypted key material stored for a wallet, comprising auth share and exec share.

## Z

### Zeroization
Security practice of overwriting sensitive data in memory with zeros after use. Better Wallet zeroizes reconstructed private keys immediately after signing.
