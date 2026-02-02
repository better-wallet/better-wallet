# Agent Wallet Design Document

> Secure, controlled on-chain execution for AI Agents. Agents can only request, never control.

## Product Positioning

### Target Users
- AI Agent developers (building autonomous trading, service, or multi-agent systems)
- Teams that need agents to operate on-chain assets but worry about loss of control

### Core Value Proposition

| Pain Point | Solution |
|------------|----------|
| Agent may go rogue (bugs, attacks, hallucinations) | Hard policy boundaries that agents cannot bypass |
| No visibility into agent actions | Complete audit logs + real-time monitoring |
| Cannot stop losses quickly when issues arise | One-click Kill Switch |
| Complex to set up wallets for agents | 5-minute API integration |

### What We Don't Do
- Agent identity/discovery/reputation (let ERC-8004 handle this)
- Agent frameworks/runtimes (focus on execution layer only)
- End-user wallets (focus on agent scenarios)

---

## Core Architecture

### Security Model: Agent as Client, Not Host

```
┌─────────────────────────────────────────────────────────────┐
│                      Principal (Human/Org)                   │
│                  - Creates Agent Wallet                      │
│                  - Defines Policy                            │
│                  - Monitors & Kill Switch                    │
└─────────────────────┬───────────────────────────────────────┘
                      │ manages
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                    Agent Wallet Service                      │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ Policy      │  │ Audit       │  │ Signing Service     │  │
│  │ Engine      │  │ Logger      │  │ (KMS/TEE)           │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
└─────────────────────┬───────────────────────────────────────┘
                      │ API (restricted)
                      ▼
┌─────────────────────────────────────────────────────────────┐
│                      AI Agent                                │
│                  - Holds Agent Credential                    │
│                  - Can only call API to request signing      │
│                  - Never has access to private keys          │
└─────────────────────────────────────────────────────────────┘
```

### Key Principles

1. **Separation** — Agent runtime and signing service are completely isolated
2. **Least Privilege** — Agent Credential grants only necessary capabilities
3. **Default Deny** — Any operation not explicitly allowed is denied
4. **Auditable** — All operations recorded: who/what/when/why
5. **Revocable** — Principal can revoke agent permissions at any time

### Core Entities

```
Principal (Human/Org)
    │
    ├── API Key (management operations)
    │
    └── Agent Wallet
            │
            ├── Private Key (protected by KMS/TEE)
            │
            ├── Policy (constraint rules)
            │
            └── Agent Credential (granted to AI Agent)
                    │
                    └── Capabilities + Limits
```

**The entire system has only 3 core entities: Principal, Agent Wallet, Agent Credential**

---

## Agent Credential Model

### Data Structure

```go
type AgentCredential struct {
    ID        string    `json:"id"`
    WalletID  string    `json:"wallet_id"`

    // Identity (optional, supports ERC-8004, etc.)
    Identity  *Identity `json:"identity,omitempty"`

    // Capability boundaries
    Capabilities Capabilities `json:"capabilities"`

    // Hard limits
    Limits    Limits    `json:"limits"`

    // Status
    Status    string    `json:"status"` // active, paused, revoked
    CreatedAt time.Time `json:"created_at"`
    LastUsedAt time.Time `json:"last_used_at"`
}

type Identity struct {
    Type  string `json:"type"`  // erc8004, api_key, did
    Value string `json:"value"`
}

type Capabilities struct {
    Chains     []string `json:"chains"`      // ethereum, base, ...
    Operations []string `json:"operations"`  // transfer, swap, ...
    Contracts  []string `json:"contracts"`   // allowlisted contract addresses
    Methods    []string `json:"methods"`     // allowlisted methods
}

type Limits struct {
    MaxValuePerTx   string `json:"max_value_per_tx"`
    MaxValuePerHour string `json:"max_value_per_hour"`
    MaxValuePerDay  string `json:"max_value_per_day"`
    MaxTxPerHour    int    `json:"max_tx_per_hour"`
}
```

### Authentication Methods
- API Key + Secret (simple scenarios)
- Signature authentication (Agent holds its own keypair to prove identity)

---

## Agent Policy Primitives

### Policy Structure

```yaml
policy:
  name: "defi-trading-agent"

  # Only allow interaction with these contracts
  allowed_contracts:
    - address: "0x..."
      methods: ["swap", "exactInput"]
    - address: "0x..."
      methods: ["supply", "withdraw"]

  # Denied operations
  denied_operations:
    - "approve_unlimited"
    - "transfer_to_unknown"

  # Rate and spending limits
  rate_limits:
    max_tx_per_minute: 10
    max_tx_per_hour: 100
    max_value_per_tx: "0.5 ETH"
    max_value_per_day: "10 ETH"
    max_gas_per_tx: "0.01 ETH"

  # Time window (optional)
  time_window:
    allowed_hours: [0, 23]

  # Anomaly detection
  anomaly_detection:
    alert_on_new_contract: true
    alert_on_large_tx: "1 ETH"
    pause_on_consecutive_failures: 5
```

### Agent-Specific Primitives

| Primitive | Description |
|-----------|-------------|
| `max_slippage` | DeFi: maximum slippage allowed |
| `required_profit_margin` | Arbitrage: minimum profit margin to execute |
| `cooldown_after_loss` | Forced cooldown period after loss |
| `daily_loss_limit` | Maximum daily loss, triggers auto-pause |
| `require_simulation` | Must pass simulation before execution |

---

## Principal Control Panel

### Real-time Monitoring UI

```
┌─────────────────────────────────────────────────────────────┐
│  Agent: defi-trading-bot                    Status: ● Active │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  Today's Stats                                               │
│  ├─ Transactions: 47                                         │
│  ├─ Success Rate: 95.7%                                      │
│  ├─ Total Spent: 3.2 ETH (limit: 10 ETH) ████████░░ 32%     │
│  └─ Gas Used: 0.08 ETH                                       │
│                                                              │
│  Recent Operations                                           │
│  ├─ 12:03:45  swap 0.5 ETH → 1,247 USDC  ✓                  │
│  ├─ 12:01:12  swap 0.3 ETH → 742 USDC    ✓                  │
│  └─ 11:58:33  swap 1.0 ETH → 2,489 USDC  ✓                  │
│                                                              │
│  Alerts                                                      │
│  └─ ⚠ 11:45:00  First interaction with contract 0x7a25...   │
│                                                              │
├─────────────────────────────────────────────────────────────┤
│  [⏸ Pause]  [⏹ Kill]  [📝 Edit Policy]  [📊 Full Logs]      │
└─────────────────────────────────────────────────────────────┘
```

### Control API

```
POST /v1/agents/{id}/pause     # Pause, can resume
POST /v1/agents/{id}/resume    # Resume
POST /v1/agents/{id}/kill      # Immediate termination, revoke credential
PUT  /v1/agents/{id}/policy    # Update policy in real-time
GET  /v1/agents/{id}/logs      # Audit logs
GET  /v1/agents/{id}/stats     # Statistics
```

### Alert Notifications
- Webhook callbacks
- Email / Slack / Telegram integration

---

## Agent Developer API

### Quick Start

```python
from agent_wallet import AgentWallet

# 1. Initialize
wallet = AgentWallet(
    endpoint="https://wallet.example.com",
    credential="ag_cred_xxxxx"
)

# 2. Query balance
balance = wallet.get_balance("ethereum")

# 3. Send transaction
result = wallet.send_transaction(
    chain="ethereum",
    to="0x...",
    value="0.1 ETH",
    data="0x..."
)

# 4. Handle result
if result.success:
    print(f"tx: {result.tx_hash}")
else:
    print(f"denied: {result.reason}")
```

### API Endpoints

```
# Wallet operations
GET  /v1/wallet/balance        # Query balance
POST /v1/wallet/sign           # Request signature
POST /v1/wallet/send           # Sign and send

# Transactions (JSON-RPC compatible)
POST /v1/rpc                   # eth_sendTransaction, etc.

# Status queries
GET  /v1/agent/me              # Current credential info
GET  /v1/agent/limits          # Remaining limits
GET  /v1/agent/history         # Operation history
```

### SDK Support

| Language | Priority |
|----------|----------|
| Python | P0 |
| TypeScript | P0 |
| Rust | P1 |
| Go | P1 |

### Error Response

```json
{
  "error": "policy_denied",
  "code": "LIMIT_EXCEEDED",
  "message": "Daily spending limit exceeded",
  "details": {
    "limit": "10 ETH",
    "used": "10 ETH",
    "requested": "0.5 ETH",
    "resets_at": "2024-01-02T00:00:00Z"
  }
}
```

---

## Implementation Path

### Remove from Current Architecture

| Feature | Reason |
|---------|--------|
| User Wallet | Agent Wallet doesn't need end-user concept |
| JWT/OIDC user auth | Agents use Credentials |
| Session Signer | Replaced by Agent Credential |
| Recovery Methods | Agents don't need recovery, just recreate |
| 2-of-2 Shamir sharing | Simplify, KMS/TEE is sufficient |
| App-level auth | Simplify to Principal model |
| Condition Sets | Write directly in Policy |

### Reuse from Current Architecture

| Component | Changes |
|-----------|---------|
| KMS/TEE signing service | No changes needed |
| Policy Engine | Extend with Agent primitives |
| Audit logs | Add Agent fields |
| PostgreSQL storage | Add Agent tables |
| API layer | Add Agent endpoints |

### Phased Delivery

**Phase 1 - MVP**
- Principal authentication
- Agent Wallet creation
- Agent Credential management
- Basic Policy (limits, allowlists)
- Signing API
- Kill Switch

**Phase 2 - Usability**
- Principal Dashboard
- Alert notifications
- Python / TS SDK
- More Policy primitives

**Phase 3 - Ecosystem**
- ERC-8004 identity integration (optional)
- Multi-chain support
- Agent template library

---

## Design Principles Summary

1. **Agent as Client, Not Host** — Architectural security isolation
2. **Capability-centric** — Identity is just an anchor, capability boundaries are core
3. **Default Deny** — Anything not explicitly allowed is forbidden
4. **Principal Supremacy** — Humans always have ultimate control
5. **Simplicity First** — 3 core entities, no over-engineering
