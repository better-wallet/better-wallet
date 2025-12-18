# Better Wallet 测试策略文档

> **版本**: 1.0
> **最后更新**: 2024-12
> **状态**: 草案

---

## 1. 测试原则

### 1.1 核心理念

作为钱包系统，我们遵循以下测试原则：

| 原则 | 说明 |
|------|------|
| **安全优先** | 任何涉及密钥、签名、授权的代码必须有 100% 路径覆盖 |
| **失败优先测试** | 先测试系统拒绝非法操作的能力，再测试正常功能 |
| **信任边界验证** | 每个信任边界必须有专门的测试用例 |
| **不可变性验证** | 测试系统在异常情况下不会产生部分状态 |
| **可审计性** | 所有关键操作必须验证审计日志的完整性 |

### 1.2 测试金字塔

```
                    ┌─────────────┐
                    │   E2E 测试   │  ← 少量，验证关键业务流程
                   ─┴─────────────┴─
                  ┌─────────────────┐
                  │   集成测试       │  ← 验证组件间交互
                 ─┴─────────────────┴─
                ┌─────────────────────┐
                │      单元测试        │  ← 大量，验证业务逻辑正确性
               ─┴─────────────────────┴─
              ┌─────────────────────────┐
              │       安全测试          │  ← 贯穿所有层次
             ─┴─────────────────────────┴─
```

### 1.3 覆盖率目标

| 模块 | 行覆盖率 | 分支覆盖率 | 说明 |
|------|---------|-----------|------|
| `internal/crypto/` | 100% | 100% | 密钥操作，零容忍 |
| `internal/keyexec/` | 95%+ | 90%+ | 签名执行，关键路径 |
| `internal/policy/` | 100% | 100% | 策略引擎，决定授权 |
| `pkg/auth/` | 100% | 100% | 签名验证，安全核心 |
| `internal/middleware/` | 90%+ | 85%+ | 认证中间件 |
| `internal/app/` | 90%+ | 85%+ | 业务逻辑 |
| `internal/storage/` | 85%+ | 80%+ | 数据访问 |
| `internal/api/` | 85%+ | 80%+ | API 处理 |

---

## 2. 测试类型

### 2.1 单元测试 (Unit Tests)

**目的**: 验证单个函数/方法的逻辑正确性

**范围**:
- 纯函数逻辑
- 边界条件
- 错误处理路径
- 类型转换

**命名规范**: `*_test.go` 与源文件同目录

**示例结构**:
```go
func TestFunctionName(t *testing.T) {
    t.Run("正常场景_描述", func(t *testing.T) { ... })
    t.Run("边界条件_描述", func(t *testing.T) { ... })
    t.Run("错误处理_描述", func(t *testing.T) { ... })
    t.Run("安全检查_描述", func(t *testing.T) { ... })
}
```

### 2.2 集成测试 (Integration Tests)

**目的**: 验证组件间交互的正确性

**范围**:
- API Handler → Service → Repository 完整流程
- 数据库事务的原子性
- 中间件链的正确执行
- 跨模块的数据流

**目录**: `tests/integration/`

### 2.3 安全测试 (Security Tests)

**目的**: 验证系统拒绝非法操作的能力

**范围**:
- 认证绕过尝试
- 授权绕过尝试
- 数据隔离验证
- 密钥安全性
- 重放攻击防护

**目录**: `tests/security/`

### 2.4 端到端测试 (E2E Tests)

**目的**: 验证完整业务流程

**范围**:
- 钱包创建 → 签名 → 验证
- 策略创建 → 关联 → 执行
- Session Signer 生命周期

**目录**: `tests/e2e/`

---

## 3. 信任边界测试矩阵

系统有 6 个关键信任边界，每个必须有专门测试：

### 3.1 边界 1: App 认证 ↔ 用户认证

```
┌─────────────────┐      ┌─────────────────┐
│   外部请求       │ ──── │  App Auth       │
│  (不可信)        │      │  Middleware     │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| 缺少 X-App-Id header | 401 Unauthorized | P0 |
| X-App-Id 格式无效 (非 UUID) | 400 Bad Request | P0 |
| X-App-Id 不存在 | 401 Unauthorized | P0 |
| App Secret 错误 | 401 Unauthorized | P0 |
| App 已暂停 | 403 Forbidden | P0 |
| 有效 App 凭据 | 通过，设置 Context | P0 |

### 3.2 边界 2: 用户认证 ↔ 授权签名

```
┌─────────────────┐      ┌─────────────────┐
│   JWT Token     │ ──── │  User Auth      │
│  (需验证)        │      │  Middleware     │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| 缺少 Authorization header | 401 Unauthorized | P0 |
| 无效 JWT 格式 | 401 Unauthorized | P0 |
| JWT 签名无效 | 401 Unauthorized | P0 |
| JWT 已过期 | 401 Unauthorized | P0 |
| JWT issuer 不匹配 | 401 Unauthorized | P0 |
| JWT audience 不匹配 | 401 Unauthorized | P0 |
| JWT sub 为空 | 401 Unauthorized | P1 |
| 有效 JWT | 通过，设置 UserSub | P0 |

### 3.3 边界 3: 授权签名 ↔ 密钥访问

```
┌─────────────────┐      ┌─────────────────┐
│  Authorization  │ ──── │  Signature      │
│  Signature      │      │  Verification   │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| 缺少 X-Authorization-Signature | 403 Forbidden | P0 |
| 签名格式无效 (非 base64) | 403 Forbidden | P0 |
| 签名来自非 Owner 密钥 | 403 Forbidden | P0 |
| 签名内容与请求不匹配 | 403 Forbidden | P0 |
| 签名来自已过期 Session Signer | 403 Forbidden | P0 |
| 签名来自已撤销 Session Signer | 403 Forbidden | P0 |
| Key Quorum 签名数量不足 | 403 Forbidden | P0 |
| App-Managed 钱包无需签名 | 通过 | P0 |
| 有效 Owner 签名 | 通过 | P0 |
| 有效 Session Signer 签名 | 通过 | P0 |
| 有效 Quorum 签名 (达到阈值) | 通过 | P0 |

### 3.4 边界 4: 策略引擎 ↔ 签名操作

```
┌─────────────────┐      ┌─────────────────┐
│  Transaction    │ ──── │  Policy         │
│  Request        │      │  Engine         │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| 钱包无策略 | DENY (默认拒绝) | P0 |
| 策略不匹配任何规则 | DENY | P0 |
| 第一条规则 DENY | DENY (停止评估) | P0 |
| 第一条规则 ALLOW | ALLOW (停止评估) | P0 |
| 多条件规则 - 部分匹配 | DENY (AND 逻辑) | P0 |
| 多条件规则 - 全部匹配 | 规则 Action | P0 |
| Session Signer 策略覆盖 | 使用覆盖策略 | P0 |
| Condition Set 引用不存在 | DENY | P1 |
| 链类型不匹配 | 跳过该策略 | P1 |

### 3.5 边界 5: 密钥存储 ↔ 密钥访问

```
┌─────────────────┐      ┌─────────────────┐
│  Encrypted      │ ──── │  Key Exec       │
│  Shares (DB)    │      │  Backend        │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| Auth Share 解密失败 | 签名失败，不泄露信息 | P0 |
| Exec Share 解密失败 | 签名失败，不泄露信息 | P0 |
| Share 数据损坏 | 签名失败，检测到损坏 | P0 |
| 只有一个 Share | 无法重建密钥 | P0 |
| 两个 Share 来自不同密钥 | 重建失败或产生无效密钥 | P0 |
| 正常重建 | 正确签名 | P0 |
| 签名后内存清理 | 密钥不可从内存恢复 | P0 |

### 3.6 边界 6: 多租户隔离

```
┌─────────────────┐      ┌─────────────────┐
│   App A         │ ──── │  Database       │
│   App B         │      │  (app_id scope) │
└─────────────────┘      └─────────────────┘
```

| 测试场景 | 预期结果 | 优先级 |
|---------|---------|--------|
| App A 创建钱包 | 只有 App A 可见 | P0 |
| App B 访问 App A 钱包 | 返回 null/404 | P0 |
| App A 列表查询 | 只返回 App A 数据 | P0 |
| 跨 App Policy 引用 | 失败 | P0 |
| 跨 App Condition Set | 失败 | P0 |
| Context 缺少 AppID | 操作失败 | P0 |

---

## 4. 关键业务场景测试

### 4.1 钱包生命周期

```
创建 → 配置策略 → 签名交易 → 更新 Owner → 导出 → 删除
```

| 阶段 | 测试场景 | 验证点 |
|------|---------|--------|
| **创建** | 用户拥有钱包 | 正确生成地址，存储加密 Share |
| | App 管理钱包 | 无 Owner，App 可直接操作 |
| | 指定已有 Owner | 关联现有 AuthorizationKey |
| | 创建新 Owner | 创建新 AuthorizationKey |
| **策略** | 添加策略 | 策略与钱包关联 |
| | 更新策略 | 需要签名验证 |
| | 删除策略 | 钱包变为 DENY ALL |
| **签名** | 策略允许 | 成功签名 |
| | 策略拒绝 | 签名失败，记录审计 |
| | Session Signer | 受限签名 |
| **更新** | 转移 Owner | 旧 Owner 签名，新 Owner 接管 |
| **导出** | 导出私钥 | 只有 Owner 可操作 |
| **删除** | 删除钱包 | 清理所有关联数据 |

### 4.2 Session Signer 生命周期

```
创建 → 使用 → 限制检查 → 过期/撤销
```

| 阶段 | 测试场景 | 验证点 |
|------|---------|--------|
| **创建** | 正常创建 | 返回 Signer ID |
| | 设置 MaxValue | 记录限制 |
| | 设置 MaxTxs | 记录限制 |
| | 设置 TTL | 计算过期时间 |
| | 策略覆盖 | 关联指定策略 |
| **使用** | 在限制内签名 | 成功 |
| | 超过 MaxValue | 失败 |
| | 超过 MaxTxs | 失败 |
| | 方法不在允许列表 | 失败 |
| **过期** | TTL 过期后签名 | 失败 |
| | 撤销后签名 | 失败 |

### 4.3 Key Quorum (M-of-N) 流程

```
创建 Quorum → 关联到钱包 → 多签验证
```

| 阶段 | 测试场景 | 验证点 |
|------|---------|--------|
| **创建** | 2-of-3 Quorum | 正确存储阈值和密钥 |
| **签名** | 1 个签名 (不足) | 失败 |
| | 2 个签名 (达标) | 成功 |
| | 3 个签名 (超过) | 成功 |
| | 2 个相同签名 | 失败 (需要不同密钥) |
| | 来自非 Quorum 成员 | 失败 |

---

## 5. 安全测试场景

### 5.1 认证攻击

| 攻击类型 | 测试方法 | 预期结果 |
|---------|---------|---------|
| JWT 伪造 | 使用错误密钥签名 JWT | 401 |
| JWT 过期绕过 | 修改 exp 声明 | 401 |
| JWT 算法混淆 | 使用 none 算法 | 401 |
| JWKS 缓存投毒 | 检查缓存刷新逻辑 | 正确刷新 |
| App Secret 暴力破解 | 多次错误尝试 | 速率限制 |

### 5.2 授权攻击

| 攻击类型 | 测试方法 | 预期结果 |
|---------|---------|---------|
| 签名重放 | 使用旧签名发送新请求 | 幂等性处理或失败 |
| 签名截断 | 发送不完整签名 | 403 |
| 跨钱包签名 | 用 A 钱包签名访问 B 钱包 | 403 |
| Session Signer 提权 | 尝试导出私钥 | 403 |
| 策略绕过 | 构造边界条件请求 | DENY |

### 5.3 数据隔离攻击

| 攻击类型 | 测试方法 | 预期结果 |
|---------|---------|---------|
| 跨 App 访问 | App A 凭据访问 App B 数据 | 404/null |
| 用户枚举 | 遍历 user_id | 只返回自己的数据 |
| 钱包枚举 | 遍历 wallet_id | 只返回有权限的 |
| IDOR | 直接访问其他用户资源 ID | 404/403 |

### 5.4 密钥安全攻击

| 攻击类型 | 测试方法 | 预期结果 |
|---------|---------|---------|
| 内存泄露 | 检查签名后内存状态 | 密钥已清零 |
| 日志泄露 | 检查所有日志输出 | 无敏感数据 |
| 错误消息泄露 | 检查错误响应 | 无内部细节 |
| Side-channel | 检查时间一致性 | 常量时间比较 |

### 5.5 输入验证攻击

| 攻击类型 | 测试方法 | 预期结果 |
|---------|---------|---------|
| SQL 注入 | 恶意字符串输入 | 参数化查询阻止 |
| 超大 payload | 发送 > 10MB 请求 | 请求被拒绝 |
| 恶意 JSON | 深度嵌套、循环引用 | 解析失败 |
| 数值溢出 | 超大 value/gas | 验证失败 |
| 负数值 | 负的 value/gas | 验证失败 |

---

## 6. 测试用例模板

### 6.1 单元测试模板

```go
func TestXxx_场景描述(t *testing.T) {
    // Arrange - 准备测试数据和依赖

    // Act - 执行被测试的操作

    // Assert - 验证结果

    // Cleanup - 清理（如果需要）
}
```

### 6.2 表驱动测试模板

```go
func TestXxx(t *testing.T) {
    tests := []struct {
        name    string
        input   InputType
        want    OutputType
        wantErr bool
        errMsg  string // 验证具体错误消息
    }{
        {
            name:  "正常场景",
            input: validInput,
            want:  expectedOutput,
        },
        {
            name:    "错误场景_具体描述",
            input:   invalidInput,
            wantErr: true,
            errMsg:  "expected error message",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := FunctionUnderTest(tt.input)

            if tt.wantErr {
                require.Error(t, err)
                assert.Contains(t, err.Error(), tt.errMsg)
                return
            }

            require.NoError(t, err)
            assert.Equal(t, tt.want, got)
        })
    }
}
```

### 6.3 安全测试模板

```go
func TestSecurity_攻击类型_场景(t *testing.T) {
    // 说明: 测试目的和攻击向量

    // Arrange - 准备恶意输入
    maliciousInput := createMaliciousInput()

    // Act - 尝试攻击
    result, err := systemUnderTest(maliciousInput)

    // Assert - 验证系统正确拒绝
    require.Error(t, err, "系统应该拒绝恶意输入")
    assert.Equal(t, expectedHTTPStatus, getStatusCode(err))

    // 验证没有敏感信息泄露
    assert.NotContains(t, err.Error(), "internal")
    assert.NotContains(t, err.Error(), "stack")

    // 验证审计日志记录
    assertAuditLogContains(t, "security_event", maliciousInput.ID)
}
```

### 6.4 集成测试模板

```go
func TestIntegration_完整流程描述(t *testing.T) {
    // Setup - 创建测试环境
    ctx := context.Background()
    db := setupTestDB(t)
    defer cleanupTestDB(t, db)

    server := setupTestServer(t, db)
    client := server.Client()

    // Step 1: 创建前置条件
    app := createTestApp(t, db)
    user := createTestUser(t, db, app.ID)

    // Step 2: 执行主要操作
    wallet := createWallet(t, client, app, user)

    // Step 3: 验证结果
    assert.NotEmpty(t, wallet.Address)

    // Step 4: 验证数据库状态
    dbWallet := getWalletFromDB(t, db, wallet.ID)
    assert.Equal(t, wallet.Address, dbWallet.Address)

    // Step 5: 验证审计日志
    auditLogs := getAuditLogs(t, db, wallet.ID)
    assert.Len(t, auditLogs, 1)
    assert.Equal(t, "wallet_created", auditLogs[0].Action)
}
```

---

## 7. 测试数据管理

### 7.1 测试夹具 (Fixtures)

位置: `tests/fixtures/`

```
tests/fixtures/
├── apps/
│   ├── valid_app.json
│   └── suspended_app.json
├── users/
│   ├── valid_user.json
│   └── user_with_wallets.json
├── wallets/
│   ├── user_owned_wallet.json
│   ├── app_managed_wallet.json
│   └── wallet_with_policies.json
├── policies/
│   ├── allow_all.json
│   ├── deny_all.json
│   ├── whitelist_addresses.json
│   └── value_limit.json
├── keys/
│   ├── test_p256_keypair.json
│   └── test_ethereum_key.json
└── transactions/
    ├── valid_eth_transfer.json
    ├── contract_call.json
    └── eip712_typed_data.json
```

### 7.2 测试密钥

**重要**: 测试密钥只用于测试环境，绝不能用于生产！

```go
// tests/testdata/keys.go
var (
    // P-256 测试密钥对 (用于签名验证测试)
    TestP256PrivateKeyPEM = `-----BEGIN EC PRIVATE KEY-----
    ... 测试用密钥 ...
    -----END EC PRIVATE KEY-----`

    TestP256PublicKeyPEM = `-----BEGIN PUBLIC KEY-----
    ... 测试用公钥 ...
    -----END PUBLIC KEY-----`

    // Ethereum 测试私钥 (用于交易签名测试)
    TestEthereumPrivateKey = "0x..." // 测试网私钥
    TestEthereumAddress    = "0x..."
)
```

### 7.3 Mock 对象

位置: `tests/mocks/`

```go
// 需要 Mock 的外部依赖
type MockKMSProvider interface {
    Encrypt(ctx context.Context, data []byte) ([]byte, error)
    Decrypt(ctx context.Context, data []byte) ([]byte, error)
}

type MockJWKSProvider interface {
    GetKey(ctx context.Context, kid string) (*jose.JSONWebKey, error)
}

type MockEnclaveClient interface {
    Send(req *EnclaveRequest) (*EnclaveResponse, error)
}
```

---

## 8. 测试执行

### 8.1 本地执行

```bash
# 运行所有单元测试
go test ./...

# 运行带覆盖率
go test -cover ./...

# 运行特定包测试
go test -v ./internal/policy/...

# 运行特定测试
go test -v -run TestPolicyEngine ./internal/policy/...

# 生成覆盖率报告
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# 运行 race detector
go test -race ./...

# 运行安全测试
go test -v -tags=security ./tests/security/...

# 运行集成测试 (需要数据库)
go test -v -tags=integration ./tests/integration/...
```

### 8.2 CI/CD 集成

```yaml
# .github/workflows/test.yml
name: Tests

on: [push, pull_request]

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Run unit tests
        run: go test -race -coverprofile=coverage.out ./...

      - name: Check coverage
        run: |
          COVERAGE=$(go tool cover -func=coverage.out | grep total | awk '{print $3}' | sed 's/%//')
          if (( $(echo "$COVERAGE < 80" | bc -l) )); then
            echo "Coverage $COVERAGE% is below 80%"
            exit 1
          fi

  security-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5

      - name: Run security tests
        run: go test -v -tags=security ./tests/security/...

      - name: Run gosec
        run: |
          go install github.com/securego/gosec/v2/cmd/gosec@latest
          gosec ./...

  integration-tests:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: test
        ports:
          - 5432:5432
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5

      - name: Run integration tests
        env:
          POSTGRES_DSN: postgres://postgres:test@localhost:5432/test
        run: go test -v -tags=integration ./tests/integration/...
```

---

## 9. 验收标准

### 9.1 功能验收

| 类别 | 标准 |
|------|------|
| 单元测试覆盖率 | ≥ 85% (安全模块 100%) |
| 所有测试通过 | 100% 通过率 |
| 无 race condition | `go test -race` 无报错 |
| 无 vet 警告 | `go vet` 无输出 |

### 9.2 安全验收

| 类别 | 标准 |
|------|------|
| 所有信任边界测试 | 100% 覆盖 |
| 所有认证绕过测试 | 全部拒绝 |
| 所有授权绕过测试 | 全部拒绝 |
| 所有注入攻击测试 | 全部阻止 |
| 敏感数据泄露检查 | 无泄露 |
| gosec 扫描 | 无高危问题 |

### 9.3 性能验收

| 类别 | 标准 |
|------|------|
| 签名延迟 | < 100ms (P99) |
| 策略评估 | < 10ms |
| 数据库查询 | < 50ms |
| 内存无泄露 | 长时间运行稳定 |

---

## 10. 测试优先级

### P0 - 必须在发布前完成

- [ ] 所有信任边界测试
- [ ] 密钥管理安全测试
- [ ] 签名验证测试
- [ ] 策略引擎核心逻辑测试
- [ ] 多租户隔离测试
- [ ] Session Signer 限制测试

### P1 - 应该尽快完成

- [ ] 完整业务流程集成测试
- [ ] 错误处理路径测试
- [ ] 审计日志完整性测试
- [ ] 幂等性测试
- [ ] 边界条件测试

### P2 - 持续改进

- [ ] 性能测试
- [ ] 压力测试
- [ ] 混沌工程测试
- [ ] API 兼容性测试

---

## 11. 测试文件结构

```
better-wallet/
├── internal/
│   ├── api/
│   │   ├── wallet_handlers.go
│   │   └── wallet_handlers_test.go      # API 层单元测试
│   ├── app/
│   │   ├── wallet_service.go
│   │   └── wallet_service_test.go       # 服务层单元测试
│   ├── policy/
│   │   ├── engine.go
│   │   └── engine_test.go               # 策略引擎测试
│   └── ...
├── pkg/
│   ├── auth/
│   │   ├── multisig.go
│   │   └── multisig_test.go             # 签名验证测试
│   └── ...
└── tests/
    ├── fixtures/                         # 测试数据
    ├── mocks/                            # Mock 对象
    ├── testdata/                         # 测试密钥等
    ├── helpers/                          # 测试辅助函数
    ├── integration/                      # 集成测试
    │   ├── wallet_flow_test.go
    │   ├── policy_flow_test.go
    │   └── session_signer_test.go
    ├── security/                         # 安全测试
    │   ├── auth_bypass_test.go
    │   ├── injection_test.go
    │   └── isolation_test.go
    └── e2e/                              # 端到端测试
        └── full_flow_test.go
```

---

## 附录 A: 检查清单

### 新功能测试检查清单

- [ ] 正常流程测试
- [ ] 所有错误路径测试
- [ ] 边界条件测试
- [ ] 权限检查测试
- [ ] 多租户隔离测试
- [ ] 审计日志验证
- [ ] 幂等性验证（如适用）
- [ ] 文档更新

### 安全功能测试检查清单

- [ ] 认证要求验证
- [ ] 授权检查验证
- [ ] 输入验证测试
- [ ] 敏感数据处理测试
- [ ] 错误消息检查（无泄露）
- [ ] 日志检查（无敏感数据）
- [ ] 时间攻击防护验证

---

## 附录 B: 相关文档

- [CLAUDE.md](../CLAUDE.md) - 项目开发指南
- [API Documentation](./API.md) - API 接口文档
- [Security Model](./SECURITY.md) - 安全模型文档
