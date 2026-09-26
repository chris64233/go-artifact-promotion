# go-artifact-promotion

受证明材料（attestation）约束的软件制品晋级服务：制品只有在满足目标环境策略
（必备的有效证明类型、上游环境已放行）时，才能把环境指针原子切换到该版本。
全部状态可持久化到本地 JSON 文件，重启后完整恢复。

开发环境：Go 1.23.0。

## 领域模型

| 概念 | 说明 |
| --- | --- |
| `Digest` | 制品的不可变摘要，形如 `sha256:hex`，全局唯一标识一个制品 |
| `Artifact` | 已登记制品（摘要、算法、名称），内容不可变 |
| `Attestation` | 证明材料，记录**类型、签发者、结论、有效期**（`ValidFrom`/`ValidUntil`）及撤销状态；撤销只打标记不删记录 |
| `Policy` | 环境策略：必备的证明类型清单 + 可选的上游环境 |
| `EnvironmentPointer` | 环境当前指针：一个环境任意时刻只指向一个已晋级版本，带单调递增的 `Version` |
| `Promotion` | 一次成功晋级的永久记录，固化当时的**策略快照**与**证明快照** |

## 核心机制

### 1. 一致快照检查与原子切换

`Promote` 在**单一串行事务**内完成全部工作，读与写共享同一个状态快照：

1. 幂等检查（外部变更号）；
2. 校验制品、策略存在；
3. 版本条件检查（CAS）；
4. 读取该制品当前**全部可用证明**，对策略要求的每种类型挑选有效材料；
5. 检查上游环境指针是否正指向同一制品；
6. 全部条件成立后，晋级记录（含快照）与环境指针在同一事务内提交，
   任一步失败则整体回滚，指针绝不移动。

证明“有效”的判定（在晋级时刻 `now` 上）：未撤销、结论为 `approved`、
`ValidFrom <= now` 且 `now <= ValidUntil`（未设 `ValidUntil` 表示长期有效）。
同一类型存在多份候选材料时任一有效即可；全部无效时按
撤销 > 拒绝 > 过期 > 未生效 的优先级给出可区分的错误。

### 2. 撤销与晋级并发

- 证明在晋级快照中表现为已撤销 → 晋级失败，**已撤销的证明不能支撑新的成功结果**；
- 晋级先于撤销提交 → 成功，且记录中的证明快照永久保持撤销前状态。
  事后撤销或改写策略都不影响历史记录，可供追溯。

写操作由互斥锁串行化，因此“检查 + 切换”不存在 TOCTOU 窗口；
`TestRevokePromoteRace` 以 100 轮并发验证两种结局互斥。

### 3. 幂等、冲突与版本条件

- **外部变更号幂等**：同一变更号 + 同一环境 + 同一摘要的重放直接返回首次记录，
  不产生新版本、不重复校验（环境版本已变化也不影响重放）。
- **冲突**：同一变更号但环境或摘要不同，返回 `ErrChangeConflict`。
- **版本条件（CAS）**：晋级请求带 `ExpectedVersion`（环境首次晋级为 0），
  与当前版本不一致时返回 `ErrConcurrentModification`，阻止多制品争用环境时
  的静默覆盖。

## API 速览

```go
// 存储
svc := artifactpromotion.NewService()                       // 纯内存
svc, err := artifactpromotion.NewPersistentService("state.json") // JSON 持久化

// 制品登记（相同摘要+相同元数据幂等）
a, err := svc.RegisterArtifact(digest, "sha256", "api-server")

// 证明签发与撤销
att, err := svc.IssueAttestation(IssueAttestationRequest{
    Digest: digest, Type: "vuln-scan", Issuer: "security-team",
    Conclusion: ConclusionApproved,
})
err = svc.RevokeAttestation(att.ID, "key rotated")

// 策略配置（整体覆盖）
svc.ConfigurePolicy(Policy{
    Environment:          "prod",
    RequiredAttestations: []AttestationType{"vuln-scan", "sbom"},
    UpstreamEnvironment:  "staging", // 可选：要求已出现在上游环境
})

// 晋级
rec, err := svc.Promote(PromotionRequest{
    ChangeNumber:    "CHG-2026-0001",
    Environment:     "prod",
    Digest:          digest,
    ExpectedVersion: 0, // 发起方预期的环境当前版本
})

// 查询
ptr, _   := svc.GetPointer("prod") // 环境当前指向
hist, _  := svc.History("prod")    // 晋级历史（"" 为全部环境，按时间排序）
p, _     := svc.GetPromotion(rec.ID)
```

辅助函数：`ComputeDigest("sha256", data)` 计算标准摘要；
`NewService().WithClock(clock)` 可注入固定/可控时钟（测试与有效期回放）。

## 错误分类

所有业务错误均为哨兵错误，用 `errors.Is` 区分：

| 错误 | 触发场景 |
| --- | --- |
| `ErrInvalidArgument` | 入参不合法（摘要格式、缺字段、有效期倒置、重复撤销等） |
| `ErrArtifactNotFound` | 制品未登记 |
| `ErrAttestationNotFound` | 证明不存在 |
| `ErrPolicyNotFound` | 目标环境（或引用的上游环境）策略未配置 |
| `ErrMissingAttestation` | 策略要求的某类证明完全不存在 |
| `ErrAttestationRevoked` | 该类型证明均已撤销 |
| `ErrAttestationExpired` / `ErrAttestationNotYetValid` | 证明超出有效期 |
| `ErrAttestationRejected` | 证明结论非 approved |
| `ErrUpstreamNotPromoted` | 上游环境当前未指向该制品 |
| `ErrChangeConflict` | 变更号已被其他环境/制品使用 |
| `ErrConcurrentModification` | 版本条件与当前环境指针不一致 |
| `ErrPromotionNotFound` | 晋级记录不存在 |

失败的晋级不移动指针、不写历史、不消耗变更号（修正条件后可用原变更号重试）。

## 持久化

`NewPersistentService(path)` 把全部状态（制品、证明、策略、指针、历史、
变更号索引、ID 计数器）存为单个 JSON 文件。每次成功提交先写临时文件再
原子 `rename`，进程崩溃不会留下半截状态；重新打开后幂等语义与版本号均延续。

## 测试

```bash
go test -race ./...          # 全部测试（含并发竞态检测）
go test -cover ./...         # 覆盖率（当前约 94%）
```

测试覆盖：登记/签发/撤销/策略配置的正常与非法路径、五类证明失败原因、
撤销与晋级并发（100 轮）、8 路环境争用（50 轮，恰好一个成功）、
变更号幂等与冲突、CAS 版本条件、上游环境链、有效期边界，以及
落盘-重启恢复与损坏状态文件。
