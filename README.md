# go-artifact-promotion

受证明材料（attestation）约束的软件制品晋级服务：制品只有在满足目标环境策略
（必备的有效证明类型、上游环境已放行）时，才能把环境指针原子切换到该版本。
在晋级之上还提供**紧急回滚**（创建冻结、普通/紧急双通道、双人批准、条件
执行、一次性通知 outbox、审计）、**历史版本安全撤销**与**受影响下游环境
追踪**，以及**跨环境分批回滚计划**（一个目标制品、多个环境、按批次推进、
失败暂停/恢复/取消）。全部状态可持久化到本地 JSON 文件，重启后完整恢复。

开发环境：Go 1.23.0。

## 领域模型

| 概念 | 说明 |
| --- | --- |
| `Digest` | 制品的不可变摘要，形如 `sha256:hex`，全局唯一标识一个制品 |
| `Artifact` | 已登记制品（摘要、算法、名称），内容不可变 |
| `Attestation` | 证明材料，记录**类型、签发者、结论、有效期**（`ValidFrom`/`ValidUntil`）及撤销状态；撤销只打标记不删记录，并推进全局**证明修订号** |
| `Policy` | 环境策略：必备的证明类型清单 + 可选的上游环境；带单调递增的策略修订号 `Version` |
| `EnvironmentPointer` | 环境当前指针：一个环境任意时刻只指向一个已晋级版本，带单调递增的 `Version` |
| `Promotion` | 一次成功晋级的永久记录，固化当时的**策略快照**与**证明快照**；可被安全撤销（打标记，不删除） |
| `RollbackPlan` | 一笔回滚计划：创建时冻结**目标版本、当前环境版本、策略版本（策略快照）、证明修订号、发起原因** |
| `RollbackApproval` | 授权人对紧急回滚的批准证据（批准人、意见、时间） |
| `StagedRollbackPlan` | 跨环境分批回滚计划：创建时冻结**目标制品、环境（批次）顺序、各环境目标版本、各环境当前版本与策略快照、证明修订号**；每个环境条目带独立的状态、结果版本与阻断原因 |
| `StagedBatchReport` | 单批执行报告：批内每个环境采用的版本、结果状态（pending/succeeded/blocked/conflicted/skipped）与阻断原因 |
| `AuditEvent` | 不可变审计事件；紧急回滚全过程与安全撤销产生**高优先级**事件 |
| `OutboxMessage` | 回滚执行后在同一事务内写入的一次性通知（事务型 outbox） |

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

### 4. 回滚：创建冻结 → 批准 → 条件执行

回滚分三阶段，全部写操作在同一串行事务模型内完成，检查与切换共享快照。

**创建（`CreateRollback`）** 时校验并冻结：

- 目标必须是该环境**历史上成功晋级过**、**未被安全撤销**、且**不是当前指针**
  的制品版本（候选可用 `RollbackCandidates` 查询）；
- 冻结目标版本（最近一次对应晋级记录 ID 与当时环境版本）、**当前环境版本**
  （版本号 + 摘要 + 指针来源记录）、**策略版本**（修订号 + 完整策略快照）、
  全局**证明修订号**与发起原因（必填）；
- 回滚号幂等：同号 + 同环境/同目标/同类型重放返回已有计划；同号不同目标或
  环境返回 `ErrChangeConflict`。紧急回滚创建时即写一条高优先级审计事件。

**批准（`ApproveRollback`）**：仅紧急回滚接受批准，必须取得**两个不同授权
人**——同一批准人重复批准被拒（`ErrInvalidArgument`），对普通回滚或已终结
计划批准返回 `ErrRollbackState`。批准人、意见、时间作为审批证据固化在计划上
（`GetRollback` 可取回），每次批准都写高优先级审计事件。

**执行（`ExecuteRollback`）** 的条件检查顺序：

1. **环境版本条件（原子切换）**：指针的版本号、摘要、来源记录必须与冻结值
   完全一致。期间若有新的晋级或另一笔回滚先落地，返回
   `ErrConcurrentModification`，计划终结为 `conflicted`，**绝不覆盖较新的
   环境状态**；
2. **证明修订条件**：全局证明修订号必须仍等于冻结值。计划创建后若有证明
   撤销先落地（即使撤销的是别的制品的证明），旧计划同样返回冲突——需要基于
   新状态重新创建计划；
3. **目标安全撤销检查**：目标晋级版本在执行前被安全撤销 →
   `ErrRollbackTargetInvalid`；
4. **策略门槛**：
   - **普通回滚**仍需满足执行时刻的**当前策略**：目标制品的证明在执行时刻
     全部有效、上游环境当前正指向目标（证明过期/策略加严/上游移走都会拒绝）；
   - **紧急回滚**可绕过证明有效性要求（过期或策略加严都不阻止），但**上游
     环境不变量按冻结的策略快照保留**，且缺少两个不同授权人批准时返回
     `ErrRollbackNotApproved`。

全部条件成立后：指针原子切换到目标（**版本号继续单调递增**，来源记录指向
那笔历史晋级）、计划状态推进、**outbox 通知**与审计事件在**同一事务**写入。
回滚只移动当前指针，**不删除任何后续晋级历史**。

### 5. 幂等执行、一次性 outbox 与冲突终结

- 已执行计划重复执行同号，直接返回**首次结果**（即使此后环境又被晋级或
  回滚），不重复检查条件、不重复切换、**outbox 只生成一条通知**；
- 同号不同目标在创建阶段即冲突（`ErrChangeConflict`）；
- 冲突终结的计划重放仍返回同一个 `ErrConcurrentModification`，不会复活。
- outbox 消息可通过 `PendingOutbox` 拉取、`MarkOutboxDispatched` 确认投递；
  `OutboxForRollback` 按回滚号查那唯一一条通知。

### 6. 安全撤销

`RevokePromotionSafety(promotionID, actor, reason)` 把历史晋级版本标记为
不安全：只打标记、不删除历史。被撤销版本立即从 `RollbackCandidates` 消失，
针对它的待执行计划在执行时返回 `ErrRollbackTargetInvalid`；时间线对应晋级
节点带 `SafetyRevoked` 标记。该操作产生高优先级审计事件。

### 7. 时间线与受影响下游环境

- `Timeline(env)`：把全部晋级与已执行回滚按**环境版本号**合并排序
  （回滚也占一个新版本号），晋级节点带变更号，回滚节点带回滚号/目标晋级/
  是否紧急；回滚之后的晋级历史完整保留。
- `AffectedDownstreams(env)`：沿各环境策略的上游依赖链做传递遍历，凡
  **当前指针与其直接上游当前指针不一致**的环境都列为受影响（`Direct`
  区分直接/间接下游）——即 env 回滚（或重新晋级）后，曾经依据旧上游指针
  放行的下游环境不再满足“上游当前正指向同一制品”的不变量，需要重新评估或
  晋级。
- `AuditLog(env, highOnly)`：审计事件查询，可只看高优先级。

### 8. 跨环境分批回滚（暂停 / 恢复 / 取消）

`CreateStagedRollback` 发起一笔覆盖多个环境的回滚计划：**统一目标制品**、
**按批次排列的环境顺序**、批内按给出的顺序执行。一笔计划在同一串行事务
模型内推进，任何时刻都能说明“每个环境最终采用了哪个版本”。

**创建时冻结**（任何一个环境不满足都整笔拒绝创建）：

- 目标制品必须在每个目标环境都**历史上成功晋级过、未被安全撤销、且不是
  当前指针**（`ErrRollbackTargetInvalid`）；制品未登记返回
  `ErrArtifactNotFound`，环境策略未配置返回 `ErrPolicyNotFound`；
- 每个环境冻结：目标版本（最近一次对应成功晋级记录 ID 与当时环境版本）、
  **当前环境版本**（版本号+摘要+来源记录）、**策略版本与完整策略快照**、
  全局**证明修订号**；计划还冻结统一原因；
- 至少一批、每批至少一个环境、同一环境不得在计划中重复；同一环境不能同时
  被两笔未终结（pending/paused）的分批计划覆盖（`ErrStagedRollbackState`），
  计划终结（completed/conflicted/canceled）后该环境才可重新加入；
- 外部分批回滚号幂等：同号 + 同类型/同目标/同批次顺序的重放返回已有计划；
  任一字段不同返回 `ErrChangeConflict`。紧急计划创建即写高优先级审计。

**执行 `ExecuteStagedRollback`** 在一个事务快照内分两阶段：

1. **版本冲突预检（针对所有尚未成功的环境）**：
   - 目标晋级记录被安全撤销 → `ErrRollbackTargetInvalid`；
   - 环境指针偏离冻结的版本/摘要/来源记录 → `ErrConcurrentModification`；
   - 全局证明修订号在创建后推进（期间有任何证明撤销）→
     `ErrConcurrentModification`。

   任一命中，计划**立即终结为 `conflicted`**，预检阶段不切换任何指针、不写
   outbox，所有已成功环境保持原状，冲突原因代码（`target_safety_revoked` /
   `environment_version_conflict` / `attestation_revision_conflict`）固化在
   首个冲突环境与计划级，重放永远返回同一冲突、不可复活。
2. **按批次顺序推进**：紧急计划先校验两个不同授权人批准；逐环境做门槛检查
   （普通计划满足**执行时刻当前策略**：证明有效 + 上游指针；紧急计划绕过
   证明但按**冻结策略快照**保留上游不变量）。**一批全部成功后才进入下一批**；
   每个环境成功都原子切换指针（版本号继续单调递增）、固化 `ResultVersion`，
   并在同一事务写一条 outbox 通知（`PendingStagedOutbox`）与审计事件。

**暂停（paused）、恢复（resume）、取消（canceled）三者的区别**：

| | 触发 | 对已成功环境 | 对阻断/未开始环境 | 后续 |
| --- | --- | --- | --- | --- |
| **暂停 paused** | 批次中某个环境门槛失败（缺批准、证明过期/缺类、上游未指向目标、策略缺失） | **保持现状、结果版本固化**，绝不回滚 | 阻断环境记 `blocked`+原因代码；其后环境仍 `pending` | 用**同一计划号再次调用** `ExecuteStagedRollback` 即**恢复：从失败环境继续**，已成功环境不重试、不重复发通知；阻断修复前重放仍返回原门槛错误并累加尝试计数 |
| **版本冲突 conflicted** | 尚未成功的环境指针漂移、目标被安全撤销、证明修订号推进 | 保持现状 | 首个冲突环境记 `conflicted`，计划终结 | **不可恢复**，只能基于新状态新建计划；重放返回同一冲突 |
| **取消 canceled** | 人工 `CancelStagedRollback`（需操作人+原因） | **绝不回滚，也不能被重新加入同一计划** | `pending`/`blocked` 环境转为 `skipped`，后续批次不再执行 | 终结状态：重复取消幂等返回；再执行/批准返回 `ErrStagedRollbackState`；已完成或已冲突的计划不能取消 |

注意暂停期间的版本漂移同样致命：恢复时预检会发现被阻断或未开始环境的指针
已偏离冻结值（或目标被撤销、证明被撤销），计划从 paused **终结为
conflicted**——这正是“尚未开始的环境版本变化时旧计划拒绝执行”的语义。

紧急分批计划通过 `ApproveStagedRollback` 取得两个**不同授权人**批准
（同一人重复批准被拒；普通计划不接受批准；仅 pending/paused 可批准）。

**查询**：`GetStagedRollback(number)` 返回计划（含审批证据）；
`plan.BatchReports()` 按批次给出每批汇总状态（pending / in_progress /
succeeded / blocked / conflicted / canceled / partially_canceled）与批内每个
环境的**采用版本、结果状态、阻断原因代码**；`plan.EntryByEnv(env)` 取单环境
结果；`StagedOutboxForPlan(number)` 取该计划已生成的全部逐环境通知。分批
回滚落地节点同样出现在各环境的 `Timeline` 中（kind 为 `staged_rollback`）。

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

// 查询可回滚候选（历史上成功晋级、未安全撤销、非当前版本）
cands, _ := svc.RollbackCandidates("prod")

// 创建回滚（冻结目标/当前环境版本/策略版本/证明修订号/原因）
plan, err := svc.CreateRollback(CreateRollbackRequest{
    Number:       "RB-2026-0007",
    Kind:         artifactpromotion.RollbackEmergency, // 或 RollbackNormal
    Environment:  "prod",
    TargetDigest: olderDigest,
    Reason:       "SEV-1: 新版本引发错误率飙升",
    RequestedBy:  "oncall",
})

// 紧急回滚：两个不同授权人批准（审批证据随计划持久化）
svc.ApproveRollback(plan.Number, "alice", "confirmed incident")
svc.ApproveRollback(plan.Number, "bob", "approved rollback")

// 执行：冻结的环境版本/证明修订已变化时返回 ErrConcurrentModification
done, err := svc.ExecuteRollback(plan.Number)

// 跨环境分批回滚：一个目标制品，按批次覆盖多个环境
staged, err := svc.CreateStagedRollback(CreateStagedRollbackRequest{
    Number:       "SR-2026-0002",
    Kind:         artifactpromotion.RollbackNormal, // 或 RollbackEmergency
    TargetDigest: olderDigest,
    Batches: []StagedBatchRequest{
        {Environments: []Environment{"dev"}},               // 第 1 批
        {Environments: []Environment{"staging"}},           // 第 1 批全成功后才执行
        {Environments: []Environment{"prod-canary", "prod"}},
    },
    Reason:      "SEV-2: 分环境逐步回退有缺陷的版本",
    RequestedBy: "oncall",
})

// 推进/恢复：门槛失败返回错误且计划 paused；修复后用同一计划号再次调用，
// 从失败批次继续。已完成计划的重放幂等返回首次结果。
staged, err = svc.ExecuteStagedRollback(staged.Number)

// 紧急分批计划：两个不同授权人（pending/paused 期间都可批准）
svc.ApproveStagedRollback(staged.Number, "alice", "confirmed")
svc.ApproveStagedRollback(staged.Number, "bob", "approved")

// 取消：只跳过未开始/被阻断的环境，已成功环境不回滚
svc.CancelStagedRollback(staged.Number, "oncall", "mitigated by forward fix")

// 查询每批采用的版本、结果与阻断原因
got, _ := svc.GetStagedRollback(staged.Number)
for _, r := range got.BatchReports() { // r.Status + 每个 r.Entries[i].ResultVersion/Status/BlockCode
}
stagedMsgs, _ := svc.PendingStagedOutbox()          // 分批回滚的逐环境通知
msgs, _       := svc.StagedOutboxForPlan(staged.Number)

// 安全撤销某个历史晋级版本（高优先级审计）
svc.RevokePromotionSafety(rec.ID, "security", "signing key compromised")

// 查询
ptr, _   := svc.GetPointer("prod")          // 环境当前指向
hist, _  := svc.History("prod")             // 晋级历史（传 "" 为全部环境，按时间排序）
tl, _    := svc.Timeline("prod")            // 晋级 + 已执行回滚的版本时间线
rb, _    := svc.GetRollback(plan.Number)    // 单笔计划含审批证据
aff, _   := svc.AffectedDownstreams("prod") // 指针不一致的直接/间接下游
audit, _ := svc.AuditLog("prod", true)      // 仅高优先级审计事件
pending, _ := svc.PendingOutbox()           // 未投递的一次性通知
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
| `ErrChangeConflict` | 变更号/回滚号已被其他环境或制品使用（含同号不同目标的回滚） |
| `ErrConcurrentModification` | 版本条件与当前环境指针不一致；或回滚执行时冻结的环境版本/证明修订号已被新的晋级、另一笔回滚或证明撤销抢先改变 |
| `ErrPromotionNotFound` | 晋级记录不存在 |
| `ErrRollbackNotFound` | 回滚计划不存在 |
| `ErrRollbackTargetInvalid` | 目标从未成功晋级到该环境、已是当前版本，或已被安全撤销（创建/执行时） |
| `ErrRollbackNotApproved` | 紧急回滚未取得两个不同授权人批准 |
| `ErrRollbackState` | 对普通回滚追加批准，或计划已终结（已执行/已冲突）后再批准 |
| `ErrStagedRollbackNotFound` | 分批回滚计划不存在 |
| `ErrStagedRollbackState` | 分批计划状态不允许该操作（活动计划覆盖同一环境、对已取消/已冲突计划执行或批准、取消已完成/已冲突计划等） |

失败的晋级不移动指针、不写历史、不消耗变更号（修正条件后可用原变更号重试）。

分批回滚的门槛失败不使用独立错误哨兵：执行直接返回底层门槛错误
（`ErrRollbackNotApproved` / `ErrMissingAttestation` /
`ErrAttestationRevoked` / `ErrAttestationExpired` /
`ErrUpstreamNotPromoted` / `ErrPolicyNotFound`），同时计划转为 `paused`，
原因代码固化在 `BlockCode` 上；版本冲突类错误终结计划为 `conflicted`。

## 持久化

`NewPersistentService(path)` 把全部状态（制品、证明、证明修订号、策略与策略
修订号、指针、晋级历史、单笔回滚计划、跨环境分批回滚计划（批次、逐环境冻结
与结果、审批证据）、回滚号索引、审计事件、outbox、各 ID 计数器）存为单个
JSON 文件。每次成功提交先写临时文件再原子 `rename`，进程崩溃不会留下半截
状态；重新打开后幂等语义、暂停/取消状态、审批证据、outbox 一次性保证与各
版本号/修订号均延续。旧版本写出的状态文件可直接打开，新增字段自动补默认值。

## 测试

```bash
go test -race ./...          # 全部测试（含并发竞态检测）
go test -cover ./...         # 覆盖率
```

新增回滚相关的测试覆盖：

- **创建**：目标合法性（从未晋级/是当前版本/安全撤销）、创建时冻结内容
  （目标版本、当前环境版本、策略版本、证明修订号、原因）、回滚号幂等与
  同号冲突；
- **普通回滚**：成功切换（版本号继续递增、历史不删除、outbox 与普通优先级
  审计）以及执行时当前策略拒绝（证明过期、策略加严、上游移走）；
- **紧急回滚**：零/单人批准被拒、同人重复批准被拒、双人不同人放行、过期
  证明与加严策略绕过、上游不变量保留、创建+2 次批准+执行共 4 条高优先级
  审计事件；
- **冲突**：新晋级抢先、两笔回滚（恰好一个落地）、证明撤销推进修订号后
  旧计划冲突并终结、目标执行前被安全撤销；
- **幂等**：已执行计划在其后又有晋级时重放仍返回首次结果、outbox 仅一条；
- **查询**：时间线合并、候选排除当前版本与撤销版本、受影响下游的直接/
  间接遍历；
- **并发与持久化**：回滚 vs 晋级 100 轮竞态（恰好一个赢家，输家 plan 终结
  且无 outbox）、紧急回滚全流程落盘-重启恢复（计划/批准/outbox/审计/时间线
  全部延续，重启后执行仍幂等）。

分批回滚相关的测试覆盖（`staged_test.go`）：

- **创建**：冻结目标/各环境当前版本/策略快照/证明修订号/批次顺序；参数校验
  （空批次/空环境/环境重复/目标从未晋级/目标即当前版本）；活动计划环境重叠
  拒绝；同号幂等与同号不同批次/类型冲突；
- **全成功**：多批次与批内多环境顺序执行、每环境版本递增、批次报告、
  逐环境 outbox 与单笔 outbox 队列隔离、时间线 `staged_rollback` 节点、
  普通优先级审计；完成后重放幂等（之后环境再被晋级也不回拉、不重发通知）；
- **暂停/恢复**：上游未对齐与策略加严把计划暂停在失败环境（已完成批次保持
  现状）、阻断条目带原因代码与尝试计数、补齐条件后同号恢复从失败批次继续、
  已成功环境不重试不重发通知、批内顺序对上游不变量的影响；
- **版本冲突**：执行前/暂停期间未开始环境被外部晋级抢占、证明撤销推进修订
  号、目标晋级被安全撤销——计划终结 conflicted、所有指针不动、无 outbox、
  重放返回同一冲突（粘性），终结后环境可重新加入新计划；
- **取消**：开始前取消（全部 skipped、零通知、幂等取消）、暂停后取消
  （已成功环境保持落地、其余 skipped、部分成功批次报告 partially_canceled）、
  已完成/已冲突计划不可取消、被跳过环境可另起计划；
- **紧急分批**：零/单人批准暂停、同人重复批准被拒、双人放行、过期证明与
  加严策略绕过、冻结策略快照的上游不变量保留、6 条高优先级审计、通知载荷
  带批准人与紧急标记；
- **持久化**：紧急计划全流程落盘重启、普通计划暂停状态跨重启后继续推进。
