# go-artifact-promotion

受证明材料（attestation）约束的软件制品晋级服务。制品按不可变摘要登记，
只有在目标环境策略要求的全部条件于同一一致快照下成立时，环境指针才会原子切换。

开发环境：Go 1.23.0。

## 核心概念

| 概念 | 类型 | 说明 |
| --- | --- | --- |
| 制品 | `Artifact` | 由内容摘要（如 `sha256:...`）唯一标识，登记后不可变；同摘要不同内容重复登记返回 `ErrArtifactConflict` |
| 证明 | `Attestation` | 记录类型、签发者、结论（`PASS`/`FAIL`）和有效期 `[NotBefore, NotAfter)`；只能撤销不能删除 |
| 策略 | `Policy` | 按环境配置：`RequiredAttestations` 列出必须具备的有效证明类型，`RequiredUpstreams` 列出制品必须已晋级到的上游环境 |
| 环境指针 | `EnvironmentState` | 一个环境任意时刻只指向一个已晋级版本；`Version` 单调递增，作为晋级的版本条件 |
| 晋级记录 | `PromotionRecord` | 不可变，永久保存晋级时刻的策略快照与全部可用证明快照（含当时的撤销状态），供后续追溯 |

## 晋级流程

`Service.Promote` 全程持有同一把互斥锁，构成一致快照：

1. **幂等判定**：`ChangeID`（外部变更号）已存在时，目标环境与制品摘要一致则直接返回原记录（幂等重放），否则返回 `ErrChangeConflict`。
2. **快照加载**：读取当时的策略、制品、环境指针与该制品的全部可用证明。
3. **策略校验**：每类必需证明都必须存在一份当前有效（未撤销、结论 `PASS`、在有效期内）的证明；制品必须是每个上游环境的当前版本。
4. **版本条件**：环境当前版本必须等于请求携带的 `ExpectedVersion`，否则返回 `ErrVersionConflict`，防止多个制品争用同一环境时静默覆盖。
5. **原子切换**：全部条件成立后，环境指针切换、版本递增、带快照的晋级记录写入，一次性完成并持久化。

## 并发语义

- **撤销 vs 晋级**：二者在同一临界区内串行。撤销先生效，则晋级因证明失效而失败（`ErrMissingAttestation`）；晋级先完成，则记录中永久保留当时的证明快照，之后的撤销不影响已完成的晋级。
- **晋级 vs 晋级**：共享环境版本号做比较并交换，后到者收到 `ErrVersionConflict`，重新读取版本后可重试。

## 错误分类

所有业务错误都是哨兵错误，可用 `errors.Is` 区分：

`ErrInvalidInput`、`ErrArtifactNotFound`、`ErrArtifactConflict`、`ErrAttestationNotFound`、`ErrPolicyNotFound`、`ErrMissingAttestation`、`ErrUpstreamNotSatisfied`、`ErrChangeConflict`、`ErrVersionConflict`。

## 使用示例

```go
store := artifactpromotion.NewFileStore("state.json")
svc, _ := artifactpromotion.NewService(store, nil) // nil 使用真实时钟

svc.RegisterArtifact(artifactpromotion.Artifact{Digest: "sha256:aaa", Name: "web", Version: "1.0.0"})
svc.IssueAttestation(artifactpromotion.Attestation{
    Digest: "sha256:aaa", Type: "unit-tests", Issuer: "ci-bot",
    Conclusion: artifactpromotion.ConclusionPass,
    NotBefore: time.Now(), NotAfter: time.Now().Add(24 * time.Hour),
})
svc.SetPolicy(artifactpromotion.Policy{
    Environment:          "prod",
    RequiredAttestations: []string{"unit-tests"},
    RequiredUpstreams:    []string{"staging"},
})

env := svc.Environment("prod") // 读取当前版本作为版本条件
rec, err := svc.Promote(artifactpromotion.PromoteRequest{
    ChangeID:        "deploy-2026-09-26-001",
    Environment:     "prod",
    Digest:          "sha256:aaa",
    ExpectedVersion: env.Version,
})

history := svc.History("prod") // 查询晋级历史（含证明快照）
```

## 持久化

`FileStore` 把全部状态以 JSON 写入单个文件（先写临时文件再原子重命名），
重启后经 `NewService` 自动恢复：环境指针、证明撤销状态、幂等索引与晋级历史均不丢失。
测试可使用不落盘的 `MemStore`。

## 运行测试

    go test ./... -race
