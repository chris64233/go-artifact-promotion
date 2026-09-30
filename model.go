package artifactpromotion

import "time"

// Digest 是制品的不可变摘要（如 sha256:hex）。同一摘要全局唯一标识一个制品。
type Digest string

// Environment 是部署环境名称，例如 dev、staging、prod。
type Environment string

// AttestationType 是证明类型，例如 vuln-scan、sbom、sign-off。
type AttestationType string

// Conclusion 是证明结论。只有 ConclusionApproved 可支撑晋级。
type Conclusion string

const (
	ConclusionApproved Conclusion = "approved"
	ConclusionRejected Conclusion = "rejected"
)

// Artifact 是已登记的不可变制品元数据。
type Artifact struct {
	Digest       Digest
	Algorithm    string // 摘要算法，例如 sha256
	Name         string // 可读名称
	RegisteredAt time.Time
}

// Attestation 是针对某个制品签发的证明材料。
//
// 撤销不会删除记录：RevokedAt 非空即表示已撤销。撤销时间作为判定依据，
// 以便和并发晋级比较先后（见 Service.Promote 的快照检查）。
type Attestation struct {
	ID         string
	Digest     Digest
	Type       AttestationType
	Issuer     string
	Conclusion Conclusion
	// ValidFrom/ValidUntil 界定有效期；ValidUntil 为零值表示长期有效。
	ValidFrom    time.Time
	ValidUntil   time.Time
	IssuedAt     time.Time
	RevokedAt    time.Time // 零值表示未撤销
	RevokeReason string
}

// Revoked 报告证明是否已撤销。
func (a Attestation) Revoked() bool { return !a.RevokedAt.IsZero() }

// Policy 是某个环境当前生效的晋级策略。
type Policy struct {
	Environment          Environment
	RequiredAttestations []AttestationType // 必须具备的有效证明类型（每种至少一份）
	// UpstreamEnvironment 非空时，要求制品已经晋级到该上游环境。
	UpstreamEnvironment Environment
	// Version 是策略在该环境上的单调修订号，每次整体覆盖配置时 +1。
	// 回滚计划创建时冻结该值，用于记录“当时的策略版本”。
	Version   int64
	UpdatedAt time.Time
}

// AttestationSnapshot 是一次晋级所采用的单份证明的存档副本，
// 连同证明 ID 与当时的撤销状态一并固化，供后续追溯。
type AttestationSnapshot struct {
	Attestation
}

// Promotion 是一次成功晋级的永久记录。
//
// 记录中固化了晋级时刻的策略（PolicySnapshot）与采用的证明快照
// （Attestations），事后即使证明被撤销或策略被改写，历史记录也保持不变。
type Promotion struct {
	ID           int64
	ChangeNumber string      // 外部变更号，全局唯一，保证幂等
	Environment  Environment // 目标环境
	Digest       Digest      // 晋级的制品
	// ExpectedVersion 是发起方预期的环境版本；空表示不检查（允许从空环境首次晋级）。
	ExpectedVersion int64
	// Version 是本次切换完成后环境的版本号，从 1 开始单调递增。
	Version        int64
	Attestations   []AttestationSnapshot
	PolicySnapshot Policy
	PromotedAt     time.Time

	// 安全撤销只打标记、不删除记录：SafetyRevokedAt 非零表示该晋级版本
	// 事后被认定为不安全（例如所携证明对应制品被召回）。被安全撤销的版本
	// 不再出现在可回滚候选中，已创建未执行的回滚计划在执行时也会被拒绝。
	SafetyRevokedAt    time.Time
	SafetyRevokeReason string
	SafetyRevokedBy    string
}

// SafetyRevoked 报告该晋级版本是否已被安全撤销。
func (p Promotion) SafetyRevoked() bool { return !p.SafetyRevokedAt.IsZero() }

// EnvironmentPointer 是某一部署环境当前指向的已晋级版本。
// 任意时刻一个环境最多只指向一个制品。
type EnvironmentPointer struct {
	Environment Environment
	Digest      Digest
	Version     int64 // 当前版本号；0 表示该环境还从未晋级
	PromotionID int64
	UpdatedAt   time.Time
}

// RollbackKind 区分普通回滚与紧急回滚。
type RollbackKind string

const (
	// RollbackNormal 普通回滚：执行时目标仍需满足当前策略的全部证明要求。
	RollbackNormal RollbackKind = "normal"
	// RollbackEmergency 紧急回滚：可绕过证明要求，但必须取得两个不同授权人批准。
	RollbackEmergency RollbackKind = "emergency"
)

// RollbackStatus 是回滚计划的生命周期状态。
type RollbackStatus string

const (
	RollbackPending    RollbackStatus = "pending"    // 已创建，等待（批准与）执行
	RollbackExecuted   RollbackStatus = "executed"   // 已执行，指针已切换
	RollbackConflicted RollbackStatus = "conflicted" // 执行时环境已被更新的操作抢先改变
)

// RollbackPlan 是一笔回滚计划。创建时冻结目标版本、当前环境版本、策略版本
// （策略快照）、全局证明修订号与发起原因；执行时据此做条件检查，过期计划
// 绝不覆盖较新的环境状态。
type RollbackPlan struct {
	ID     int64
	Number string // 外部回滚号，全局唯一，保证创建/执行幂等
	Kind   RollbackKind

	Environment Environment

	// 冻结的目标：目标制品 + 它在该环境最近一次成功晋级的记录。
	TargetDigest      Digest
	TargetPromotionID int64
	TargetVersion     int64 // 目标晋级当时的环境版本号（仅作存档）

	// 创建时冻结的环境状态：执行时必须仍与之完全一致，否则判定为冲突。
	FrozenCurrentDigest  Digest
	FrozenCurrentVersion int64
	FrozenCurrentPromoID int64
	FrozenPolicyVersion  int64 // 创建时当前策略修订号
	PolicySnapshot       Policy
	// FrozenAttestationRevision 是创建时的全局证明修订号。它只在证明撤销时
	// 推进；计划执行时若已推进，说明期间发生过证明撤销（紧急回滚场景下尤其
	// 可能是支撑证明被撤销），旧计划必须返回冲突。
	FrozenAttestationRevision int64

	Reason      string // 发起原因（必填）
	RequestedBy string
	CreatedAt   time.Time

	Status     RollbackStatus
	Approvals  []RollbackApproval
	ExecutedAt time.Time
	// ResultVersion/ResultPromotionID 是执行完成后环境的新版本与指针来源记录。
	ResultVersion     int64
	ResultPromotionID int64
}

// RollbackApproval 是一位授权人对（紧急）回滚计划的批准证据。
type RollbackApproval struct {
	Approver  string
	Comment   string
	GrantedAt time.Time
}

// AuditPriority 是审计事件优先级。
type AuditPriority string

const (
	AuditPriorityNormal AuditPriority = "normal"
	AuditPriorityHigh   AuditPriority = "high"
)

// AuditAction 标识审计事件类型。
type AuditAction string

const (
	AuditRollbackCreated  AuditAction = "rollback.created"
	AuditRollbackApproved AuditAction = "rollback.approved"
	AuditRollbackExecuted AuditAction = "rollback.executed"
	AuditSafetyRevocation AuditAction = "promotion.safety_revoked"
	// 跨环境分批回滚计划的生命周期事件。
	AuditStagedRollbackCreated  AuditAction = "staged_rollback.created"
	AuditStagedRollbackApproved AuditAction = "staged_rollback.approved"
	AuditStagedRollbackExecuted AuditAction = "staged_rollback.executed" // 每个环境一条
	AuditStagedRollbackCanceled AuditAction = "staged_rollback.canceled"
)

// AuditEvent 是不可变的审计事件。紧急回滚与安全撤销产生高优先级事件。
type AuditEvent struct {
	ID          int64
	Action      AuditAction
	Priority    AuditPriority
	Environment Environment
	// RollbackNumber / PromotionID 标识事件关联的对象（按事件类型二选一）。
	RollbackNumber string
	// StagedNumber 标识事件关联的跨环境分批回滚号（分批回滚事件使用）。
	// 计划级事件（创建/批准/取消）的 Environment 为空；逐环境执行事件同时
	// 记录 Environment。
	StagedNumber string
	PromotionID  int64
	Actor        string
	Detail       string
	OccurredAt   time.Time
}

// OutboxMessage 是回滚执行后在同一事务内写入的一次性通知。
// 相同回滚号重复执行只返回首次结果，绝不会产生第二条消息。
type OutboxMessage struct {
	ID             int64
	RollbackNumber string
	// StagedNumber 非空表示这是跨环境分批回滚中某个环境落地时生成的通知
	// （此时 RollbackNumber 为空），可用 PendingStagedOutbox 拉取。
	StagedNumber string
	Environment  Environment
	// FromDigest/ToDigest 记录指针从哪个制品切换回哪个制品。
	FromDigest Digest
	ToDigest   Digest
	Kind       RollbackKind
	Payload    string
	CreatedAt  time.Time
	// DispatchedAt 非零表示已被外部投递器取走（MarkOutboxDispatched）。
	DispatchedAt time.Time
}

// TimelineEntry 是环境版本时间线上的一个节点：一次晋级，或一次已执行的回滚。
type TimelineEntry struct {
	Environment Environment
	// Version 是该节点落地后的环境版本号；回滚同样消耗一个新版本号。
	Version int64
	// Kind 为 "promotion"、"rollback" 或 "staged_rollback"。
	Kind string
	// Digest 是该节点之后环境指向的制品。
	Digest         Digest
	PromotionID    int64  // Kind=promotion 时的晋级记录
	RollbackNumber string // Kind=rollback 时的回滚号
	StagedNumber   string // Kind=staged_rollback 时的分批回滚计划号
	// TargetPromotionID 用于回滚节点：回到的那笔历史晋级。
	TargetPromotionID int64
	ChangeNumber      string // 晋级节点的外部变更号
	Emergency         bool   // 回滚节点是否为紧急回滚
	// SafetyRevoked 用于晋级节点：该晋级版本事后是否已被安全撤销。
	SafetyRevoked bool
	OccurredAt    time.Time
}

// RollbackCandidate 是某环境当前可回滚到的历史版本。
type RollbackCandidate struct {
	Environment Environment
	Digest      Digest
	PromotionID int64
	// PromotedVersion 是该制品最后一次晋级到该环境时的版本号。
	PromotedVersion int64
	PromotedAt      time.Time
	ChangeNumber    string
}

// AffectedDownstream 描述一个会被上游环境指针变化影响的下游环境。
type AffectedDownstream struct {
	Environment Environment
	// Upstream 是它（传递）依赖、且指针刚发生变化的上游环境。
	Upstream Environment
	// CurrentDigest 是下游当前指向的制品；UpstreamDigest 是上游当前制品。
	// 两者不一致意味着下游当前版本不再是其上游的当前版本
	//（它晋级时所依据的上游指针已被回滚/重新晋级改变）。
	CurrentDigest  Digest
	UpstreamDigest Digest
	// Direct 为 true 表示直接下游，false 表示沿上游链传递发现的间接下游。
	Direct bool
}

// ---- 跨环境分批回滚 ----

// StagedRollbackStatus 是跨环境分批回滚计划的生命周期状态。
type StagedRollbackStatus string

const (
	// StagedRollbackPending 已创建，尚未取得任何环境成功。
	StagedRollbackPending StagedRollbackStatus = "pending"
	// StagedRollbackPaused 某批（含批次内的某个环境）被门槛失败阻断，
	// 已完成环境保持现状，等待恢复后从失败批次继续。
	StagedRollbackPaused StagedRollbackStatus = "paused"
	// StagedRollbackCompleted 全部批次、全部环境成功落地。
	StagedRollbackCompleted StagedRollbackStatus = "completed"
	// StagedRollbackConflicted 版本冲突终结：尚未成功的环境指针已偏离
	// 冻结版本、全局证明修订号推进，或目标制品被安全撤销。计划不可恢复。
	StagedRollbackConflicted StagedRollbackStatus = "conflicted"
	// StagedRollbackCanceled 被取消：只阻止尚未开始/已阻断的后续批次，
	// 已成功的环境不回滚。
	StagedRollbackCanceled StagedRollbackStatus = "canceled"
)

// StagedEntryStatus 是分批计划中单个环境条目的执行状态。
type StagedEntryStatus string

const (
	StagedEntryPending    StagedEntryStatus = "pending"    // 尚未轮到
	StagedEntrySucceeded  StagedEntryStatus = "succeeded"  // 该环境已落地，版本已冻结为最终结果
	StagedEntryBlocked    StagedEntryStatus = "blocked"    // 门槛失败：恢复时本环境将被重试
	StagedEntryConflicted StagedEntryStatus = "conflicted" // 版本冲突：计划终结
	StagedEntrySkipped    StagedEntryStatus = "skipped"    // 计划取消时尚未成功
)

// StagedBatchStatus 是报告中某一批的汇总状态。
type StagedBatchStatus string

const (
	StagedBatchPending    StagedBatchStatus = "pending"     // 批内尚无成功
	StagedBatchInProgress StagedBatchStatus = "in_progress" // 批内部分环境成功、部分待执行
	StagedBatchSucceeded  StagedBatchStatus = "succeeded"   // 批内全部成功
	StagedBatchBlocked    StagedBatchStatus = "blocked"     // 批内存在被阻断环境（计划暂停中）
	StagedBatchConflicted StagedBatchStatus = "conflicted"  // 批内存在冲突环境（计划终结）
	// StagedBatchCanceled 批内没有成功环境且未执行的环境全部被取消跳过；
	// 若批内已有成功环境再取消，则报告 partially_canceled（已成功结果保留）。
	StagedBatchCanceled          StagedBatchStatus = "canceled"
	StagedBatchPartiallyCanceled StagedBatchStatus = "partially_canceled"
)

// 阻断/冲突原因代码，固化在条目与计划上供查询，不必解析错误文本。
const (
	StagedBlockNotApproved       = "rollback_not_approved"         // 紧急计划缺双人批准
	StagedBlockAttestationFailed = "attestation_failed"            // 当前策略的证明门槛未满足
	StagedBlockUpstream          = "upstream_not_promoted"         // 上游环境未指向目标
	StagedBlockPolicyNotFound    = "policy_not_found"              // 执行时该环境策略已消失
	StagedConflictEnvVersion     = "environment_version_conflict"  // 环境指针偏离冻结版本
	StagedConflictAttestationRev = "attestation_revision_conflict" // 全局证明修订号已推进
	StagedConflictTargetRevoked  = "target_safety_revoked"         // 目标晋级版本被安全撤销
)

// StagedRollbackEntry 是分批计划中一个环境的冻结信息与执行结果。
//
// 创建时固化目标（最近一次成功且未撤销的晋级记录）、该环境当前指针
// （版本号+摘要+来源记录）、当前策略（修订号+完整快照）与全局证明修订号；
// 执行时这些冻结值用于条件检查，结果版本/阻断原因随时可查询。
type StagedRollbackEntry struct {
	Environment Environment

	// 冻结的目标。
	TargetDigest      Digest
	TargetPromotionID int64
	TargetVersion     int64

	// 创建时冻结的环境状态：尚未成功的环境在执行前必须仍与之完全一致。
	FrozenCurrentDigest  Digest
	FrozenCurrentVersion int64
	FrozenCurrentPromoID int64
	FrozenPolicyVersion  int64
	PolicySnapshot       Policy
	// FrozenAttestationRevision 是创建时的全局证明修订号；执行时若已推进，
	// 说明期间发生过证明撤销，旧计划必须拒绝执行（版本冲突）。
	FrozenAttestationRevision int64

	Status      StagedEntryStatus
	Attempts    int    // 被阻断后（含首次）执行尝试的次数，幂等重放也计数
	BlockCode   string // blocked/conflicted 时的原因代码
	BlockReason string // blocked/conflicted 时的人类可读说明

	// 成功后的最终结果：该环境最终采用的版本。
	ResultVersion     int64
	ResultPromotionID int64
	ExecutedAt        time.Time
}

// StagedRollbackPlan 是一笔覆盖多个环境、按批次推进的回滚计划。
//
// 计划只锚定一个目标制品；Batches 按推进顺序排列，每个批次是一个环境
// 列表（批次内也按创建顺序执行）。一批全部成功后才会进入下一批。
type StagedRollbackPlan struct {
	ID     int64
	Number string // 外部分批回滚号，全局唯一，保证创建/执行/取消幂等
	Kind   RollbackKind

	// TargetDigest 是本次跨环境回滚的统一目标制品。它必须在计划覆盖的
	// 每个环境都有历史上成功晋级且未被安全撤销的记录。
	TargetDigest Digest

	// Entries 按批次顺序、批次内顺序扁平化保存全部环境条目；
	// BatchIndex/BatchSize 由 BatchReports 重建，无需单独存储。
	Batches [][]Environment
	Entries []StagedRollbackEntry

	Reason      string // 创建时冻结
	RequestedBy string
	CreatedAt   time.Time

	Status       StagedRollbackStatus
	Approvals    []RollbackApproval // 仅紧急计划使用：两个不同授权人
	BlockCode    string             // paused/conflicted 时计划级阻断/冲突代码
	BlockReason  string
	CompletedAt  time.Time
	CanceledAt   time.Time
	CanceledBy   string
	CancelReason string
}

// StagedBatchReport 是单个批次的执行报告：可查询批内每个环境最终采用的
// 版本、结果状态与阻断原因。
type StagedBatchReport struct {
	BatchIndex int // 0 起的批次序号
	Status     StagedBatchStatus
	Entries    []StagedRollbackEntry
}

// EntryByEnv 返回计划中某个环境的条目与是否存在。
func (p StagedRollbackPlan) EntryByEnv(env Environment) (StagedRollbackEntry, bool) {
	for _, e := range p.Entries {
		if e.Environment == env {
			return e, true
		}
	}
	return StagedRollbackEntry{}, false
}

// BatchReports 按批次顺序重建每批的汇总状态与条目快照。
func (p StagedRollbackPlan) BatchReports() []StagedBatchReport {
	byEnv := make(map[Environment]StagedRollbackEntry, len(p.Entries))
	for _, e := range p.Entries {
		byEnv[e.Environment] = e
	}
	reports := make([]StagedBatchReport, 0, len(p.Batches))
	for i, batch := range p.Batches {
		r := StagedBatchReport{BatchIndex: i, Entries: make([]StagedRollbackEntry, 0, len(batch))}
		var succeeded, blocked, conflicted, pending int
		for _, env := range batch {
			e := byEnv[env]
			r.Entries = append(r.Entries, e)
			switch e.Status {
			case StagedEntrySucceeded:
				succeeded++
			case StagedEntryBlocked:
				blocked++
			case StagedEntryConflicted:
				conflicted++
			case StagedEntrySkipped:
				// 单独统计，不影响下面的推进状态。
			default:
				pending++
			}
		}
		switch {
		case conflicted > 0:
			r.Status = StagedBatchConflicted
		case blocked > 0:
			r.Status = StagedBatchBlocked
		case succeeded == len(batch):
			r.Status = StagedBatchSucceeded
		case succeeded == 0 && pending == 0:
			// 没有任何成功也没有待执行，其余全部 skipped。
			r.Status = StagedBatchCanceled
		case succeeded > 0 && pending == 0:
			// 部分成功、其余 skipped：取消发生在该批已有环境落地之后。
			r.Status = StagedBatchPartiallyCanceled
		case succeeded > 0:
			r.Status = StagedBatchInProgress
		default:
			r.Status = StagedBatchPending
		}
		reports = append(reports, r)
	}
	return reports
}
