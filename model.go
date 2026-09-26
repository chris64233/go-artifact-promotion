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
	UpdatedAt           time.Time
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
}

// EnvironmentPointer 是某一部署环境当前指向的已晋级版本。
// 任意时刻一个环境最多只指向一个制品。
type EnvironmentPointer struct {
	Environment Environment
	Digest      Digest
	Version     int64 // 当前版本号；0 表示该环境还从未晋级
	PromotionID int64
	UpdatedAt   time.Time
}
