package artifactpromotion

import "time"

// Conclusion 是证明给出的结论。
type Conclusion string

const (
	// ConclusionPass 表示证明主体通过了对应类型的检查。
	ConclusionPass Conclusion = "PASS"
	// ConclusionFail 表示证明主体未通过检查，永远不能用于支撑晋级。
	ConclusionFail Conclusion = "FAIL"
)

// Artifact 是一个不可变软件制品，由内容摘要唯一标识。
// 同一摘要一旦登记，其名称与版本不可再变更。
type Artifact struct {
	Digest       string            `json:"digest"`
	Name         string            `json:"name"`
	Version      string            `json:"version"`
	RegisteredAt time.Time         `json:"registeredAt"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

// Attestation 是针对某个制品签发的一份证明材料。
// 它至少记录类型、签发者、结论和有效期 [NotBefore, NotAfter)。
// 撤销通过 Revoked/RevokedAt 记录，证明本身从不被删除。
type Attestation struct {
	ID         string     `json:"id"`
	Digest     string     `json:"digest"`
	Type       string     `json:"type"`
	Issuer     string     `json:"issuer"`
	Conclusion Conclusion `json:"conclusion"`
	IssuedAt   time.Time  `json:"issuedAt"`
	NotBefore  time.Time  `json:"notBefore"`
	NotAfter   time.Time  `json:"notAfter"`
	Revoked    bool       `json:"revoked"`
	RevokedAt  *time.Time `json:"revokedAt,omitempty"`
}

// Effective 报告该证明在 now 时刻是否可以支撑一次晋级：
// 未被撤销、结论为 PASS、且当前时刻落在有效期内。
func (a Attestation) Effective(now time.Time) bool {
	return !a.Revoked &&
		a.Conclusion == ConclusionPass &&
		!now.Before(a.NotBefore) &&
		now.Before(a.NotAfter)
}

// Policy 是某个部署环境的晋级策略。
// RequiredAttestations 列出必须具备的有效证明类型；
// RequiredUpstreams 列出制品必须已经晋级到的上游环境。
type Policy struct {
	Environment          string    `json:"environment"`
	RequiredAttestations []string  `json:"requiredAttestations,omitempty"`
	RequiredUpstreams    []string  `json:"requiredUpstreams,omitempty"`
	UpdatedAt            time.Time `json:"updatedAt"`
}

// EnvironmentState 是一个部署环境的当前指针。
// 任意时刻一个环境只指向一个已晋级版本；Version 单调递增，
// 用于晋级时的版本条件检查，防止并发晋级静默覆盖。
type EnvironmentState struct {
	Name    string `json:"name"`
	Digest  string `json:"digest"`
	Version int64  `json:"version"`
}

// PromoteRequest 描述一次晋级请求。
// ChangeID 是调用方提供的外部变更号，用于幂等；
// ExpectedVersion 是调用方读到的环境当前版本，作为原子切换的版本条件。
type PromoteRequest struct {
	ChangeID        string `json:"changeId"`
	Environment     string `json:"environment"`
	Digest          string `json:"digest"`
	ExpectedVersion int64  `json:"expectedVersion"`
}

// PromotionRecord 是一次成功晋级的不可变记录。
// 它永久保存晋级时刻采用的策略与证明快照，供后续追溯；
// 之后证明被撤销或策略被修改都不影响该记录。
type PromotionRecord struct {
	ChangeID    string    `json:"changeId"`
	Environment string    `json:"environment"`
	Digest      string    `json:"digest"`
	FromVersion int64     `json:"fromVersion"`
	ToVersion   int64     `json:"toVersion"`
	PromotedAt  time.Time `json:"promotedAt"`
	// PolicySnapshot 是晋级时生效的策略副本。
	PolicySnapshot Policy `json:"policySnapshot"`
	// AttestationSnapshot 是晋级时该制品全部可用证明的副本，
	// 包含当时每份证明的撤销状态。
	AttestationSnapshot []Attestation `json:"attestationSnapshot"`
}
