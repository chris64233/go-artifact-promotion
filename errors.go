package artifactpromotion

import "errors"

// 服务返回的所有业务错误都由下列哨兵错误包装而来，
// 调用方可以用 errors.Is 区分各类失败原因。
var (
	// ErrInvalidInput 表示请求参数缺失或非法。
	ErrInvalidInput = errors.New("invalid input")
	// ErrArtifactNotFound 表示指定摘要的制品尚未登记。
	ErrArtifactNotFound = errors.New("artifact not found")
	// ErrArtifactConflict 表示同一摘要被以不同的名称或版本重复登记。
	ErrArtifactConflict = errors.New("artifact digest already registered with different content")
	// ErrAttestationNotFound 表示指定 ID 的证明不存在。
	ErrAttestationNotFound = errors.New("attestation not found")
	// ErrPolicyNotFound 表示目标环境尚未配置晋级策略。
	ErrPolicyNotFound = errors.New("policy not found")
	// ErrMissingAttestation 表示策略要求的某类证明缺失、已过期、
	// 已撤销或结论不是 PASS。
	ErrMissingAttestation = errors.New("required attestation missing or not currently effective")
	// ErrUpstreamNotSatisfied 表示制品还不是某个上游环境的当前版本。
	ErrUpstreamNotSatisfied = errors.New("artifact is not the current version of a required upstream environment")
	// ErrChangeConflict 表示外部变更号已被一次目标环境或制品摘要
	// 不同的晋级占用。
	ErrChangeConflict = errors.New("change id already used with different environment or digest")
	// ErrVersionConflict 表示环境的当前版本与请求携带的期望版本不一致，
	// 说明有并发晋级先一步切换了环境指针。
	ErrVersionConflict = errors.New("environment version does not match expected version")
)
