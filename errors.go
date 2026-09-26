package artifactpromotion

import (
	"errors"
	"fmt"
)

// 可通过 errors.Is 判别的错误类别。业务细节（例如缺少哪一类证明、
// 哪个变更号冲突）以 fmt.Errorf("%w: ...", ErrXxx) 的形式附带在错误链上。
var (
	// ErrInvalidArgument 入参不合法。
	ErrInvalidArgument = errors.New("invalid argument")
	// ErrArtifactNotFound 制品未登记。
	ErrArtifactNotFound = errors.New("artifact not found")
	// ErrAttestationNotFound 证明不存在。
	ErrAttestationNotFound = errors.New("attestation not found")
	// ErrPolicyNotFound 目标环境尚未配置策略。
	ErrPolicyNotFound = errors.New("policy not found")
	// ErrChangeConflict 外部变更号已被另一个环境或制品使用。
	ErrChangeConflict = errors.New("change number conflict")
	// ErrConcurrentModification 版本条件（或摘要条件）与当前环境指针不一致。
	ErrConcurrentModification = errors.New("concurrent modification")
	// ErrMissingAttestation 策略要求的某类证明完全不存在。
	ErrMissingAttestation = errors.New("missing required attestation")
	// ErrAttestationRevoked 唯一可用的证明已被撤销。
	ErrAttestationRevoked = errors.New("attestation revoked")
	// ErrAttestationExpired 证明已超过有效期。
	ErrAttestationExpired = errors.New("attestation expired")
	// ErrAttestationNotYetValid 证明尚未进入有效期。
	ErrAttestationNotYetValid = errors.New("attestation not yet valid")
	// ErrAttestationRejected 证明结论不被接受（非 approved）。
	ErrAttestationRejected = errors.New("attestation conclusion rejected")
	// ErrUpstreamNotPromoted 策略要求上游环境已放行该制品，但条件未满足。
	ErrUpstreamNotPromoted = errors.New("artifact not promoted in upstream environment")
	// ErrPromotionNotFound 晋级记录不存在。
	ErrPromotionNotFound = errors.New("promotion not found")
)

func invalidArgument(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidArgument, fmt.Sprintf(format, args...))
}
