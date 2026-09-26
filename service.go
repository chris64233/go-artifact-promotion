package artifactpromotion

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// IssueAttestationRequest 是签发证明的完整参数。
type IssueAttestationRequest struct {
	Digest     Digest
	Type       AttestationType
	Issuer     string
	Conclusion Conclusion
	// ValidFrom 为零值时取当前时间；ValidUntil 为零值时表示长期有效。
	ValidFrom  time.Time
	ValidUntil time.Time
}

// PromotionRequest 是发起晋级的参数。
type PromotionRequest struct {
	// ChangeNumber 是外部变更号，同一变更号的重复请求具有幂等语义。
	ChangeNumber string
	Environment  Environment
	Digest       Digest
	// ExpectedVersion 是发起方预期的环境当前版本：
	//   - 环境从未晋级时当前版本为 0（首次晋级传 0）；
	//   - 与当前版本不一致时晋级被拒绝（ErrConcurrentModification），
	//     从而阻止并发争用下的静默覆盖。
	ExpectedVersion int64
}

// Service 是制品晋级服务。所有方法都是并发安全的：写操作在单一事务内
// 串行执行，校验与状态切换共享同一个一致快照。
type Service struct {
	store store
	clock Clock
}

// NewService 创建纯内存存储的服务，主要用于测试。
func NewService() *Service {
	return &Service{store: newMemStore(), clock: SystemClock()}
}

// NewPersistentService 创建把状态持久化到 path（JSON 文件）的服务。
// 文件不存在时自动初始化；每次成功提交都会原子落盘，重启后状态完整保留。
func NewPersistentService(path string) (*Service, error) {
	m, err := newFileStore(path)
	if err != nil {
		return nil, err
	}
	return &Service{store: m, clock: SystemClock()}, nil
}

// WithClock 替换服务时钟，返回服务自身以便链式构造（主要用于测试）。
func (s *Service) WithClock(c Clock) *Service {
	s.clock = c
	return s
}

// ComputeDigest 以指定算法计算数据摘要，返回 "algo:hex" 形式的 Digest。
func ComputeDigest(algorithm string, data []byte) (Digest, error) {
	switch algorithm {
	case "sha256":
		sum := sha256.Sum256(data)
		return Digest("sha256:" + hex.EncodeToString(sum[:])), nil
	default:
		return "", invalidArgument("unsupported digest algorithm %q", algorithm)
	}
}

func parseDigest(s string) error {
	algo, hexPart, ok := strings.Cut(s, ":")
	if !ok || algo == "" || len(hexPart) == 0 {
		return invalidArgument("digest must be in algorithm:hex form, got %q", s)
	}
	for _, r := range hexPart {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return invalidArgument("digest hex part contains non-hex character in %q", s)
		}
	}
	return nil
}

// RegisterArtifact 登记一个由不可变摘要标识的制品。重复登记相同摘要且
// 元数据一致时幂等返回已有记录；元数据冲突则返回 ErrInvalidArgument。
func (s *Service) RegisterArtifact(digest Digest, algorithm, name string) (Artifact, error) {
	if err := parseDigest(string(digest)); err != nil {
		return Artifact{}, err
	}
	if algorithm == "" {
		return Artifact{}, invalidArgument("algorithm is required")
	}
	if name == "" {
		return Artifact{}, invalidArgument("name is required")
	}
	now := s.clock.Now().UTC()
	err := s.store.update(func(tx kvTx) error {
		if existing, ok := tx.getArtifact(digest); ok {
			if existing.Algorithm != algorithm || existing.Name != name {
				return invalidArgument("artifact %s already registered with different metadata", digest)
			}
			return nil
		}
		tx.putArtifact(Artifact{
			Digest:       digest,
			Algorithm:    algorithm,
			Name:         name,
			RegisteredAt: now,
		})
		return nil
	})
	if err != nil {
		return Artifact{}, err
	}
	var out Artifact
	err = s.store.view(func(tx kvTx) error {
		out, _ = tx.getArtifact(digest)
		return nil
	})
	return out, err
}

// GetArtifact 查询已登记制品，不存在时返回 ErrArtifactNotFound。
func (s *Service) GetArtifact(digest Digest) (Artifact, error) {
	var out Artifact
	err := s.store.view(func(tx kvTx) error {
		a, ok := tx.getArtifact(digest)
		if !ok {
			return fmt.Errorf("%w: %s", ErrArtifactNotFound, digest)
		}
		out = a
		return nil
	})
	return out, err
}

// IssueAttestation 按完整参数签发证明。证明 ID 由服务分配并返回。
func (s *Service) IssueAttestation(req IssueAttestationRequest) (Attestation, error) {
	if err := parseDigest(string(req.Digest)); err != nil {
		return Attestation{}, err
	}
	if req.Type == "" {
		return Attestation{}, invalidArgument("attestation type is required")
	}
	if req.Issuer == "" {
		return Attestation{}, invalidArgument("issuer is required")
	}
	if req.Conclusion != ConclusionApproved && req.Conclusion != ConclusionRejected {
		return Attestation{}, invalidArgument("conclusion must be %q or %q",
			ConclusionApproved, ConclusionRejected)
	}
	if !req.ValidUntil.IsZero() && !req.ValidFrom.IsZero() && !req.ValidUntil.After(req.ValidFrom) {
		return Attestation{}, invalidArgument("valid until must be later than valid from")
	}

	var out Attestation
	err := s.store.update(func(tx kvTx) error {
		if _, ok := tx.getArtifact(req.Digest); !ok {
			return fmt.Errorf("%w: %s", ErrArtifactNotFound, req.Digest)
		}
		now := s.clock.Now().UTC()
		from := req.ValidFrom.UTC()
		if from.IsZero() {
			from = now
		}
		a := Attestation{
			ID:         tx.newAttestationID(),
			Digest:     req.Digest,
			Type:       req.Type,
			Issuer:     req.Issuer,
			Conclusion: req.Conclusion,
			ValidFrom:  from,
			ValidUntil: req.ValidUntil.UTC(),
			IssuedAt:   now,
		}
		tx.putAttestation(a)
		out = a
		return nil
	})
	return out, err
}

// RevokeAttestation 撤销证明。已撤销的证明不再能支撑任何新的晋级，
// 但已完成晋级保存的证明快照不受影响。重复撤销返回 ErrInvalidArgument。
func (s *Service) RevokeAttestation(id, reason string) error {
	if id == "" {
		return invalidArgument("attestation id is required")
	}
	return s.store.update(func(tx kvTx) error {
		a, ok := tx.getAttestation(id)
		if !ok {
			return fmt.Errorf("%w: %s", ErrAttestationNotFound, id)
		}
		if a.Revoked() {
			return invalidArgument("attestation %s is already revoked", id)
		}
		a.RevokedAt = s.clock.Now().UTC()
		a.RevokeReason = reason
		tx.putAttestation(a)
		return nil
	})
}

// GetAttestation 查询证明，不存在时返回 ErrAttestationNotFound。
func (s *Service) GetAttestation(id string) (Attestation, error) {
	var out Attestation
	err := s.store.view(func(tx kvTx) error {
		a, ok := tx.getAttestation(id)
		if !ok {
			return fmt.Errorf("%w: %s", ErrAttestationNotFound, id)
		}
		out = a
		return nil
	})
	return out, err
}

// ListAttestations 列出某制品当前全部证明（含已撤销/已过期），按 ID 排序。
func (s *Service) ListAttestations(digest Digest) ([]Attestation, error) {
	var out []Attestation
	err := s.store.view(func(tx kvTx) error {
		out = tx.listAttestations(digest)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// ConfigurePolicy 配置（整体覆盖）某环境的晋级策略。
func (s *Service) ConfigurePolicy(p Policy) (Policy, error) {
	if p.Environment == "" {
		return Policy{}, invalidArgument("environment is required")
	}
	if p.UpstreamEnvironment == p.Environment {
		return Policy{}, invalidArgument("upstream environment must differ from target environment")
	}
	seen := map[AttestationType]bool{}
	for _, t := range p.RequiredAttestations {
		if t == "" {
			return Policy{}, invalidArgument("attestation type must not be empty")
		}
		if seen[t] {
			return Policy{}, invalidArgument("duplicate required attestation type %q", t)
		}
		seen[t] = true
	}
	requirements := append([]AttestationType(nil), p.RequiredAttestations...)
	now := s.clock.Now().UTC()

	var out Policy
	err := s.store.update(func(tx kvTx) error {
		if p.UpstreamEnvironment != "" {
			if _, ok := tx.getPolicy(p.UpstreamEnvironment); !ok {
				return fmt.Errorf("%w: upstream policy for %q is not configured",
					ErrPolicyNotFound, p.UpstreamEnvironment)
			}
		}
		out = Policy{
			Environment:          p.Environment,
			RequiredAttestations: requirements,
			UpstreamEnvironment:  p.UpstreamEnvironment,
			UpdatedAt:            now,
		}
		tx.putPolicy(out)
		return nil
	})
	return out, err
}

// GetPolicy 查询环境当前策略，未配置时返回 ErrPolicyNotFound。
func (s *Service) GetPolicy(env Environment) (Policy, error) {
	var out Policy
	err := s.store.view(func(tx kvTx) error {
		p, ok := tx.getPolicy(env)
		if !ok {
			return fmt.Errorf("%w: %s", ErrPolicyNotFound, env)
		}
		out = p
		return nil
	})
	return out, err
}

// validityFailure 对单份证明在 now 时刻做有效性判定，返回阻止其被采用的
// 错误类别；nil 表示该证明当前有效且结论为 approved。
func validityFailure(a Attestation, now time.Time) error {
	switch {
	case a.Revoked():
		return fmt.Errorf("%w: %s", ErrAttestationRevoked, a.ID)
	case a.Conclusion != ConclusionApproved:
		return fmt.Errorf("%w: %s has conclusion %q", ErrAttestationRejected, a.ID, a.Conclusion)
	case now.Before(a.ValidFrom):
		return fmt.Errorf("%w: %s", ErrAttestationNotYetValid, a.ID)
	case !a.ValidUntil.IsZero() && now.After(a.ValidUntil):
		return fmt.Errorf("%w: %s", ErrAttestationExpired, a.ID)
	default:
		return nil
	}
}

// failurePriority 决定同一证明类型存在多份候选材料时，采用哪一种失败原因。
func failurePriority(err error) int {
	switch {
	case errors.Is(err, ErrAttestationRevoked):
		return 5
	case errors.Is(err, ErrAttestationRejected):
		return 4
	case errors.Is(err, ErrAttestationExpired):
		return 3
	case errors.Is(err, ErrAttestationNotYetValid):
		return 2
	default:
		return 1
	}
}

// Promote 在一致快照上检查全部晋级条件，全部成立后原子切换环境指针，
// 并把当时的策略与采用的证明快照永久固化到晋级记录中。
//
// 同一变更号、同一环境、同一制品的重复请求直接返回首次结果（幂等）；
// 同号但环境或摘要不同返回 ErrChangeConflict。
func (s *Service) Promote(req PromotionRequest) (Promotion, error) {
	if req.ChangeNumber == "" {
		return Promotion{}, invalidArgument("change number is required")
	}
	if req.Environment == "" {
		return Promotion{}, invalidArgument("environment is required")
	}
	if err := parseDigest(string(req.Digest)); err != nil {
		return Promotion{}, err
	}

	var out Promotion
	err := s.store.update(func(tx kvTx) error {
		// 幂等：变更号已经用过时，只能是同一次请求的重放。
		if existing, ok := tx.promotionByChange(req.ChangeNumber); ok {
			if existing.Environment == req.Environment && existing.Digest == req.Digest {
				out = existing
				return nil
			}
			return fmt.Errorf("%w: change %q already promoted %s to %s",
				ErrChangeConflict, req.ChangeNumber, existing.Digest, existing.Environment)
		}

		if _, ok := tx.getArtifact(req.Digest); !ok {
			return fmt.Errorf("%w: %s", ErrArtifactNotFound, req.Digest)
		}
		policy, ok := tx.getPolicy(req.Environment)
		if !ok {
			return fmt.Errorf("%w: %s", ErrPolicyNotFound, req.Environment)
		}

		// 版本条件：阻止并发争用同一环境时的静默覆盖。
		pointer := tx.getPointer(req.Environment)
		if pointer.Version != req.ExpectedVersion {
			return fmt.Errorf("%w: environment %s is at version %d, expected %d",
				ErrConcurrentModification, req.Environment, pointer.Version, req.ExpectedVersion)
		}

		now := s.clock.Now().UTC()

		// 一致快照检查：此刻读取该制品全部可用证明，逐类型挑选有效材料。
		available := tx.listAttestations(req.Digest)
		chosen := make([]AttestationSnapshot, 0, len(policy.RequiredAttestations))
		for _, required := range policy.RequiredAttestations {
			var candidates []Attestation
			for _, a := range available {
				if a.Type == required {
					candidates = append(candidates, a)
				}
			}
			if len(candidates) == 0 {
				return fmt.Errorf("%w: type %q for artifact %s",
					ErrMissingAttestation, required, req.Digest)
			}
			var picked *Attestation
			var bestFailure error
			for i := range candidates {
				if fErr := validityFailure(candidates[i], now); fErr == nil {
					picked = &candidates[i]
					break
				} else if bestFailure == nil ||
					failurePriority(fErr) > failurePriority(bestFailure) {
					bestFailure = fErr
				}
			}
			if picked == nil {
				return fmt.Errorf("%w: no valid attestation of type %q: %v",
					bestFailure, required, bestFailure)
			}
			chosen = append(chosen, AttestationSnapshot{Attestation: *picked})
		}

		// 上游晋级要求：上游环境当前必须正指向同一制品。
		if policy.UpstreamEnvironment != "" {
			upstream := tx.getPointer(policy.UpstreamEnvironment)
			if upstream.Version == 0 || upstream.Digest != req.Digest {
				return fmt.Errorf("%w: artifact %s is not the current version of %s",
					ErrUpstreamNotPromoted, req.Digest, policy.UpstreamEnvironment)
			}
		}

		// 全部条件成立：记录与指针在同一事务内原子提交。
		newVersion := pointer.Version + 1
		record := Promotion{
			ChangeNumber:    req.ChangeNumber,
			Environment:     req.Environment,
			Digest:          req.Digest,
			ExpectedVersion: req.ExpectedVersion,
			Version:         newVersion,
			Attestations:    chosen,
			PolicySnapshot:  policy,
			PromotedAt:      now,
		}
		record = tx.addPromotion(record)
		tx.putPointer(EnvironmentPointer{
			Environment: req.Environment,
			Digest:      req.Digest,
			Version:     newVersion,
			PromotionID: record.ID,
			UpdatedAt:   now,
		})
		out = record
		return nil
	})
	return out, err
}

// GetPointer 查询环境当前指向的版本。环境从未晋级时返回 Version 为 0 的指针。
func (s *Service) GetPointer(env Environment) (EnvironmentPointer, error) {
	if env == "" {
		return EnvironmentPointer{}, invalidArgument("environment is required")
	}
	var out EnvironmentPointer
	err := s.store.view(func(tx kvTx) error {
		out = tx.getPointer(env)
		return nil
	})
	return out, err
}

// History 按时间先后返回晋级历史；env 为空时返回所有环境的历史。
func (s *Service) History(env Environment) ([]Promotion, error) {
	var out []Promotion
	err := s.store.view(func(tx kvTx) error {
		out = tx.listPromotions(env)
		return nil
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].PromotedAt.Equal(out[j].PromotedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].PromotedAt.Before(out[j].PromotedAt)
	})
	return out, err
}

// GetPromotion 按内部 ID 查询一次晋级记录。
func (s *Service) GetPromotion(id int64) (Promotion, error) {
	if id <= 0 {
		return Promotion{}, invalidArgument("promotion id must be positive")
	}
	var out Promotion
	err := s.store.view(func(tx kvTx) error {
		if id > int64(len(tx.s.Promotions)) {
			return fmt.Errorf("%w: id %d", ErrPromotionNotFound, id)
		}
		out = *tx.s.Promotions[id-1]
		return nil
	})
	return out, err
}
