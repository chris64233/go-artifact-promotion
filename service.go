package artifactpromotion

import (
	"fmt"
	"sort"
	"sync"
	"time"
)

// Service 提供制品登记、证明签发与撤销、策略配置、晋级与历史查询。
//
// 所有方法共享一把互斥锁：晋级评估（制品 + 策略 + 可用证明的一致快照）
// 与环境指针切换在同一个临界区内完成，因此撤销与晋级并发时，
// 二者必然串行——要么撤销先生效（晋级因证明失效而失败），
// 要么晋级先完成（记录中永久保留当时的证明快照）。
type Service struct {
	mu    sync.Mutex
	store Store
	st    *state
	now   func() time.Time
}

// NewService 从 store 加载状态并创建服务。
// now 为 nil 时使用真实时钟；测试可注入假时钟。
func NewService(store Store, now func() time.Time) (*Service, error) {
	st, err := store.Load()
	if err != nil {
		return nil, err
	}
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, st: st, now: now}, nil
}

// save 持久化当前状态，调用方必须持有锁。
func (s *Service) save() error {
	return s.store.Save(s.st)
}

// RegisterArtifact 登记一个不可变制品。
// 同一摘要重复登记且内容一致时为幂等成功；内容不一致返回 ErrArtifactConflict。
func (s *Service) RegisterArtifact(a Artifact) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if a.Digest == "" {
		return Artifact{}, fmt.Errorf("%w: digest is required", ErrInvalidInput)
	}
	if existing, ok := s.st.Artifacts[a.Digest]; ok {
		if existing.Name != a.Name || existing.Version != a.Version {
			return Artifact{}, fmt.Errorf("%w: digest %s", ErrArtifactConflict, a.Digest)
		}
		return existing, nil
	}
	a.RegisteredAt = s.now()
	s.st.Artifacts[a.Digest] = a
	if err := s.save(); err != nil {
		return Artifact{}, err
	}
	return a, nil
}

// GetArtifact 按摘要查询制品。
func (s *Service) GetArtifact(digest string) (Artifact, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.st.Artifacts[digest]
	if !ok {
		return Artifact{}, fmt.Errorf("%w: digest %s", ErrArtifactNotFound, digest)
	}
	return a, nil
}

// IssueAttestation 为已登记的制品签发一份证明。
// ID 为空时由服务分配；返回签发后的完整证明。
func (s *Service) IssueAttestation(att Attestation) (Attestation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if att.Type == "" || att.Issuer == "" {
		return Attestation{}, fmt.Errorf("%w: attestation type and issuer are required", ErrInvalidInput)
	}
	if att.Conclusion != ConclusionPass && att.Conclusion != ConclusionFail {
		return Attestation{}, fmt.Errorf("%w: conclusion must be PASS or FAIL", ErrInvalidInput)
	}
	if !att.NotAfter.After(att.NotBefore) {
		return Attestation{}, fmt.Errorf("%w: validity window must be non-empty", ErrInvalidInput)
	}
	if _, ok := s.st.Artifacts[att.Digest]; !ok {
		return Attestation{}, fmt.Errorf("%w: digest %s", ErrArtifactNotFound, att.Digest)
	}
	if att.ID == "" {
		att.ID = fmt.Sprintf("att-%06d", len(s.st.Attestations)+1)
	} else if _, ok := s.st.Attestations[att.ID]; ok {
		return Attestation{}, fmt.Errorf("%w: attestation id %s already exists", ErrInvalidInput, att.ID)
	}
	att.IssuedAt = s.now()
	att.Revoked = false
	att.RevokedAt = nil
	s.st.Attestations[att.ID] = att
	if err := s.save(); err != nil {
		return Attestation{}, err
	}
	return att, nil
}

// RevokeAttestation 撤销一份证明。撤销是幂等的；
// 已被撤销的证明从撤销生效起不能再支撑新的晋级，
// 但此前已完成的晋级记录中仍保留当时的证明快照。
func (s *Service) RevokeAttestation(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	att, ok := s.st.Attestations[id]
	if !ok {
		return fmt.Errorf("%w: id %s", ErrAttestationNotFound, id)
	}
	if att.Revoked {
		return nil
	}
	now := s.now()
	att.Revoked = true
	att.RevokedAt = &now
	s.st.Attestations[id] = att
	return s.save()
}

// ListAttestations 返回某个制品的全部证明（含已撤销），按 ID 排序。
func (s *Service) ListAttestations(digest string) []Attestation {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Attestation
	for _, att := range s.st.Attestations {
		if att.Digest == digest {
			out = append(out, att)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// SetPolicy 配置（或整体替换）某个环境的晋级策略。
func (s *Service) SetPolicy(p Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if p.Environment == "" {
		return fmt.Errorf("%w: policy environment is required", ErrInvalidInput)
	}
	p.UpdatedAt = s.now()
	s.st.Policies[p.Environment] = p
	return s.save()
}

// GetPolicy 查询某个环境的晋级策略。
func (s *Service) GetPolicy(env string) (Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p, ok := s.st.Policies[env]
	if !ok {
		return Policy{}, fmt.Errorf("%w: environment %s", ErrPolicyNotFound, env)
	}
	return p, nil
}

// Environment 返回环境的当前指针。
// 环境从未发生过晋级时返回 Version 为 0、Digest 为空的零值状态，
// 调用方可据此构造首次晋级的 ExpectedVersion。
func (s *Service) Environment(env string) EnvironmentState {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.st.Environments[env]
	if !ok {
		return EnvironmentState{Name: env}
	}
	return st
}

// Promote 把制品晋级到目标环境。
//
// 流程（全程持有锁，构成一致快照）：
//  1. 幂等判定：同一 ChangeID 且目标环境、摘要一致时直接返回原记录；
//     一致但参数不同返回 ErrChangeConflict。
//  2. 加载当时的策略、制品与全部可用证明。
//  3. 校验策略条件：每类必需证明都存在当前有效的证明；
//     制品已是每个上游环境的当前版本。
//  4. 版本条件：环境当前版本必须等于 ExpectedVersion，否则 ErrVersionConflict。
//  5. 全部条件成立后原子切换环境指针，并写入带快照的晋级记录。
func (s *Service) Promote(req PromoteRequest) (PromotionRecord, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if req.ChangeID == "" || req.Environment == "" || req.Digest == "" {
		return PromotionRecord{}, fmt.Errorf("%w: change id, environment and digest are required", ErrInvalidInput)
	}

	// 1. 幂等判定。
	if rec, ok := s.st.Changes[req.ChangeID]; ok {
		if rec.Environment == req.Environment && rec.Digest == req.Digest {
			return rec, nil
		}
		return PromotionRecord{}, fmt.Errorf("%w: change %s", ErrChangeConflict, req.ChangeID)
	}

	// 2. 一致快照：策略、制品、环境、证明。
	pol, ok := s.st.Policies[req.Environment]
	if !ok {
		return PromotionRecord{}, fmt.Errorf("%w: environment %s", ErrPolicyNotFound, req.Environment)
	}
	if _, ok := s.st.Artifacts[req.Digest]; !ok {
		return PromotionRecord{}, fmt.Errorf("%w: digest %s", ErrArtifactNotFound, req.Digest)
	}
	env := s.st.Environments[req.Environment] // 不存在时为零值（Version 0）
	now := s.now()

	snapshot := make([]Attestation, 0, len(s.st.Attestations))
	for _, att := range s.st.Attestations {
		if att.Digest == req.Digest {
			snapshot = append(snapshot, att)
		}
	}
	sort.Slice(snapshot, func(i, j int) bool { return snapshot[i].ID < snapshot[j].ID })

	// 3. 策略条件。
	for _, typ := range pol.RequiredAttestations {
		effective := false
		for _, att := range snapshot {
			if att.Type == typ && att.Effective(now) {
				effective = true
				break
			}
		}
		if !effective {
			return PromotionRecord{}, fmt.Errorf("%w: type %q for environment %s", ErrMissingAttestation, typ, req.Environment)
		}
	}
	for _, up := range pol.RequiredUpstreams {
		upEnv, ok := s.st.Environments[up]
		if !ok || upEnv.Digest != req.Digest {
			return PromotionRecord{}, fmt.Errorf("%w: upstream %s", ErrUpstreamNotSatisfied, up)
		}
	}

	// 4. 版本条件，阻止并发晋级静默覆盖。
	if env.Version != req.ExpectedVersion {
		return PromotionRecord{}, fmt.Errorf("%w: environment %s at version %d, expected %d",
			ErrVersionConflict, req.Environment, env.Version, req.ExpectedVersion)
	}

	// 5. 原子切换环境指针并记录晋级。
	env.Name = req.Environment
	env.Digest = req.Digest
	env.Version++
	s.st.Environments[req.Environment] = env

	rec := PromotionRecord{
		ChangeID:            req.ChangeID,
		Environment:         req.Environment,
		Digest:              req.Digest,
		FromVersion:         req.ExpectedVersion,
		ToVersion:           env.Version,
		PromotedAt:          now,
		PolicySnapshot:      pol,
		AttestationSnapshot: snapshot,
	}
	s.st.Changes[req.ChangeID] = rec
	s.st.History = append(s.st.History, rec)
	if err := s.save(); err != nil {
		return PromotionRecord{}, err
	}
	return rec, nil
}

// History 返回晋级历史。env 为空时返回全部记录，
// 否则只返回该环境的记录；按发生顺序排列。
func (s *Service) History(env string) []PromotionRecord {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]PromotionRecord, 0, len(s.st.History))
	for _, rec := range s.st.History {
		if env == "" || rec.Environment == env {
			out = append(out, rec)
		}
	}
	return out
}
