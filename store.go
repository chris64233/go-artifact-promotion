package artifactpromotion

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// commitError 包装一个业务错误，告知 store.update：事务内的状态修改仍然
// 提交（含持久化），但把 inner 返回给调用方。用于回滚冲突——既要把计划
// 终结为 conflicted，又必须让 ExecuteRollback 返回 ErrConcurrentModification。
type commitError struct{ inner error }

func (e *commitError) Error() string { return e.inner.Error() }
func (e *commitError) Unwrap() error { return e.inner }

// commitWithError 在提交事务状态的同时向调用方返回业务错误。
func commitWithError(err error) error { return &commitError{inner: err} }

// kvTx 是一次事务内可访问的状态读写句柄。所有方法只在事务回调内有效。
type kvTx struct {
	s *state
}

func (t kvTx) getArtifact(d Digest) (Artifact, bool) {
	if a, ok := t.s.Artifacts[string(d)]; ok {
		return *a, true
	}
	return Artifact{}, false
}

func (t kvTx) putArtifact(a Artifact) { t.s.Artifacts[string(a.Digest)] = &a }

func (t kvTx) getAttestation(id string) (Attestation, bool) {
	if a, ok := t.s.Attestations[id]; ok {
		return *a, true
	}
	return Attestation{}, false
}

func (t kvTx) putAttestation(a Attestation) { t.s.Attestations[a.ID] = &a }

// newAttestationID 分配单调的证明 ID。
func (t kvTx) newAttestationID() string {
	id := fmt.Sprintf("att-%d", t.s.NextAttID)
	t.s.NextAttID++
	return id
}

func (t kvTx) listAttestations(d Digest) []Attestation {
	var out []Attestation
	for _, a := range t.s.Attestations {
		if a.Digest == d {
			out = append(out, *a)
		}
	}
	return out
}

func (t kvTx) getPolicy(env Environment) (Policy, bool) {
	if p, ok := t.s.Policies[string(env)]; ok {
		return *p, true
	}
	return Policy{}, false
}

func (t kvTx) putPolicy(p Policy) { t.s.Policies[string(p.Environment)] = &p }

// listPolicies 返回全部环境的当前策略。
func (t kvTx) listPolicies() []Policy {
	var out []Policy
	for _, p := range t.s.Policies {
		out = append(out, *p)
	}
	return out
}

// bumpPolicyVersion 为环境分配下一个策略修订号（首次配置为 1）。
func (t kvTx) bumpPolicyVersion(env Environment) int64 {
	v := t.s.PolicyVersions[string(env)] + 1
	t.s.PolicyVersions[string(env)] = v
	return v
}

// attestationRevision 返回当前全局证明修订号。
func (t kvTx) attestationRevision() int64 { return t.s.AttestationRevision }

// bumpAttestationRevision 在证明签发/撤销后推进全局证明修订号，
// 供回滚计划检测“创建之后是否发生过证明变更”。
func (t kvTx) bumpAttestationRevision() { t.s.AttestationRevision++ }

func (t kvTx) getPointer(env Environment) EnvironmentPointer {
	if p, ok := t.s.Pointers[string(env)]; ok {
		return *p
	}
	return EnvironmentPointer{Environment: env}
}

func (t kvTx) putPointer(p EnvironmentPointer) { t.s.Pointers[string(p.Environment)] = &p }

func (t kvTx) promotionByChange(changeNumber string) (Promotion, bool) {
	id, ok := t.s.ChangeIndex[changeNumber]
	if !ok {
		return Promotion{}, false
	}
	return *t.s.Promotions[id-1], true
}

// addPromotion 分配单调 ID 并写入晋级记录，返回新记录。
func (t kvTx) addPromotion(p Promotion) Promotion {
	p.ID = t.s.NextID
	t.s.NextID++
	t.s.Promotions = append(t.s.Promotions, &p)
	t.s.ChangeIndex[p.ChangeNumber] = p.ID
	return p
}

func (t kvTx) listPromotions(env Environment) []Promotion {
	var out []Promotion
	for _, p := range t.s.Promotions {
		if env == "" || p.Environment == env {
			out = append(out, *p)
		}
	}
	return out
}

// getPromotionByID 按内部 ID 取晋级记录（记录不可变、永不删除）。
func (t kvTx) getPromotionByID(id int64) (Promotion, bool) {
	if id <= 0 || id > int64(len(t.s.Promotions)) {
		return Promotion{}, false
	}
	return *t.s.Promotions[id-1], true
}

// updatePromotion 原地更新已存在的晋级记录（目前用于安全撤销打标记）。
// 历史记录永不被删除。
func (t kvTx) updatePromotion(p Promotion) { t.s.Promotions[p.ID-1] = &p }

// ---- 回滚计划 ----

func (t kvTx) rollbackByNumber(number string) (RollbackPlan, bool) {
	id, ok := t.s.RollbackIndex[number]
	if !ok {
		return RollbackPlan{}, false
	}
	return *t.s.Rollbacks[id-1], true
}

// addRollback 分配单调 ID 并写入回滚计划，返回新计划。
func (t kvTx) addRollback(r RollbackPlan) RollbackPlan {
	r.ID = t.s.NextRollbackID
	t.s.NextRollbackID++
	t.s.Rollbacks = append(t.s.Rollbacks, &r)
	t.s.RollbackIndex[r.Number] = r.ID
	return r
}

// updateRollback 原地更新回滚计划（批准追加、状态推进）。
func (t kvTx) updateRollback(r RollbackPlan) { t.s.Rollbacks[r.ID-1] = &r }

func (t kvTx) listRollbacks(env Environment) []RollbackPlan {
	var out []RollbackPlan
	for _, r := range t.s.Rollbacks {
		if env == "" || r.Environment == env {
			out = append(out, *r)
		}
	}
	return out
}

// ---- 跨环境分批回滚计划 ----

func (t kvTx) stagedRollbackByNumber(number string) (StagedRollbackPlan, bool) {
	id, ok := t.s.StagedRollbackIndex[number]
	if !ok {
		return StagedRollbackPlan{}, false
	}
	return *t.s.StagedRollbacks[id-1], true
}

// addStagedRollback 分配单调 ID 并写入分批回滚计划，返回新计划。
func (t kvTx) addStagedRollback(p StagedRollbackPlan) StagedRollbackPlan {
	p.ID = t.s.NextStagedRollbackID
	t.s.NextStagedRollbackID++
	t.s.StagedRollbacks = append(t.s.StagedRollbacks, &p)
	t.s.StagedRollbackIndex[p.Number] = p.ID
	return p
}

// updateStagedRollback 原地更新分批回滚计划（状态推进、批准追加）。
func (t kvTx) updateStagedRollback(p StagedRollbackPlan) {
	t.s.StagedRollbacks[p.ID-1] = &p
}

func (t kvTx) listStagedRollbacks() []StagedRollbackPlan {
	out := make([]StagedRollbackPlan, 0, len(t.s.StagedRollbacks))
	for _, p := range t.s.StagedRollbacks {
		out = append(out, *p)
	}
	return out
}

// ---- 审计事件 ----

// addAuditEvent 追加一条不可变审计事件，返回带 ID 的副本。
func (t kvTx) addAuditEvent(e AuditEvent) AuditEvent {
	e.ID = t.s.NextAuditID
	t.s.NextAuditID++
	t.s.AuditEvents = append(t.s.AuditEvents, &e)
	return e
}

func (t kvTx) listAuditEvents(env Environment) []AuditEvent {
	var out []AuditEvent
	for _, e := range t.s.AuditEvents {
		if env == "" || e.Environment == env {
			out = append(out, *e)
		}
	}
	return out
}

// ---- 通知 outbox ----

// addOutboxMessage 在 outbox 中追加一条通知。调用方负责保证每个回滚号只追加一次。
func (t kvTx) addOutboxMessage(m OutboxMessage) OutboxMessage {
	m.ID = t.s.NextOutboxID
	t.s.NextOutboxID++
	t.s.Outbox = append(t.s.Outbox, &m)
	return m
}

// outboxByRollback 返回某回滚号已经生成的通知（用于一次性保证）。
func (t kvTx) outboxByRollback(number string) (OutboxMessage, bool) {
	for _, m := range t.s.Outbox {
		if m.RollbackNumber == number {
			return *m, true
		}
	}
	return OutboxMessage{}, false
}

func (t kvTx) listOutbox(includeDispatched bool) []OutboxMessage {
	var out []OutboxMessage
	for _, m := range t.s.Outbox {
		if includeDispatched || m.DispatchedAt.IsZero() {
			out = append(out, *m)
		}
	}
	return out
}

// markOutboxDispatched 把消息标记为已投递。
func (t kvTx) markOutboxDispatched(id int64, at time.Time) bool {
	if id <= 0 || id > int64(len(t.s.Outbox)) {
		return false
	}
	if !t.s.Outbox[id-1].DispatchedAt.IsZero() {
		return false
	}
	t.s.Outbox[id-1].DispatchedAt = at
	return true
}

// state 是服务的完整持久化状态。
type state struct {
	Artifacts    map[string]*Artifact    `json:"artifacts"`
	Attestations map[string]*Attestation `json:"attestations"`
	// AttestationRevision 是证明域的全局修订号，只在证明撤销时推进，
	// 回滚计划冻结创建时的取值，执行时据此发现“证明撤销先落地”。
	AttestationRevision  int64                          `json:"attestation_revision"`
	Policies             map[string]*Policy             `json:"policies"`
	PolicyVersions       map[string]int64               `json:"policy_versions"`
	Pointers             map[string]*EnvironmentPointer `json:"pointers"`
	Promotions           []*Promotion                   `json:"promotions"`
	ChangeIndex          map[string]int64               `json:"change_index"`
	Rollbacks            []*RollbackPlan                `json:"rollbacks"`
	RollbackIndex        map[string]int64               `json:"rollback_index"`
	StagedRollbacks      []*StagedRollbackPlan          `json:"staged_rollbacks"`
	StagedRollbackIndex  map[string]int64               `json:"staged_rollback_index"`
	AuditEvents          []*AuditEvent                  `json:"audit_events"`
	Outbox               []*OutboxMessage               `json:"outbox"`
	NextID               int64                          `json:"next_id"`
	NextAttID            int64                          `json:"next_attestation_id"`
	NextRollbackID       int64                          `json:"next_rollback_id"`
	NextStagedRollbackID int64                          `json:"next_staged_rollback_id"`
	NextAuditID          int64                          `json:"next_audit_id"`
	NextOutboxID         int64                          `json:"next_outbox_id"`
}

func newState() *state {
	return &state{
		Artifacts:            map[string]*Artifact{},
		Attestations:         map[string]*Attestation{},
		Policies:             map[string]*Policy{},
		PolicyVersions:       map[string]int64{},
		Pointers:             map[string]*EnvironmentPointer{},
		ChangeIndex:          map[string]int64{},
		RollbackIndex:        map[string]int64{},
		StagedRollbackIndex:  map[string]int64{},
		NextID:               1,
		NextAttID:            1,
		NextRollbackID:       1,
		NextStagedRollbackID: 1,
		NextAuditID:          1,
		NextOutboxID:         1,
	}
}

// clone 生成深拷贝，事务在副本上修改，失败回滚不影响已提交状态。
func (s *state) clone() *state {
	c := &state{
		Artifacts:            make(map[string]*Artifact, len(s.Artifacts)),
		Attestations:         make(map[string]*Attestation, len(s.Attestations)),
		AttestationRevision:  s.AttestationRevision,
		Policies:             make(map[string]*Policy, len(s.Policies)),
		PolicyVersions:       make(map[string]int64, len(s.PolicyVersions)),
		Pointers:             make(map[string]*EnvironmentPointer, len(s.Pointers)),
		Promotions:           make([]*Promotion, 0, len(s.Promotions)),
		ChangeIndex:          make(map[string]int64, len(s.ChangeIndex)),
		Rollbacks:            make([]*RollbackPlan, 0, len(s.Rollbacks)),
		RollbackIndex:        make(map[string]int64, len(s.RollbackIndex)),
		StagedRollbacks:      make([]*StagedRollbackPlan, 0, len(s.StagedRollbacks)),
		StagedRollbackIndex:  make(map[string]int64, len(s.StagedRollbackIndex)),
		AuditEvents:          make([]*AuditEvent, 0, len(s.AuditEvents)),
		Outbox:               make([]*OutboxMessage, 0, len(s.Outbox)),
		NextID:               s.NextID,
		NextAttID:            s.NextAttID,
		NextRollbackID:       s.NextRollbackID,
		NextStagedRollbackID: s.NextStagedRollbackID,
		NextAuditID:          s.NextAuditID,
		NextOutboxID:         s.NextOutboxID,
	}
	for k, v := range s.Artifacts {
		a := *v
		c.Artifacts[k] = &a
	}
	for k, v := range s.Attestations {
		a := *v
		c.Attestations[k] = &a
	}
	for k, v := range s.Policies {
		p := *v
		p.RequiredAttestations = append([]AttestationType(nil), v.RequiredAttestations...)
		c.Policies[k] = &p
	}
	for k, v := range s.PolicyVersions {
		c.PolicyVersions[k] = v
	}
	for k, v := range s.Pointers {
		p := *v
		c.Pointers[k] = &p
	}
	for k, v := range s.ChangeIndex {
		c.ChangeIndex[k] = v
	}
	for k, v := range s.RollbackIndex {
		c.RollbackIndex[k] = v
	}
	for k, v := range s.StagedRollbackIndex {
		c.StagedRollbackIndex[k] = v
	}
	for _, p := range s.Promotions {
		q := *p
		q.Attestations = append([]AttestationSnapshot(nil), p.Attestations...)
		q.PolicySnapshot.RequiredAttestations =
			append([]AttestationType(nil), p.PolicySnapshot.RequiredAttestations...)
		c.Promotions = append(c.Promotions, &q)
	}
	for _, r := range s.Rollbacks {
		q := *r
		q.Approvals = append([]RollbackApproval(nil), r.Approvals...)
		q.PolicySnapshot.RequiredAttestations =
			append([]AttestationType(nil), r.PolicySnapshot.RequiredAttestations...)
		c.Rollbacks = append(c.Rollbacks, &q)
	}
	for _, p := range s.StagedRollbacks {
		q := *p
		q.Approvals = append([]RollbackApproval(nil), p.Approvals...)
		q.Batches = nil
		for _, batch := range p.Batches {
			q.Batches = append(q.Batches, append([]Environment(nil), batch...))
		}
		q.Entries = nil
		for _, e := range p.Entries {
			eq := e
			eq.PolicySnapshot.RequiredAttestations =
				append([]AttestationType(nil), e.PolicySnapshot.RequiredAttestations...)
			q.Entries = append(q.Entries, eq)
		}
		c.StagedRollbacks = append(c.StagedRollbacks, &q)
	}
	for _, e := range s.AuditEvents {
		ev := *e
		c.AuditEvents = append(c.AuditEvents, &ev)
	}
	for _, m := range s.Outbox {
		msg := *m
		c.Outbox = append(c.Outbox, &msg)
	}
	return c
}

// store 是事务式存储：Update 串行执行，回调返回错误即回滚。
type store interface {
	update(fn func(kvTx) error) error
	view(fn func(kvTx) error) error
}

// memStore 同时承担内存存储与 JSON 文件持久化：path 为空时纯内存，
// 非空时每次提交都写入临时文件并原子 rename。
type memStore struct {
	mu   sync.Mutex
	root *state
	path string
}

func newMemStore() *memStore { return &memStore{root: newState()} }

// newFileStore 打开 path 上的 JSON 状态文件；文件不存在则初始化为空状态。
func newFileStore(path string) (*memStore, error) {
	m := &memStore{path: path, root: newState()}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return m, nil
		}
		return nil, fmt.Errorf("read state file %s: %w", path, err)
	}
	if err := json.Unmarshal(data, m.root); err != nil {
		return nil, fmt.Errorf("decode state file %s: %w", path, err)
	}
	if m.root.Artifacts == nil {
		m.root = newState()
	}
	// 兼容由旧版本写入、尚不含分批回滚字段的状态文件。
	if m.root.StagedRollbackIndex == nil {
		m.root.StagedRollbackIndex = map[string]int64{}
	}
	return m, nil
}

func (m *memStore) update(fn func(kvTx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := m.root.clone()
	err := fn(kvTx{s: snap})
	if err != nil {
		// commitError 表示“状态修改照常提交，但把内层错误返回给调用方”：
		// 用于回滚冲突这类既要终结计划、又必须返回冲突错误的场景。
		var ce *commitError
		if errors.As(err, &ce) {
			if m.path != "" {
				if perr := m.persist(snap); perr != nil {
					return perr
				}
			}
			m.root = snap
			return ce.inner
		}
		return err
	}
	if m.path != "" {
		if err := m.persist(snap); err != nil {
			return err
		}
	}
	m.root = snap
	return nil
}

func (m *memStore) view(fn func(kvTx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(kvTx{s: m.root})
}

// persist 将状态写入临时文件后原子改名，避免进程崩溃留下半截文件。
func (m *memStore) persist(s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	dir := filepath.Dir(m.path)
	tmp, err := os.CreateTemp(dir, ".promotion-state-*")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("sync temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, m.path); err != nil {
		return fmt.Errorf("replace state file: %w", err)
	}
	return nil
}
