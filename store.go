package artifactpromotion

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

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

func (t kvTx) rollbackByNumber(number string) (RollbackPlan, bool) {
	id, ok := t.s.RollbackIndex[number]
	if !ok {
		return RollbackPlan{}, false
	}
	return *t.s.Rollbacks[id-1], true
}

// addRollback 分配单调 ID 并写入回滚计划，返回新计划。
func (t kvTx) addRollback(p RollbackPlan) RollbackPlan {
	p.ID = t.s.NextRollbackID
	t.s.NextRollbackID++
	t.s.Rollbacks = append(t.s.Rollbacks, &p)
	t.s.RollbackIndex[p.RollbackNumber] = p.ID
	return p
}

// putRollback 按 ID 覆盖已有回滚计划（用于审批与执行状态推进）。
func (t kvTx) putRollback(p RollbackPlan) { t.s.Rollbacks[p.ID-1] = &p }

func (t kvTx) listRollbacks(env Environment) []RollbackPlan {
	var out []RollbackPlan
	for _, p := range t.s.Rollbacks {
		if env == "" || p.Environment == env {
			out = append(out, *p)
		}
	}
	return out
}

// addOutbox 追加一条通知 outbox 消息，返回带 ID 的消息。
func (t kvTx) addOutbox(m OutboxMessage) OutboxMessage {
	m.ID = t.s.NextOutboxID
	t.s.NextOutboxID++
	t.s.Outbox = append(t.s.Outbox, &m)
	return m
}

// addAudit 追加一条审计事件，返回带 ID 的事件。
func (t kvTx) addAudit(e AuditEvent) AuditEvent {
	e.ID = t.s.NextAuditID
	t.s.NextAuditID++
	t.s.AuditEvents = append(t.s.AuditEvents, &e)
	return e
}

// state 是服务的完整持久化状态。
type state struct {
	Artifacts    map[string]*Artifact           `json:"artifacts"`
	Attestations map[string]*Attestation        `json:"attestations"`
	Policies     map[string]*Policy             `json:"policies"`
	Pointers     map[string]*EnvironmentPointer `json:"pointers"`
	Promotions   []*Promotion                   `json:"promotions"`
	ChangeIndex  map[string]int64               `json:"change_index"`
	// AttestationRevision 在每次证明撤销时递增；回滚计划在创建时冻结该值，
	// 执行时若不匹配则说明有撤销先落地，必须冲突。
	AttestationRevision int64            `json:"attestation_revision"`
	Rollbacks           []*RollbackPlan  `json:"rollbacks"`
	RollbackIndex       map[string]int64 `json:"rollback_index"`
	Outbox              []*OutboxMessage `json:"outbox"`
	AuditEvents         []*AuditEvent    `json:"audit_events"`
	NextID              int64            `json:"next_id"`
	NextAttID           int64            `json:"next_attestation_id"`
	NextRollbackID      int64            `json:"next_rollback_id"`
	NextOutboxID        int64            `json:"next_outbox_id"`
	NextAuditID         int64            `json:"next_audit_id"`
}

func newState() *state {
	return &state{
		Artifacts:      map[string]*Artifact{},
		Attestations:   map[string]*Attestation{},
		Policies:       map[string]*Policy{},
		Pointers:       map[string]*EnvironmentPointer{},
		ChangeIndex:    map[string]int64{},
		RollbackIndex:  map[string]int64{},
		NextID:         1,
		NextAttID:      1,
		NextRollbackID: 1,
		NextOutboxID:   1,
		NextAuditID:    1,
	}
}

// clone 生成深拷贝，事务在副本上修改，失败回滚不影响已提交状态。
func (s *state) clone() *state {
	c := &state{
		Artifacts:           make(map[string]*Artifact, len(s.Artifacts)),
		Attestations:        make(map[string]*Attestation, len(s.Attestations)),
		Policies:            make(map[string]*Policy, len(s.Policies)),
		Pointers:            make(map[string]*EnvironmentPointer, len(s.Pointers)),
		Promotions:          make([]*Promotion, 0, len(s.Promotions)),
		ChangeIndex:         make(map[string]int64, len(s.ChangeIndex)),
		AttestationRevision: s.AttestationRevision,
		Rollbacks:           make([]*RollbackPlan, 0, len(s.Rollbacks)),
		RollbackIndex:       make(map[string]int64, len(s.RollbackIndex)),
		Outbox:              make([]*OutboxMessage, 0, len(s.Outbox)),
		AuditEvents:         make([]*AuditEvent, 0, len(s.AuditEvents)),
		NextID:              s.NextID,
		NextAttID:           s.NextAttID,
		NextRollbackID:      s.NextRollbackID,
		NextOutboxID:        s.NextOutboxID,
		NextAuditID:         s.NextAuditID,
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
	for k, v := range s.Pointers {
		p := *v
		c.Pointers[k] = &p
	}
	for k, v := range s.ChangeIndex {
		c.ChangeIndex[k] = v
	}
	for _, p := range s.Promotions {
		q := *p
		q.Attestations = append([]AttestationSnapshot(nil), p.Attestations...)
		q.PolicySnapshot.RequiredAttestations =
			append([]AttestationType(nil), p.PolicySnapshot.RequiredAttestations...)
		c.Promotions = append(c.Promotions, &q)
	}
	for k, v := range s.RollbackIndex {
		c.RollbackIndex[k] = v
	}
	for _, r := range s.Rollbacks {
		q := *r
		q.Approvals = append([]Approval(nil), r.Approvals...)
		q.PolicySnapshot.RequiredAttestations =
			append([]AttestationType(nil), r.PolicySnapshot.RequiredAttestations...)
		c.Rollbacks = append(c.Rollbacks, &q)
	}
	for _, m := range s.Outbox {
		q := *m
		c.Outbox = append(c.Outbox, &q)
	}
	for _, e := range s.AuditEvents {
		q := *e
		c.AuditEvents = append(c.AuditEvents, &q)
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
	// 兼容旧版本状态文件：补齐后引入的字段。
	if m.root.RollbackIndex == nil {
		m.root.RollbackIndex = map[string]int64{}
	}
	if m.root.NextRollbackID == 0 {
		m.root.NextRollbackID = 1
	}
	if m.root.NextOutboxID == 0 {
		m.root.NextOutboxID = 1
	}
	if m.root.NextAuditID == 0 {
		m.root.NextAuditID = 1
	}
	return m, nil
}

func (m *memStore) update(fn func(kvTx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	snap := m.root.clone()
	if err := fn(kvTx{s: snap}); err != nil {
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
