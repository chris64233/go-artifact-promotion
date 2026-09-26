package artifactpromotion

import (
	"fmt"
	"sort"
	"time"
)

// RollbackStatus 是回滚计划的生命周期状态。
type RollbackStatus string

const (
	// RollbackPending 计划已创建，尚未执行。
	RollbackPending RollbackStatus = "pending"
	// RollbackExecuted 计划已执行，环境指针已切换。
	RollbackExecuted RollbackStatus = "executed"
)

// Approval 是一名授权人对紧急回滚的批准证据。
type Approval struct {
	Approver   string
	Comment    string
	ApprovedAt time.Time
}

// RollbackPlan 是一笔回滚计划。创建时冻结目标版本、当前环境版本、
// 策略快照、证明修订号与发起原因；执行时以这些冻结值做冲突检测。
type RollbackPlan struct {
	ID             int64
	RollbackNumber string      // 外部回滚号，全局唯一，保证幂等
	Environment    Environment // 目标环境
	TargetDigest   Digest      // 回滚到的制品版本
	// TargetPromotionID 是目标版本在该环境最近一次成功晋级的记录 ID。
	TargetPromotionID int64
	// FrozenCurrentVersion/FrozenCurrentDigest 是创建计划时环境的当前版本与制品。
	FrozenCurrentVersion int64
	FrozenCurrentDigest  Digest
	// PolicySnapshot 是创建计划时环境策略的存档副本。
	PolicySnapshot Policy
	// AttestationRevision 是创建计划时的全局证明修订号；
	// 执行前若有证明撤销落地，该值不再匹配，计划必须冲突。
	AttestationRevision int64
	Reason              string
	// Emergency 为真表示紧急回滚：执行时绕过证明有效性要求，
	// 但必须取得两个不同授权人的批准，并产生高优先级审计事件。
	Emergency  bool
	Approvals  []Approval
	Status     RollbackStatus
	CreatedAt  time.Time
	ExecutedAt time.Time
	// ResultVersion 是执行完成后环境的版本号（仅 Status 为 executed 时有意义）。
	ResultVersion int64
}

// RollbackRequest 是创建回滚计划的参数。
type RollbackRequest struct {
	// RollbackNumber 是外部回滚号，同一回滚号的重复请求具有幂等语义。
	RollbackNumber string
	Environment    Environment
	TargetDigest   Digest
	Reason         string
	Emergency      bool
}

// OutboxMessage 是回滚执行后生成的一次性通知消息。
type OutboxMessage struct {
	ID             int64
	Type           string // 当前固定为 "rollback.executed"
	Environment    Environment
	RollbackNumber string
	FromDigest     Digest
	ToDigest       Digest
	Version        int64 // 回滚完成后的环境版本号
	CreatedAt      time.Time
}

// AuditPriority 是审计事件优先级。
type AuditPriority string

const (
	AuditNormal AuditPriority = "normal"
	AuditHigh   AuditPriority = "high"
)

// AuditEvent 是一条不可变审计事件。紧急回滚的创建、批准与执行，
// 以及晋级版本的安全撤销，都会生成高优先级事件。
type AuditEvent struct {
	ID          int64
	Priority    AuditPriority
	Type        string // rollback.created / rollback.approved / rollback.executed / promotion.safety_revoked
	Environment Environment
	Message     string
	At          time.Time
}

// RollbackCandidate 是一个可回滚目标：在该环境成功晋级过、
// 未被安全撤销、且不是当前版本的制品版本。
type RollbackCandidate struct {
	PromotionID int64
	Digest      Digest
	Version     int64 // 该制品最近一次晋级到本环境后的环境版本号
	PromotedAt  time.Time
}

// TimelineEntry 是环境版本时间线上的一项：一次晋级或一次已执行的回滚。
type TimelineEntry struct {
	Version int64
	Kind    string // "promotion" 或 "rollback"
	Digest  Digest
	// RecordID 是晋级记录 ID（Kind 为 promotion）或回滚计划 ID（Kind 为 rollback）。
	RecordID int64
	At       time.Time
}

// AffectedEnvironment 是一个受上游版本回退影响的下游环境。
type AffectedEnvironment struct {
	Environment Environment
	Digest      Digest // 该环境当前指向的制品
	Version     int64
	// Upstream 是依赖链上与其当前制品不一致的直接上游环境。
	Upstream Environment
}

// CreateRollback 创建回滚计划：冻结目标版本、当前环境版本、策略快照、
// 证明修订号与发起原因。目标必须是该环境历史上成功晋级且未被安全撤销、
// 且不是当前版本的制品。
//
// 同一回滚号、同一环境、同一目标的重复请求直接返回已有计划（幂等）；
// 同号但环境或目标不同返回 ErrChangeConflict。
func (s *Service) CreateRollback(req RollbackRequest) (RollbackPlan, error) {
	if req.RollbackNumber == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	if req.Environment == "" {
		return RollbackPlan{}, invalidArgument("environment is required")
	}
	if err := parseDigest(string(req.TargetDigest)); err != nil {
		return RollbackPlan{}, err
	}
	if req.Reason == "" {
		return RollbackPlan{}, invalidArgument("reason is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		// 幂等：回滚号已经用过时，只能是同一笔计划的重放。
		if existing, ok := tx.rollbackByNumber(req.RollbackNumber); ok {
			if existing.Environment == req.Environment && existing.TargetDigest == req.TargetDigest {
				out = existing
				return nil
			}
			return fmt.Errorf("%w: rollback %q already targets %s in %s",
				ErrChangeConflict, req.RollbackNumber, existing.TargetDigest, existing.Environment)
		}

		if _, ok := tx.getArtifact(req.TargetDigest); !ok {
			return fmt.Errorf("%w: %s", ErrArtifactNotFound, req.TargetDigest)
		}
		policy, ok := tx.getPolicy(req.Environment)
		if !ok {
			return fmt.Errorf("%w: %s", ErrPolicyNotFound, req.Environment)
		}

		pointer := tx.getPointer(req.Environment)
		if pointer.Digest == req.TargetDigest {
			return fmt.Errorf("%w: %s is already the current version of %s",
				ErrRollbackTargetInvalid, req.TargetDigest, req.Environment)
		}

		// 目标必须在该环境成功晋级过且未被安全撤销；取最近一次晋级记录。
		var target *Promotion
		for _, p := range tx.s.Promotions {
			if p.Environment == req.Environment && p.Digest == req.TargetDigest &&
				!p.SafetyRevoked() {
				if target == nil || p.ID > target.ID {
					target = p
				}
			}
		}
		if target == nil {
			return fmt.Errorf("%w: %s was never successfully promoted to %s or has been safety-revoked",
				ErrRollbackTargetInvalid, req.TargetDigest, req.Environment)
		}

		now := s.clock.Now().UTC()
		plan := RollbackPlan{
			RollbackNumber:       req.RollbackNumber,
			Environment:          req.Environment,
			TargetDigest:         req.TargetDigest,
			TargetPromotionID:    target.ID,
			FrozenCurrentVersion: pointer.Version,
			FrozenCurrentDigest:  pointer.Digest,
			PolicySnapshot:       policy,
			AttestationRevision:  tx.s.AttestationRevision,
			Reason:               req.Reason,
			Emergency:            req.Emergency,
			Status:               RollbackPending,
			CreatedAt:            now,
		}
		plan = tx.addRollback(plan)
		tx.addAudit(AuditEvent{
			Priority:    rollbackAuditPriority(plan),
			Type:        "rollback.created",
			Environment: plan.Environment,
			Message: fmt.Sprintf("rollback %s created: %s -> %s (reason: %s)",
				plan.RollbackNumber, plan.FrozenCurrentDigest, plan.TargetDigest, plan.Reason),
			At: now,
		})
		out = plan
		return nil
	})
	return out, err
}

// ApproveRollback 为回滚计划登记一名授权人的批准。同一授权人重复批准
// 返回 ErrInvalidArgument；计划已执行后不得再批准。
func (s *Service) ApproveRollback(rollbackNumber, approver, comment string) (RollbackPlan, error) {
	if rollbackNumber == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	if approver == "" {
		return RollbackPlan{}, invalidArgument("approver is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(rollbackNumber)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, rollbackNumber)
		}
		if plan.Status == RollbackExecuted {
			return invalidArgument("rollback %s is already executed", rollbackNumber)
		}
		for _, ap := range plan.Approvals {
			if ap.Approver == approver {
				return invalidArgument("approver %q has already approved rollback %s",
					approver, rollbackNumber)
			}
		}
		now := s.clock.Now().UTC()
		plan.Approvals = append(plan.Approvals, Approval{
			Approver:   approver,
			Comment:    comment,
			ApprovedAt: now,
		})
		tx.putRollback(plan)
		tx.addAudit(AuditEvent{
			Priority:    rollbackAuditPriority(plan),
			Type:        "rollback.approved",
			Environment: plan.Environment,
			Message:     fmt.Sprintf("rollback %s approved by %s", rollbackNumber, approver),
			At:          now,
		})
		out = plan
		return nil
	})
	return out, err
}

// ExecuteRollback 执行回滚：以创建时冻结的环境版本与证明修订号做冲突检测，
// 全部条件成立后在同一事务内原子切换环境指针、推进计划状态、生成唯一的
// outbox 通知与审计事件。
//
// 冲突检测保证：计划创建后若有新的晋级、另一笔回滚先执行（环境版本变化），
// 或有证明撤销先落地（证明修订号变化），本计划返回 ErrConcurrentModification，
// 绝不覆盖较新的环境状态。
//
// 普通回滚在执行时仍需满足当前策略（证明有效性与上游要求）；紧急回滚绕过
// 证明有效性要求（上游要求仍保留），但必须已取得两个不同授权人的批准。
//
// 已执行计划的重复执行直接返回首次执行结果，不重复生成 outbox 消息。
func (s *Service) ExecuteRollback(rollbackNumber string) (RollbackPlan, error) {
	if rollbackNumber == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(rollbackNumber)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, rollbackNumber)
		}
		// 幂等：已执行的计划直接返回首次结果。
		if plan.Status == RollbackExecuted {
			out = plan
			return nil
		}

		if plan.Emergency {
			distinct := map[string]bool{}
			for _, ap := range plan.Approvals {
				distinct[ap.Approver] = true
			}
			if len(distinct) < 2 {
				return fmt.Errorf("%w: emergency rollback %s requires approvals from two distinct approvers, has %d",
					ErrRollbackNotApproved, rollbackNumber, len(distinct))
			}
		}

		// 版本条件：环境版本自计划创建后未变，否则说明有新的晋级或另一笔
		// 回滚先落地。
		pointer := tx.getPointer(plan.Environment)
		if pointer.Version != plan.FrozenCurrentVersion {
			return fmt.Errorf("%w: environment %s is at version %d, rollback %s frozen at %d",
				ErrConcurrentModification, plan.Environment, pointer.Version,
				rollbackNumber, plan.FrozenCurrentVersion)
		}
		// 证明修订号条件：计划创建后有证明撤销先落地。
		if tx.s.AttestationRevision != plan.AttestationRevision {
			return fmt.Errorf("%w: attestations were revoked after rollback %s was created",
				ErrConcurrentModification, rollbackNumber)
		}

		// 目标版本在计划创建后被安全撤销：不得再回滚到它。
		target := tx.s.Promotions[plan.TargetPromotionID-1]
		if target.SafetyRevoked() {
			return fmt.Errorf("%w: target %s was safety-revoked after rollback %s was created",
				ErrRollbackTargetInvalid, plan.TargetDigest, rollbackNumber)
		}

		policy, ok := tx.getPolicy(plan.Environment)
		if !ok {
			return fmt.Errorf("%w: %s", ErrPolicyNotFound, plan.Environment)
		}
		now := s.clock.Now().UTC()
		if !plan.Emergency {
			// 普通回滚仍需满足当前策略的证明有效性要求。
			if _, err := selectAttestations(tx, policy, plan.TargetDigest, now); err != nil {
				return err
			}
		}
		// 上游要求对普通与紧急回滚同样保留。
		if err := checkUpstream(tx, policy, plan.TargetDigest); err != nil {
			return err
		}

		// 全部条件成立：指针切换、计划推进、outbox 与审计在同一事务内提交。
		newVersion := pointer.Version + 1
		tx.putPointer(EnvironmentPointer{
			Environment: plan.Environment,
			Digest:      plan.TargetDigest,
			Version:     newVersion,
			PromotionID: plan.TargetPromotionID,
			UpdatedAt:   now,
		})
		plan.Status = RollbackExecuted
		plan.ExecutedAt = now
		plan.ResultVersion = newVersion
		tx.putRollback(plan)
		tx.addOutbox(OutboxMessage{
			Type:           "rollback.executed",
			Environment:    plan.Environment,
			RollbackNumber: plan.RollbackNumber,
			FromDigest:     plan.FrozenCurrentDigest,
			ToDigest:       plan.TargetDigest,
			Version:        newVersion,
			CreatedAt:      now,
		})
		tx.addAudit(AuditEvent{
			Priority:    rollbackAuditPriority(plan),
			Type:        "rollback.executed",
			Environment: plan.Environment,
			Message: fmt.Sprintf("rollback %s executed: %s -> %s, environment version %d",
				plan.RollbackNumber, plan.FrozenCurrentDigest, plan.TargetDigest, newVersion),
			At: now,
		})
		out = plan
		return nil
	})
	return out, err
}

func rollbackAuditPriority(plan RollbackPlan) AuditPriority {
	if plan.Emergency {
		return AuditHigh
	}
	return AuditNormal
}

// RevokePromotionSafety 安全撤销一次晋级版本：该版本此后不得再作为回滚
// 目标（已创建未执行的同类计划也会在执行时失败）。撤销只打标记，不删除
// 晋级历史，并生成高优先级审计事件。重复撤销返回 ErrInvalidArgument。
func (s *Service) RevokePromotionSafety(promotionID int64, reason string) error {
	if promotionID <= 0 {
		return invalidArgument("promotion id must be positive")
	}
	return s.store.update(func(tx kvTx) error {
		if promotionID > int64(len(tx.s.Promotions)) {
			return fmt.Errorf("%w: id %d", ErrPromotionNotFound, promotionID)
		}
		p := tx.s.Promotions[promotionID-1]
		if p.SafetyRevoked() {
			return invalidArgument("promotion %d is already safety-revoked", promotionID)
		}
		now := s.clock.Now().UTC()
		p.SafetyRevokedAt = now
		p.SafetyRevokeReason = reason
		tx.addAudit(AuditEvent{
			Priority:    AuditHigh,
			Type:        "promotion.safety_revoked",
			Environment: p.Environment,
			Message: fmt.Sprintf("promotion %d (%s in %s) safety-revoked: %s",
				p.ID, p.Digest, p.Environment, reason),
			At: now,
		})
		return nil
	})
}

// GetRollback 按回滚号查询回滚计划（含审批证据），不存在时返回 ErrRollbackNotFound。
func (s *Service) GetRollback(rollbackNumber string) (RollbackPlan, error) {
	if rollbackNumber == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	var out RollbackPlan
	err := s.store.view(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(rollbackNumber)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, rollbackNumber)
		}
		out = plan
		return nil
	})
	return out, err
}

// ListRollbacks 列出回滚计划；env 为空时返回所有环境的计划，按创建先后排序。
func (s *Service) ListRollbacks(env Environment) ([]RollbackPlan, error) {
	var out []RollbackPlan
	err := s.store.view(func(tx kvTx) error {
		out = tx.listRollbacks(env)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// RollbackCandidates 列出环境的可回滚目标：成功晋级过、未被安全撤销、
// 且不是当前版本的制品版本，按版本号从新到旧排序。
func (s *Service) RollbackCandidates(env Environment) ([]RollbackCandidate, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []RollbackCandidate
	err := s.store.view(func(tx kvTx) error {
		current := tx.getPointer(env)
		// 同一制品可能多次晋级，取最近一次记录。
		latest := map[Digest]Promotion{}
		for _, p := range tx.s.Promotions {
			if p.Environment != env || p.SafetyRevoked() || p.Digest == current.Digest {
				continue
			}
			if prev, ok := latest[p.Digest]; !ok || p.ID > prev.ID {
				latest[p.Digest] = *p
			}
		}
		for _, p := range latest {
			out = append(out, RollbackCandidate{
				PromotionID: p.ID,
				Digest:      p.Digest,
				Version:     p.Version,
				PromotedAt:  p.PromotedAt,
			})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Version > out[j].Version })
	return out, err
}

// Timeline 返回环境版本时间线：晋级与已执行回滚按环境版本号升序排列。
// 回滚只移动指针，不删除后续晋级历史，因此时间线上同一制品可能出现多次。
func (s *Service) Timeline(env Environment) ([]TimelineEntry, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []TimelineEntry
	err := s.store.view(func(tx kvTx) error {
		for _, p := range tx.s.Promotions {
			if p.Environment != env {
				continue
			}
			out = append(out, TimelineEntry{
				Version:  p.Version,
				Kind:     "promotion",
				Digest:   p.Digest,
				RecordID: p.ID,
				At:       p.PromotedAt,
			})
		}
		for _, r := range tx.s.Rollbacks {
			if r.Environment != env || r.Status != RollbackExecuted {
				continue
			}
			out = append(out, TimelineEntry{
				Version:  r.ResultVersion,
				Kind:     "rollback",
				Digest:   r.TargetDigest,
				RecordID: r.ID,
				At:       r.ExecutedAt,
			})
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Version < out[j].Version })
	return out, err
}

// AffectedDownstreams 查询受 env 当前版本影响的下游环境：沿策略的
// 上游依赖链（传递）找出当前指向的制品与其直接上游不一致的环境。
// 典型场景是 env 回滚后，曾经从 env 晋级过旧版本的下游环境不再满足
// “上游当前正指向同一制品”的不变量。
func (s *Service) AffectedDownstreams(env Environment) ([]AffectedEnvironment, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []AffectedEnvironment
	err := s.store.view(func(tx kvTx) error {
		// 沿上游依赖关系做广度优先遍历。
		queue := []Environment{env}
		visited := map[Environment]bool{env: true}
		for len(queue) > 0 {
			up := queue[0]
			queue = queue[1:]
			upPtr := tx.getPointer(up)
			for _, p := range tx.s.Policies {
				if p.UpstreamEnvironment != up || visited[p.Environment] {
					continue
				}
				visited[p.Environment] = true
				queue = append(queue, p.Environment)
				ptr := tx.getPointer(p.Environment)
				if ptr.Version > 0 && ptr.Digest != upPtr.Digest {
					out = append(out, AffectedEnvironment{
						Environment: p.Environment,
						Digest:      ptr.Digest,
						Version:     ptr.Version,
						Upstream:    up,
					})
				}
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Environment < out[j].Environment })
	return out, err
}

// ListOutbox 按生成顺序返回全部通知 outbox 消息。
func (s *Service) ListOutbox() ([]OutboxMessage, error) {
	var out []OutboxMessage
	err := s.store.view(func(tx kvTx) error {
		for _, m := range tx.s.Outbox {
			out = append(out, *m)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// AuditLog 按发生顺序返回全部审计事件。
func (s *Service) AuditLog() ([]AuditEvent, error) {
	var out []AuditEvent
	err := s.store.view(func(tx kvTx) error {
		for _, e := range tx.s.AuditEvents {
			out = append(out, *e)
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}
