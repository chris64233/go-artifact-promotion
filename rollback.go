package artifactpromotion

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"
)

// CreateRollbackRequest 是发起回滚的参数。
type CreateRollbackRequest struct {
	// Number 是外部回滚号，全局唯一：同号重放具有幂等语义，
	// 同号但环境/目标不同返回 ErrChangeConflict。
	Number string
	Kind   RollbackKind
	// Environment 与 TargetDigest 指明把哪个环境切回哪个历史版本。
	Environment  Environment
	TargetDigest Digest
	Reason       string // 发起原因（必填），创建时冻结
	RequestedBy  string
}

// latestPromotionFor 返回某环境内某制品最近一次“未被安全撤销”的成功晋级
// 记录（按版本号）。同一制品可能多次晋级；若最近一次被安全撤销而更早的
// 晋级仍然有效，回滚目标锚定到那条更早的记录。
func latestPromotionFor(tx kvTx, env Environment, d Digest) (Promotion, bool) {
	var found Promotion
	ok := false
	for _, p := range tx.listPromotions(env) {
		if p.Digest == d && !p.SafetyRevoked() && (!ok || p.Version > found.Version) {
			found, ok = p, true
		}
	}
	return found, ok
}

// CreateRollback 创建一笔回滚计划。
//
// 目标必须是该环境历史上成功晋级过、未被安全撤销、且不是当前指针的制品版本。
// 创建时在同一快照上冻结：目标版本（最近一次对应晋级记录）、环境当前版本与
// 摘要、策略版本（连同策略快照）、全局证明修订号与发起原因。
func (s *Service) CreateRollback(req CreateRollbackRequest) (RollbackPlan, error) {
	if req.Number == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	if req.Kind != RollbackNormal && req.Kind != RollbackEmergency {
		return RollbackPlan{}, invalidArgument("rollback kind must be %q or %q",
			RollbackNormal, RollbackEmergency)
	}
	if req.Environment == "" {
		return RollbackPlan{}, invalidArgument("environment is required")
	}
	if err := parseDigest(string(req.TargetDigest)); err != nil {
		return RollbackPlan{}, err
	}
	if req.Reason == "" {
		return RollbackPlan{}, invalidArgument("rollback reason is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		// 回滚号幂等：同号只能是同一笔计划的重放。
		if existing, ok := tx.rollbackByNumber(req.Number); ok {
			if existing.Environment == req.Environment &&
				existing.TargetDigest == req.TargetDigest &&
				existing.Kind == req.Kind {
				out = existing
				return nil
			}
			return fmt.Errorf("%w: rollback %q already targets %s in %s",
				ErrChangeConflict, req.Number, existing.TargetDigest, existing.Environment)
		}

		// 目标必须是该环境历史上成功晋级过的版本。
		target, ok := latestPromotionFor(tx, req.Environment, req.TargetDigest)
		if !ok {
			return fmt.Errorf("%w: artifact %s was never successfully promoted to %s",
				ErrRollbackTargetInvalid, req.TargetDigest, req.Environment)
		}
		// 已被安全撤销的历史版本不能作为回滚目标。
		if target.SafetyRevoked() {
			return fmt.Errorf("%w: promotion %d of %s is safety-revoked",
				ErrRollbackTargetInvalid, target.ID, req.TargetDigest)
		}

		pointer := tx.getPointer(req.Environment)
		if pointer.Version == 0 {
			return fmt.Errorf("%w: environment %s has never been promoted",
				ErrRollbackTargetInvalid, req.Environment)
		}
		if pointer.Digest == req.TargetDigest {
			return fmt.Errorf("%w: artifact %s is already the current version of %s",
				ErrRollbackTargetInvalid, req.TargetDigest, req.Environment)
		}

		// 冻结创建时的当前策略与策略版本。
		policy, ok := tx.getPolicy(req.Environment)
		if !ok {
			return fmt.Errorf("%w: %s", ErrPolicyNotFound, req.Environment)
		}

		now := s.clock.Now().UTC()
		plan := RollbackPlan{
			Number:                    req.Number,
			Kind:                      req.Kind,
			Environment:               req.Environment,
			TargetDigest:              req.TargetDigest,
			TargetPromotionID:         target.ID,
			TargetVersion:             target.Version,
			FrozenCurrentDigest:       pointer.Digest,
			FrozenCurrentVersion:      pointer.Version,
			FrozenCurrentPromoID:      pointer.PromotionID,
			FrozenPolicyVersion:       policy.Version,
			PolicySnapshot:            policy,
			FrozenAttestationRevision: tx.attestationRevision(),
			Reason:                    req.Reason,
			RequestedBy:               req.RequestedBy,
			CreatedAt:                 now,
			Status:                    RollbackPending,
		}
		plan = tx.addRollback(plan)

		// 紧急回滚从创建起即进入高优先级审计轨迹。
		priority := AuditPriorityNormal
		if req.Kind == RollbackEmergency {
			priority = AuditPriorityHigh
		}
		tx.addAuditEvent(AuditEvent{
			Action:         AuditRollbackCreated,
			Priority:       priority,
			Environment:    req.Environment,
			RollbackNumber: req.Number,
			Actor:          req.RequestedBy,
			Detail: fmt.Sprintf("%s rollback created: %s -> %s (frozen env version %d, policy version %d)",
				req.Kind, pointer.Digest, req.TargetDigest, pointer.Version, policy.Version),
			OccurredAt: now,
		})
		out = plan
		return nil
	})
	return out, err
}

// ApproveRollback 记录一位授权人对紧急回滚计划的批准。
//
// 紧急回滚必须取得两个不同授权人的批准：重复批准人、对普通回滚批准、
// 对已终结（已执行/已冲突）计划批准都会被拒绝。每次批准都写入高优先级
// 审计事件，批准证据固化在计划上可随时查询。
func (s *Service) ApproveRollback(number, approver, comment string) (RollbackPlan, error) {
	if number == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	if approver == "" {
		return RollbackPlan{}, invalidArgument("approver is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, number)
		}
		if plan.Kind != RollbackEmergency {
			return fmt.Errorf("%w: rollback %s is %s and does not accept approvals",
				ErrRollbackState, number, plan.Kind)
		}
		if plan.Status != RollbackPending {
			return fmt.Errorf("%w: rollback %s is %s", ErrRollbackState, number, plan.Status)
		}
		for _, a := range plan.Approvals {
			if a.Approver == approver {
				return invalidArgument("approver %q has already approved rollback %s", approver, number)
			}
		}
		now := s.clock.Now().UTC()
		plan.Approvals = append(plan.Approvals, RollbackApproval{
			Approver:  approver,
			Comment:   comment,
			GrantedAt: now,
		})
		tx.updateRollback(plan)
		tx.addAuditEvent(AuditEvent{
			Action:         AuditRollbackApproved,
			Priority:       AuditPriorityHigh,
			Environment:    plan.Environment,
			RollbackNumber: number,
			Actor:          approver,
			Detail:         fmt.Sprintf("emergency rollback approval %d/2: %s", len(plan.Approvals), comment),
			OccurredAt:     now,
		})
		out = plan
		return nil
	})
	return out, err
}

// rollbackPayload 是写入 outbox 的通知内容。
type rollbackPayload struct {
	Number          string       `json:"number"`
	Kind            RollbackKind `json:"kind"`
	Environment     Environment  `json:"environment"`
	FromDigest      Digest       `json:"from_digest"`
	ToDigest        Digest       `json:"to_digest"`
	ResultVersion   int64        `json:"result_version"`
	TargetPromotion int64        `json:"target_promotion_id"`
	Emergency       bool         `json:"emergency"`
	Approvers       []string     `json:"approvers,omitempty"`
	ExecutedAt      time.Time    `json:"executed_at"`
}

// ExecuteRollback 按创建时冻结的条件原子执行回滚。
//
// 冲突检测（任一不满足都绝不移动指针）：
//   - 环境版本/摘要仍与冻结值一致——期间有新的晋级或另一笔回滚先落地则
//     返回 ErrConcurrentModification，并把计划终结为 conflicted；
//   - 全局证明修订号未推进——期间有证明撤销先落地同样返回冲突；
//   - 目标晋级版本未被安全撤销（ErrRollbackTargetInvalid）。
//
// 普通回滚还必须满足执行时刻的当前策略（证明有效性 + 上游指针）；
// 紧急回滚绕过证明有效性要求（上游要求按冻结的策略快照保留），但缺少
// 两个不同授权人批准时返回 ErrRollbackNotApproved。
//
// 成功执行只推进环境指针（版本号继续单调递增），不删除任何后续晋级历史；
// outbox 通知与审计事件在同一事务内写入。同号重复执行直接返回首次结果。
func (s *Service) ExecuteRollback(number string) (RollbackPlan, error) {
	if number == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}

	var out RollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, number)
		}

		// 幂等：已执行计划的重放返回首次结果，不再写 outbox、不再移动指针。
		if plan.Status == RollbackExecuted {
			out = plan
			return nil
		}
		// 已终结为冲突的计划，重放仍返回同一个冲突。
		if plan.Status == RollbackConflicted {
			return fmt.Errorf("%w: rollback %s is stale (environment moved past frozen version %d)",
				ErrConcurrentModification, number, plan.FrozenCurrentVersion)
		}

		now := s.clock.Now().UTC()

		// 目标在执行前被安全撤销：计划不可再执行。
		target, ok := tx.getPromotionByID(plan.TargetPromotionID)
		if !ok || target.SafetyRevoked() {
			return fmt.Errorf("%w: target promotion %d of %s",
				ErrRollbackTargetInvalid, plan.TargetPromotionID, plan.TargetDigest)
		}

		// 环境版本条件：新的晋级或另一笔回滚先落地都会改变指针。
		pointer := tx.getPointer(plan.Environment)
		if pointer.Version != plan.FrozenCurrentVersion ||
			pointer.Digest != plan.FrozenCurrentDigest ||
			pointer.PromotionID != plan.FrozenCurrentPromoID {
			plan.Status = RollbackConflicted
			tx.updateRollback(plan)
			// 终结状态要随事务提交，但错误仍要返回给调用方。
			return commitWithError(fmt.Errorf("%w: environment %s is at version %d (%s), rollback %s froze version %d",
				ErrConcurrentModification, plan.Environment, pointer.Version, pointer.Digest,
				number, plan.FrozenCurrentVersion))
		}

		// 证明修订条件：创建之后有证明撤销先落地，旧计划必须冲突。
		if rev := tx.attestationRevision(); rev != plan.FrozenAttestationRevision {
			plan.Status = RollbackConflicted
			tx.updateRollback(plan)
			return commitWithError(fmt.Errorf("%w: attestation revision moved %d -> %d after rollback %s was created",
				ErrConcurrentModification, plan.FrozenAttestationRevision, rev, number))
		}

		if plan.Kind == RollbackNormal {
			// 普通回滚仍需满足执行时刻的当前策略。
			currentPolicy, ok := tx.getPolicy(plan.Environment)
			if !ok {
				return fmt.Errorf("%w: %s", ErrPolicyNotFound, plan.Environment)
			}
			if _, err := checkPolicyAttestations(tx, currentPolicy, plan.TargetDigest, now); err != nil {
				return err
			}
			if err := checkUpstream(tx, currentPolicy, plan.TargetDigest); err != nil {
				return err
			}
		} else {
			// 紧急回滚：双人不同授权人批准是硬门槛。
			if len(plan.Approvals) < 2 {
				return fmt.Errorf("%w: emergency rollback %s requires 2 distinct approvers, got %d",
					ErrRollbackNotApproved, number, len(plan.Approvals))
			}
			// 证明要求绕过；上游要求按创建时冻结的策略快照保留。
			if err := checkUpstream(tx, plan.PolicySnapshot, plan.TargetDigest); err != nil {
				return err
			}
		}

		// 全部条件成立：原子切换指针。回滚同样消耗一个新环境版本号。
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
		plan.ResultPromotionID = plan.TargetPromotionID
		tx.updateRollback(plan)

		// outbox 通知只可能在这里生成一次（重放走幂等分支）。
		approvers := make([]string, 0, len(plan.Approvals))
		for _, a := range plan.Approvals {
			approvers = append(approvers, a.Approver)
		}
		payload, err := json.Marshal(rollbackPayload{
			Number:          plan.Number,
			Kind:            plan.Kind,
			Environment:     plan.Environment,
			FromDigest:      plan.FrozenCurrentDigest,
			ToDigest:        plan.TargetDigest,
			ResultVersion:   newVersion,
			TargetPromotion: plan.TargetPromotionID,
			Emergency:       plan.Kind == RollbackEmergency,
			Approvers:       approvers,
			ExecutedAt:      now,
		})
		if err != nil {
			return fmt.Errorf("encode outbox payload: %w", err)
		}
		tx.addOutboxMessage(OutboxMessage{
			RollbackNumber: plan.Number,
			Environment:    plan.Environment,
			FromDigest:     plan.FrozenCurrentDigest,
			ToDigest:       plan.TargetDigest,
			Kind:           plan.Kind,
			Payload:        string(payload),
			CreatedAt:      now,
		})

		priority := AuditPriorityNormal
		if plan.Kind == RollbackEmergency {
			priority = AuditPriorityHigh
		}
		tx.addAuditEvent(AuditEvent{
			Action:         AuditRollbackExecuted,
			Priority:       priority,
			Environment:    plan.Environment,
			RollbackNumber: plan.Number,
			Detail: fmt.Sprintf("%s rollback executed: %s -> %s (environment version %d -> %d)",
				plan.Kind, plan.FrozenCurrentDigest, plan.TargetDigest,
				plan.FrozenCurrentVersion, newVersion),
			OccurredAt: now,
		})
		out = plan
		return nil
	})
	return out, err
}

// RevokePromotionSafety 把某个历史晋级版本标记为不安全（安全撤销）。
//
// 只打标记、不删除历史：被撤销版本立即从可回滚候选中消失，已创建未执行的
// 回滚计划在执行时返回 ErrRollbackTargetInvalid。重复撤销返回
// ErrInvalidArgument。该操作产生高优先级审计事件。
func (s *Service) RevokePromotionSafety(promotionID int64, by, reason string) (Promotion, error) {
	if promotionID <= 0 {
		return Promotion{}, invalidArgument("promotion id must be positive")
	}
	if by == "" {
		return Promotion{}, invalidArgument("revoking actor is required")
	}
	if reason == "" {
		return Promotion{}, invalidArgument("revoke reason is required")
	}

	var out Promotion
	err := s.store.update(func(tx kvTx) error {
		p, ok := tx.getPromotionByID(promotionID)
		if !ok {
			return fmt.Errorf("%w: id %d", ErrPromotionNotFound, promotionID)
		}
		if p.SafetyRevoked() {
			return invalidArgument("promotion %d is already safety-revoked", promotionID)
		}
		now := s.clock.Now().UTC()
		p.SafetyRevokedAt = now
		p.SafetyRevokedBy = by
		p.SafetyRevokeReason = reason
		tx.updatePromotion(p)
		tx.addAuditEvent(AuditEvent{
			Action:      AuditSafetyRevocation,
			Priority:    AuditPriorityHigh,
			Environment: p.Environment,
			PromotionID: p.ID,
			Actor:       by,
			Detail: fmt.Sprintf("promotion %d of %s in %s safety-revoked: %s",
				p.ID, p.Digest, p.Environment, reason),
			OccurredAt: now,
		})
		out = p
		return nil
	})
	return out, err
}

// GetRollback 按外部回滚号查询计划（含审批证据），不存在返回 ErrRollbackNotFound。
func (s *Service) GetRollback(number string) (RollbackPlan, error) {
	if number == "" {
		return RollbackPlan{}, invalidArgument("rollback number is required")
	}
	var out RollbackPlan
	err := s.store.view(func(tx kvTx) error {
		plan, ok := tx.rollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrRollbackNotFound, number)
		}
		out = plan
		return nil
	})
	return out, err
}

// Timeline 返回某环境的完整版本时间线：全部成功晋级与已执行回滚按环境版本
// 号排序合并。回滚之后的晋级历史仍然保留在时间线上。
func (s *Service) Timeline(env Environment) ([]TimelineEntry, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []TimelineEntry
	err := s.store.view(func(tx kvTx) error {
		for _, p := range tx.listPromotions(env) {
			out = append(out, TimelineEntry{
				Environment:   env,
				Version:       p.Version,
				Kind:          "promotion",
				Digest:        p.Digest,
				PromotionID:   p.ID,
				ChangeNumber:  p.ChangeNumber,
				SafetyRevoked: p.SafetyRevoked(),
				OccurredAt:    p.PromotedAt,
			})
		}
		for _, r := range tx.listRollbacks(env) {
			if r.Status != RollbackExecuted {
				continue
			}
			out = append(out, TimelineEntry{
				Environment:       env,
				Version:           r.ResultVersion,
				Kind:              "rollback",
				Digest:            r.TargetDigest,
				RollbackNumber:    r.Number,
				TargetPromotionID: r.TargetPromotionID,
				Emergency:         r.Kind == RollbackEmergency,
				OccurredAt:        r.ExecutedAt,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Version != out[j].Version {
			return out[i].Version < out[j].Version
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out, nil
}

// RollbackCandidates 返回某环境当前可回滚到的历史版本：该环境历史上成功
// 晋级过、未被安全撤销、且不是当前指针的制品，按最近晋级版本倒序排列。
func (s *Service) RollbackCandidates(env Environment) ([]RollbackCandidate, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []RollbackCandidate
	err := s.store.view(func(tx kvTx) error {
		latest := map[Digest]Promotion{}
		for _, p := range tx.listPromotions(env) {
			if p.SafetyRevoked() {
				continue
			}
			if cur, ok := latest[p.Digest]; !ok || p.Version > cur.Version {
				latest[p.Digest] = p
			}
		}
		pointer := tx.getPointer(env)
		for d, p := range latest {
			if d == pointer.Digest {
				continue
			}
			out = append(out, RollbackCandidate{
				Environment:     env,
				Digest:          d,
				PromotionID:     p.ID,
				PromotedVersion: p.Version,
				PromotedAt:      p.PromotedAt,
				ChangeNumber:    p.ChangeNumber,
			})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].PromotedVersion > out[j].PromotedVersion })
	return out, nil
}

// AffectedDownstreams 返回某环境指针变化（回滚或重新晋级）后受影响的下游
// 环境：沿各环境策略的上游依赖链做传递遍历，凡当前指针与其直接上游当前
// 指针不一致的环境都在结果中（Direct 区分直接/间接下游）。
func (s *Service) AffectedDownstreams(env Environment) ([]AffectedDownstream, error) {
	if env == "" {
		return nil, invalidArgument("environment is required")
	}
	var out []AffectedDownstream
	err := s.store.view(func(tx kvTx) error {
		// 建立 上游 -> 直接下游列表 的图。
		children := map[Environment][]Environment{}
		for _, p := range tx.listPolicies() {
			if p.UpstreamEnvironment != "" {
				children[p.UpstreamEnvironment] = append(children[p.UpstreamEnvironment], p.Environment)
			}
		}

		type frame struct {
			env    Environment
			direct bool
		}
		visited := map[Environment]bool{env: true}
		queue := []frame{{env: env, direct: true}}
		for len(queue) > 0 {
			cur := queue[0]
			queue = queue[1:]
			for _, child := range children[cur.env] {
				if visited[child] {
					continue
				}
				visited[child] = true

				childPtr := tx.getPointer(child)
				upstreamPtr := tx.getPointer(cur.env)
				if childPtr.Version != 0 && childPtr.Digest != upstreamPtr.Digest {
					out = append(out, AffectedDownstream{
						Environment:    child,
						Upstream:       cur.env,
						CurrentDigest:  childPtr.Digest,
						UpstreamDigest: upstreamPtr.Digest,
						Direct:         cur.direct,
					})
				}
				// 无论是否失配都继续向下遍历，以发现间接下游。
				queue = append(queue, frame{env: child, direct: false})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Direct != out[j].Direct {
			return out[i].Direct
		}
		return out[i].Environment < out[j].Environment
	})
	return out, nil
}

// AuditLog 返回审计事件（env 为空表示全部环境），按时间先后排序。
// highOnly 为 true 时只返回高优先级事件。
func (s *Service) AuditLog(env Environment, highOnly bool) ([]AuditEvent, error) {
	var out []AuditEvent
	err := s.store.view(func(tx kvTx) error {
		for _, e := range tx.listAuditEvents(env) {
			if highOnly && e.Priority != AuditPriorityHigh {
				continue
			}
			out = append(out, e)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OccurredAt.Equal(out[j].OccurredAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].OccurredAt.Before(out[j].OccurredAt)
	})
	return out, nil
}

// PendingOutbox 返回尚未被投递器取走的 outbox 通知，按生成顺序排列。
func (s *Service) PendingOutbox() ([]OutboxMessage, error) {
	var out []OutboxMessage
	err := s.store.view(func(tx kvTx) error {
		out = tx.listOutbox(false)
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// OutboxForRollback 返回某回滚号生成的唯一通知；未执行/不存在时第二返回值为 false。
func (s *Service) OutboxForRollback(number string) (OutboxMessage, bool, error) {
	var out OutboxMessage
	var found bool
	err := s.store.view(func(tx kvTx) error {
		out, found = tx.outboxByRollback(number)
		return nil
	})
	return out, found, err
}

// MarkOutboxDispatched 由外部投递器在成功投递后调用，把消息标记为已投递。
// 消息不存在或已投递过返回 ErrInvalidArgument。
func (s *Service) MarkOutboxDispatched(id int64) error {
	if id <= 0 {
		return invalidArgument("outbox message id must be positive")
	}
	return s.store.update(func(tx kvTx) error {
		if !tx.markOutboxDispatched(id, s.clock.Now().UTC()) {
			return invalidArgument("outbox message %d not found or already dispatched", id)
		}
		return nil
	})
}
