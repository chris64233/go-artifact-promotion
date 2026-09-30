package artifactpromotion

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// StagedBatchRequest 是分批回滚计划中的一批：同一批内的环境全部成功后
// 才会进入下一批；批内按给出的顺序执行。
type StagedBatchRequest struct {
	Environments []Environment
}

// CreateStagedRollbackRequest 是发起跨环境分批回滚的参数。
type CreateStagedRollbackRequest struct {
	// Number 是外部分批回滚号，全局唯一：同号重放具有幂等语义，
	// 同号但类型/目标/环境顺序不同返回 ErrChangeConflict。
	Number string
	Kind   RollbackKind
	// TargetDigest 是统一目标制品：它必须在 Batches 覆盖的每个环境都有
	// 历史上成功晋级且未被安全撤销的记录。
	TargetDigest Digest
	// Batches 按推进顺序给出批次；至少一批，环境不得重复或为空。
	Batches     []StagedBatchRequest
	Reason      string // 发起原因（必填），创建时冻结
	RequestedBy string
}

// stagedPriority 返回紧急计划对应的高优先级，其余为普通优先级。
func stagedPriority(kind RollbackKind) AuditPriority {
	if kind == RollbackEmergency {
		return AuditPriorityHigh
	}
	return AuditPriorityNormal
}

// CreateStagedRollback 创建一笔跨环境分批回滚计划。
//
// 创建时在同一快照上冻结：统一目标制品、环境（批次）顺序、每个环境的目标
// 版本（最近一次对应成功晋级记录）、各环境当前版本（版本号+摘要+来源记录）、
// 各环境策略版本（含完整策略快照）、全局证明修订号与发起原因。
//
// 目标制品必须在每个目标环境都历史上成功晋级过、未被安全撤销、且不是该
// 环境当前指针；任一环境不满足，整笔计划不会创建。同一环境不能同时出现在
// 两笔未终结（pending/paused）的分批计划中；计划终结（完成/冲突/取消）后，
// 尚未成功的环境可以重新加入新计划，已经成功的环境不再被新计划覆盖。
func (s *Service) CreateStagedRollback(req CreateStagedRollbackRequest) (StagedRollbackPlan, error) {
	if req.Number == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback number is required")
	}
	if req.Kind != RollbackNormal && req.Kind != RollbackEmergency {
		return StagedRollbackPlan{}, invalidArgument("rollback kind must be %q or %q",
			RollbackNormal, RollbackEmergency)
	}
	if err := parseDigest(string(req.TargetDigest)); err != nil {
		return StagedRollbackPlan{}, err
	}
	if req.Reason == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback reason is required")
	}
	if len(req.Batches) == 0 {
		return StagedRollbackPlan{}, invalidArgument("at least one batch is required")
	}

	batches := make([][]Environment, len(req.Batches))
	seenEnv := map[Environment]bool{}
	for i, b := range req.Batches {
		if len(b.Environments) == 0 {
			return StagedRollbackPlan{}, invalidArgument("batch %d must contain at least one environment", i+1)
		}
		for _, env := range b.Environments {
			if env == "" {
				return StagedRollbackPlan{}, invalidArgument("environment must not be empty in batch %d", i+1)
			}
			if seenEnv[env] {
				return StagedRollbackPlan{}, invalidArgument("environment %s appears more than once in the plan", env)
			}
			seenEnv[env] = true
			batches[i] = append(batches[i], env)
		}
	}

	var out StagedRollbackPlan
	err := s.store.update(func(tx kvTx) error {
		// 回滚号幂等：同号只能是同一笔计划的重放。
		if existing, ok := tx.stagedRollbackByNumber(req.Number); ok {
			if existing.Kind == req.Kind && existing.TargetDigest == req.TargetDigest &&
				sameBatches(existing.Batches, batches) {
				out = existing
				return nil
			}
			return fmt.Errorf("%w: staged rollback %q already targets %s across %d environments",
				ErrChangeConflict, req.Number, existing.TargetDigest, len(existing.Entries))
		}

		if _, ok := tx.getArtifact(req.TargetDigest); !ok {
			return fmt.Errorf("%w: %s", ErrArtifactNotFound, req.TargetDigest)
		}

		// 同一环境不能同时被两笔未终结的分批计划覆盖（终结后可重新加入）。
		for _, other := range tx.listStagedRollbacks() {
			if other.Status == StagedRollbackCompleted ||
				other.Status == StagedRollbackConflicted ||
				other.Status == StagedRollbackCanceled {
				continue
			}
			for _, e := range other.Entries {
				if seenEnv[e.Environment] {
					return fmt.Errorf("%w: environment %s is already covered by active staged rollback %s",
						ErrStagedRollbackState, e.Environment, other.Number)
				}
			}
		}

		now := s.clock.Now().UTC()
		entries := make([]StagedRollbackEntry, 0)
		for _, batch := range batches {
			for _, env := range batch {
				// 目标必须是该环境历史上成功晋级、未被安全撤销的版本。
				target, ok := latestPromotionFor(tx, env, req.TargetDigest)
				if !ok || target.SafetyRevoked() {
					return fmt.Errorf("%w: artifact %s was never successfully promoted to %s",
						ErrRollbackTargetInvalid, req.TargetDigest, env)
				}
				pointer := tx.getPointer(env)
				if pointer.Version == 0 {
					return fmt.Errorf("%w: environment %s has never been promoted",
						ErrRollbackTargetInvalid, env)
				}
				if pointer.Digest == req.TargetDigest {
					return fmt.Errorf("%w: artifact %s is already the current version of %s",
						ErrRollbackTargetInvalid, req.TargetDigest, env)
				}
				policy, ok := tx.getPolicy(env)
				if !ok {
					return fmt.Errorf("%w: %s", ErrPolicyNotFound, env)
				}
				entries = append(entries, StagedRollbackEntry{
					Environment:               env,
					TargetDigest:              req.TargetDigest,
					TargetPromotionID:         target.ID,
					TargetVersion:             target.Version,
					FrozenCurrentDigest:       pointer.Digest,
					FrozenCurrentVersion:      pointer.Version,
					FrozenCurrentPromoID:      pointer.PromotionID,
					FrozenPolicyVersion:       policy.Version,
					PolicySnapshot:            policy,
					FrozenAttestationRevision: tx.attestationRevision(),
					Status:                    StagedEntryPending,
				})
			}
		}

		plan := StagedRollbackPlan{
			Number:       req.Number,
			Kind:         req.Kind,
			TargetDigest: req.TargetDigest,
			Batches:      batches,
			Entries:      entries,
			Reason:       req.Reason,
			RequestedBy:  req.RequestedBy,
			CreatedAt:    now,
			Status:       StagedRollbackPending,
		}
		plan = tx.addStagedRollback(plan)
		tx.addAuditEvent(AuditEvent{
			Action:       AuditStagedRollbackCreated,
			Priority:     stagedPriority(req.Kind),
			StagedNumber: req.Number,
			Actor:        req.RequestedBy,
			Detail: fmt.Sprintf("%s staged rollback created: target %s across %d batch(es), %d environment(s)",
				req.Kind, req.TargetDigest, len(batches), len(entries)),
			OccurredAt: now,
		})
		out = plan
		return nil
	})
	return out, err
}

// sameBatches 比较两笔计划的批次顺序与批内环境顺序是否完全一致。
func sameBatches(a, b [][]Environment) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			if a[i][j] != b[i][j] {
				return false
			}
		}
	}
	return true
}

// ApproveStagedRollback 记录一位授权人对紧急分批回滚计划的批准。
//
// 仅紧急计划、且计划处于 pending/paused 时接受批准；必须取得两个不同
// 授权人。每次批准写一条高优先级审计事件，证据固化在计划上。
func (s *Service) ApproveStagedRollback(number, approver, comment string) (StagedRollbackPlan, error) {
	if number == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback number is required")
	}
	if approver == "" {
		return StagedRollbackPlan{}, invalidArgument("approver is required")
	}

	var out StagedRollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.stagedRollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrStagedRollbackNotFound, number)
		}
		if plan.Kind != RollbackEmergency {
			return fmt.Errorf("%w: staged rollback %s is %s and does not accept approvals",
				ErrStagedRollbackState, number, plan.Kind)
		}
		if plan.Status != StagedRollbackPending && plan.Status != StagedRollbackPaused {
			return fmt.Errorf("%w: staged rollback %s is %s", ErrStagedRollbackState, number, plan.Status)
		}
		for _, a := range plan.Approvals {
			if a.Approver == approver {
				return invalidArgument("approver %q has already approved staged rollback %s", approver, number)
			}
		}
		now := s.clock.Now().UTC()
		plan.Approvals = append(plan.Approvals, RollbackApproval{
			Approver: approver, Comment: comment, GrantedAt: now,
		})
		tx.updateStagedRollback(plan)
		tx.addAuditEvent(AuditEvent{
			Action:       AuditStagedRollbackApproved,
			Priority:     AuditPriorityHigh,
			StagedNumber: number,
			Actor:        approver,
			Detail:       fmt.Sprintf("emergency staged rollback approval %d/2: %s", len(plan.Approvals), comment),
			OccurredAt:   now,
		})
		out = plan
		return nil
	})
	return out, err
}

// stagedRollbackPayload 是分批回滚逐环境通知的 outbox 内容。
type stagedRollbackPayload struct {
	Number          string       `json:"number"`
	Kind            RollbackKind `json:"kind"`
	BatchIndex      int          `json:"batch_index"`
	Environment     Environment  `json:"environment"`
	FromDigest      Digest       `json:"from_digest"`
	ToDigest        Digest       `json:"to_digest"`
	ResultVersion   int64        `json:"result_version"`
	TargetPromotion int64        `json:"target_promotion_id"`
	Emergency       bool         `json:"emergency"`
	Approvers       []string     `json:"approvers,omitempty"`
	ExecutedAt      time.Time    `json:"executed_at"`
}

// markStagedConflict 把计划终结为 conflicted：记在首个冲突环境与计划级，
// 通过 commitWithError 让终结状态随事务提交，同时返回冲突错误。
func markStagedConflict(tx kvTx, plan *StagedRollbackPlan, idx int, code, reason string, cause error) error {
	plan.Entries[idx].Status = StagedEntryConflicted
	plan.Entries[idx].BlockCode = code
	plan.Entries[idx].BlockReason = reason
	plan.Status = StagedRollbackConflicted
	plan.BlockCode = code
	plan.BlockReason = reason
	tx.updateStagedRollback(*plan)
	return commitWithError(cause)
}

// stickyConflictError 在冲突终结计划被重放时，按固化的冲突代码返回与首次
// 相同类别的错误，使冲突不可“复活”。
func (s *Service) stickyConflictError(plan StagedRollbackPlan) error {
	switch plan.BlockCode {
	case StagedConflictTargetRevoked:
		return fmt.Errorf("%w: staged rollback %s target %s was safety-revoked",
			ErrRollbackTargetInvalid, plan.Number, plan.TargetDigest)
	case StagedConflictAttestationRev:
		return fmt.Errorf("%w: staged rollback %s froze attestation revision %s",
			ErrConcurrentModification, plan.Number, plan.BlockReason)
	default:
		return fmt.Errorf("%w: staged rollback %s is stale: %s",
			ErrConcurrentModification, plan.Number, plan.BlockReason)
	}
}

// classifyPolicyBlock 把策略门槛错误映射为可查询的阻断原因代码。
func classifyPolicyBlock(err error) string {
	switch {
	case errors.Is(err, ErrPolicyNotFound):
		return StagedBlockPolicyNotFound
	case errors.Is(err, ErrUpstreamNotPromoted):
		return StagedBlockUpstream
	default:
		return StagedBlockAttestationFailed
	}
}

// ExecuteStagedRollback 按批次推进分批回滚计划（暂停后再次调用即恢复）。
//
// 执行分两个阶段，且全部在同一个串行事务快照内完成：
//
//  1. 冲突预检（针对所有尚未成功的环境）：目标晋级版本被安全撤销
//     （ErrRollbackTargetInvalid）、环境指针偏离冻结的版本/摘要/来源记录，
//     或全局证明修订号在创建后推进（后两者 ErrConcurrentModification），
//     计划立即终结为 conflicted，所有环境指针都不移动；
//  2. 按批次顺序、批内顺序推进：紧急计划先校验双人批准，随后逐环境做
//     门槛检查（普通回滚满足执行时刻当前策略，紧急回滚绕过证明但保留冻结
//     策略快照的上游不变量）。首个失败的环境把计划暂停为 paused，
//     已成功环境保持现状；恢复调用从该环境继续，一批全部成功后才进入下一批。
//
// 每个环境成功都原子切换指针（版本号继续单调递增）、固化结果版本，并在
// 同一事务写一条 outbox 通知与审计事件。同一执行请求幂等：已完成计划的
// 重放直接返回首次结果；暂停计划的重放只重试尚未成功的环境。
func (s *Service) ExecuteStagedRollback(number string) (StagedRollbackPlan, error) {
	if number == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback number is required")
	}

	var out StagedRollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.stagedRollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrStagedRollbackNotFound, number)
		}

		// 终结状态的重放语义。
		switch plan.Status {
		case StagedRollbackCompleted:
			out = plan
			return nil
		case StagedRollbackCanceled:
			return fmt.Errorf("%w: staged rollback %s is canceled", ErrStagedRollbackState, number)
		case StagedRollbackConflicted:
			return s.stickyConflictError(plan)
		}

		now := s.clock.Now().UTC()

		// ---- 阶段 1：对所有尚未成功的环境做版本冲突预检 ----
		currentRevision := tx.attestationRevision()
		for i := range plan.Entries {
			e := &plan.Entries[i]
			if e.Status == StagedEntrySucceeded {
				continue
			}
			target, exists := tx.getPromotionByID(e.TargetPromotionID)
			if !exists || target.SafetyRevoked() {
				reason := fmt.Sprintf("target promotion %d of %s in %s was safety-revoked",
					e.TargetPromotionID, e.TargetDigest, e.Environment)
				cause := fmt.Errorf("%w: %s", ErrRollbackTargetInvalid, reason)
				return markStagedConflict(tx, &plan, i, StagedConflictTargetRevoked, reason, cause)
			}
			pointer := tx.getPointer(e.Environment)
			if pointer.Version != e.FrozenCurrentVersion ||
				pointer.Digest != e.FrozenCurrentDigest ||
				pointer.PromotionID != e.FrozenCurrentPromoID {
				reason := fmt.Sprintf("environment %s is at version %d (%s), staged rollback %s froze version %d",
					e.Environment, pointer.Version, pointer.Digest, number, e.FrozenCurrentVersion)
				cause := fmt.Errorf("%w: %s", ErrConcurrentModification, reason)
				return markStagedConflict(tx, &plan, i, StagedConflictEnvVersion, reason, cause)
			}
			if currentRevision != e.FrozenAttestationRevision {
				reason := fmt.Sprintf("attestation revision moved %d -> %d after staged rollback %s was created",
					e.FrozenAttestationRevision, currentRevision, number)
				cause := fmt.Errorf("%w: %s", ErrConcurrentModification, reason)
				return markStagedConflict(tx, &plan, i, StagedConflictAttestationRev, reason, cause)
			}
		}

		// ---- 阶段 2：按批次、批内顺序执行 ----
		entryIndex := map[Environment]int{}
		for i := range plan.Entries {
			entryIndex[plan.Entries[i].Environment] = i
		}
		approvers := make([]string, 0, len(plan.Approvals))
		for _, a := range plan.Approvals {
			approvers = append(approvers, a.Approver)
		}

		// pauseAt 记录首个阻断环境：暂停状态随事务提交（已成功的环境一并
		// 落地），同时把原始门槛错误返回给调用方。
		pauseAt := -1
		pauseCode := ""
		pauseCause := error(nil)

		for batchIdx, batch := range plan.Batches {
			for _, env := range batch {
				idx := entryIndex[env]
				e := &plan.Entries[idx]
				if e.Status == StagedEntrySucceeded {
					continue
				}

				// 紧急计划：双人不同授权人批准是计划级硬门槛。
				if plan.Kind == RollbackEmergency && len(plan.Approvals) < 2 {
					cause := fmt.Errorf("%w: emergency staged rollback %s requires 2 distinct approvers, got %d",
						ErrRollbackNotApproved, number, len(plan.Approvals))
					e.Attempts++
					pauseAt, pauseCode, pauseCause = idx, StagedBlockNotApproved, cause
					break
				}

				// 门槛检查：普通回滚满足执行时刻当前策略；紧急回滚绕过
				// 证明，但按冻结的策略快照保留上游不变量。
				var gateErr error
				if plan.Kind == RollbackNormal {
					currentPolicy, ok := tx.getPolicy(env)
					if !ok {
						gateErr = fmt.Errorf("%w: %s", ErrPolicyNotFound, env)
					} else {
						if _, err := checkPolicyAttestations(tx, currentPolicy, e.TargetDigest, now); err != nil {
							gateErr = err
						} else if err := checkUpstream(tx, currentPolicy, e.TargetDigest); err != nil {
							gateErr = err
						}
					}
				} else if err := checkUpstream(tx, e.PolicySnapshot, e.TargetDigest); err != nil {
					gateErr = err
				}
				if gateErr != nil {
					e.Attempts++
					pauseAt, pauseCode, pauseCause = idx, classifyPolicyBlock(gateErr), gateErr
					break
				}

				// 全部条件成立：原子切换指针。预检保证指针仍是冻结值。
				pointer := tx.getPointer(env)
				newVersion := pointer.Version + 1
				tx.putPointer(EnvironmentPointer{
					Environment: env,
					Digest:      e.TargetDigest,
					Version:     newVersion,
					PromotionID: e.TargetPromotionID,
					UpdatedAt:   now,
				})
				e.Status = StagedEntrySucceeded
				e.BlockCode = ""
				e.BlockReason = ""
				e.ResultVersion = newVersion
				e.ResultPromotionID = e.TargetPromotionID
				e.ExecutedAt = now

				payload, err := json.Marshal(stagedRollbackPayload{
					Number:          number,
					Kind:            plan.Kind,
					BatchIndex:      batchIdx,
					Environment:     env,
					FromDigest:      e.FrozenCurrentDigest,
					ToDigest:        e.TargetDigest,
					ResultVersion:   newVersion,
					TargetPromotion: e.TargetPromotionID,
					Emergency:       plan.Kind == RollbackEmergency,
					Approvers:       approvers,
					ExecutedAt:      now,
				})
				if err != nil {
					return fmt.Errorf("encode staged outbox payload: %w", err)
				}
				tx.addOutboxMessage(OutboxMessage{
					StagedNumber: number,
					Environment:  env,
					FromDigest:   e.FrozenCurrentDigest,
					ToDigest:     e.TargetDigest,
					Kind:         plan.Kind,
					Payload:      string(payload),
					CreatedAt:    now,
				})
				tx.addAuditEvent(AuditEvent{
					Action:       AuditStagedRollbackExecuted,
					Priority:     stagedPriority(plan.Kind),
					Environment:  env,
					StagedNumber: number,
					Actor:        plan.RequestedBy,
					Detail: fmt.Sprintf("%s staged rollback %s executed in %s (batch %d): %s -> %s (environment version %d -> %d)",
						plan.Kind, number, env, batchIdx+1, e.FrozenCurrentDigest, e.TargetDigest,
						e.FrozenCurrentVersion, newVersion),
					OccurredAt: now,
				})
			}
			if pauseAt >= 0 {
				break
			}
		}

		if pauseAt >= 0 {
			e := &plan.Entries[pauseAt]
			e.Status = StagedEntryBlocked
			e.BlockCode = pauseCode
			e.BlockReason = pauseCause.Error()
			plan.Status = StagedRollbackPaused
			plan.BlockCode = pauseCode
			plan.BlockReason = pauseCause.Error()
			tx.updateStagedRollback(plan)
			out = plan
			return commitWithError(pauseCause)
		}

		// 没有阻断：所有环境都已成功。
		plan.Status = StagedRollbackCompleted
		plan.BlockCode = ""
		plan.BlockReason = ""
		plan.CompletedAt = now
		tx.updateStagedRollback(plan)
		out = plan
		return nil
	})
	return out, err
}

// CancelStagedRollback 取消一笔分批回滚计划。
//
// 取消只阻止尚未开始（pending）与已被阻断（blocked）的后续环境：它们被
// 标记为 skipped，不再执行；已经成功的环境保持落地结果，绝不回滚，也不能
// 被重新加入同一计划。已取消是终结状态，重复取消幂等返回；对已完成或已
// 冲突的计划取消返回 ErrStagedRollbackState。
func (s *Service) CancelStagedRollback(number, by, reason string) (StagedRollbackPlan, error) {
	if number == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback number is required")
	}
	if by == "" {
		return StagedRollbackPlan{}, invalidArgument("canceling actor is required")
	}
	if reason == "" {
		return StagedRollbackPlan{}, invalidArgument("cancel reason is required")
	}

	var out StagedRollbackPlan
	err := s.store.update(func(tx kvTx) error {
		plan, ok := tx.stagedRollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrStagedRollbackNotFound, number)
		}
		// 终结状态：已取消幂等返回；已完成/已冲突拒绝取消。
		switch plan.Status {
		case StagedRollbackCanceled:
			out = plan
			return nil
		case StagedRollbackCompleted:
			return fmt.Errorf("%w: staged rollback %s is completed", ErrStagedRollbackState, number)
		case StagedRollbackConflicted:
			return fmt.Errorf("%w: staged rollback %s is conflicted", ErrStagedRollbackState, number)
		}

		now := s.clock.Now().UTC()
		for i := range plan.Entries {
			e := &plan.Entries[i]
			if e.Status == StagedEntryPending || e.Status == StagedEntryBlocked {
				e.Status = StagedEntrySkipped
				e.BlockCode = ""
				e.BlockReason = ""
			}
		}
		plan.Status = StagedRollbackCanceled
		plan.BlockCode = ""
		plan.BlockReason = ""
		plan.CanceledAt = now
		plan.CanceledBy = by
		plan.CancelReason = reason
		tx.updateStagedRollback(plan)
		tx.addAuditEvent(AuditEvent{
			Action:       AuditStagedRollbackCanceled,
			Priority:     stagedPriority(plan.Kind),
			StagedNumber: number,
			Actor:        by,
			Detail:       fmt.Sprintf("staged rollback %s canceled: %s", number, reason),
			OccurredAt:   now,
		})
		out = plan
		return nil
	})
	return out, err
}

// GetStagedRollback 按外部分批回滚号查询计划（含批次报告与审批证据），
// 不存在返回 ErrStagedRollbackNotFound。
func (s *Service) GetStagedRollback(number string) (StagedRollbackPlan, error) {
	if number == "" {
		return StagedRollbackPlan{}, invalidArgument("staged rollback number is required")
	}
	var out StagedRollbackPlan
	err := s.store.view(func(tx kvTx) error {
		plan, ok := tx.stagedRollbackByNumber(number)
		if !ok {
			return fmt.Errorf("%w: %s", ErrStagedRollbackNotFound, number)
		}
		out = plan
		return nil
	})
	return out, err
}

// PendingStagedOutbox 返回分批回滚逐环境落地后尚未投递的通知，按生成顺序
// 排列（与普通单笔回滚通知分开；PendingOutbox 仍只返回单笔回滚通知）。
func (s *Service) PendingStagedOutbox() ([]OutboxMessage, error) {
	var out []OutboxMessage
	err := s.store.view(func(tx kvTx) error {
		for _, m := range tx.listOutbox(false) {
			if m.StagedNumber != "" {
				out = append(out, m)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

// StagedOutboxForPlan 返回某分批回滚号已经生成的全部逐环境通知，
// 按通知 ID 排序；尚未有环境落地时返回空切片。
func (s *Service) StagedOutboxForPlan(number string) ([]OutboxMessage, error) {
	if number == "" {
		return nil, invalidArgument("staged rollback number is required")
	}
	var out []OutboxMessage
	err := s.store.view(func(tx kvTx) error {
		for _, m := range tx.listOutbox(true) {
			if m.StagedNumber == number {
				out = append(out, m)
			}
		}
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}
