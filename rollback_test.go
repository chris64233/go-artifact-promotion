package artifactpromotion

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// rollbackFixture 搭好一个带策略的环境并依次晋级 versions 中的制品，
// 返回各版本的摘要。策略要求 vuln-scan 证明（每个版本都签发）。
func rollbackFixture(t *testing.T, s *Service, env Environment, versions ...string) []Digest {
	t.Helper()
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          env,
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}
	digests := make([]Digest, 0, len(versions))
	for i, v := range versions {
		d := mustDigest(t, "sha256", []byte(v))
		mustRegister(t, s, d, v)
		mustIssue(t, s, d, "vuln-scan")
		if _, err := s.Promote(PromotionRequest{
			ChangeNumber:    fmt.Sprintf("CHG-%s-%d", env, i+1),
			Environment:     env,
			Digest:          d,
			ExpectedVersion: int64(i),
		}); err != nil {
			t.Fatalf("Promote %s: %v", v, err)
		}
		digests = append(digests, d)
	}
	return digests
}

func mustCreateRollback(t *testing.T, s *Service, number string, env Environment, target Digest, emergency bool) RollbackPlan {
	t.Helper()
	plan, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: number,
		Environment:    env,
		TargetDigest:   target,
		Reason:         "bad deploy",
		Emergency:      emergency,
	})
	if err != nil {
		t.Fatalf("CreateRollback: %v", err)
	}
	return plan
}

// ---------- 创建与冻结 ----------

func TestCreateRollbackFreezesSnapshot(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")

	plan := mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	if plan.Status != RollbackPending {
		t.Fatalf("expected pending, got %s", plan.Status)
	}
	if plan.TargetDigest != ds[0] || plan.TargetPromotionID != 1 {
		t.Fatalf("unexpected target: %+v", plan)
	}
	if plan.FrozenCurrentVersion != 2 || plan.FrozenCurrentDigest != ds[1] {
		t.Fatalf("frozen current version mismatch: %+v", plan)
	}
	if plan.Reason != "bad deploy" {
		t.Fatalf("reason not frozen: %+v", plan)
	}
	if len(plan.PolicySnapshot.RequiredAttestations) != 1 ||
		plan.PolicySnapshot.RequiredAttestations[0] != "vuln-scan" {
		t.Fatalf("policy snapshot not frozen: %+v", plan.PolicySnapshot)
	}
	if plan.AttestationRevision != 0 {
		t.Fatalf("unexpected attestation revision %d", plan.AttestationRevision)
	}
}

func TestCreateRollbackValidation(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")

	// 缺字段。
	for _, req := range []RollbackRequest{
		{RollbackNumber: "", Environment: "prod", TargetDigest: ds[0], Reason: "r"},
		{RollbackNumber: "RB", Environment: "", TargetDigest: ds[0], Reason: "r"},
		{RollbackNumber: "RB", Environment: "prod", TargetDigest: "bad-digest", Reason: "r"},
		{RollbackNumber: "RB", Environment: "prod", TargetDigest: ds[0], Reason: ""},
	} {
		if _, err := s.CreateRollback(req); !errors.Is(err, ErrInvalidArgument) {
			t.Fatalf("expected ErrInvalidArgument for %+v, got %v", req, err)
		}
	}

	// 目标是当前版本。
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-cur", Environment: "prod", TargetDigest: ds[1], Reason: "r",
	}); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("expected ErrRollbackTargetInvalid for current version, got %v", err)
	}

	// 目标从未晋级到该环境。
	other := mustDigest(t, "sha256", []byte("other"))
	mustRegister(t, s, other, "other")
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-never", Environment: "prod", TargetDigest: other, Reason: "r",
	}); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("expected ErrRollbackTargetInvalid for never-promoted, got %v", err)
	}

	// 制品未登记。
	unregistered := mustDigest(t, "sha256", []byte("ghost"))
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-ghost", Environment: "prod", TargetDigest: unregistered, Reason: "r",
	}); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("expected ErrArtifactNotFound, got %v", err)
	}

	// 环境未配置策略。
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-nopol", Environment: "no-such-env", TargetDigest: ds[0], Reason: "r",
	}); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("expected ErrPolicyNotFound, got %v", err)
	}
}

func TestCreateRollbackIdempotentAndConflict(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2", "v3")

	first := mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	// 同号同目标：幂等返回同一计划。
	again := mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	if again.ID != first.ID || again.CreatedAt != first.CreatedAt {
		t.Fatalf("idempotent replay returned different plan: %+v vs %+v", again, first)
	}
	// 同号不同目标：冲突。
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-1", Environment: "prod", TargetDigest: ds[1], Reason: "r",
	}); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict, got %v", err)
	}
	// 同号不同环境：冲突。
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-1", Environment: "staging", TargetDigest: ds[0], Reason: "r",
	}); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("expected ErrChangeConflict for different env, got %v", err)
	}
}

// ---------- 普通回滚的策略约束 ----------

func TestNormalRollbackSuccess(t *testing.T) {
	s, clk := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	clk.Add(time.Hour)

	plan := mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	executed, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatalf("ExecuteRollback: %v", err)
	}
	if executed.Status != RollbackExecuted || executed.ResultVersion != 3 {
		t.Fatalf("unexpected executed plan: %+v", executed)
	}
	if !executed.ExecutedAt.Equal(clk.Now()) {
		t.Fatalf("executed time mismatch: %+v", executed)
	}
	ptr, err := s.GetPointer("prod")
	if err != nil {
		t.Fatal(err)
	}
	if ptr.Digest != ds[0] || ptr.Version != 3 || ptr.PromotionID != plan.TargetPromotionID {
		t.Fatalf("pointer not switched: %+v", ptr)
	}
}

func TestNormalRollbackStillRequiresPolicy(t *testing.T) {
	s, clk := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("v1"))
	d2 := mustDigest(t, "sha256", []byte("v2"))
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, s, d1, "v1")
	mustRegister(t, s, d2, "v2")
	// v1 的证明只在一小时内有效。
	if _, err := s.IssueAttestation(IssueAttestationRequest{
		Digest: d1, Type: "vuln-scan", Issuer: "sec", Conclusion: ConclusionApproved,
		ValidUntil: clk.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, s, d2, "vuln-scan")
	for i, d := range []Digest{d1, d2} {
		if _, err := s.Promote(PromotionRequest{
			ChangeNumber: fmt.Sprintf("CHG-%d", i), Environment: "prod",
			Digest: d, ExpectedVersion: int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	mustCreateRollback(t, s, "RB-1", "prod", d1, false)
	// v1 的证明过期后，普通回滚不再满足当前策略。
	clk.Add(2 * time.Hour)
	if _, err := s.ExecuteRollback("RB-1"); !errors.Is(err, ErrAttestationExpired) {
		t.Fatalf("expected ErrAttestationExpired, got %v", err)
	}
	// 指针未移动。
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d2 || ptr.Version != 2 {
		t.Fatalf("pointer moved on failed rollback: %+v", ptr)
	}
}

// ---------- 紧急回滚：双人批准 + 绕过证明 + 高优先级审计 ----------

func TestEmergencyRollbackRequiresTwoDistinctApprovers(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-911", "prod", ds[0], true)

	// 无批准。
	if _, err := s.ExecuteRollback("RB-911"); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("expected ErrRollbackNotApproved, got %v", err)
	}
	// 一个批准仍不够。
	if _, err := s.ApproveRollback("RB-911", "alice", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteRollback("RB-911"); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("expected ErrRollbackNotApproved with one approver, got %v", err)
	}
	// 同一授权人重复批准被拒绝。
	if _, err := s.ApproveRollback("RB-911", "alice", "again"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument for duplicate approver, got %v", err)
	}
	// 第二个不同授权人批准后执行成功。
	if _, err := s.ApproveRollback("RB-911", "bob", "lgtm"); err != nil {
		t.Fatal(err)
	}
	executed, err := s.ExecuteRollback("RB-911")
	if err != nil {
		t.Fatalf("ExecuteRollback: %v", err)
	}
	if executed.Status != RollbackExecuted {
		t.Fatalf("expected executed, got %+v", executed)
	}

	// 审批证据可查询。
	plan, err := s.GetRollback("RB-911")
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.Approvals) != 2 || plan.Approvals[0].Approver != "alice" ||
		plan.Approvals[1].Approver != "bob" {
		t.Fatalf("approval evidence missing: %+v", plan.Approvals)
	}

	// 紧急回滚全生命周期生成高优先级审计事件。
	events, err := s.AuditLog()
	if err != nil {
		t.Fatal(err)
	}
	high := map[string]bool{}
	for _, e := range events {
		if e.Priority == AuditHigh {
			high[e.Type] = true
		}
	}
	for _, typ := range []string{"rollback.created", "rollback.approved", "rollback.executed"} {
		if !high[typ] {
			t.Fatalf("expected high-priority audit event %q, got %+v", typ, events)
		}
	}
}

func TestEmergencyRollbackBypassesAttestationChecks(t *testing.T) {
	s, clk := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("v1"))
	d2 := mustDigest(t, "sha256", []byte("v2"))
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatal(err)
	}
	mustRegister(t, s, d1, "v1")
	mustRegister(t, s, d2, "v2")
	if _, err := s.IssueAttestation(IssueAttestationRequest{
		Digest: d1, Type: "vuln-scan", Issuer: "sec", Conclusion: ConclusionApproved,
		ValidUntil: clk.Now().Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	mustIssue(t, s, d2, "vuln-scan")
	for i, d := range []Digest{d1, d2} {
		if _, err := s.Promote(PromotionRequest{
			ChangeNumber: fmt.Sprintf("CHG-%d", i), Environment: "prod",
			Digest: d, ExpectedVersion: int64(i),
		}); err != nil {
			t.Fatal(err)
		}
	}

	mustCreateRollback(t, s, "RB-911", "prod", d1, true)
	if _, err := s.ApproveRollback("RB-911", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRollback("RB-911", "bob", ""); err != nil {
		t.Fatal(err)
	}
	// v1 的证明已过期：普通回滚会被拒，紧急回滚绕过证明检查。
	clk.Add(2 * time.Hour)
	executed, err := s.ExecuteRollback("RB-911")
	if err != nil {
		t.Fatalf("emergency rollback should bypass expired attestation: %v", err)
	}
	if executed.ResultVersion != 3 {
		t.Fatalf("unexpected result version: %+v", executed)
	}
}

func TestApproveRollbackValidation(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")

	if _, err := s.ApproveRollback("", "alice", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := s.ApproveRollback("RB-x", "", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := s.ApproveRollback("RB-x", "alice", ""); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("expected ErrRollbackNotFound, got %v", err)
	}

	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatal(err)
	}
	// 已执行的计划不得再批准。
	if _, err := s.ApproveRollback("RB-1", "alice", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument approving executed plan, got %v", err)
	}
}

// ---------- 执行冲突：更新的状态先落地 ----------

func TestExecuteRollbackConflictAfterNewPromotion(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)

	// 计划创建后又有新的晋级先落地。
	d3 := mustDigest(t, "sha256", []byte("v3"))
	mustRegister(t, s, d3, "v3")
	mustIssue(t, s, d3, "vuln-scan")
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-3", Environment: "prod", Digest: d3, ExpectedVersion: 2,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := s.ExecuteRollback("RB-1"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected ErrConcurrentModification, got %v", err)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d3 || ptr.Version != 3 {
		t.Fatalf("stale rollback overwrote newer state: %+v", ptr)
	}
}

func TestExecuteRollbackConflictAfterAnotherRollback(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2", "v3")

	// 两笔计划都冻结在环境版本 3。
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	mustCreateRollback(t, s, "RB-2", "prod", ds[1], false)

	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatal(err)
	}
	// 另一笔回滚先执行后，本计划必须冲突。
	if _, err := s.ExecuteRollback("RB-2"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected ErrConcurrentModification, got %v", err)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != ds[0] || ptr.Version != 4 {
		t.Fatalf("unexpected pointer: %+v", ptr)
	}
}

func TestExecuteRollbackConflictAfterRevocation(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)

	// 计划创建后有证明撤销先落地（撤销的是无关制品的证明也一样）。
	att := mustIssue(t, s, ds[1], "sbom")
	if err := s.RevokeAttestation(att.ID, "compromised"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteRollback("RB-1"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("expected ErrConcurrentModification after revocation, got %v", err)
	}
}

// ---------- 幂等执行与 outbox ----------

func TestExecuteRollbackIdempotentAndOutboxOnce(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)

	first, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatal(err)
	}
	// 重复执行相同回滚号：返回首次结果，即使环境状态此后又变化。
	d3 := mustDigest(t, "sha256", []byte("v3"))
	mustRegister(t, s, d3, "v3")
	mustIssue(t, s, d3, "vuln-scan")
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-3", Environment: "prod", Digest: d3, ExpectedVersion: 3,
	}); err != nil {
		t.Fatal(err)
	}
	again, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatalf("idempotent re-execute should succeed: %v", err)
	}
	if again.ID != first.ID || again.ResultVersion != first.ResultVersion ||
		!again.ExecutedAt.Equal(first.ExecutedAt) {
		t.Fatalf("re-execute returned different result: %+v vs %+v", again, first)
	}

	// outbox 只生成一次。
	outbox, err := s.ListOutbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(outbox) != 1 {
		t.Fatalf("expected exactly one outbox message, got %+v", outbox)
	}
	msg := outbox[0]
	if msg.Type != "rollback.executed" || msg.RollbackNumber != "RB-1" ||
		msg.FromDigest != ds[1] || msg.ToDigest != ds[0] || msg.Version != 3 {
		t.Fatalf("unexpected outbox message: %+v", msg)
	}
}

// ---------- 历史保留与时间线 ----------

func TestRollbackKeepsHistoryAndTimeline(t *testing.T) {
	s, clk := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	clk.Add(time.Minute)
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatal(err)
	}

	// 回滚不删除后续晋级历史。
	hist, err := s.History("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(hist) != 2 || hist[0].Digest != ds[0] || hist[1].Digest != ds[1] {
		t.Fatalf("promotion history rewritten: %+v", hist)
	}

	// 时间线包含晋级与回滚，按环境版本号升序。
	tl, err := s.Timeline("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 3 {
		t.Fatalf("expected 3 timeline entries, got %+v", tl)
	}
	want := []struct {
		version int64
		kind    string
		digest  Digest
	}{
		{1, "promotion", ds[0]},
		{2, "promotion", ds[1]},
		{3, "rollback", ds[0]},
	}
	for i, w := range want {
		if tl[i].Version != w.version || tl[i].Kind != w.kind || tl[i].Digest != w.digest {
			t.Fatalf("timeline[%d] = %+v, want %+v", i, tl[i], w)
		}
	}
	if _, err := s.Timeline(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
}

// ---------- 可回滚候选与安全撤销 ----------

func TestRollbackCandidates(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2", "v3")

	cands, err := s.RollbackCandidates("prod")
	if err != nil {
		t.Fatal(err)
	}
	// 当前版本 v3 不在候选中；按版本号从新到旧。
	if len(cands) != 2 || cands[0].Digest != ds[1] || cands[1].Digest != ds[0] {
		t.Fatalf("unexpected candidates: %+v", cands)
	}

	// 安全撤销 v2 后，候选只剩 v1，且不能再以 v2 为目标创建回滚。
	if err := s.RevokePromotionSafety(2, "v2 has a critical CVE"); err != nil {
		t.Fatal(err)
	}
	cands, err = s.RollbackCandidates("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(cands) != 1 || cands[0].Digest != ds[0] {
		t.Fatalf("safety-revoked version still a candidate: %+v", cands)
	}
	if _, err := s.CreateRollback(RollbackRequest{
		RollbackNumber: "RB-bad", Environment: "prod", TargetDigest: ds[1], Reason: "r",
	}); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("expected ErrRollbackTargetInvalid for safety-revoked target, got %v", err)
	}

	// 重复安全撤销报错；历史记录保留撤销标记。
	if err := s.RevokePromotionSafety(2, "again"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	p, err := s.GetPromotion(2)
	if err != nil {
		t.Fatal(err)
	}
	if !p.SafetyRevoked() || p.SafetyRevokeReason != "v2 has a critical CVE" {
		t.Fatalf("safety revocation not recorded: %+v", p)
	}
	if err := s.RevokePromotionSafety(99, "x"); !errors.Is(err, ErrPromotionNotFound) {
		t.Fatalf("expected ErrPromotionNotFound, got %v", err)
	}
	if err := s.RevokePromotionSafety(0, "x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}

	// 安全撤销生成高优先级审计事件。
	events, _ := s.AuditLog()
	found := false
	for _, e := range events {
		if e.Type == "promotion.safety_revoked" && e.Priority == AuditHigh {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected high-priority safety revocation audit event, got %+v", events)
	}
}

func TestSafetyRevocationAfterPlanCreationBlocksExecution(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)

	// 目标版本在计划创建后被安全撤销。
	if err := s.RevokePromotionSafety(1, "v1 also bad"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteRollback("RB-1"); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("expected ErrRollbackTargetInvalid, got %v", err)
	}
}

// ---------- 受影响下游环境 ----------

func TestAffectedDownstreams(t *testing.T) {
	s, _ := newTestService(t)
	// 依赖链：prod <- staging <- dev（dev 的上游是 staging）。
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "staging",
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "dev",
		RequiredAttestations: []AttestationType{"vuln-scan"},
		UpstreamEnvironment:  "staging",
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan"},
		UpstreamEnvironment:  "staging",
	}); err != nil {
		t.Fatal(err)
	}

	promote := func(env Environment, payload string, version int64) Digest {
		t.Helper()
		d := mustDigest(t, "sha256", []byte(payload))
		mustRegister(t, s, d, payload)
		mustIssue(t, s, d, "vuln-scan")
		if _, err := s.Promote(PromotionRequest{
			ChangeNumber: "CHG-" + string(env) + "-" + payload, Environment: env,
			Digest: d, ExpectedVersion: version,
		}); err != nil {
			t.Fatalf("promote %s to %s: %v", payload, env, err)
		}
		return d
	}

	v1 := promote("staging", "v1", 0)
	promote("dev", "v1", 0)
	promote("prod", "v1", 0)

	// 全部一致：无受影响环境。
	affected, err := s.AffectedDownstreams("staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 0 {
		t.Fatalf("expected no affected environments, got %+v", affected)
	}

	// staging 晋级 v2：dev 与 prod 仍指向 v1，均受影响。
	promote("staging", "v2", 1)
	affected, err = s.AffectedDownstreams("staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 2 {
		t.Fatalf("expected dev and prod affected, got %+v", affected)
	}
	byEnv := map[Environment]AffectedEnvironment{}
	for _, a := range affected {
		byEnv[a.Environment] = a
	}
	if byEnv["dev"].Digest != v1 || byEnv["dev"].Upstream != "staging" ||
		byEnv["prod"].Digest != v1 || byEnv["prod"].Upstream != "staging" {
		t.Fatalf("unexpected affected set: %+v", affected)
	}

	// staging 回滚到 v1 后恢复一致。
	mustCreateRollback(t, s, "RB-1", "staging", v1, false)
	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatal(err)
	}
	affected, err = s.AffectedDownstreams("staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(affected) != 0 {
		t.Fatalf("expected no affected environments after rollback, got %+v", affected)
	}
}

// ---------- 并发与持久化 ----------

func TestConcurrentRollbackExecution(t *testing.T) {
	for round := 0; round < 50; round++ {
		s, _ := newTestService(t)
		ds := rollbackFixture(t, s, "prod", "v1", "v2", "v3")
		// 两笔计划冻结在同一环境版本，并发执行时恰好一个成功。
		mustCreateRollback(t, s, "RB-1", "prod", ds[0], false)
		mustCreateRollback(t, s, "RB-2", "prod", ds[1], false)

		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, num := range []string{"RB-1", "RB-2"} {
			wg.Add(1)
			go func(i int, num string) {
				defer wg.Done()
				_, results[i] = s.ExecuteRollback(num)
			}(i, num)
		}
		wg.Wait()

		succeeded := 0
		for _, err := range results {
			switch {
			case err == nil:
				succeeded++
			case errors.Is(err, ErrConcurrentModification):
			default:
				t.Fatalf("round %d: unexpected error %v", round, err)
			}
		}
		if succeeded != 1 {
			t.Fatalf("round %d: expected exactly one rollback to succeed, got %d", round, succeeded)
		}
		outbox, _ := s.ListOutbox()
		if len(outbox) != 1 {
			t.Fatalf("round %d: expected exactly one outbox message, got %d", round, len(outbox))
		}
	}
}

func TestRollbackPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	s, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	ds := rollbackFixture(t, s, "prod", "v1", "v2")
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], true)
	if _, err := s.ApproveRollback("RB-1", "alice", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ApproveRollback("RB-1", "bob", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatal(err)
	}

	// 重启后：计划状态、审批证据、outbox、审计、指针全部保留。
	s2, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s2.GetRollback("RB-1")
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != RollbackExecuted || plan.ResultVersion != 3 || len(plan.Approvals) != 2 {
		t.Fatalf("rollback plan not persisted: %+v", plan)
	}
	// 幂等语义跨重启延续。
	again, err := s2.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatal(err)
	}
	if again.ResultVersion != 3 {
		t.Fatalf("idempotent replay after restart mismatch: %+v", again)
	}
	outbox, _ := s2.ListOutbox()
	if len(outbox) != 1 {
		t.Fatalf("outbox duplicated after restart: %+v", outbox)
	}
	events, _ := s2.AuditLog()
	if len(events) != 4 { // created + 2 次 approved + executed
		t.Fatalf("audit events not persisted: %+v", events)
	}
	ptr, _ := s2.GetPointer("prod")
	if ptr.Digest != ds[0] || ptr.Version != 3 {
		t.Fatalf("pointer not persisted: %+v", ptr)
	}
	tl, _ := s2.Timeline("prod")
	if len(tl) != 3 {
		t.Fatalf("timeline not persisted: %+v", tl)
	}
}

func TestGetAndListRollbacks(t *testing.T) {
	s, _ := newTestService(t)
	ds := rollbackFixture(t, s, "prod", "v1", "v2", "v3")
	mustCreateRollback(t, s, "RB-2", "prod", ds[1], false)
	mustCreateRollback(t, s, "RB-1", "prod", ds[0], true)

	if _, err := s.GetRollback("RB-x"); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("expected ErrRollbackNotFound, got %v", err)
	}
	if _, err := s.GetRollback(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := s.ExecuteRollback("RB-x"); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("expected ErrRollbackNotFound, got %v", err)
	}

	all, err := s.ListRollbacks("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 || all[0].RollbackNumber != "RB-2" || all[1].RollbackNumber != "RB-1" {
		t.Fatalf("unexpected rollback list: %+v", all)
	}
	other, err := s.ListRollbacks("staging")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("unexpected rollbacks for staging: %+v", other)
	}
}
