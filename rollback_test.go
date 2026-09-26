package artifactpromotion

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// ---- 测试辅助 ----

func mustConfigure(t *testing.T, s *Service, env Environment, upstream Environment, reqs ...AttestationType) {
	t.Helper()
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          env,
		RequiredAttestations: reqs,
		UpstreamEnvironment:  upstream,
	}); err != nil {
		t.Fatalf("ConfigurePolicy %s: %v", env, err)
	}
}

func mustPromote(t *testing.T, s *Service, change string, env Environment, d Digest, expected int64) Promotion {
	t.Helper()
	rec, err := s.Promote(PromotionRequest{
		ChangeNumber: change, Environment: env, Digest: d, ExpectedVersion: expected,
	})
	if err != nil {
		t.Fatalf("Promote %s %s: %v", change, env, err)
	}
	return rec
}

func mustCreateRollback(t *testing.T, s *Service, req CreateRollbackRequest) RollbackPlan {
	t.Helper()
	plan, err := s.CreateRollback(req)
	if err != nil {
		t.Fatalf("CreateRollback %s: %v", req.Number, err)
	}
	return plan
}

func mustApprove(t *testing.T, s *Service, number, approver string) RollbackPlan {
	t.Helper()
	plan, err := s.ApproveRollback(number, approver, "LGTM by "+approver)
	if err != nil {
		t.Fatalf("ApproveRollback %s by %s: %v", number, approver, err)
	}
	return plan
}

// setupProdChain 在 prod 连续晋级 d1 -> d2 -> d3（策略仅要求 vuln-scan），
// 返回三个摘要与三次晋级记录。
func setupProdChain(t *testing.T) (*Service, *mutableClock, Digest, Digest, Digest) {
	t.Helper()
	s, clk := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("rel-1"))
	d2 := mustDigest(t, "sha256", []byte("rel-2"))
	d3 := mustDigest(t, "sha256", []byte("rel-3"))
	for _, d := range []Digest{d1, d2, d3} {
		mustRegister(t, s, d, "api")
		mustIssue(t, s, d, "vuln-scan")
	}
	mustConfigure(t, s, "prod", "", "vuln-scan")
	mustPromote(t, s, "CHG-1", "prod", d1, 0)
	mustPromote(t, s, "CHG-2", "prod", d2, 1)
	mustPromote(t, s, "CHG-3", "prod", d3, 2)
	return s, clk, d1, d2, d3
}

// ---- 可回滚候选 ----

func TestRollbackCandidates(t *testing.T) {
	s, _, d1, d2, _ := setupProdChain(t)

	got, err := s.RollbackCandidates("prod")
	if err != nil {
		t.Fatal(err)
	}
	// 当前指针 d3 被排除；d1/d2 按最近晋级版本倒序。
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates, got %+v", got)
	}
	if got[0].Digest != d2 || got[1].Digest != d1 {
		t.Fatalf("candidates order mismatch: %+v", got)
	}
	if got[0].PromotedVersion != 2 || got[0].ChangeNumber != "CHG-2" {
		t.Fatalf("candidate should point at latest promotion: %+v", got[0])
	}

	if _, err := s.RollbackCandidates(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	// 从未使用的环境：空候选、无错误。
	empty, err := s.RollbackCandidates("qa")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty env candidates: %+v err=%v", empty, err)
	}
}

func TestRollbackCandidatesExcludeSafetyRevokedAndCurrent(t *testing.T) {
	s, _, _, d2, d3 := setupProdChain(t)

	// 安全撤销 d1 的晋级版本：候选中消失。
	rec1, err := s.GetPromotion(1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RevokePromotionSafety(rec1.ID, "sec", "compromised build"); err != nil {
		t.Fatal(err)
	}
	got, _ := s.RollbackCandidates("prod")
	if len(got) != 1 || got[0].Digest != d2 {
		t.Fatalf("revoked d1 must disappear, current d3 excluded: %+v", got)
	}

	// 回滚到 d2 后，d2 成为当前指针，候选只剩未被撤销的 d3。
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d2, Reason: "bad d3", RequestedBy: "ops",
	})
	if _, err := s.ExecuteRollback(plan.Number); err != nil {
		t.Fatalf("execute: %v", err)
	}
	got, _ = s.RollbackCandidates("prod")
	if len(got) != 1 || got[0].Digest != d3 {
		t.Fatalf("after rollback, d2 current and d1 revoked: %+v", got)
	}
}

// 同一制品多次晋级、只撤销最近一次：回滚锚定到更早的未撤销晋级记录。
func TestRollbackAnchorFallsBackToEarlierNonRevokedPromotion(t *testing.T) {
	s, _, d1, d2, _ := setupProdChain(t) // d1@v1, d2@v2, d3@v3
	// d1 再晋级一次到 v4。
	mustPromote(t, s, "CHG-4", "prod", d1, 3)
	ptr, _ := s.GetPointer("prod")
	if ptr.Version != 4 || ptr.PromotionID == 1 {
		t.Fatalf("precondition pointer: %+v", ptr)
	}

	// 安全撤销 v4（d1 最近一次晋级），d2 成为当前之外的候选之一；
	// d1 仍应以 v1 那条未撤销记录作为候选与回滚锚点。
	if _, err := s.RevokePromotionSafety(ptr.PromotionID, "sec", "bad repromotion"); err != nil {
		t.Fatal(err)
	}
	// 让 d2 成为当前版本，使 d1 可以作为回滚目标。
	toD2 := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-0", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d2, Reason: "step",
	})
	if _, err := s.ExecuteRollback(toD2.Number); err != nil {
		t.Fatal(err)
	}
	cands, _ := s.RollbackCandidates("prod")
	var d1cand *RollbackCandidate
	for i := range cands {
		if cands[i].Digest == d1 {
			d1cand = &cands[i]
		}
	}
	if d1cand == nil || d1cand.PromotionID != 1 || d1cand.PromotedVersion != 1 {
		t.Fatalf("d1 candidate must anchor to non-revoked v1: %+v", cands)
	}

	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if plan.TargetPromotionID != 1 || plan.TargetVersion != 1 {
		t.Fatalf("plan must anchor to v1, got %+v", plan)
	}
	if _, err := s.ExecuteRollback("RB-1"); err != nil {
		t.Fatalf("rollback to earlier non-revoked promotion should execute: %v", err)
	}
	p, _ := s.GetPointer("prod")
	if p.Digest != d1 || p.PromotionID != 1 {
		t.Fatalf("pointer must source from v1: %+v", p)
	}
}

// ---- 创建回滚：冻结与校验 ----

func TestCreateRollbackFreezesSnapshot(t *testing.T) {
	s, clk, d1, _, d3 := setupProdChain(t)

	plan, err := s.CreateRollback(CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "regression in d3", RequestedBy: "alice",
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != RollbackPending || plan.ID <= 0 {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if plan.TargetDigest != d1 || plan.TargetVersion != 1 {
		t.Fatalf("target not frozen from latest promotion of d1: %+v", plan)
	}
	if plan.FrozenCurrentDigest != d3 || plan.FrozenCurrentVersion != 3 {
		t.Fatalf("current env state not frozen: %+v", plan)
	}
	if plan.FrozenPolicyVersion != 1 {
		t.Fatalf("policy version not frozen: %+v", plan)
	}
	if plan.FrozenAttestationRevision != 0 || plan.Reason != "regression in d3" {
		t.Fatalf("revision/reason not frozen: %+v", plan)
	}
	if !plan.CreatedAt.Equal(clk.Now()) {
		t.Fatalf("CreatedAt mismatch: %v", plan.CreatedAt)
	}
}

func TestCreateRollbackValidation(t *testing.T) {
	s, _, d1, d2, d3 := setupProdChain(t)
	notPromoted := mustDigest(t, "sha256", []byte("elsewhere"))
	mustRegister(t, s, notPromoted, "api")

	base := CreateRollbackRequest{
		Number: "RB-X", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	}
	check := func(mut func(*CreateRollbackRequest), target error, name string) {
		req := base
		mut(&req)
		_, err := s.CreateRollback(req)
		if !errors.Is(err, target) {
			t.Fatalf("%s: expected %v, got %v", name, target, err)
		}
	}
	check(func(r *CreateRollbackRequest) { r.Number = "" }, ErrInvalidArgument, "empty number")
	check(func(r *CreateRollbackRequest) { r.Kind = "weird" }, ErrInvalidArgument, "bad kind")
	check(func(r *CreateRollbackRequest) { r.Environment = "" }, ErrInvalidArgument, "empty env")
	check(func(r *CreateRollbackRequest) { r.TargetDigest = "sha256:zz" }, ErrInvalidArgument, "bad digest")
	check(func(r *CreateRollbackRequest) { r.Reason = "" }, ErrInvalidArgument, "empty reason")
	check(func(r *CreateRollbackRequest) { r.TargetDigest = notPromoted }, ErrRollbackTargetInvalid, "never promoted")
	check(func(r *CreateRollbackRequest) { r.TargetDigest = d3 }, ErrRollbackTargetInvalid, "is current")

	// 环境从未晋级：无可回滚版本。
	_, err := s.CreateRollback(CreateRollbackRequest{
		Number: "RB-Y", Kind: RollbackNormal, Environment: "qa",
		TargetDigest: d1, Reason: "r",
	})
	if !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("empty env rollback: %v", err)
	}

	// 目标晋级版本已被安全撤销：拒绝创建。
	if _, err := s.RevokePromotionSafety(1, "sec", "recall"); err != nil {
		t.Fatal(err)
	}
	_, err = s.CreateRollback(CreateRollbackRequest{
		Number: "RB-Z", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("safety-revoked target: %v", err)
	}

	// d2 仍可创建（验证不是全部被拒）。
	_ = mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-OK", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d2, Reason: "r",
	})
}

func TestCreateRollbackIdempotencyAndConflict(t *testing.T) {
	s, _, d1, d2, _ := setupProdChain(t)
	req := CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r", RequestedBy: "ops",
	}
	first := mustCreateRollback(t, s, req)
	second := mustCreateRollback(t, s, req)
	if first.ID != second.ID || first.TargetVersion != second.TargetVersion {
		t.Fatalf("same number must return the original plan: %+v %+v", first, second)
	}

	// 同号不同目标：冲突。
	_, err := s.CreateRollback(CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d2, Reason: "r",
	})
	if !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("same number different target: %v", err)
	}
	// 同号不同环境：冲突。
	mustConfigure(t, s, "staging", "", "vuln-scan")
	_, err = s.CreateRollback(CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "staging",
		TargetDigest: d1, Reason: "r",
	})
	if !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("same number different env: %v", err)
	}
}

// ---- 普通回滚执行 ----

func TestNormalRollbackExecution(t *testing.T) {
	s, clk, d1, _, d3 := setupProdChain(t)
	clk.Add(time.Minute)

	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "regression", RequestedBy: "ops",
	})
	executed, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatalf("ExecuteRollback: %v", err)
	}
	if executed.Status != RollbackExecuted || executed.ResultVersion != 4 {
		t.Fatalf("unexpected executed plan: %+v", executed)
	}
	if executed.ExecutedAt.IsZero() || executed.ResultPromotionID != plan.TargetPromotionID {
		t.Fatalf("execution result fields missing: %+v", executed)
	}

	// 指针原子切换到 d1，版本号继续单调递增；指针来源记录是历史晋级 v1。
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d1 || ptr.Version != 4 || ptr.PromotionID != plan.TargetPromotionID {
		t.Fatalf("pointer mismatch after rollback: %+v", ptr)
	}

	// 后续晋级历史不删除：三次晋级记录都还在。
	hist, _ := s.History("prod")
	if len(hist) != 3 {
		t.Fatalf("promotion history must be preserved, got %d records", len(hist))
	}

	// outbox 恰好一条通知。
	pending, _ := s.PendingOutbox()
	if len(pending) != 1 || pending[0].RollbackNumber != "RB-1" ||
		pending[0].FromDigest != d3 || pending[0].ToDigest != d1 ||
		pending[0].Kind != RollbackNormal {
		t.Fatalf("unexpected outbox: %+v", pending)
	}

	// 时间线：v1/v2/v3 晋级 + v4 回滚，顺序完整。
	tl, err := s.Timeline("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 4 {
		t.Fatalf("timeline should merge 3 promotions + 1 rollback, got %+v", tl)
	}
	last := tl[3]
	if last.Kind != "rollback" || last.Version != 4 || last.Digest != d1 ||
		last.RollbackNumber != "RB-1" || last.Emergency {
		t.Fatalf("timeline rollback node mismatch: %+v", last)
	}
	if tl[0].Digest != d1 || tl[2].Digest != d3 {
		t.Fatalf("timeline promotions mismatch: %+v", tl)
	}

	// 普通回滚的审计事件为普通优先级。
	log, _ := s.AuditLog("prod", false)
	if len(log) != 2 || log[0].Action != AuditRollbackCreated || log[1].Action != AuditRollbackExecuted {
		t.Fatalf("audit actions mismatch: %+v", log)
	}
	for _, e := range log {
		if e.Priority != AuditPriorityNormal {
			t.Fatalf("normal rollback audit must be normal priority: %+v", e)
		}
	}
}

func TestExecuteRollbackNotFoundAndArgs(t *testing.T) {
	s, _, _, _, _ := setupProdChain(t)
	if _, err := s.ExecuteRollback("missing"); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("expected ErrRollbackNotFound, got %v", err)
	}
	if _, err := s.ExecuteRollback(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	if _, err := s.GetRollback("missing"); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("GetRollback: %v", err)
	}
	if _, err := s.GetRollback(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("GetRollback empty number: %v", err)
	}
	if _, err := s.AuditLog("prod", true); err != nil {
		t.Fatalf("empty audit log should be empty, not error: %v", err)
	}
	if _, _, err := s.OutboxForRollback("missing"); err != nil {
		t.Fatalf("lookup without message should not error: %v", err)
	}
}

// 普通回滚执行时仍需满足当前策略：
//   - 证明过期 → 失败；
//   - 策略新增证明类型且目标缺少 → 失败；
//   - 上游指针移走 → 失败。
func TestNormalRollbackMustSatisfyCurrentPolicy(t *testing.T) {
	t.Run("expired attestation", func(t *testing.T) {
		s, clk := newTestService(t)
		d1 := mustDigest(t, "sha256", []byte("n1"))
		d2 := mustDigest(t, "sha256", []byte("n2"))
		mustRegister(t, s, d1, "api")
		mustRegister(t, s, d2, "api")
		base := clk.Now()
		if _, err := s.IssueAttestation(IssueAttestationRequest{
			Digest: d1, Type: "vuln-scan", Issuer: "sec",
			Conclusion: ConclusionApproved,
			ValidFrom:  base.Add(-time.Hour), ValidUntil: base.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		mustIssue(t, s, d2, "vuln-scan")
		mustConfigure(t, s, "prod", "", "vuln-scan")
		mustPromote(t, s, "C1", "prod", d1, 0)
		mustPromote(t, s, "C2", "prod", d2, 1)

		plan := mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-E", Kind: RollbackNormal, Environment: "prod",
			TargetDigest: d1, Reason: "r",
		})
		clk.Add(2 * time.Hour) // d1 的证明已过期；过期不推进证明修订号。
		_, err := s.ExecuteRollback(plan.Number)
		if !errors.Is(err, ErrAttestationExpired) {
			t.Fatalf("expired target attestation must block normal rollback: %v", err)
		}
		ptr, _ := s.GetPointer("prod")
		if ptr.Digest != d2 {
			t.Fatalf("pointer must not move on failed rollback: %+v", ptr)
		}
	})

	t.Run("policy requires more", func(t *testing.T) {
		s, clk, d1, _, _ := setupProdChain(t)
		// 策略升级为同时要求 sbom：d1 只有 vuln-scan。
		mustConfigure(t, s, "prod", "", "vuln-scan", "sbom")
		plan := mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-P", Kind: RollbackNormal, Environment: "prod",
			TargetDigest: d1, Reason: "r",
		})
		if plan.FrozenPolicyVersion != 2 {
			t.Fatalf("plan should freeze policy version 2, got %d", plan.FrozenPolicyVersion)
		}
		clk.Add(time.Minute)
		if _, err := s.ExecuteRollback(plan.Number); !errors.Is(err, ErrMissingAttestation) {
			t.Fatalf("new policy requirement must block normal rollback: %v", err)
		}
	})

	t.Run("upstream moved", func(t *testing.T) {
		s, _ := newTestService(t)
		d1 := mustDigest(t, "sha256", []byte("u1"))
		d2 := mustDigest(t, "sha256", []byte("u2"))
		mustRegister(t, s, d1, "api")
		mustRegister(t, s, d2, "api")
		mustConfigure(t, s, "dev", "")
		mustConfigure(t, s, "staging", "dev")
		mustPromote(t, s, "C1", "dev", d1, 0)
		mustPromote(t, s, "C2", "staging", d1, 0)
		mustPromote(t, s, "C3", "dev", d2, 1)
		mustPromote(t, s, "C4", "staging", d2, 1)
		// dev 现为 d2；普通回滚 staging -> d1 时上游条件失败。
		plan := mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-U", Kind: RollbackNormal, Environment: "staging",
			TargetDigest: d1, Reason: "r",
		})
		_, err := s.ExecuteRollback(plan.Number)
		if !errors.Is(err, ErrUpstreamNotPromoted) {
			t.Fatalf("upstream moved must block rollback: %v", err)
		}
	})
}

// ---- 紧急回滚：双人批准、绕过证明、高优先级审计 ----

func TestEmergencyRollbackTwoApprovers(t *testing.T) {
	s, clk, d1, _, _ := setupProdChain(t)

	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-EM", Kind: RollbackEmergency, Environment: "prod",
		TargetDigest: d1, Reason: "SEV-1 outage", RequestedBy: "oncall",
	})

	// 零批准不能执行。
	if _, err := s.ExecuteRollback(plan.Number); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("0 approvals: %v", err)
	}
	// 单个批准仍不能执行。
	mustApprove(t, s, "RB-EM", "alice")
	if _, err := s.ExecuteRollback(plan.Number); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("1 approval: %v", err)
	}
	// 同一授权人不能重复批准。
	if _, err := s.ApproveRollback("RB-EM", "alice", "again"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("duplicate approver: %v", err)
	}
	// 两个不同授权人：可以执行。
	plan = mustApprove(t, s, "RB-EM", "bob")
	if len(plan.Approvals) != 2 || plan.Approvals[0].Approver != "alice" {
		t.Fatalf("approval evidence mismatch: %+v", plan.Approvals)
	}

	clk.Add(time.Minute)
	executed, err := s.ExecuteRollback("RB-EM")
	if err != nil {
		t.Fatalf("execute after two approvals: %v", err)
	}
	if executed.ResultVersion != 4 {
		t.Fatalf("unexpected result version %d", executed.ResultVersion)
	}

	// 已执行计划不能再追加批准。
	if _, err := s.ApproveRollback("RB-EM", "carol", "late"); !errors.Is(err, ErrRollbackState) {
		t.Fatalf("approve executed plan: %v", err)
	}

	// 查询能取回完整审批证据。
	got, err := s.GetRollback("RB-EM")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Approvals) != 2 || got.Approvals[1].GrantedAt.IsZero() ||
		got.Approvals[1].Comment == "" {
		t.Fatalf("approval evidence not persisted: %+v", got.Approvals)
	}

	// 紧急回滚全程高优先级审计：创建 + 两次批准 + 执行。
	high, _ := s.AuditLog("prod", true)
	if len(high) != 4 {
		t.Fatalf("expected 4 high-priority events, got %+v", high)
	}
	want := []AuditAction{AuditRollbackCreated, AuditRollbackApproved, AuditRollbackApproved, AuditRollbackExecuted}
	for i, e := range high {
		if e.Action != want[i] || e.Priority != AuditPriorityHigh {
			t.Fatalf("event %d mismatch: %+v", i, e)
		}
	}
}

func TestApproveRollbackStateRules(t *testing.T) {
	s, _, d1, _, _ := setupProdChain(t)

	// 普通回滚不接受批准。
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-N", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if _, err := s.ApproveRollback("RB-N", "alice", "x"); !errors.Is(err, ErrRollbackState) {
		t.Fatalf("approve normal rollback: %v", err)
	}
	if _, err := s.ApproveRollback("missing", "alice", "x"); !errors.Is(err, ErrRollbackNotFound) {
		t.Fatalf("approve missing rollback: %v", err)
	}
	if _, err := s.ApproveRollback(plan.Number, "", "x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty approver: %v", err)
	}
}

// 紧急回滚可绕过证明要求：目标证明过期或策略加严都不阻止执行。
func TestEmergencyRollbackBypassesAttestationRequirements(t *testing.T) {
	t.Run("expired attestation", func(t *testing.T) {
		s, clk := newTestService(t)
		d1 := mustDigest(t, "sha256", []byte("e1"))
		d2 := mustDigest(t, "sha256", []byte("e2"))
		mustRegister(t, s, d1, "api")
		mustRegister(t, s, d2, "api")
		base := clk.Now()
		if _, err := s.IssueAttestation(IssueAttestationRequest{
			Digest: d1, Type: "vuln-scan", Issuer: "sec", Conclusion: ConclusionApproved,
			ValidFrom: base.Add(-time.Hour), ValidUntil: base.Add(time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
		mustIssue(t, s, d2, "vuln-scan")
		mustConfigure(t, s, "prod", "", "vuln-scan")
		mustPromote(t, s, "C1", "prod", d1, 0)
		mustPromote(t, s, "C2", "prod", d2, 1)

		mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-EE", Kind: RollbackEmergency, Environment: "prod",
			TargetDigest: d1, Reason: "SEV",
		})
		mustApprove(t, s, "RB-EE", "alice")
		mustApprove(t, s, "RB-EE", "bob")
		clk.Add(2 * time.Hour) // 目标证明已过期，紧急回滚仍可执行。
		if _, err := s.ExecuteRollback("RB-EE"); err != nil {
			t.Fatalf("emergency rollback should bypass expired attestations: %v", err)
		}
		ptr, _ := s.GetPointer("prod")
		if ptr.Digest != d1 {
			t.Fatalf("pointer mismatch: %+v", ptr)
		}
	})

	t.Run("policy tightened", func(t *testing.T) {
		s, _, d1, _, _ := setupProdChain(t)
		// 创建计划之后策略新增 sbom 要求（d1 没有 sbom）。
		mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-EP", Kind: RollbackEmergency, Environment: "prod",
			TargetDigest: d1, Reason: "SEV",
		})
		mustConfigure(t, s, "prod", "", "vuln-scan", "sbom")
		mustApprove(t, s, "RB-EP", "alice")
		mustApprove(t, s, "RB-EP", "bob")
		if _, err := s.ExecuteRollback("RB-EP"); err != nil {
			t.Fatalf("emergency rollback bypasses new attestation requirements: %v", err)
		}
	})

	// 撤销发生在计划创建之前：修订号已冻结在新值，紧急回滚仍可绕过
	// “目标证明已撤销”这一证明要求执行。
	t.Run("attestation revoked before plan", func(t *testing.T) {
		s, _, d1, _, _ := setupProdChain(t)
		atts, _ := s.ListAttestations(d1)
		if err := s.RevokeAttestation(atts[0].ID, "compromised"); err != nil {
			t.Fatal(err)
		}
		mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-ER", Kind: RollbackEmergency, Environment: "prod",
			TargetDigest: d1, Reason: "SEV",
		})
		mustApprove(t, s, "RB-ER", "alice")
		mustApprove(t, s, "RB-ER", "bob")
		if _, err := s.ExecuteRollback("RB-ER"); err != nil {
			t.Fatalf("emergency rollback should bypass pre-existing revocation: %v", err)
		}
		// 对照：普通回滚在同样状态下被证明撤销拒绝。
		s2, _, nd1, _, _ := setupProdChain(t)
		atts2, _ := s2.ListAttestations(nd1)
		if err := s2.RevokeAttestation(atts2[0].ID, "compromised"); err != nil {
			t.Fatal(err)
		}
		mustCreateRollback(t, s2, CreateRollbackRequest{
			Number: "RB-NR", Kind: RollbackNormal, Environment: "prod",
			TargetDigest: nd1, Reason: "r",
		})
		if _, err := s2.ExecuteRollback("RB-NR"); !errors.Is(err, ErrAttestationRevoked) {
			t.Fatalf("normal rollback must fail on revoked attestation: %v", err)
		}
	})
}

// 紧急回滚绕过证明要求，但上游环境不变量仍然保留（按冻结的策略快照）。
func TestEmergencyRollbackStillRequiresUpstream(t *testing.T) {
	s, _ := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("u1"))
	d2 := mustDigest(t, "sha256", []byte("u2"))
	mustRegister(t, s, d1, "api")
	mustRegister(t, s, d2, "api")
	mustConfigure(t, s, "dev", "")
	mustConfigure(t, s, "staging", "dev")
	mustPromote(t, s, "C1", "dev", d1, 0)
	mustPromote(t, s, "C2", "staging", d1, 0)
	mustPromote(t, s, "C3", "dev", d2, 1)
	mustPromote(t, s, "C4", "staging", d2, 1)
	// dev 当前 d2，staging 想紧急回到 d1：上游不匹配，即使双人批准也拒绝。
	mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-EU", Kind: RollbackEmergency, Environment: "staging",
		TargetDigest: d1, Reason: "SEV",
	})
	mustApprove(t, s, "RB-EU", "alice")
	mustApprove(t, s, "RB-EU", "bob")
	if _, err := s.ExecuteRollback("RB-EU"); !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("emergency rollback must keep upstream invariant: %v", err)
	}

	// dev 先回到 d1 后（不触碰 staging 版本/证明修订号），staging 的紧急回滚可执行。
	devBack := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-DEV", Kind: RollbackNormal, Environment: "dev",
		TargetDigest: d1, Reason: "restore",
	})
	if _, err := s.ExecuteRollback(devBack.Number); err != nil {
		t.Fatalf("dev rollback: %v", err)
	}
	if _, err := s.ExecuteRollback("RB-EU"); err != nil {
		t.Fatalf("upstream realigned, emergency rollback should execute: %v", err)
	}
}

// ---- 执行冲突：新晋级 / 另一笔回滚 / 证明撤销抢先落地 ----

func TestExecuteRollbackConflictNewPromotion(t *testing.T) {
	s, _, d1, _, d3 := setupProdChain(t)
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-C", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})

	// 计划创建后一笔新晋级抢先落地（重新晋级 d3 也消耗版本号）。
	d4 := mustDigest(t, "sha256", []byte("rel-4"))
	mustRegister(t, s, d4, "api")
	mustIssue(t, s, d4, "vuln-scan")
	mustPromote(t, s, "CHG-4", "prod", d4, 3)

	_, err := s.ExecuteRollback(plan.Number)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("stale plan must conflict: %v", err)
	}
	stored, _ := s.GetRollback("RB-C")
	if stored.Status != RollbackConflicted {
		t.Fatalf("plan should be terminal conflicted, got %s", stored.Status)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d4 || ptr.Version != 4 {
		t.Fatalf("pointer must stay on the newer promotion: %+v", ptr)
	}

	// 重放同一回滚号仍返回同一个冲突，不产生通知。
	if _, err := s.ExecuteRollback("RB-C"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("replay of conflicted plan: %v", err)
	}
	if pending, _ := s.PendingOutbox(); len(pending) != 0 {
		t.Fatalf("conflicted rollback must not emit outbox: %+v", pending)
	}

	// d3 历史版本仍可基于新版本创建新计划并执行成功。
	plan2 := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-C2", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d3, Reason: "r",
	})
	if plan2.FrozenCurrentVersion != 4 {
		t.Fatalf("new plan should freeze version 4, got %d", plan2.FrozenCurrentVersion)
	}
	if _, err := s.ExecuteRollback("RB-C2"); err != nil {
		t.Fatalf("fresh plan should execute: %v", err)
	}
}

func TestExecuteRollbackConflictAnotherRollback(t *testing.T) {
	s, _, d1, d2, _ := setupProdChain(t)
	rb1 := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	rb2 := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-2", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d2, Reason: "r",
	})

	// rb1 先落地：环境到 v4 指向 d1。
	if _, err := s.ExecuteRollback(rb1.Number); err != nil {
		t.Fatal(err)
	}
	// rb2 冻结的是 v3/d3，必须冲突，不能把指针覆盖回 d2。
	if _, err := s.ExecuteRollback(rb2.Number); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("second rollback must conflict: %v", err)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d1 || ptr.Version != 4 {
		t.Fatalf("first rollback must win intact: %+v", ptr)
	}
}

func TestExecuteRollbackConflictAttestationRevocation(t *testing.T) {
	s, _, d1, d2, d3 := setupProdChain(t)
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-R", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	// 计划冻结修订号 0；撤销 d2（当前版本）的证明后修订号推进。
	attestations, _ := s.ListAttestations(d2)
	if len(attestations) == 0 {
		t.Fatal("d2 has no attestations")
	}
	if err := s.RevokeAttestation(attestations[0].ID, "security incident"); err != nil {
		t.Fatal(err)
	}

	// 即使回滚目标 d1 的证明仍有效，证明撤销先落地也必须让旧计划冲突。
	_, err := s.ExecuteRollback(plan.Number)
	if !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("revocation landing first must conflict stale plan: %v", err)
	}
	stored, _ := s.GetRollback("RB-R")
	if stored.Status != RollbackConflicted {
		t.Fatalf("plan status: %s", stored.Status)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d3 {
		t.Fatalf("pointer must not move: %+v", ptr)
	}

	// 紧急计划同样受证明修订条件约束。
	em := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-RE", Kind: RollbackEmergency, Environment: "prod",
		TargetDigest: d1, Reason: "SEV",
	})
	if em.FrozenAttestationRevision != 1 {
		t.Fatalf("emergency plan should freeze revision 1, got %d", em.FrozenAttestationRevision)
	}
	if err := s.RevokeAttestation(func() string {
		as, _ := s.ListAttestations(d3)
		return as[0].ID
	}(), "again"); err != nil {
		t.Fatal(err)
	}
	mustApprove(t, s, "RB-RE", "alice")
	mustApprove(t, s, "RB-RE", "bob")
	if _, err := s.ExecuteRollback("RB-RE"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("emergency stale plan must conflict on revision: %v", err)
	}
}

// 目标在计划执行前被安全撤销：ErrRollbackTargetInvalid。
func TestExecuteRollbackTargetSafetyRevoked(t *testing.T) {
	s, _, d1, _, _ := setupProdChain(t)
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-S", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if _, err := s.RevokePromotionSafety(plan.TargetPromotionID, "sec", "recall after plan"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteRollback("RB-S"); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("revoked target at execute time: %v", err)
	}
}

// ---- 幂等执行：重复执行返回首次结果，outbox 只生成一次 ----

func TestExecuteRollbackIdempotent(t *testing.T) {
	s, clk, d1, _, d3 := setupProdChain(t)
	mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	first, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatal(err)
	}
	firstTime := first.ExecutedAt

	// 之后环境又发生新的晋级。
	clk.Add(time.Hour)
	d4 := mustDigest(t, "sha256", []byte("rel-4"))
	mustRegister(t, s, d4, "api")
	mustIssue(t, s, d4, "vuln-scan")
	mustPromote(t, s, "CHG-4", "prod", d4, 4)

	// 重复执行同号：返回首次结果（v4），不检查当前环境版本、不再切换、不发通知。
	second, err := s.ExecuteRollback("RB-1")
	if err != nil {
		t.Fatalf("replay must be idempotent: %v", err)
	}
	if second.ID != first.ID || second.ResultVersion != first.ResultVersion ||
		!second.ExecutedAt.Equal(firstTime) {
		t.Fatalf("replay must return the first result: first=%+v second=%+v", first, second)
	}
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d4 || ptr.Version != 5 {
		t.Fatalf("replay must not move the newer pointer: %+v", ptr)
	}
	pending, _ := s.PendingOutbox()
	if len(pending) != 1 || pending[0].ToDigest != d1 || pending[0].FromDigest != d3 {
		t.Fatalf("outbox must contain exactly the first notification: %+v", pending)
	}
	msg, found, _ := s.OutboxForRollback("RB-1")
	if !found || msg.ID != pending[0].ID {
		t.Fatalf("outbox lookup by rollback number failed: %+v found=%v", msg, found)
	}
}

// ---- 时间线 ----

func TestTimelineMerge(t *testing.T) {
	s, _, d1, d2, d3 := setupProdChain(t)

	// v4: 普通回滚到 d1；v5: 重新晋级 d2；v6: 紧急回滚到 d1。
	rb1 := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if _, err := s.ExecuteRollback(rb1.Number); err != nil {
		t.Fatal(err)
	}
	mustPromote(t, s, "CHG-5", "prod", d2, 4)
	mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-2", Kind: RollbackEmergency, Environment: "prod",
		TargetDigest: d1, Reason: "SEV",
	})
	mustApprove(t, s, "RB-2", "alice")
	mustApprove(t, s, "RB-2", "bob")
	if _, err := s.ExecuteRollback("RB-2"); err != nil {
		t.Fatal(err)
	}

	tl, err := s.Timeline("prod")
	if err != nil {
		t.Fatal(err)
	}
	if len(tl) != 6 {
		t.Fatalf("expected 6 timeline nodes, got %+v", tl)
	}
	want := []struct {
		version int64
		kind    string
		digest  Digest
		number  string
		em      bool
	}{
		{1, "promotion", d1, "", false},
		{2, "promotion", d2, "", false},
		{3, "promotion", d3, "", false},
		{4, "rollback", d1, "RB-1", false},
		{5, "promotion", d2, "", false},
		{6, "rollback", d1, "RB-2", true},
	}
	for i, w := range want {
		got := tl[i]
		if got.Version != w.version || got.Kind != w.kind || got.Digest != w.digest ||
			got.Emergency != w.em || got.RollbackNumber != w.number {
			t.Fatalf("timeline node %d mismatch: got %+v want %+v", i, got, w)
		}
	}
	if tl[4].ChangeNumber != "CHG-5" || tl[4].PromotionID == 0 {
		t.Fatalf("re-promotion node should keep promotion fields: %+v", tl[4])
	}

	// 安全撤销标记反映在时间线的晋级节点上。
	if _, err := s.RevokePromotionSafety(1, "sec", "r"); err != nil {
		t.Fatal(err)
	}
	tl, _ = s.Timeline("prod")
	if !tl[0].SafetyRevoked {
		t.Fatalf("timeline should show safety revocation on v1 node: %+v", tl[0])
	}

	if _, err := s.Timeline(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("timeline empty env: %v", err)
	}
}

// ---- 受影响下游环境追踪 ----

func TestAffectedDownstreams(t *testing.T) {
	s, _ := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("down-1"))
	d2 := mustDigest(t, "sha256", []byte("down-2"))
	mustRegister(t, s, d1, "api")
	mustRegister(t, s, d2, "api")
	mustConfigure(t, s, "dev", "")
	mustConfigure(t, s, "staging", "dev")
	mustConfigure(t, s, "prod", "staging")
	mustConfigure(t, s, "qa", "staging")

	// d1 沿整条链放行。
	mustPromote(t, s, "C1", "dev", d1, 0)
	mustPromote(t, s, "C2", "staging", d1, 0)
	mustPromote(t, s, "C3", "prod", d1, 0)
	mustPromote(t, s, "C4", "qa", d1, 0)

	// 全部对齐：没有受影响下游。
	aff, err := s.AffectedDownstreams("dev")
	if err != nil {
		t.Fatal(err)
	}
	if len(aff) != 0 {
		t.Fatalf("aligned chain should have no affected downstreams: %+v", aff)
	}

	// d2 晋级到 dev 与 staging，然后把 dev 回滚回 d1。
	mustPromote(t, s, "C5", "dev", d2, 1)
	mustPromote(t, s, "C6", "staging", d2, 1)
	devBack := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-D", Kind: RollbackNormal, Environment: "dev",
		TargetDigest: d1, Reason: "restore",
	})
	if _, err := s.ExecuteRollback(devBack.Number); err != nil {
		t.Fatal(err)
	}

	aff, _ = s.AffectedDownstreams("dev")
	// staging（直接，d2 vs dev 的 d1）；prod/qa（间接，d1 vs staging 的 d2）。
	if len(aff) != 3 {
		t.Fatalf("expected 3 affected downstreams, got %+v", aff)
	}
	byEnv := map[string]AffectedDownstream{}
	for _, a := range aff {
		byEnv[string(a.Environment)] = a
	}
	st := byEnv["staging"]
	if !st.Direct || st.CurrentDigest != d2 || st.UpstreamDigest != d1 || st.Upstream != "dev" {
		t.Fatalf("direct downstream mismatch: %+v", st)
	}
	for _, env := range []string{"prod", "qa"} {
		a := byEnv[env]
		if a.Direct || a.Upstream != "staging" || a.CurrentDigest != d1 || a.UpstreamDigest != d2 {
			t.Fatalf("transitive downstream %s mismatch: %+v", env, a)
		}
	}

	if _, err := s.AffectedDownstreams(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty env: %v", err)
	}
}

// ---- 安全撤销审计 ----

func TestRevokePromotionSafety(t *testing.T) {
	s, _, _, _, _ := setupProdChain(t)
	p, err := s.RevokePromotionSafety(2, "security", "tampered signing key")
	if err != nil {
		t.Fatal(err)
	}
	if !p.SafetyRevoked() || p.SafetyRevokedBy != "security" || p.SafetyRevokeReason != "tampered signing key" {
		t.Fatalf("safety fields not recorded: %+v", p)
	}
	// 历史记录仍可读取，撤销标记持久。
	got, _ := s.GetPromotion(2)
	if !got.SafetyRevoked() {
		t.Fatal("promotion not marked revoked")
	}
	// 重复撤销 / 参数非法 / 不存在 各自可区分。
	if _, err := s.RevokePromotionSafety(2, "x", "y"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("double revoke: %v", err)
	}
	if _, err := s.RevokePromotionSafety(0, "x", "y"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad id: %v", err)
	}
	if _, err := s.RevokePromotionSafety(999, "x", "y"); !errors.Is(err, ErrPromotionNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if _, err := s.RevokePromotionSafety(1, "", "y"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty actor: %v", err)
	}
	if _, err := s.RevokePromotionSafety(1, "x", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty reason: %v", err)
	}
	// 高优先级审计事件。
	high, _ := s.AuditLog("", true)
	if len(high) != 1 || high[0].Action != AuditSafetyRevocation || high[0].PromotionID != 2 {
		t.Fatalf("safety revoke audit mismatch: %+v", high)
	}
}

// ---- outbox 投递 ----

func TestOutboxDispatch(t *testing.T) {
	s, _, d1, _, _ := setupProdChain(t)
	plan := mustCreateRollback(t, s, CreateRollbackRequest{
		Number: "RB-1", Kind: RollbackNormal, Environment: "prod",
		TargetDigest: d1, Reason: "r",
	})
	if _, err := s.ExecuteRollback(plan.Number); err != nil {
		t.Fatal(err)
	}
	pending, _ := s.PendingOutbox()
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending message: %+v", pending)
	}
	msg := pending[0]
	if msg.DispatchedAt.IsZero() == false {
		t.Fatal("new message should be undispatched")
	}
	if err := s.MarkOutboxDispatched(msg.ID); err != nil {
		t.Fatalf("mark dispatched: %v", err)
	}
	if left, _ := s.PendingOutbox(); len(left) != 0 {
		t.Fatalf("dispatched message must leave pending queue: %+v", left)
	}
	// 重复标记与非法 ID。
	if err := s.MarkOutboxDispatched(msg.ID); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("double dispatch: %v", err)
	}
	if err := s.MarkOutboxDispatched(0); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("bad id: %v", err)
	}
}

// ---- 回滚与晋级并发：恰好一个赢家，输家冲突且不覆盖 ----

func TestRollbackPromoteRace(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		s, _, d1, _, d3 := setupProdChain(t)
		d4 := mustDigest(t, "sha256", []byte("race-4"))
		mustRegister(t, s, d4, "api")
		mustIssue(t, s, d4, "vuln-scan")
		mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-RACE", Kind: RollbackNormal, Environment: "prod",
			TargetDigest: d1, Reason: "r",
		})

		var wg sync.WaitGroup
		wg.Add(2)
		var execErr, promoteErr error
		go func() {
			defer wg.Done()
			_, execErr = s.ExecuteRollback("RB-RACE")
		}()
		go func() {
			defer wg.Done()
			_, promoteErr = s.Promote(PromotionRequest{
				ChangeNumber: "CHG-RACE", Environment: "prod", Digest: d4, ExpectedVersion: 3,
			})
		}()
		wg.Wait()

		ptr, _ := s.GetPointer("prod")
		if ptr.Version != 4 {
			t.Fatalf("iter %d: env must advance exactly one version, got %+v", iter, ptr)
		}
		switch {
		case execErr == nil && promoteErr != nil:
			if !errors.Is(promoteErr, ErrConcurrentModification) {
				t.Fatalf("iter %d: losing promote should CAS-fail: %v", iter, promoteErr)
			}
			if ptr.Digest != d1 {
				t.Fatalf("iter %d: rollback winner, pointer=%s", iter, ptr.Digest)
			}
			pending, _ := s.PendingOutbox()
			if len(pending) != 1 || pending[0].RollbackNumber != "RB-RACE" {
				t.Fatalf("iter %d: winner outbox mismatch: %+v", iter, pending)
			}
		case execErr != nil && promoteErr == nil:
			if !errors.Is(execErr, ErrConcurrentModification) {
				t.Fatalf("iter %d: losing rollback should conflict: %v", iter, execErr)
			}
			if ptr.Digest != d4 {
				t.Fatalf("iter %d: promote winner, pointer=%s", iter, ptr.Digest)
			}
			plan, _ := s.GetRollback("RB-RACE")
			if plan.Status != RollbackConflicted {
				t.Fatalf("iter %d: losing plan should be conflicted: %s", iter, plan.Status)
			}
			if pending, _ := s.PendingOutbox(); len(pending) != 0 {
				t.Fatalf("iter %d: losing rollback must not emit outbox: %+v", iter, pending)
			}
		default:
			t.Fatalf("iter %d: exactly one must win, exec=%v promote=%v (d3=%s)", iter, execErr, promoteErr, d3)
		}
	}
}

// ---- 持久化 ----

func TestRollbackPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rollback-state.json")
	d1 := mustDigest(t, "sha256", []byte("persist-r1"))
	d2 := mustDigest(t, "sha256", []byte("persist-r2"))

	func() {
		s, err := NewPersistentService(path)
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, s, d1, "api")
		mustRegister(t, s, d2, "api")
		mustConfigure(t, s, "prod", "", "vuln-scan")
		mustIssue(t, s, d1, "vuln-scan")
		mustIssue(t, s, d2, "vuln-scan")
		mustPromote(t, s, "P-1", "prod", d1, 0)
		mustPromote(t, s, "P-2", "prod", d2, 1)
		mustCreateRollback(t, s, CreateRollbackRequest{
			Number: "RB-P", Kind: RollbackEmergency, Environment: "prod",
			TargetDigest: d1, Reason: "SEV persist", RequestedBy: "oncall",
		})
		mustApprove(t, s, "RB-P", "alice")
		mustApprove(t, s, "RB-P", "bob")
		if _, err := s.ExecuteRollback("RB-P"); err != nil {
			t.Fatal(err)
		}
	}()

	// 重启恢复：计划（含审批证据）、outbox、审计、指针全部延续。
	s2, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s2.GetRollback("RB-P")
	if err != nil {
		t.Fatalf("rollback not restored: %v", err)
	}
	if plan.Status != RollbackExecuted || plan.ResultVersion != 3 ||
		len(plan.Approvals) != 2 || plan.Approvals[0].Approver != "alice" {
		t.Fatalf("plan/approvals not restored: %+v", plan)
	}
	ptr, _ := s2.GetPointer("prod")
	if ptr.Digest != d1 || ptr.Version != 3 {
		t.Fatalf("pointer not restored: %+v", ptr)
	}
	msg, found, _ := s2.OutboxForRollback("RB-P")
	if !found || msg.ToDigest != d1 || msg.FromDigest != d2 {
		t.Fatalf("outbox not restored: %+v found=%v", msg, found)
	}
	high, _ := s2.AuditLog("prod", true)
	if len(high) != 4 {
		t.Fatalf("audit trail not restored: %+v", high)
	}
	tl, _ := s2.Timeline("prod")
	if len(tl) != 3 || tl[2].Kind != "rollback" {
		t.Fatalf("timeline not restored: %+v", tl)
	}
	candidates, _ := s2.RollbackCandidates("prod")
	if len(candidates) != 1 || candidates[0].Digest != d2 {
		t.Fatalf("candidates not restored: %+v", candidates)
	}

	// 重启后重复执行仍是幂等的，且不产生第二条通知。
	replay, err := s2.ExecuteRollback("RB-P")
	if err != nil || replay.ID != plan.ID {
		t.Fatalf("idempotent execute must survive restart: %+v err=%v", replay, err)
	}
	pending, _ := s2.PendingOutbox()
	if len(pending) != 1 {
		t.Fatalf("replay must not duplicate outbox: %+v", pending)
	}
}

// 全新状态文件上的只读查询应当返回零结果而非报错（确保新增状态字段零值可用）。
func TestRollbackFreshStateFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	s, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	aff, err := s.AffectedDownstreams("prod")
	if err != nil || aff != nil {
		t.Fatalf("fresh AffectedDownstreams: %v %v", aff, err)
	}
	if c, err := s.RollbackCandidates("prod"); err != nil || c != nil {
		t.Fatalf("fresh RollbackCandidates: %v %v", c, err)
	}
	if tl, err := s.Timeline("prod"); err != nil || tl != nil {
		t.Fatalf("fresh Timeline: %v %v", tl, err)
	}
	if p, err := s.PendingOutbox(); err != nil || p != nil {
		t.Fatalf("fresh PendingOutbox: %v %v", p, err)
	}
}
