package artifactpromotion

import (
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

// setupThreeEnvChain 构造 dev -> staging -> prod 的升级链：每个环境先放行
// d1（v1）再放行 d2（v2），当前三环境都指向 d2，d1 是统一回滚目标。
func setupThreeEnvChain(t *testing.T) (*Service, *mutableClock, Digest, Digest) {
	t.Helper()
	s, clk := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("staged-rel-1"))
	d2 := mustDigest(t, "sha256", []byte("staged-rel-2"))
	mustRegister(t, s, d1, "api")
	mustRegister(t, s, d2, "api")
	mustIssue(t, s, d1, "vuln-scan")
	mustIssue(t, s, d2, "vuln-scan")
	mustConfigure(t, s, "dev", "", "vuln-scan")
	mustConfigure(t, s, "staging", "dev", "vuln-scan")
	mustConfigure(t, s, "prod", "staging", "vuln-scan")
	envs := []Environment{"dev", "staging", "prod"}
	for _, env := range envs {
		mustPromote(t, s, "S-C1-"+string(env), env, d1, 0)
	}
	for _, env := range envs {
		mustPromote(t, s, "S-C2-"+string(env), env, d2, 1)
	}
	return s, clk, d1, d2
}

func stagedReq(number string, kind RollbackKind, target Digest, batches ...[]Environment) CreateStagedRollbackRequest {
	req := CreateStagedRollbackRequest{
		Number:       number,
		Kind:         kind,
		TargetDigest: target,
		Reason:       "SEV: staged rollback",
		RequestedBy:  "oncall",
	}
	for _, b := range batches {
		req.Batches = append(req.Batches, StagedBatchRequest{Environments: b})
	}
	return req
}

func mustCreateStaged(t *testing.T, s *Service, req CreateStagedRollbackRequest) StagedRollbackPlan {
	t.Helper()
	plan, err := s.CreateStagedRollback(req)
	if err != nil {
		t.Fatalf("CreateStagedRollback %s: %v", req.Number, err)
	}
	return plan
}

func mustApproveStaged(t *testing.T, s *Service, number, approver string) StagedRollbackPlan {
	t.Helper()
	plan, err := s.ApproveStagedRollback(number, approver, "LGTM by "+approver)
	if err != nil {
		t.Fatalf("ApproveStagedRollback %s by %s: %v", number, approver, err)
	}
	return plan
}

func assertPtr(t *testing.T, s *Service, env Environment, d Digest, version int64) {
	t.Helper()
	ptr, err := s.GetPointer(env)
	if err != nil {
		t.Fatalf("GetPointer %s: %v", env, err)
	}
	if ptr.Digest != d || ptr.Version != version {
		t.Fatalf("pointer %s = %s@v%d, want %s@v%d", env, ptr.Digest, ptr.Version, d, version)
	}
}

// ---- 创建：冻结目标、环境顺序与各环境版本 ----

func TestStagedCreateFreezes(t *testing.T) {
	s, clk, d1, _ := setupThreeEnvChain(t)
	plan := mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))

	if plan.Status != StagedRollbackPending || plan.ID <= 0 || !plan.CreatedAt.Equal(clk.Now()) {
		t.Fatalf("unexpected plan: %+v", plan)
	}
	if len(plan.Batches) != 2 || len(plan.Entries) != 3 {
		t.Fatalf("batches/entries mismatch: %+v", plan)
	}
	byEnv := map[Environment]StagedRollbackEntry{}
	for _, e := range plan.Entries {
		byEnv[e.Environment] = e
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		e := byEnv[env]
		if e.TargetDigest != d1 || e.TargetVersion != 1 || e.TargetPromotionID == 0 {
			t.Fatalf("%s target not frozen: %+v", env, e)
		}
		if e.FrozenCurrentDigest == d1 || e.FrozenCurrentVersion != 2 || e.FrozenCurrentPromoID == 0 {
			t.Fatalf("%s current state not frozen: %+v", env, e)
		}
		if e.FrozenPolicyVersion != 1 || e.PolicySnapshot.Environment == "" {
			t.Fatalf("%s policy not frozen: %+v", env, e)
		}
		if e.FrozenAttestationRevision != 0 || e.Status != StagedEntryPending {
			t.Fatalf("%s entry should start pending with frozen revision: %+v", env, e)
		}
	}
	if byEnv["prod"].PolicySnapshot.UpstreamEnvironment != "staging" {
		t.Fatalf("prod policy snapshot lost upstream: %+v", byEnv["prod"])
	}
	// 创建审计：普通优先级。
	log, _ := s.AuditLog("", false)
	var created int
	for _, e := range log {
		if e.StagedNumber == "SR-1" && e.Action == AuditStagedRollbackCreated &&
			e.Priority == AuditPriorityNormal {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("expected 1 created audit event, got %d", created)
	}
	got, err := s.GetStagedRollback("SR-1")
	if err != nil {
		t.Fatal(err)
	}
	reports := got.BatchReports()
	if len(reports) != 2 || reports[0].Status != StagedBatchPending || reports[1].Status != StagedBatchPending {
		t.Fatalf("initial reports mismatch: %+v", reports)
	}
}

// ---- 创建：参数校验、目标合法性、活动计划重叠、查询不存在 ----

func TestStagedCreateValidation(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	neverPromoted := mustDigest(t, "sha256", []byte("staged-elsewhere"))
	mustRegister(t, s, neverPromoted, "api")

	base := stagedReq("SR-X", RollbackNormal, d1, []Environment{"dev"})
	check := func(mut func(*CreateStagedRollbackRequest), target error, name string) {
		t.Helper()
		req := base
		mut(&req)
		if _, err := s.CreateStagedRollback(req); !errors.Is(err, target) {
			t.Fatalf("%s: expected %v, got %v", name, target, err)
		}
	}
	check(func(r *CreateStagedRollbackRequest) { r.Number = "" }, ErrInvalidArgument, "empty number")
	check(func(r *CreateStagedRollbackRequest) { r.Kind = "weird" }, ErrInvalidArgument, "bad kind")
	check(func(r *CreateStagedRollbackRequest) { r.Reason = "" }, ErrInvalidArgument, "empty reason")
	check(func(r *CreateStagedRollbackRequest) { r.TargetDigest = "sha256:zz" }, ErrInvalidArgument, "bad digest")
	check(func(r *CreateStagedRollbackRequest) { r.Batches = nil }, ErrInvalidArgument, "no batches")
	check(func(r *CreateStagedRollbackRequest) {
		r.Batches = []StagedBatchRequest{{Environments: nil}}
	}, ErrInvalidArgument, "empty batch")
	check(func(r *CreateStagedRollbackRequest) {
		r.Batches = []StagedBatchRequest{{Environments: []Environment{""}}}
	}, ErrInvalidArgument, "empty env")
	check(func(r *CreateStagedRollbackRequest) {
		r.Batches = []StagedBatchRequest{
			{Environments: []Environment{"dev"}},
			{Environments: []Environment{"dev"}},
		}
	}, ErrInvalidArgument, "duplicate env across batches")
	check(func(r *CreateStagedRollbackRequest) { r.TargetDigest = neverPromoted },
		ErrRollbackTargetInvalid, "never promoted")

	// 目标是某环境当前指针：整笔计划拒绝创建。
	if _, err := s.CreateStagedRollback(stagedReq("SR-CUR", RollbackNormal, d2,
		[]Environment{"dev"}, []Environment{"staging"})); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("target already current: %v", err)
	}
	// 制品未登记。
	unregistered := mustDigest(t, "sha256", []byte("staged-unregistered"))
	if _, err := s.CreateStagedRollback(stagedReq("SR-ART", RollbackNormal, unregistered,
		[]Environment{"dev"})); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("unregistered target: %v", err)
	}

	// 同一环境不能同时被两笔未终结计划覆盖。
	mustCreateStaged(t, s, stagedReq("SR-A", RollbackNormal, d1, []Environment{"dev"}))
	if _, err := s.CreateStagedRollback(stagedReq("SR-B", RollbackNormal, d1,
		[]Environment{"dev", "staging"})); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("active overlap must be rejected: %v", err)
	}

	if _, err := s.GetStagedRollback("missing"); !errors.Is(err, ErrStagedRollbackNotFound) {
		t.Fatalf("get missing: %v", err)
	}
	if _, err := s.ExecuteStagedRollback("missing"); !errors.Is(err, ErrStagedRollbackNotFound) {
		t.Fatalf("execute missing: %v", err)
	}
	if _, err := s.CancelStagedRollback("missing", "ops", "r"); !errors.Is(err, ErrStagedRollbackNotFound) {
		t.Fatalf("cancel missing: %v", err)
	}
	if _, err := s.ExecuteStagedRollback(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("execute empty number: %v", err)
	}
}

// 目标的历史晋级被安全撤销：该环境不能作为计划目标。
func TestStagedCreateRejectsSafetyRevokedTarget(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	cands, err := s.RollbackCandidates("dev")
	if err != nil || len(cands) == 0 {
		t.Fatalf("precondition candidates: %+v err=%v", cands, err)
	}
	if _, err := s.RevokePromotionSafety(cands[len(cands)-1].PromotionID, "sec", "recall"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateStagedRollback(stagedReq("SR-R", RollbackNormal, d1,
		[]Environment{"dev"})); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("revoked target must block creation: %v", err)
	}
}

// ---- 创建：同号幂等与冲突 ----

func TestStagedCreateIdempotencyAndConflict(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	req := stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"})
	first := mustCreateStaged(t, s, req)
	second := mustCreateStaged(t, s, req)
	if first.ID != second.ID {
		t.Fatalf("same number must return the original plan: %d vs %d", first.ID, second.ID)
	}
	if _, err := s.CreateStagedRollback(stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev", "staging", "prod"})); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("same number different batches: %v", err)
	}
	if _, err := s.CreateStagedRollback(stagedReq("SR-1", RollbackEmergency, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"})); !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("same number different kind: %v", err)
	}
}

// ---- 全部成功：批次顺序、结果版本、outbox、时间线、审计 ----

func TestStagedFullSuccess(t *testing.T) {
	s, clk, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging"}, []Environment{"prod"}))
	clk.Add(time.Minute)

	done, err := s.ExecuteStagedRollback("SR-1")
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if done.Status != StagedRollbackCompleted || done.CompletedAt.IsZero() {
		t.Fatalf("plan not completed: %+v", done)
	}

	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d1, 3)
		e, ok := done.EntryByEnv(env)
		if !ok || e.Status != StagedEntrySucceeded || e.ResultVersion != 3 ||
			e.ResultPromotionID != e.TargetPromotionID || !e.ExecutedAt.Equal(clk.Now()) {
			t.Fatalf("entry %s result mismatch: %+v", env, e)
		}
	}

	reports := done.BatchReports()
	if len(reports) != 3 {
		t.Fatalf("reports: %+v", reports)
	}
	for i, r := range reports {
		if r.Status != StagedBatchSucceeded || r.BatchIndex != i || len(r.Entries) != 1 {
			t.Fatalf("report %d mismatch: %+v", i, r)
		}
	}

	msgs, err := s.PendingStagedOutbox()
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 3 {
		t.Fatalf("expected 3 staged outbox messages, got %+v", msgs)
	}
	wantEnvs := []Environment{"dev", "staging", "prod"}
	for i, m := range msgs {
		if m.StagedNumber != "SR-1" || m.Environment != wantEnvs[i] ||
			m.FromDigest != d2 || m.ToDigest != d1 || m.RollbackNumber != "" {
			t.Fatalf("message %d mismatch: %+v", i, m)
		}
		var p stagedRollbackPayload
		if err := json.Unmarshal([]byte(m.Payload), &p); err != nil {
			t.Fatal(err)
		}
		if p.BatchIndex != i || p.ResultVersion != 3 || p.Emergency {
			t.Fatalf("payload %d mismatch: %+v", i, p)
		}
	}
	byPlan, err := s.StagedOutboxForPlan("SR-1")
	if err != nil || len(byPlan) != 3 {
		t.Fatalf("plan outbox lookup: %+v err=%v", byPlan, err)
	}
	if pending, _ := s.PendingOutbox(); len(pending) != 0 {
		t.Fatalf("staged messages must not appear in single rollback outbox: %+v", pending)
	}

	for _, env := range wantEnvs {
		tl, err := s.Timeline(env)
		if err != nil {
			t.Fatal(err)
		}
		last := tl[len(tl)-1]
		if last.Kind != "staged_rollback" || last.Version != 3 || last.Digest != d1 ||
			last.StagedNumber != "SR-1" || last.Emergency {
			t.Fatalf("timeline node mismatch for %s: %+v", env, last)
		}
	}

	var created, executed int
	log, _ := s.AuditLog("", false)
	for _, e := range log {
		if e.StagedNumber != "SR-1" {
			continue
		}
		if e.Priority != AuditPriorityNormal {
			t.Fatalf("normal staged rollback audit must be normal priority: %+v", e)
		}
		switch e.Action {
		case AuditStagedRollbackCreated:
			created++
		case AuditStagedRollbackExecuted:
			executed++
		}
	}
	if created != 1 || executed != 3 {
		t.Fatalf("audit counts mismatch: created=%d executed=%d", created, executed)
	}
}

// 批内多个环境：一批全部成功后才进入下一批。
func TestStagedBatchWithMultipleEnvs(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	done, err := s.ExecuteStagedRollback(mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev", "staging"}, []Environment{"prod"})).Number)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	reports := done.BatchReports()
	if reports[0].Status != StagedBatchSucceeded || len(reports[0].Entries) != 2 ||
		reports[0].Entries[0].Environment != "dev" || reports[0].Entries[1].Environment != "staging" {
		t.Fatalf("batch 1 mismatch: %+v", reports[0])
	}
	if reports[1].Status != StagedBatchSucceeded || reports[1].Entries[0].Environment != "prod" {
		t.Fatalf("batch 2 mismatch: %+v", reports[1])
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d1, 3)
	}
}

// 批内顺序：同一批中把上游排在前面即可一次成功；反向顺序在首个环境暂停。
func TestStagedWithinBatchOrdering(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	done, err := s.ExecuteStagedRollback(mustCreateStaged(t, s, stagedReq("SR-OK", RollbackNormal, d1,
		[]Environment{"dev", "staging", "prod"})).Number)
	if err != nil {
		t.Fatalf("ordered single batch must succeed: %v", err)
	}
	for _, e := range done.Entries {
		if e.Status != StagedEntrySucceeded {
			t.Fatalf("entry %s not succeeded: %+v", e.Environment, e)
		}
	}

	s2, _, nd1, nd2 := setupThreeEnvChain(t)
	paused, err := s2.ExecuteStagedRollback(mustCreateStaged(t, s2, stagedReq("SR-BAD", RollbackNormal, nd1,
		[]Environment{"prod", "staging", "dev"})).Number)
	if !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("reversed order must pause on prod upstream: %v", err)
	}
	if paused.Status != StagedRollbackPaused {
		t.Fatalf("paused plan: %+v", paused)
	}
	assertPtr(t, s2, "dev", nd2, 2)
	if e, _ := paused.EntryByEnv("prod"); e.Status != StagedEntryBlocked {
		t.Fatalf("prod blocked: %+v", e)
	}
	// 上游环境尚未落地前，恢复仍被阻断，计划保持暂停。
	if _, err := s2.ExecuteStagedRollback("SR-BAD"); !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("resume still blocked until upstream envs land: %v", err)
	}
}

// 完成后重放幂等：即使环境又被移动，也返回首次结果、不重复切换、不重发通知。
func TestStagedExecuteIdempotent(t *testing.T) {
	s, clk, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	first, err := s.ExecuteStagedRollback("SR-1")
	if err != nil {
		t.Fatal(err)
	}

	clk.Add(time.Hour)
	mustPromote(t, s, "S-C3-dev", "dev", d2, 3)
	mustPromote(t, s, "S-C3-staging", "staging", d2, 3)
	mustPromote(t, s, "S-C3-prod", "prod", d2, 3)

	second, err := s.ExecuteStagedRollback("SR-1")
	if err != nil {
		t.Fatalf("replay must be idempotent: %v", err)
	}
	if second.ID != first.ID || second.Status != StagedRollbackCompleted ||
		!second.CompletedAt.Equal(first.CompletedAt) {
		t.Fatalf("replay must return the first result: first=%+v second=%+v", first, second)
	}
	assertPtr(t, s, "dev", d2, 4)
	assertPtr(t, s, "staging", d2, 4)
	assertPtr(t, s, "prod", d2, 4)
	if msgs, _ := s.PendingStagedOutbox(); len(msgs) != 3 {
		t.Fatalf("replay must not duplicate outbox: %+v", msgs)
	}
	if e, _ := second.EntryByEnv("prod"); e.ResultVersion != 3 {
		t.Fatalf("replayed prod entry must keep first result version: %+v", e)
	}
}

// 某批失败时暂停：已完成环境保持现状；恢复从失败批次继续。
func TestStagedPauseUpstreamKeepsCompletedBatches(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	// batch1=[dev]；batch2=[prod, staging]：prod 先查上游 staging（仍 d2），暂停。
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"prod", "staging"}))

	paused, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("prod upstream staging still on d2 must block: %v", err)
	}
	if paused.Status != StagedRollbackPaused || paused.BlockCode != StagedBlockUpstream {
		t.Fatalf("plan should pause with upstream block: %+v", paused)
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "staging", d2, 2)
	assertPtr(t, s, "prod", d2, 2)
	prodEntry, _ := paused.EntryByEnv("prod")
	if prodEntry.Status != StagedEntryBlocked || prodEntry.BlockCode != StagedBlockUpstream ||
		prodEntry.Attempts != 1 || prodEntry.BlockReason == "" || prodEntry.ResultVersion != 0 {
		t.Fatalf("prod entry block state mismatch: %+v", prodEntry)
	}
	stagingEntry, _ := paused.EntryByEnv("staging")
	if stagingEntry.Status != StagedEntryPending {
		t.Fatalf("staging after blocked prod must remain pending: %+v", stagingEntry)
	}
	reports := paused.BatchReports()
	if reports[0].Status != StagedBatchSucceeded || reports[1].Status != StagedBatchBlocked {
		t.Fatalf("paused batch reports mismatch: %+v", reports)
	}
	if msgs, _ := s.PendingStagedOutbox(); len(msgs) != 1 || msgs[0].Environment != "dev" {
		t.Fatalf("only dev should have produced outbox: %+v", msgs)
	}

	// 条件未变时恢复仍被阻断：尝试计数累加，dev 不受影响。
	pausedAgain, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("resume before fix must re-block: %v", err)
	}
	if e, _ := pausedAgain.EntryByEnv("prod"); e.Attempts != 2 {
		t.Fatalf("attempts should accumulate on blocked replay: %+v", e)
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "staging", d2, 2)
	assertPtr(t, s, "prod", d2, 2)
}

// 策略加严把批次 2 阻断，补齐证明后从失败批次继续，已完成批次不重复执行。
func TestStagedPauseAndResumePolicyTightened(t *testing.T) {
	s, clk, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging"}, []Environment{"prod"}))

	mustConfigure(t, s, "staging", "dev", "vuln-scan", "sbom")

	paused, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("tightened policy must block staging: %v", err)
	}
	if paused.Status != StagedRollbackPaused || paused.BlockCode != StagedBlockAttestationFailed {
		t.Fatalf("plan pause state/code mismatch: %+v", paused)
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "staging", d2, 2)
	assertPtr(t, s, "prod", d2, 2)
	if e, _ := paused.EntryByEnv("dev"); e.Status != StagedEntrySucceeded || e.ResultVersion != 3 {
		t.Fatalf("dev entry should be succeeded with frozen result: %+v", e)
	}
	if e, _ := paused.EntryByEnv("staging"); e.Status != StagedEntryBlocked {
		t.Fatalf("staging should be blocked: %+v", e)
	}
	if e, _ := paused.EntryByEnv("prod"); e.Status != StagedEntryPending {
		t.Fatalf("prod should still be pending: %+v", e)
	}

	clk.Add(time.Minute)
	mustIssue(t, s, d1, "sbom") // 签发不推进修订号（只有撤销推进）。

	resumed, err := s.ExecuteStagedRollback("SR-1")
	if err != nil {
		t.Fatalf("resume must continue from failed batch and finish: %v", err)
	}
	if resumed.Status != StagedRollbackCompleted {
		t.Fatalf("plan should complete after resume: %+v", resumed)
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d1, 3)
	}
	if e, _ := resumed.EntryByEnv("dev"); e.Attempts != 0 || e.ResultVersion != 3 {
		t.Fatalf("completed dev must not be retried: %+v", e)
	}
	if e, _ := resumed.EntryByEnv("staging"); e.Attempts != 1 {
		t.Fatalf("staging attempted once then succeeds: %+v", e)
	}
	if msgs, _ := s.PendingStagedOutbox(); len(msgs) != 3 {
		t.Fatalf("exactly one outbox per env after resume: %+v", msgs)
	}
	for _, r := range resumed.BatchReports() {
		if r.Status != StagedBatchSucceeded {
			t.Fatalf("all batches must report succeeded: %+v", r)
		}
	}
}

// ---- 版本冲突：尚未开始的环境版本变化 → 旧计划拒绝执行并终结 ----

func TestStagedConflictEnvironmentMoved(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-C", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	// 外部变化：staging 被一次新晋级抢占（v2 -> v3，仍指向 d2）。
	mustPromote(t, s, "S-C3-staging", "staging", d2, 2)

	_, err := s.ExecuteStagedRollback("SR-C")
	if !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("stale staged plan must conflict: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-C")
	if got.Status != StagedRollbackConflicted || got.BlockCode != StagedConflictEnvVersion {
		t.Fatalf("plan must terminate conflicted: %+v", got)
	}
	if e, _ := got.EntryByEnv("staging"); e.Status != StagedEntryConflicted ||
		e.BlockCode != StagedConflictEnvVersion || e.BlockReason == "" {
		t.Fatalf("staging entry must carry conflict reason: %+v", e)
	}
	// 预检阶段不切换任何指针：dev 也不落地。
	assertPtr(t, s, "dev", d2, 2)
	assertPtr(t, s, "staging", d2, 3)
	assertPtr(t, s, "prod", d2, 2)
	if msgs, _ := s.PendingStagedOutbox(); len(msgs) != 0 {
		t.Fatalf("conflicted plan must not emit outbox: %+v", msgs)
	}
	if _, err := s.ExecuteStagedRollback("SR-C"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("conflicted replay must stay conflicted: %v", err)
	}
	// 终结后环境可重新加入新计划。
	fresh := mustCreateStaged(t, s, stagedReq("SR-C2", RollbackNormal, d1,
		[]Environment{"staging"}))
	if fresh.Status != StagedRollbackPending {
		t.Fatalf("env freed after terminal plan: %+v", fresh)
	}
}

// 暂停期间尚未开始的环境被外部改变：恢复时预检判定版本冲突并终结。
func TestStagedConflictWhilePaused(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging"}, []Environment{"prod"}))
	mustConfigure(t, s, "staging", "dev", "vuln-scan", "sbom")
	if _, err := s.ExecuteStagedRollback("SR-1"); !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("precondition pause failed")
	}

	// 暂停期间 prod（尚未开始）被外部晋级改变版本。
	mustPromote(t, s, "S-C3-prod", "prod", d2, 2)

	_, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("drift while paused must conflict on resume: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-1")
	if got.Status != StagedRollbackConflicted {
		t.Fatalf("plan should terminate conflicted: %+v", got)
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "staging", d2, 2)
	assertPtr(t, s, "prod", d2, 3)
}

// 证明撤销推进全局修订号：旧计划即使撤销的是别的制品的证明也冲突终结。
func TestStagedConflictAttestationRevision(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	attestations, _ := s.ListAttestations(d2)
	if len(attestations) == 0 {
		t.Fatal("d2 has no attestations")
	}
	if err := s.RevokeAttestation(attestations[0].ID, "incident"); err != nil {
		t.Fatal(err)
	}
	_, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("revision drift must conflict: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-1")
	if got.BlockCode != StagedConflictAttestationRev {
		t.Fatalf("conflict code mismatch: %+v", got)
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d2, 2)
	}
}

// 目标制品（某环境的目标晋级记录）被安全撤销：计划拒绝执行并终结。
func TestStagedConflictTargetSafetyRevoked(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	plan := mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	stagingEntry, _ := plan.EntryByEnv("staging")
	if _, err := s.RevokePromotionSafety(stagingEntry.TargetPromotionID, "sec", "recall"); err != nil {
		t.Fatal(err)
	}
	_, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("revoked target must invalidate plan: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-1")
	if got.Status != StagedRollbackConflicted || got.BlockCode != StagedConflictTargetRevoked {
		t.Fatalf("target-revoked conflict: %+v", got)
	}
	if e, _ := got.EntryByEnv("staging"); e.Status != StagedEntryConflicted {
		t.Fatalf("staging entry conflicted: %+v", e)
	}
	// 预检按条目顺序，任何指针都不移动。
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d2, 2)
	}
	if _, err := s.ExecuteStagedRollback("SR-1"); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("sticky replay must preserve target-invalid: %v", err)
	}
}

// ---- 取消：开始前取消，全部 skipped、零通知、重复取消幂等 ----

func TestStagedCancelBeforeStart(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))

	canceled, err := s.CancelStagedRollback("SR-1", "ops", "incident mitigated")
	if err != nil {
		t.Fatal(err)
	}
	if canceled.Status != StagedRollbackCanceled || canceled.CanceledAt.IsZero() ||
		canceled.CanceledBy != "ops" || canceled.CancelReason != "incident mitigated" {
		t.Fatalf("cancel fields mismatch: %+v", canceled)
	}
	for _, e := range canceled.Entries {
		if e.Status != StagedEntrySkipped {
			t.Fatalf("entry %s should be skipped: %+v", e.Environment, e)
		}
	}
	for _, r := range canceled.BatchReports() {
		if r.Status != StagedBatchCanceled {
			t.Fatalf("batch %d should be canceled: %+v", r.BatchIndex, r)
		}
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d2, 2)
	}
	if msgs, _ := s.PendingStagedOutbox(); len(msgs) != 0 {
		t.Fatalf("canceled-before-start must have no outbox: %+v", msgs)
	}

	// 取消幂等；执行/批准已取消计划被拒绝。
	again, err := s.CancelStagedRollback("SR-1", "ops2", "again")
	if err != nil || again.ID != canceled.ID {
		t.Fatalf("cancel must be idempotent: %+v err=%v", again, err)
	}
	if _, err := s.ExecuteStagedRollback("SR-1"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("execute canceled plan: %v", err)
	}
	if _, err := s.ApproveStagedRollback("SR-1", "alice", "x"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("approve canceled plan: %v", err)
	}
	if _, err := s.CancelStagedRollback("", "x", "y"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("cancel empty number: %v", err)
	}
	if _, err := s.CancelStagedRollback("SR-NEW", "", "y"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("cancel empty actor: %v", err)
	}
	if _, err := s.CancelStagedRollback("SR-NEW", "x", ""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("cancel empty reason: %v", err)
	}
}

// 暂停后取消：已成功环境保持落地结果、不回滚；被阻断与未开始的环境 skipped。
func TestStagedCancelAfterPartialProgress(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-1", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"prod", "staging"}))
	paused, err := s.ExecuteStagedRollback("SR-1")
	if !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("precondition pause: %v", err)
	}
	if e, _ := paused.EntryByEnv("dev"); e.Status != StagedEntrySucceeded {
		t.Fatalf("dev must have succeeded before pause: %+v", e)
	}

	canceled, err := s.CancelStagedRollback("SR-1", "ops", "stop rollout")
	if err != nil {
		t.Fatal(err)
	}
	if e, _ := canceled.EntryByEnv("dev"); e.Status != StagedEntrySucceeded || e.ResultVersion != 3 {
		t.Fatalf("completed dev must stay put after cancel: %+v", e)
	}
	for _, env := range []Environment{"prod", "staging"} {
		if e, _ := canceled.EntryByEnv(env); e.Status != StagedEntrySkipped {
			t.Fatalf("%s must be skipped after cancel: %+v", env, e)
		}
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "staging", d2, 2)
	assertPtr(t, s, "prod", d2, 2)

	reports := canceled.BatchReports()
	if reports[0].Status != StagedBatchSucceeded {
		t.Fatalf("batch 1 stays succeeded: %+v", reports[0])
	}
	if reports[1].Status != StagedBatchCanceled {
		t.Fatalf("batch 2 fully canceled: %+v", reports[1])
	}

	// 已完成环境不能被重新加入计划：dev 当前已是目标版本，新建计划必被拒绝。
	if _, err := s.CreateStagedRollback(stagedReq("SR-2", RollbackNormal, d1,
		[]Environment{"dev"})); !errors.Is(err, ErrRollbackTargetInvalid) {
		t.Fatalf("re-adding completed-at-target env must be rejected: %v", err)
	}
	// 未完成环境已被释放，可以另起计划。
	fresh := mustCreateStaged(t, s, stagedReq("SR-3", RollbackNormal, d1,
		[]Environment{"staging", "prod"}))
	if fresh.Status != StagedRollbackPending {
		t.Fatalf("skipped envs can join a new plan: %+v", fresh)
	}
}

// 已完成/已冲突的计划不能取消。
func TestStagedCancelTerminalStates(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-DONE", RollbackNormal, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	if _, err := s.ExecuteStagedRollback("SR-DONE"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CancelStagedRollback("SR-DONE", "ops", "r"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("cancel completed: %v", err)
	}

	s2, _, nd1, nd2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s2, stagedReq("SR-CF", RollbackNormal, nd1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))
	mustPromote(t, s2, "S-C3-dev", "dev", nd2, 2)
	if _, err := s2.ExecuteStagedRollback("SR-CF"); !errors.Is(err, ErrConcurrentModification) {
		t.Fatalf("precondition conflict: %v", err)
	}
	if _, err := s2.CancelStagedRollback("SR-CF", "ops", "r"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("cancel conflicted: %v", err)
	}
}

// ---- 紧急分批回滚：双人批准、绕过证明、保留上游不变量、高优先级审计 ----

func TestStagedEmergencyApprovalsAndBypass(t *testing.T) {
	s, clk, d1, _ := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-EM", RollbackEmergency, d1,
		[]Environment{"dev"}, []Environment{"staging", "prod"}))

	// 零批准：计划在第一个环境处暂停，零环境落地。
	if _, err := s.ExecuteStagedRollback("SR-EM"); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("0 approvals: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-EM")
	if got.Status != StagedRollbackPaused || got.BlockCode != StagedBlockNotApproved {
		t.Fatalf("plan should pause pending approvals: %+v", got)
	}
	if e, _ := got.EntryByEnv("dev"); e.Status != StagedEntryBlocked || e.BlockCode != StagedBlockNotApproved {
		t.Fatalf("dev entry blocked on approval: %+v", e)
	}

	if _, err := s.ApproveStagedRollback("SR-EM", "alice", "ok"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ExecuteStagedRollback("SR-EM"); !errors.Is(err, ErrRollbackNotApproved) {
		t.Fatalf("1 approval still blocked: %v", err)
	}
	if _, err := s.ApproveStagedRollback("SR-EM", "alice", "again"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("duplicate approver: %v", err)
	}
	plan := mustApproveStaged(t, s, "SR-EM", "bob")
	if len(plan.Approvals) != 2 || plan.Approvals[0].Approver != "alice" {
		t.Fatalf("approval evidence mismatch: %+v", plan.Approvals)
	}

	// 双人批准后，即使证明过期 + 策略加严，紧急分批回滚仍可推进。
	mustConfigure(t, s, "staging", "dev", "vuln-scan", "sbom")
	mustConfigure(t, s, "prod", "staging", "vuln-scan", "sbom")
	clk.Add(48 * time.Hour)
	done, err := s.ExecuteStagedRollback("SR-EM")
	if err != nil {
		t.Fatalf("two approvals must let emergency staged rollback finish: %v", err)
	}
	if done.Status != StagedRollbackCompleted {
		t.Fatalf("completed: %+v", done)
	}
	for _, env := range []Environment{"dev", "staging", "prod"} {
		assertPtr(t, s, env, d1, 3)
	}

	if _, err := s.ApproveStagedRollback("SR-EM", "carol", "late"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("approve completed: %v", err)
	}

	// 高优先级审计：创建 1 + 批准 2 + 逐环境执行 3 = 6。
	high, _ := s.AuditLog("", true)
	count := 0
	for _, e := range high {
		if e.StagedNumber == "SR-EM" {
			count++
		}
	}
	if count != 6 {
		t.Fatalf("expected 6 high-priority events for SR-EM, got %d: %+v", count, high)
	}
	msgs, _ := s.PendingStagedOutbox()
	if len(msgs) != 3 {
		t.Fatalf("outbox: %+v", msgs)
	}
	var p stagedRollbackPayload
	if err := json.Unmarshal([]byte(msgs[0].Payload), &p); err != nil {
		t.Fatal(err)
	}
	if !p.Emergency || len(p.Approvers) != 2 {
		t.Fatalf("emergency payload mismatch: %+v", p)
	}
}

// 紧急分批回滚仍按冻结的策略快照保留上游不变量。
func TestStagedEmergencyKeepsUpstreamInvariant(t *testing.T) {
	s, _, d1, d2 := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-EM", RollbackEmergency, d1,
		[]Environment{"dev"}, []Environment{"prod"}, []Environment{"staging"}))
	mustApproveStaged(t, s, "SR-EM", "alice")
	mustApproveStaged(t, s, "SR-EM", "bob")

	_, err := s.ExecuteStagedRollback("SR-EM")
	if !errors.Is(err, ErrUpstreamNotPromoted) {
		t.Fatalf("emergency staged rollback must keep upstream invariant: %v", err)
	}
	got, _ := s.GetStagedRollback("SR-EM")
	if got.Status != StagedRollbackPaused || got.BlockCode != StagedBlockUpstream {
		t.Fatalf("paused on upstream: %+v", got)
	}
	assertPtr(t, s, "dev", d1, 3)
	assertPtr(t, s, "prod", d2, 2)
}

func TestStagedApproveRules(t *testing.T) {
	s, _, d1, _ := setupThreeEnvChain(t)
	mustCreateStaged(t, s, stagedReq("SR-N", RollbackNormal, d1, []Environment{"dev"}))
	if _, err := s.ApproveStagedRollback("SR-N", "alice", "x"); !errors.Is(err, ErrStagedRollbackState) {
		t.Fatalf("approve normal staged plan: %v", err)
	}
	if _, err := s.ApproveStagedRollback("missing", "alice", "x"); !errors.Is(err, ErrStagedRollbackNotFound) {
		t.Fatalf("approve missing: %v", err)
	}
	if _, err := s.ApproveStagedRollback("SR-N", "", "x"); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("empty approver: %v", err)
	}
}

// ---- 持久化：暂停/批准/取消状态与逐环境结果跨重启延续 ----

func TestStagedPersistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "staged-state.json")
	d1 := mustDigest(t, "sha256", []byte("staged-persist-1"))
	d2 := mustDigest(t, "sha256", []byte("staged-persist-2"))

	func() {
		s, err := NewPersistentService(path)
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, s, d1, "api")
		mustRegister(t, s, d2, "api")
		mustIssue(t, s, d1, "vuln-scan")
		mustIssue(t, s, d2, "vuln-scan")
		mustConfigure(t, s, "dev", "", "vuln-scan")
		mustConfigure(t, s, "staging", "dev", "vuln-scan")
		mustPromote(t, s, "P-1", "dev", d1, 0)
		mustPromote(t, s, "P-2", "staging", d1, 0)
		mustPromote(t, s, "P-3", "dev", d2, 1)
		mustPromote(t, s, "P-4", "staging", d2, 1)
		mustCreateStaged(t, s, stagedReq("SR-P", RollbackEmergency, d1,
			[]Environment{"dev"}, []Environment{"staging"}))
		mustApproveStaged(t, s, "SR-P", "alice")
		mustApproveStaged(t, s, "SR-P", "bob")
		if _, err := s.ExecuteStagedRollback("SR-P"); err != nil {
			t.Fatal(err)
		}
	}()

	s2, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s2.GetStagedRollback("SR-P")
	if err != nil {
		t.Fatalf("staged plan not restored: %v", err)
	}
	if plan.Status != StagedRollbackCompleted || len(plan.Approvals) != 2 ||
		plan.Approvals[0].Approver != "alice" || len(plan.Batches) != 2 {
		t.Fatalf("plan/approvals/batches not restored: %+v", plan)
	}
	for _, e := range plan.Entries {
		if e.Status != StagedEntrySucceeded || e.ResultVersion != 3 || e.PolicySnapshot.Environment == "" {
			t.Fatalf("entry result not restored: %+v", e)
		}
	}
	for _, env := range []Environment{"dev", "staging"} {
		assertPtr(t, s2, env, d1, 3)
	}
	if msgs, _ := s2.PendingStagedOutbox(); len(msgs) != 2 {
		t.Fatalf("staged outbox not restored: %+v", msgs)
	}
	tl, _ := s2.Timeline("staging")
	last := tl[len(tl)-1]
	if last.Kind != "staged_rollback" || last.StagedNumber != "SR-P" {
		t.Fatalf("timeline staged node not restored: %+v", last)
	}

	// 重启后重复执行仍幂等。
	replay, err := s2.ExecuteStagedRollback("SR-P")
	if err != nil || replay.ID != plan.ID {
		t.Fatalf("idempotent execute must survive restart: %+v err=%v", replay, err)
	}
	if again, _ := s2.PendingStagedOutbox(); len(again) != 2 {
		t.Fatalf("replay must not duplicate outbox: %+v", again)
	}

	// 暂停状态也能跨重启恢复，随后继续推进。
	func() {
		s3, err := NewPersistentService(path)
		if err != nil {
			t.Fatal(err)
		}
		mustPromote(t, s3, "P-5", "dev", d2, 3)
		mustPromote(t, s3, "P-6", "staging", d2, 3)
		mustCreateStaged(t, s3, stagedReq("SR-2", RollbackNormal, d1,
			[]Environment{"dev"}, []Environment{"staging"}))
		mustConfigure(t, s3, "staging", "dev", "vuln-scan", "sbom")
		if _, err := s3.ExecuteStagedRollback("SR-2"); !errors.Is(err, ErrMissingAttestation) {
			t.Fatalf("precondition pause: %v", err)
		}
	}()
	s4, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	paused, err := s4.GetStagedRollback("SR-2")
	if err != nil {
		t.Fatal(err)
	}
	if paused.Status != StagedRollbackPaused {
		t.Fatalf("paused state not restored: %+v", paused)
	}
	assertPtr(t, s4, "dev", d1, 5)
	assertPtr(t, s4, "staging", d2, 4)
	mustIssue(t, s4, d1, "sbom")
	if _, err := s4.ExecuteStagedRollback("SR-2"); err != nil {
		t.Fatalf("resume after restart must finish: %v", err)
	}
	assertPtr(t, s4, "staging", d1, 5)
}
