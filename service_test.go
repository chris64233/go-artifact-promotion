package artifactpromotion

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var base = time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)

// testEnv 构造一个带假时钟的服务，时钟可通过返回的指针推进。
func testEnv(t *testing.T) (*Service, *time.Time) {
	t.Helper()
	now := base
	svc, err := NewService(&MemStore{}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	return svc, &now
}

func mustRegister(t *testing.T, svc *Service, digest, name, version string) Artifact {
	t.Helper()
	a, err := svc.RegisterArtifact(Artifact{Digest: digest, Name: name, Version: version})
	if err != nil {
		t.Fatalf("RegisterArtifact(%s): %v", digest, err)
	}
	return a
}

func mustIssue(t *testing.T, svc *Service, digest, typ string) Attestation {
	t.Helper()
	att, err := svc.IssueAttestation(Attestation{
		Digest:     digest,
		Type:       typ,
		Issuer:     "ci-bot",
		Conclusion: ConclusionPass,
		NotBefore:  base.Add(-time.Hour),
		NotAfter:   base.Add(24 * time.Hour),
	})
	if err != nil {
		t.Fatalf("IssueAttestation(%s, %s): %v", digest, typ, err)
	}
	return att
}

func mustSetPolicy(t *testing.T, svc *Service, p Policy) {
	t.Helper()
	if err := svc.SetPolicy(p); err != nil {
		t.Fatalf("SetPolicy(%s): %v", p.Environment, err)
	}
}

func mustPromote(t *testing.T, svc *Service, changeID, env, digest string, expected int64) PromotionRecord {
	t.Helper()
	rec, err := svc.Promote(PromoteRequest{
		ChangeID:        changeID,
		Environment:     env,
		Digest:          digest,
		ExpectedVersion: expected,
	})
	if err != nil {
		t.Fatalf("Promote(%s -> %s): %v", digest, env, err)
	}
	return rec
}

func TestRegisterArtifactImmutable(t *testing.T) {
	svc, _ := testEnv(t)

	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")

	// 同摘要同内容：幂等成功。
	if _, err := svc.RegisterArtifact(Artifact{Digest: "sha256:aaa", Name: "web", Version: "1.0.0"}); err != nil {
		t.Fatalf("idempotent re-register: %v", err)
	}
	// 同摘要不同内容：冲突。
	_, err := svc.RegisterArtifact(Artifact{Digest: "sha256:aaa", Name: "web", Version: "1.0.1"})
	if !errors.Is(err, ErrArtifactConflict) {
		t.Fatalf("want ErrArtifactConflict, got %v", err)
	}
	// 缺摘要：参数错误。
	if _, err := svc.RegisterArtifact(Artifact{Name: "web"}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
	// 未登记的制品：查询不到。
	if _, err := svc.GetArtifact("sha256:missing"); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("want ErrArtifactNotFound, got %v", err)
	}
}

func TestIssueAndRevokeAttestation(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")

	att := mustIssue(t, svc, "sha256:aaa", "unit-tests")
	if att.ID == "" {
		t.Fatal("expected service-assigned attestation id")
	}
	if !att.Effective(base) {
		t.Fatal("fresh PASS attestation should be effective")
	}

	// 给未登记的制品签发证明：失败。
	_, err := svc.IssueAttestation(Attestation{
		Digest: "sha256:missing", Type: "unit-tests", Issuer: "ci-bot",
		Conclusion: ConclusionPass, NotBefore: base, NotAfter: base.Add(time.Hour),
	})
	if !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("want ErrArtifactNotFound, got %v", err)
	}
	// 有效期为空：参数错误。
	_, err = svc.IssueAttestation(Attestation{
		Digest: "sha256:aaa", Type: "unit-tests", Issuer: "ci-bot",
		Conclusion: ConclusionPass, NotBefore: base, NotAfter: base,
	})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}

	// 撤销：幂等，撤销后不再有效。
	if err := svc.RevokeAttestation(att.ID); err != nil {
		t.Fatalf("RevokeAttestation: %v", err)
	}
	if err := svc.RevokeAttestation(att.ID); err != nil {
		t.Fatalf("revoke should be idempotent: %v", err)
	}
	if err := svc.RevokeAttestation("att-999999"); !errors.Is(err, ErrAttestationNotFound) {
		t.Fatalf("want ErrAttestationNotFound, got %v", err)
	}
	got := svc.ListAttestations("sha256:aaa")
	if len(got) != 1 || !got[0].Revoked || got[0].RevokedAt == nil {
		t.Fatalf("expected revoked attestation with timestamp, got %+v", got)
	}
	if got[0].Effective(base) {
		t.Fatal("revoked attestation must not be effective")
	}
}

func TestPromoteHappyPathWithSnapshot(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustIssue(t, svc, "sha256:aaa", "unit-tests")
	mustIssue(t, svc, "sha256:aaa", "vuln-scan")
	mustSetPolicy(t, svc, Policy{
		Environment:          "staging",
		RequiredAttestations: []string{"unit-tests", "vuln-scan"},
	})

	rec := mustPromote(t, svc, "chg-1", "staging", "sha256:aaa", 0)
	if rec.FromVersion != 0 || rec.ToVersion != 1 {
		t.Fatalf("unexpected version transition: %+v", rec)
	}
	if len(rec.AttestationSnapshot) != 2 {
		t.Fatalf("snapshot should contain both attestations, got %+v", rec.AttestationSnapshot)
	}
	if rec.PolicySnapshot.Environment != "staging" {
		t.Fatalf("policy snapshot missing: %+v", rec.PolicySnapshot)
	}

	env := svc.Environment("staging")
	if env.Digest != "sha256:aaa" || env.Version != 1 {
		t.Fatalf("environment pointer not switched: %+v", env)
	}
}

func TestPromoteRequiresEffectiveAttestations(t *testing.T) {
	svc, now := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustSetPolicy(t, svc, Policy{Environment: "staging", RequiredAttestations: []string{"unit-tests"}})

	// 完全没有证明。
	_, err := svc.Promote(PromoteRequest{ChangeID: "c1", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("want ErrMissingAttestation, got %v", err)
	}

	// 结论为 FAIL 的证明不算数。
	if _, err := svc.IssueAttestation(Attestation{
		Digest: "sha256:aaa", Type: "unit-tests", Issuer: "ci-bot",
		Conclusion: ConclusionFail, NotBefore: base.Add(-time.Hour), NotAfter: base.Add(time.Hour),
	}); err != nil {
		t.Fatalf("IssueAttestation FAIL: %v", err)
	}
	_, err = svc.Promote(PromoteRequest{ChangeID: "c2", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("FAIL conclusion must not satisfy policy, got %v", err)
	}

	// 签发有效证明后可以晋级。
	mustIssue(t, svc, "sha256:aaa", "unit-tests")
	mustPromote(t, svc, "c3", "staging", "sha256:aaa", 0)

	// 证明过期后不能支撑新的晋级。
	*now = base.Add(48 * time.Hour)
	mustRegister(t, svc, "sha256:bbb", "web", "1.0.1")
	_, err = svc.Promote(PromoteRequest{ChangeID: "c4", Environment: "staging", Digest: "sha256:bbb", ExpectedVersion: 1})
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("want ErrMissingAttestation for digest without attestations, got %v", err)
	}
	mustIssue(t, svc, "sha256:bbb", "unit-tests") // 有效期基于 base，此刻已过期
	_, err = svc.Promote(PromoteRequest{ChangeID: "c5", Environment: "staging", Digest: "sha256:bbb", ExpectedVersion: 1})
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("expired attestation must not satisfy policy, got %v", err)
	}
}

func TestPromoteUpstreamRequirement(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustIssue(t, svc, "sha256:aaa", "unit-tests")
	mustSetPolicy(t, svc, Policy{Environment: "staging", RequiredAttestations: []string{"unit-tests"}})
	mustSetPolicy(t, svc, Policy{Environment: "prod", RequiredUpstreams: []string{"staging"}})

	// 制品尚未晋级到 staging，直接晋级 prod 失败。
	_, err := svc.Promote(PromoteRequest{ChangeID: "c1", Environment: "prod", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrUpstreamNotSatisfied) {
		t.Fatalf("want ErrUpstreamNotSatisfied, got %v", err)
	}

	mustPromote(t, svc, "c2", "staging", "sha256:aaa", 0)
	mustPromote(t, svc, "c3", "prod", "sha256:aaa", 0)

	// staging 前进到新版本后，旧版本不再是 staging 当前版本，
	// 不能再晋级到 prod。
	mustRegister(t, svc, "sha256:bbb", "web", "1.0.1")
	mustIssue(t, svc, "sha256:bbb", "unit-tests")
	mustPromote(t, svc, "c4", "staging", "sha256:bbb", 1)
	_, err = svc.Promote(PromoteRequest{ChangeID: "c5", Environment: "prod", Digest: "sha256:aaa", ExpectedVersion: 1})
	if !errors.Is(err, ErrUpstreamNotSatisfied) {
		t.Fatalf("stale upstream version must fail, got %v", err)
	}
}

func TestPromoteIdempotencyAndChangeConflict(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustRegister(t, svc, "sha256:bbb", "web", "1.0.1")
	mustSetPolicy(t, svc, Policy{Environment: "staging"})
	mustSetPolicy(t, svc, Policy{Environment: "prod"})

	rec := mustPromote(t, svc, "chg-1", "staging", "sha256:aaa", 0)

	// 同号同参数：幂等重放，返回原记录，版本不再前进。
	replay, err := svc.Promote(PromoteRequest{ChangeID: "chg-1", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if err != nil {
		t.Fatalf("idempotent replay: %v", err)
	}
	if replay.ChangeID != rec.ChangeID || replay.ToVersion != rec.ToVersion ||
		replay.Digest != rec.Digest || !replay.PromotedAt.Equal(rec.PromotedAt) {
		t.Fatalf("replay should return the original record:\nfirst:  %+v\nreplay: %+v", rec, replay)
	}
	if got := svc.Environment("staging").Version; got != 1 {
		t.Fatalf("replay must not advance version, got %d", got)
	}

	// 同号不同摘要：冲突。
	_, err = svc.Promote(PromoteRequest{ChangeID: "chg-1", Environment: "staging", Digest: "sha256:bbb", ExpectedVersion: 1})
	if !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("want ErrChangeConflict, got %v", err)
	}
	// 同号不同环境：冲突。
	_, err = svc.Promote(PromoteRequest{ChangeID: "chg-1", Environment: "prod", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrChangeConflict) {
		t.Fatalf("want ErrChangeConflict, got %v", err)
	}
}

func TestPromoteVersionConditionPreventsOverwrite(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustRegister(t, svc, "sha256:bbb", "web", "1.0.1")
	mustSetPolicy(t, svc, Policy{Environment: "staging"})

	// 两个调用方同时读到版本 0，只有一个能成功。
	mustPromote(t, svc, "c1", "staging", "sha256:aaa", 0)
	_, err := svc.Promote(PromoteRequest{ChangeID: "c2", Environment: "staging", Digest: "sha256:bbb", ExpectedVersion: 0})
	if !errors.Is(err, ErrVersionConflict) {
		t.Fatalf("want ErrVersionConflict, got %v", err)
	}
	if got := svc.Environment("staging").Digest; got != "sha256:aaa" {
		t.Fatalf("loser must not overwrite environment pointer, got %s", got)
	}

	// 重新读取版本后可以正常晋级。
	mustPromote(t, svc, "c3", "staging", "sha256:bbb", 1)
	if got := svc.Environment("staging"); got.Digest != "sha256:bbb" || got.Version != 2 {
		t.Fatalf("unexpected environment state: %+v", got)
	}
}

func TestRevocationRacesWithPromotion(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	att := mustIssue(t, svc, "sha256:aaa", "unit-tests")
	mustSetPolicy(t, svc, Policy{Environment: "staging", RequiredAttestations: []string{"unit-tests"}})

	// 先撤销，后晋级：已撤销的证明不能支撑新的成功结果。
	if err := svc.RevokeAttestation(att.ID); err != nil {
		t.Fatalf("RevokeAttestation: %v", err)
	}
	_, err := svc.Promote(PromoteRequest{ChangeID: "c1", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrMissingAttestation) {
		t.Fatalf("revoked attestation must not support promotion, got %v", err)
	}

	// 先晋级，后撤销：晋级保留当时的证明快照，供后续追溯。
	mustIssue(t, svc, "sha256:aaa", "unit-tests")
	rec := mustPromote(t, svc, "c2", "staging", "sha256:aaa", 0)
	var usedID string
	for _, a := range rec.AttestationSnapshot {
		if a.Type == "unit-tests" && !a.Revoked {
			usedID = a.ID
		}
	}
	if usedID == "" {
		t.Fatal("snapshot should contain the effective attestation used")
	}
	if err := svc.RevokeAttestation(usedID); err != nil {
		t.Fatalf("RevokeAttestation: %v", err)
	}
	history := svc.History("staging")
	if len(history) != 1 {
		t.Fatalf("expected 1 history record, got %d", len(history))
	}
	for _, a := range history[0].AttestationSnapshot {
		if a.ID == usedID && a.Revoked {
			t.Fatal("completed promotion must permanently retain the attestation snapshot as it was")
		}
	}
	// 已完成的晋级不受撤销影响。
	if got := svc.Environment("staging").Digest; got != "sha256:aaa" {
		t.Fatalf("revocation must not roll back a completed promotion, got %s", got)
	}
}

func TestConcurrentRevokeAndPromote(t *testing.T) {
	// 并发压力下验证：任何成功的晋级，其记录快照中都存在当时有效的证明；
	// 任何失败的晋级都是 ErrMissingAttestation 或 ErrVersionConflict。
	for i := 0; i < 20; i++ {
		svc, _ := testEnv(t)
		digest := fmt.Sprintf("sha256:%03d", i)
		mustRegister(t, svc, digest, "web", "1.0.0")
		att := mustIssue(t, svc, digest, "unit-tests")
		mustSetPolicy(t, svc, Policy{Environment: "staging", RequiredAttestations: []string{"unit-tests"}})

		var wg sync.WaitGroup
		var rec PromotionRecord
		var promoteErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			rec, promoteErr = svc.Promote(PromoteRequest{
				ChangeID: "c1", Environment: "staging", Digest: digest, ExpectedVersion: 0,
			})
		}()
		go func() {
			defer wg.Done()
			_ = svc.RevokeAttestation(att.ID)
		}()
		wg.Wait()

		if promoteErr == nil {
			effective := false
			for _, a := range rec.AttestationSnapshot {
				if a.Type == "unit-tests" && a.Effective(base) {
					effective = true
				}
			}
			if !effective {
				t.Fatalf("iter %d: promotion succeeded on a revoked attestation", i)
			}
		} else if !errors.Is(promoteErr, ErrMissingAttestation) && !errors.Is(promoteErr, ErrVersionConflict) {
			t.Fatalf("iter %d: unexpected promote error %v", i, promoteErr)
		}
	}
}

func TestHistoryQuery(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	mustSetPolicy(t, svc, Policy{Environment: "staging"})
	mustSetPolicy(t, svc, Policy{Environment: "prod"})

	mustPromote(t, svc, "c1", "staging", "sha256:aaa", 0)
	mustPromote(t, svc, "c2", "prod", "sha256:aaa", 0)

	if got := len(svc.History("")); got != 2 {
		t.Fatalf("expected 2 total records, got %d", got)
	}
	staging := svc.History("staging")
	if len(staging) != 1 || staging[0].ChangeID != "c1" {
		t.Fatalf("unexpected staging history: %+v", staging)
	}
	if got := len(svc.History("nonexistent")); got != 0 {
		t.Fatalf("expected empty history, got %d", got)
	}
}

func TestPersistenceAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	now := base
	clock := func() time.Time { return now }

	svc, err := NewService(NewFileStore(path), clock)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")
	att := mustIssue(t, svc, "sha256:aaa", "unit-tests")
	mustSetPolicy(t, svc, Policy{Environment: "staging", RequiredAttestations: []string{"unit-tests"}})
	mustPromote(t, svc, "c1", "staging", "sha256:aaa", 0)
	if err := svc.RevokeAttestation(att.ID); err != nil {
		t.Fatalf("RevokeAttestation: %v", err)
	}

	// 模拟重启：从同一文件重新加载。
	svc2, err := NewService(NewFileStore(path), clock)
	if err != nil {
		t.Fatalf("NewService after restart: %v", err)
	}
	if got := svc2.Environment("staging"); got.Digest != "sha256:aaa" || got.Version != 1 {
		t.Fatalf("environment pointer not persisted: %+v", got)
	}
	history := svc2.History("staging")
	if len(history) != 1 || len(history[0].AttestationSnapshot) != 1 {
		t.Fatalf("history not persisted: %+v", history)
	}
	if history[0].AttestationSnapshot[0].Revoked {
		t.Fatal("snapshot must reflect attestation state at promotion time")
	}
	// 撤销状态本身也被持久化。
	if atts := svc2.ListAttestations("sha256:aaa"); len(atts) != 1 || !atts[0].Revoked {
		t.Fatalf("revocation not persisted: %+v", atts)
	}
	// 幂等索引被持久化：重启后同号重放仍返回原记录。
	replay, err := svc2.Promote(PromoteRequest{ChangeID: "c1", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if err != nil {
		t.Fatalf("replay after restart: %v", err)
	}
	if replay.ToVersion != 1 {
		t.Fatalf("unexpected replay record: %+v", replay)
	}
}

func TestPromoteValidationAndPolicyErrors(t *testing.T) {
	svc, _ := testEnv(t)
	mustRegister(t, svc, "sha256:aaa", "web", "1.0.0")

	// 缺参数。
	_, err := svc.Promote(PromoteRequest{Environment: "staging", Digest: "sha256:aaa"})
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
	// 环境无策略。
	_, err = svc.Promote(PromoteRequest{ChangeID: "c1", Environment: "staging", Digest: "sha256:aaa", ExpectedVersion: 0})
	if !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("want ErrPolicyNotFound, got %v", err)
	}
	// 制品未登记。
	mustSetPolicy(t, svc, Policy{Environment: "staging"})
	_, err = svc.Promote(PromoteRequest{ChangeID: "c2", Environment: "staging", Digest: "sha256:missing", ExpectedVersion: 0})
	if !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("want ErrArtifactNotFound, got %v", err)
	}
	// 策略查询。
	if _, err := svc.GetPolicy("prod"); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("want ErrPolicyNotFound, got %v", err)
	}
	if err := svc.SetPolicy(Policy{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("want ErrInvalidInput, got %v", err)
	}
}
