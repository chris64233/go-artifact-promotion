package artifactpromotion

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// mutableClock 是可在测试中任意拨快/回拨的时钟。
type mutableClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *mutableClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *mutableClock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

func (c *mutableClock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newTestService(t *testing.T) (*Service, *mutableClock) {
	t.Helper()
	clk := &mutableClock{t: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}
	return NewService().WithClock(clk), clk
}

func mustDigest(t *testing.T, algo string, payload []byte) Digest {
	t.Helper()
	d, err := ComputeDigest(algo, payload)
	if err != nil {
		t.Fatalf("ComputeDigest: %v", err)
	}
	return d
}

func mustRegister(t *testing.T, s *Service, d Digest, name string) {
	t.Helper()
	if _, err := s.RegisterArtifact(d, "sha256", name); err != nil {
		t.Fatalf("RegisterArtifact %s: %v", d, err)
	}
}

func mustIssue(t *testing.T, s *Service, d Digest, typ AttestationType) Attestation {
	t.Helper()
	a, err := s.IssueAttestation(IssueAttestationRequest{
		Digest:     d,
		Type:       typ,
		Issuer:     "security-team",
		Conclusion: ConclusionApproved,
	})
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}
	return a
}

func assertErrorIs(t *testing.T, err error, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("expected error wrapping %v, got %v", target, err)
	}
}

// ---------- 制品登记 ----------

func TestRegisterArtifactAndGet(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("release-1.0.0"))

	mustRegister(t, s, d, "api-server")
	got, err := s.GetArtifact(d)
	if err != nil {
		t.Fatalf("GetArtifact: %v", err)
	}
	if got.Digest != d || got.Name != "api-server" || got.Algorithm != "sha256" {
		t.Fatalf("unexpected artifact: %+v", got)
	}

	if _, err := s.GetArtifact("sha256:0000000000000000000000000000000000000000000000000000000000000000"); !errors.Is(err, ErrArtifactNotFound) {
		t.Fatalf("expected ErrArtifactNotFound, got %v", err)
	}
}

func TestRegisterArtifactInvalidDigest(t *testing.T) {
	s, _ := newTestService(t)
	for _, bad := range []Digest{"", "noscheme", "sha256:", "sha256:xyz"} {
		_, err := s.RegisterArtifact(bad, "sha256", "name")
		assertErrorIs(t, err, ErrInvalidArgument)
	}
	_, err := s.RegisterArtifact("sha256:"+"aa", "", "name")
	assertErrorIs(t, err, ErrInvalidArgument)
	_, err = s.RegisterArtifact("sha256:"+"aa", "sha256", "")
	assertErrorIs(t, err, ErrInvalidArgument)
}

func TestRegisterArtifactIdempotentAndConflict(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "name")

	// 相同摘要 + 相同元数据：幂等。
	if _, err := s.RegisterArtifact(d, "sha256", "name"); err != nil {
		t.Fatalf("identical re-register should be idempotent: %v", err)
	}
	// 相同摘要 + 不同元数据：冲突报错。
	_, err := s.RegisterArtifact(d, "sha256", "other-name")
	assertErrorIs(t, err, ErrInvalidArgument)
}

// ---------- 证明签发与撤销 ----------

func TestAttestationIssueRevoke(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")

	a, err := s.IssueAttestation(IssueAttestationRequest{
		Digest:     d,
		Type:       "vuln-scan",
		Issuer:     "scanner",
		Conclusion: ConclusionApproved,
	})
	if err != nil {
		t.Fatalf("IssueAttestation: %v", err)
	}
	if a.ID == "" || a.Revoked() {
		t.Fatalf("unexpected attestation: %+v", a)
	}

	if err := s.RevokeAttestation(a.ID, "key-rotated"); err != nil {
		t.Fatalf("RevokeAttestation: %v", err)
	}
	got, err := s.GetAttestation(a.ID)
	if err != nil {
		t.Fatalf("GetAttestation: %v", err)
	}
	if !got.Revoked() || got.RevokeReason != "key-rotated" {
		t.Fatalf("revocation not recorded: %+v", got)
	}

	// 重复撤销与撤销不存在的证明都应可区分。
	assertErrorIs(t, s.RevokeAttestation(a.ID, "again"), ErrInvalidArgument)
	assertErrorIs(t, s.RevokeAttestation("att-missing", ""), ErrAttestationNotFound)
	_, err = s.GetAttestation("att-missing")
	assertErrorIs(t, err, ErrAttestationNotFound)
}

func TestIssueAttestationValidation(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")

	base := IssueAttestationRequest{
		Digest: d, Type: "t", Issuer: "i", Conclusion: ConclusionApproved,
	}
	r := base
	r.Type = ""
	_, err := s.IssueAttestation(r)
	assertErrorIs(t, err, ErrInvalidArgument)

	r = base
	r.Issuer = ""
	_, err = s.IssueAttestation(r)
	assertErrorIs(t, err, ErrInvalidArgument)

	r = base
	r.Conclusion = "maybe"
	_, err = s.IssueAttestation(r)
	assertErrorIs(t, err, ErrInvalidArgument)

	r = base
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	r.ValidFrom = now
	r.ValidUntil = now // 不晚于 ValidFrom
	_, err = s.IssueAttestation(r)
	assertErrorIs(t, err, ErrInvalidArgument)

	// 为未登记制品签发证明。
	_, err = s.IssueAttestation(IssueAttestationRequest{
		Digest: "sha256:" + "bb", Type: "t", Issuer: "i", Conclusion: ConclusionApproved,
	})
	assertErrorIs(t, err, ErrArtifactNotFound)
}

// ---------- 策略配置 ----------

func TestConfigurePolicy(t *testing.T) {
	s, _ := newTestService(t)

	p, err := s.ConfigurePolicy(Policy{
		Environment:          "dev",
		RequiredAttestations: []AttestationType{"vuln-scan", "sbom"},
	})
	if err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}
	if len(p.RequiredAttestations) != 2 || p.UpdatedAt.IsZero() {
		t.Fatalf("unexpected policy: %+v", p)
	}
	got, err := s.GetPolicy("dev")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if len(got.RequiredAttestations) != 2 {
		t.Fatalf("policy not persisted: %+v", got)
	}

	// 覆盖式更新。
	if _, err := s.ConfigurePolicy(Policy{Environment: "dev"}); err != nil {
		t.Fatalf("ConfigurePolicy update: %v", err)
	}
	got, _ = s.GetPolicy("dev")
	if len(got.RequiredAttestations) != 0 {
		t.Fatalf("expected policy to be replaced, got %+v", got)
	}

	_, err = s.GetPolicy("prod")
	assertErrorIs(t, err, ErrPolicyNotFound)

	// 输入校验。
	_, err = s.ConfigurePolicy(Policy{RequiredAttestations: []AttestationType{"t"}})
	assertErrorIs(t, err, ErrInvalidArgument)
	_, err = s.ConfigurePolicy(Policy{Environment: "dev", RequiredAttestations: []AttestationType{"t", "t"}})
	assertErrorIs(t, err, ErrInvalidArgument)
	// 上游不能是自己。
	_, err = s.ConfigurePolicy(Policy{Environment: "dev", UpstreamEnvironment: "dev"})
	assertErrorIs(t, err, ErrInvalidArgument)
	// 上游策略必须已存在。
	_, err = s.ConfigurePolicy(Policy{Environment: "prod", UpstreamEnvironment: "staging"})
	assertErrorIs(t, err, ErrPolicyNotFound)
}

// ---------- 晋级主流程 ----------

func TestPromoteHappyPath(t *testing.T) {
	s, clk := newTestService(t)
	d := mustDigest(t, "sha256", []byte("release-1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan", "sbom"},
	}); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}
	a1 := mustIssue(t, s, d, "vuln-scan")
	a2 := mustIssue(t, s, d, "sbom")

	rec, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-1", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	if err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if rec.Version != 1 || rec.Environment != "prod" || rec.Digest != d {
		t.Fatalf("unexpected promotion record: %+v", rec)
	}
	if len(rec.Attestations) != 2 {
		t.Fatalf("expected 2 attestation snapshots, got %d", len(rec.Attestations))
	}
	if rec.PolicySnapshot.Environment != "prod" ||
		len(rec.PolicySnapshot.RequiredAttestations) != 2 {
		t.Fatalf("policy not snapshotted: %+v", rec.PolicySnapshot)
	}

	ptr, err := s.GetPointer("prod")
	if err != nil {
		t.Fatalf("GetPointer: %v", err)
	}
	if ptr.Version != 1 || ptr.Digest != d || ptr.PromotionID != rec.ID {
		t.Fatalf("unexpected pointer: %+v", ptr)
	}

	// 历史可查，记录顺序正确。
	hist, err := s.History("prod")
	if err != nil || len(hist) != 1 || hist[0].ID != rec.ID {
		t.Fatalf("history mismatch: %+v, err=%v", hist, err)
	}
	got, err := s.GetPromotion(rec.ID)
	if err != nil || got.ChangeNumber != "CHG-1" {
		t.Fatalf("GetPromotion: %+v, err=%v", got, err)
	}

	// 快照内容与当时证明一致。
	ids := map[string]bool{rec.Attestations[0].ID: true, rec.Attestations[1].ID: true}
	if !ids[a1.ID] || !ids[a2.ID] {
		t.Fatalf("snapshot attestation ids mismatch: %v", ids)
	}
	for _, snap := range rec.Attestations {
		if snap.Revoked() {
			t.Fatalf("snapshot should be pre-revocation: %+v", snap)
		}
		if snap.Issuer != "security-team" {
			t.Fatalf("snapshot should preserve issuer: %+v", snap)
		}
	}

	// 指针版本单调递增：第二个制品晋级后版本为 2。
	d2 := mustDigest(t, "sha256", []byte("release-2"))
	mustRegister(t, s, d2, "api")
	mustIssue(t, s, d2, "vuln-scan")
	mustIssue(t, s, d2, "sbom")
	clk.Add(time.Second)
	rec2, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-2", Environment: "prod", Digest: d2, ExpectedVersion: 1,
	})
	if err != nil {
		t.Fatalf("second Promote: %v", err)
	}
	if rec2.Version != 2 {
		t.Fatalf("expected version 2, got %d", rec2.Version)
	}
	ptr, _ = s.GetPointer("prod")
	if ptr.Digest != d2 {
		t.Fatalf("pointer should switch to d2, got %s", ptr.Digest)
	}
	// 上一版本的记录仍可追溯。
	hist, _ = s.History("prod")
	if len(hist) != 2 || hist[0].Digest != d || hist[1].Digest != d2 {
		t.Fatalf("history order/content mismatch: %+v", hist)
	}
}

func TestPromoteMissingPrerequisites(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")

	// 策略未配置。
	_, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrPolicyNotFound)

	if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
		t.Fatalf("ConfigurePolicy: %v", err)
	}
	// 制品不存在。
	missing := Digest("sha256:" + "cc")
	_, err = s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "prod", Digest: missing, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrArtifactNotFound)

	// 参数校验。
	_, err = s.Promote(PromotionRequest{Environment: "prod", Digest: d})
	assertErrorIs(t, err, ErrInvalidArgument)
	_, err = s.Promote(PromotionRequest{ChangeNumber: "C", Digest: d})
	assertErrorIs(t, err, ErrInvalidArgument)
}

// 各类证明条件不满足时必须返回可区分的错误类别。
func TestPromoteAttestationConditions(t *testing.T) {
	type tc struct {
		name        string
		setup       func(s *Service, clk *mutableClock, d Digest)
		wantSatisfy func(error) bool
	}
	base := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	cases := []tc{
		{
			name:        "missing type",
			setup:       func(s *Service, clk *mutableClock, d Digest) {},
			wantSatisfy: func(e error) bool { return errors.Is(e, ErrMissingAttestation) },
		},
		{
			name: "revoked",
			setup: func(s *Service, clk *mutableClock, d Digest) {
				a := mustIssue(t, s, d, "vuln-scan")
				if err := s.RevokeAttestation(a.ID, "bad"); err != nil {
					t.Fatal(err)
				}
			},
			wantSatisfy: func(e error) bool { return errors.Is(e, ErrAttestationRevoked) },
		},
		{
			name: "rejected conclusion",
			setup: func(s *Service, clk *mutableClock, d Digest) {
				if _, err := s.IssueAttestation(IssueAttestationRequest{
					Digest: d, Type: "vuln-scan", Issuer: "scanner",
					Conclusion: ConclusionRejected,
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantSatisfy: func(e error) bool { return errors.Is(e, ErrAttestationRejected) },
		},
		{
			name: "expired",
			setup: func(s *Service, clk *mutableClock, d Digest) {
				if _, err := s.IssueAttestation(IssueAttestationRequest{
					Digest: d, Type: "vuln-scan", Issuer: "scanner",
					Conclusion: ConclusionApproved,
					ValidFrom:  base.Add(-2 * time.Hour),
					ValidUntil: base.Add(-1 * time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantSatisfy: func(e error) bool { return errors.Is(e, ErrAttestationExpired) },
		},
		{
			name: "not yet valid",
			setup: func(s *Service, clk *mutableClock, d Digest) {
				if _, err := s.IssueAttestation(IssueAttestationRequest{
					Digest: d, Type: "vuln-scan", Issuer: "scanner",
					Conclusion: ConclusionApproved,
					ValidFrom:  base.Add(1 * time.Hour),
				}); err != nil {
					t.Fatal(err)
				}
			},
			wantSatisfy: func(e error) bool { return errors.Is(e, ErrAttestationNotYetValid) },
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, clk := newTestService(t)
			d := mustDigest(t, "sha256", []byte("x-"+c.name))
			mustRegister(t, s, d, "api")
			if _, err := s.ConfigurePolicy(Policy{
				Environment:          "prod",
				RequiredAttestations: []AttestationType{"vuln-scan"},
			}); err != nil {
				t.Fatal(err)
			}
			c.setup(s, clk, d)
			_, err := s.Promote(PromotionRequest{
				ChangeNumber: "CHG-" + c.name, Environment: "prod", Digest: d, ExpectedVersion: 0,
			})
			if err == nil {
				t.Fatal("expected promotion to fail")
			}
			if !c.wantSatisfy(err) {
				t.Fatalf("error category mismatch for %s: %v", c.name, err)
			}
			// 失败不得移动环境指针，也不得留下晋级记录。
			ptr, _ := s.GetPointer("prod")
			if ptr.Version != 0 {
				t.Fatalf("pointer must not move on failed promotion: %+v", ptr)
			}
			hist, _ := s.History("prod")
			if len(hist) != 0 {
				t.Fatalf("no promotion record expected, got %+v", hist)
			}
			// 失败不消耗变更号：补上有效证明后同号重试应当成功。
			mustIssue(t, s, d, "vuln-scan")
			rec, err := s.Promote(PromotionRequest{
				ChangeNumber: "CHG-" + c.name, Environment: "prod", Digest: d, ExpectedVersion: 0,
			})
			if err != nil {
				t.Fatalf("retry with valid attestation should succeed: %v", err)
			}
			if rec.Version != 1 {
				t.Fatalf("unexpected version %d", rec.Version)
			}
		})
	}
}

// 同一类型有多份候选材料时，一份有效即放行；全部无效才拒绝。
func TestPromoteMultipleCandidatesSameType(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatal(err)
	}
	bad := mustIssue(t, s, d, "vuln-scan")
	if err := s.RevokeAttestation(bad.ID, ""); err != nil {
		t.Fatal(err)
	}
	good := mustIssue(t, s, d, "vuln-scan")

	rec, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	if err != nil {
		t.Fatalf("valid candidate should satisfy requirement: %v", err)
	}
	if len(rec.Attestations) != 1 || rec.Attestations[0].ID != good.ID {
		t.Fatalf("snapshot should pick the valid candidate: %+v", rec.Attestations)
	}
}

// ---------- 撤销与晋级并发 ----------

func TestRevokeAfterPromotionPreservesSnapshot(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{
		Environment:          "prod",
		RequiredAttestations: []AttestationType{"vuln-scan"},
	}); err != nil {
		t.Fatal(err)
	}
	a := mustIssue(t, s, d, "vuln-scan")
	rec, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	if err != nil {
		t.Fatal(err)
	}

	// 晋级完成后撤销证明：历史快照必须永久保留撤销前的状态。
	if err := s.RevokeAttestation(a.ID, "later"); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetPromotion(rec.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Attestations) != 1 || got.Attestations[0].Revoked() {
		t.Fatalf("historical snapshot must remain non-revoked: %+v", got.Attestations)
	}
	live, _ := s.GetAttestation(a.ID)
	if !live.Revoked() {
		t.Fatal("live attestation should be revoked")
	}

	// 已撤销的证明不能支撑新的成功晋级（第二个制品）。
	d2 := mustDigest(t, "sha256", []byte("v2"))
	mustRegister(t, s, d2, "api")
	a2 := mustIssue(t, s, d2, "vuln-scan")
	if err := s.RevokeAttestation(a2.ID, ""); err != nil {
		t.Fatal(err)
	}
	_, err = s.Promote(PromotionRequest{
		ChangeNumber: "C2", Environment: "prod", Digest: d2, ExpectedVersion: 1,
	})
	assertErrorIs(t, err, ErrAttestationRevoked)
	ptr, _ := s.GetPointer("prod")
	if ptr.Version != 1 || ptr.Digest != d {
		t.Fatalf("pointer must stay at the earlier promotion: %+v", ptr)
	}
}

// 撤销与晋级真正并发：晋级要么先于撤销提交（成功，快照保持未撤销），
// 要么在快照中看到撤销（失败）。不存在“证明已撤销却晋级成功”的结果。
func TestRevokePromoteRace(t *testing.T) {
	for iter := 0; iter < 100; iter++ {
		s, _ := newTestService(t)
		d := mustDigest(t, "sha256", []byte("race"))
		mustRegister(t, s, d, "api")
		if _, err := s.ConfigurePolicy(Policy{
			Environment:          "prod",
			RequiredAttestations: []AttestationType{"vuln-scan"},
		}); err != nil {
			t.Fatal(err)
		}
		a := mustIssue(t, s, d, "vuln-scan")

		var wg sync.WaitGroup
		wg.Add(2)
		var revokeErr, promoteErr error
		var rec Promotion
		go func() {
			defer wg.Done()
			revokeErr = s.RevokeAttestation(a.ID, "race")
		}()
		go func() {
			defer wg.Done()
			rec, promoteErr = s.Promote(PromotionRequest{
				ChangeNumber: "R1", Environment: "prod", Digest: d, ExpectedVersion: 0,
			})
		}()
		wg.Wait()

		if revokeErr != nil {
			t.Fatalf("revoke should always succeed: %v", revokeErr)
		}
		ptr, _ := s.GetPointer("prod")
		switch {
		case promoteErr == nil:
			// 晋级先提交：必须成功落位，快照保持未撤销状态。
			if ptr.Version != 1 || ptr.Digest != d {
				t.Fatalf("committed promotion not reflected: %+v", ptr)
			}
			got, _ := s.GetPromotion(rec.ID)
			if got.Attestations[0].Revoked() {
				t.Fatal("snapshot of a promotion committed before revoke must be non-revoked")
			}
		case errors.Is(promoteErr, ErrAttestationRevoked):
			// 撤销先提交：指针必须保持空。
			if ptr.Version != 0 {
				t.Fatalf("revoked attestation must not support promotion: %+v", ptr)
			}
		default:
			t.Fatalf("unexpected promotion error: %v", promoteErr)
		}
	}
}

// ---------- 幂等、冲突与版本条件 ----------

func TestPromoteIdempotency(t *testing.T) {
	s, clk := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	req := PromotionRequest{ChangeNumber: "CHG-1", Environment: "prod", Digest: d, ExpectedVersion: 0}
	first, err := s.Promote(req)
	if err != nil {
		t.Fatal(err)
	}

	// 第二次晋级发生在环境已变更之后，但同号重放仍应原样返回，
	// 不做版本条件检查、不产生新版本。
	clk.Add(time.Hour)
	second, err := s.Promote(req)
	if err != nil {
		t.Fatalf("replay must be idempotent: %v", err)
	}
	if second.ID != first.ID || second.Version != first.Version ||
		!second.PromotedAt.Equal(first.PromotedAt) {
		t.Fatalf("replay must return the original record: first=%+v second=%+v", first, second)
	}
	hist, _ := s.History("prod")
	if len(hist) != 1 {
		t.Fatalf("replay must not append history: %+v", hist)
	}
}

func TestPromoteChangeNumberConflict(t *testing.T) {
	s, _ := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("v1"))
	d2 := mustDigest(t, "sha256", []byte("v2"))
	mustRegister(t, s, d1, "a1")
	mustRegister(t, s, d2, "a2")
	if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-1", Environment: "prod", Digest: d1, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}

	// 同号但目标制品不同：冲突。
	_, err := s.Promote(PromotionRequest{
		ChangeNumber: "CHG-1", Environment: "prod", Digest: d2, ExpectedVersion: 1,
	})
	assertErrorIs(t, err, ErrChangeConflict)

	// 同号但目标环境不同：冲突。
	if _, err := s.ConfigurePolicy(Policy{Environment: "staging"}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Promote(PromotionRequest{
		ChangeNumber: "CHG-1", Environment: "staging", Digest: d1, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrChangeConflict)

	// 冲突不得移动 staging 指针，也不得消耗 staging 的版本。
	ptr, _ := s.GetPointer("staging")
	if ptr.Version != 0 {
		t.Fatalf("staging pointer must remain empty: %+v", ptr)
	}
}

func TestPromoteVersionCondition(t *testing.T) {
	s, _ := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("v1"))
	d2 := mustDigest(t, "sha256", []byte("v2"))
	mustRegister(t, s, d1, "a1")
	mustRegister(t, s, d2, "a2")
	if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "prod", Digest: d1, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}

	// 发起方以为环境还是空的（ExpectedVersion=0）：拒绝静默覆盖。
	_, err := s.Promote(PromotionRequest{
		ChangeNumber: "C2", Environment: "prod", Digest: d2, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrConcurrentModification)
	ptr, _ := s.GetPointer("prod")
	if ptr.Digest != d1 {
		t.Fatalf("failed CAS must not move pointer: %+v", ptr)
	}

	// 带上正确的当前版本后晋级成功。
	rec, err := s.Promote(PromotionRequest{
		ChangeNumber: "C2", Environment: "prod", Digest: d2, ExpectedVersion: 1,
	})
	if err != nil {
		t.Fatalf("promotion with correct expected version: %v", err)
	}
	if rec.Version != 2 {
		t.Fatalf("expected version 2, got %d", rec.Version)
	}
}

// 多个制品争用同一环境：只有一个能以 ExpectedVersion=0 成功，其余被 CAS 拒绝。
func TestConcurrentContention(t *testing.T) {
	for iter := 0; iter < 50; iter++ {
		s, _ := newTestService(t)
		if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
			t.Fatal(err)
		}
		const n = 8
		digests := make([]Digest, n)
		for i := range digests {
			d := mustDigest(t, "sha256", []byte("candidate-"+string(rune('a'+i))))
			digests[i] = d
			mustRegister(t, s, d, "candidate")
		}

		var wg sync.WaitGroup
		wg.Add(n)
		errs := make([]error, n)
		for i := 0; i < n; i++ {
			i := i
			go func() {
				defer wg.Done()
				_, errs[i] = s.Promote(PromotionRequest{
					ChangeNumber:    "CC-" + string(rune('a'+i)),
					Environment:     "prod",
					Digest:          digests[i],
					ExpectedVersion: 0,
				})
			}()
		}
		wg.Wait()

		ok, casFail := 0, 0
		for _, e := range errs {
			switch {
			case e == nil:
				ok++
			case errors.Is(e, ErrConcurrentModification):
				casFail++
			default:
				t.Fatalf("unexpected error: %v", e)
			}
		}
		if ok != 1 || casFail != n-1 {
			t.Fatalf("iter %d: expected exactly 1 success, got ok=%d cas=%d", iter, ok, casFail)
		}
		ptr, _ := s.GetPointer("prod")
		if ptr.Version != 1 {
			t.Fatalf("pointer should be version 1, got %d", ptr.Version)
		}
	}
}

// ---------- 上游环境要求 ----------

func TestUpstreamEnvironmentRequirement(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{Environment: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigurePolicy(Policy{
		Environment: "staging", UpstreamEnvironment: "dev",
	}); err != nil {
		t.Fatal(err)
	}

	// 上游 dev 尚未指向该制品：晋级 staging 被拒。
	_, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "staging", Digest: d, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrUpstreamNotPromoted)

	// 晋级到 dev。
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C2", Environment: "dev", Digest: d, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	// 上游已放行：staging 晋级成功。
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C3", Environment: "staging", Digest: d, ExpectedVersion: 0,
	}); err != nil {
		t.Fatalf("promotion after upstream promotion should succeed: %v", err)
	}

	// dev 之后指向了别的制品：d 不再是上游当前版本，prod 要求 dev/staging 链时失败。
	d2 := mustDigest(t, "sha256", []byte("v2"))
	mustRegister(t, s, d2, "api")
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C4", Environment: "dev", Digest: d2, ExpectedVersion: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigurePolicy(Policy{
		Environment: "prod", UpstreamEnvironment: "dev",
	}); err != nil {
		t.Fatal(err)
	}
	_, err = s.Promote(PromotionRequest{
		ChangeNumber: "C5", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	assertErrorIs(t, err, ErrUpstreamNotPromoted)
}

// ---------- 持久化 ----------

func TestPersistentService(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	d := mustDigest(t, "sha256", []byte("persist-v1"))
	var promotionID int64
	var attID string
	func() {
		s, err := NewPersistentService(path)
		if err != nil {
			t.Fatal(err)
		}
		mustRegister(t, s, d, "api")
		if _, err := s.ConfigurePolicy(Policy{
			Environment:          "prod",
			RequiredAttestations: []AttestationType{"vuln-scan"},
		}); err != nil {
			t.Fatal(err)
		}
		a := mustIssue(t, s, d, "vuln-scan")
		attID = a.ID
		rec, err := s.Promote(PromotionRequest{
			ChangeNumber: "P-1", Environment: "prod", Digest: d, ExpectedVersion: 0,
		})
		if err != nil {
			t.Fatal(err)
		}
		promotionID = rec.ID
	}()

	// 状态文件确实存在且为合法 JSON。
	if info, err := os.Stat(path); err != nil || info.Size() == 0 {
		t.Fatalf("state file missing or empty: %v", err)
	}

	// 重新打开：全部状态完整保留。
	s2, err := NewPersistentService(path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := s2.GetArtifact(d)
	if err != nil || a.Name != "api" {
		t.Fatalf("artifact not restored: %+v err=%v", a, err)
	}
	pol, err := s2.GetPolicy("prod")
	if err != nil || len(pol.RequiredAttestations) != 1 {
		t.Fatalf("policy not restored: %+v err=%v", pol, err)
	}
	ptr, err := s2.GetPointer("prod")
	if err != nil || ptr.Digest != d || ptr.Version != 1 {
		t.Fatalf("pointer not restored: %+v err=%v", ptr, err)
	}
	rec, err := s2.GetPromotion(promotionID)
	if err != nil {
		t.Fatalf("promotion not restored: %v", err)
	}
	if len(rec.Attestations) != 1 || rec.Attestations[0].ID != attID {
		t.Fatalf("attestation snapshot not restored: %+v", rec.Attestations)
	}

	// 幂等语义在重启后仍然成立，且计数器延续。
	again, err := s2.Promote(PromotionRequest{
		ChangeNumber: "P-1", Environment: "prod", Digest: d, ExpectedVersion: 0,
	})
	if err != nil || again.ID != promotionID {
		t.Fatalf("idempotency must survive restart: %+v err=%v", again, err)
	}
	d2 := mustDigest(t, "sha256", []byte("persist-v2"))
	mustRegister(t, s2, d2, "api2")
	a2, err := s2.IssueAttestation(IssueAttestationRequest{
		Digest: d2, Type: "vuln-scan", Issuer: "x", Conclusion: ConclusionApproved,
	})
	if err != nil {
		t.Fatal(err)
	}
	if a2.ID == attID {
		t.Fatalf("attestation id counter must survive restart: %s", a2.ID)
	}
	if _, err := s2.Promote(PromotionRequest{
		ChangeNumber: "P-2", Environment: "prod", Digest: d2, ExpectedVersion: 1,
	}); err != nil {
		t.Fatalf("promotion after restart: %v", err)
	}
}

func TestHistoryFiltersByEnvironment(t *testing.T) {
	s, _ := newTestService(t)
	d := mustDigest(t, "sha256", []byte("v1"))
	mustRegister(t, s, d, "api")
	if _, err := s.ConfigurePolicy(Policy{Environment: "dev"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfigurePolicy(Policy{Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C1", Environment: "dev", Digest: d, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(PromotionRequest{
		ChangeNumber: "C2", Environment: "prod", Digest: d, ExpectedVersion: 0,
	}); err != nil {
		t.Fatal(err)
	}
	all, _ := s.History("")
	if len(all) != 2 {
		t.Fatalf("expected 2 records across envs, got %d", len(all))
	}
	dev, _ := s.History("dev")
	if len(dev) != 1 || dev[0].Environment != "dev" {
		t.Fatalf("dev filter mismatch: %+v", dev)
	}
	_, err := s.GetPromotion(0)
	assertErrorIs(t, err, ErrInvalidArgument)
	_, err = s.GetPromotion(999)
	assertErrorIs(t, err, ErrPromotionNotFound)
}
