package artifactpromotion

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestComputeDigestUnsupportedAlgorithm(t *testing.T) {
	if _, err := ComputeDigest("md5", []byte("x")); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	d, err := ComputeDigest("sha256", []byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	if string(d) != "sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881" {
		t.Fatalf("unexpected digest %s", d)
	}
}

func TestListAttestations(t *testing.T) {
	s, _ := newTestService(t)
	d1 := mustDigest(t, "sha256", []byte("v1"))
	d2 := mustDigest(t, "sha256", []byte("v2"))
	mustRegister(t, s, d1, "a1")
	mustRegister(t, s, d2, "a2")
	a1 := mustIssue(t, s, d1, "vuln-scan")
	a2 := mustIssue(t, s, d1, "sbom")
	mustIssue(t, s, d2, "vuln-scan")

	list, err := s.ListAttestations(d1)
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].ID != a1.ID || list[1].ID != a2.ID {
		t.Fatalf("expected both attestations of d1 sorted by id, got %+v", list)
	}
}

func TestGetPointerValidation(t *testing.T) {
	s, _ := newTestService(t)
	if _, err := s.GetPointer(""); !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("expected ErrInvalidArgument, got %v", err)
	}
	ptr, err := s.GetPointer("never-used")
	if err != nil {
		t.Fatalf("empty environment should return zero-value pointer, got %v", err)
	}
	if ptr.Version != 0 || ptr.Digest != "" {
		t.Fatalf("unexpected pointer: %+v", ptr)
	}
}

func TestPersistentServiceCorruptFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPersistentService(path); err == nil {
		t.Fatal("expected error opening corrupt state file")
	}

	// 状态目录不存在：服务可构造，但首次提交必须返回错误而非静默丢数据。
	s, err := NewPersistentService(filepath.Join(dir, "no-such-dir", "state.json"))
	if err != nil {
		t.Fatalf("service construction is lazy, got error: %v", err)
	}
	if err := s.store.update(func(tx kvTx) error { return nil }); err == nil {
		t.Fatal("expected persistence error when state directory does not exist")
	}
}

// 有效期边界：ValidUntil 时刻本身仍然有效（判定使用严格 After）。
func TestValidityBoundary(t *testing.T) {
	deadline := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	a := Attestation{
		ID: "x", Conclusion: ConclusionApproved,
		ValidFrom: deadline.Add(-time.Hour), ValidUntil: deadline,
	}
	if err := validityFailure(a, deadline); err != nil {
		t.Fatalf("attestation should be valid exactly at ValidUntil: %v", err)
	}
	if err := validityFailure(a, deadline.Add(time.Nanosecond)); !errors.Is(err, ErrAttestationExpired) {
		t.Fatalf("expected expired just after ValidUntil, got %v", err)
	}

	b := Attestation{ID: "y", Conclusion: ConclusionApproved, ValidFrom: deadline}
	if err := validityFailure(b, deadline); err != nil {
		t.Fatalf("attestation should be valid exactly at ValidFrom: %v", err)
	}
	if err := validityFailure(b, deadline.Add(-time.Nanosecond)); !errors.Is(err, ErrAttestationNotYetValid) {
		t.Fatalf("expected not-yet-valid before ValidFrom, got %v", err)
	}
}

func TestFixedClock(t *testing.T) {
	at := time.Date(2026, 9, 26, 8, 0, 0, 0, time.UTC)
	if got := FixedClock(at).Now(); !got.Equal(at) {
		t.Fatalf("FixedClock returned %v, want %v", got, at)
	}
	if got := SystemClock().Now(); got.IsZero() {
		t.Fatal("SystemClock returned zero time")
	}
}
