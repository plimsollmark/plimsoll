package sandbox

import (
	"errors"
	"strings"
	"testing"
)

func TestSoftwareRuleAdmission(t *testing.T) {
	a := "oci-manifest:linux/amd64@sha256:" + repeatHex('a')
	b := "oci-manifest:linux/arm64@sha256:" + repeatHex('b')
	exact := SoftwareRule{Mode: SoftwareExact, Identities: []string{a}}
	approved := SoftwareRule{Mode: SoftwareApproved, Identities: []string{b, a}}
	if err := exact.Check(a); err != nil {
		t.Fatal(err)
	}
	for _, identity := range []string{"", b} {
		err := exact.Check(identity)
		if !errors.Is(err, ErrSoftwareMismatch) {
			t.Fatalf("selected %q: %v", identity, err)
		}
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalEnvironment {
			t.Fatalf("selected %q: reason %v, marked %v", identity, reason, ok)
		}
	}
	if err := approved.Check(b); err != nil {
		t.Fatal(err)
	}
	otherOrder := SoftwareRule{Mode: SoftwareApproved, Identities: []string{a, b}}
	if approved.ID() != otherOrder.ID() {
		t.Fatal("approved-set identity depends on order")
	}
	merged, err := MergeSoftwareRules(approved, exact)
	if err != nil || merged.Mode != SoftwareExact || merged.ID() != exact.ID() {
		t.Fatalf("intersection: %+v, %v", merged, err)
	}
	if _, err := MergeSoftwareRules(exact, SoftwareRule{Mode: SoftwareExact, Identities: []string{b}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("disjoint rules: %v", err)
	}
}

func TestSoftwareRuleRejectsInvalid(t *testing.T) {
	for _, r := range []SoftwareRule{
		{Mode: SoftwareExact},
		{Mode: SoftwareExact, Identities: []string{"a", "b"}},
		{Mode: SoftwareApproved, Identities: []string{"a", "a"}},
		{Mode: SoftwareApproved, Identities: []string{"a b"}},
		{Mode: "trust-builder", Identities: []string{"a"}},
	} {
		err := r.Validate()
		if !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("%+v: %v", r, err)
		}
		if reason, ok := NotDispatchedReason(err); !ok || reason != RefusalRequest {
			t.Fatalf("%+v: reason %v, marked %v", r, reason, ok)
		}
	}
}

func repeatHex(c byte) string {
	b := make([]byte, 64)
	for i := range b {
		b[i] = c
	}
	return string(b)
}

// A rule merged with itself keeps its ID. A session resends the rule it was opened
// with on every call, and the daemon refuses a call whose merged rule changes the ID.
func TestSoftwareRuleMergedWithItselfKeepsItsID(t *testing.T) {
	a := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)
	b := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)
	for _, r := range []SoftwareRule{
		{Mode: SoftwareExact, Identities: []string{a}},
		{Mode: SoftwareApproved, Identities: []string{a}},
		{Mode: SoftwareApproved, Identities: []string{a, b}},
	} {
		merged, err := MergeSoftwareRules(r, r)
		if err != nil || merged.ID() != r.ID() {
			t.Fatalf("%+v merged with itself: %+v (%q, want %q), %v", r, merged, merged.ID(), r.ID(), err)
		}
	}
	one := SoftwareRule{Mode: SoftwareApproved, Identities: []string{a}}
	if one.ID() != "exact:"+a {
		t.Fatalf("approved with one identity: ID %q, want the exact rule's", one.ID())
	}
}
