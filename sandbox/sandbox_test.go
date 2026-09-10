package sandbox

import "testing"

func TestIsolationClassMeetsRejectsUnknownOnEitherSide(t *testing.T) {
	for _, class := range []IsolationClass{
		IsolationUnknown,
		IsolationNone,
		IsolationProcess,
		IsolationContainer,
		IsolationKernel,
		IsolationVM,
	} {
		if class.Meets(IsolationUnknown) {
			t.Errorf("%s.Meets(unknown) = true; an unknown requirement must never be satisfied", class)
		}
		if IsolationUnknown.Meets(class) {
			t.Errorf("unknown.Meets(%s) = true; an unknown provider must never satisfy a requirement", class)
		}
	}
	if !IsolationVM.Meets(IsolationKernel) {
		t.Error("vm should meet a kernel-tier requirement")
	}
	if IsolationContainer.Meets(IsolationKernel) {
		t.Error("container should not meet a kernel-tier requirement")
	}
	if IsolationClass(99).Meets(IsolationKernel) || IsolationVM.Meets(IsolationClass(99)) {
		t.Error("out-of-range isolation values must fail closed")
	}
}
