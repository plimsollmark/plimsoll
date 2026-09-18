package sandbox

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// blockingSandbox holds each run until release is signaled, so a test can pin slots
// in flight and observe admission decisions.
type blockingSandbox struct {
	enter     chan struct{} // signaled when a run has entered
	block     chan struct{} // a run returns once this is closed
	isolation IsolationClass
}

func (b *blockingSandbox) RunJavaScript(ctx context.Context, _ Request) (Result, error) {
	b.enter <- struct{}{}
	<-b.block
	return Result{Sandbox: "fake"}, nil
}
func (b *blockingSandbox) RunProject(ctx context.Context, _ ProjectRequest) (ProjectResult, error) {
	b.enter <- struct{}{}
	<-b.block
	return ProjectResult{Sandbox: "fake"}, nil
}
func (b *blockingSandbox) RunModule(ctx context.Context, _ ModuleRequest) (ModuleResult, error) {
	b.enter <- struct{}{}
	<-b.block
	return ModuleResult{Sandbox: "fake"}, nil
}
func (b *blockingSandbox) Name() string { return "fake" }
func (b *blockingSandbox) IsolationClass() IsolationClass {
	if b.isolation == IsolationUnknown {
		return IsolationVM
	}
	return b.isolation
}
func (b *blockingSandbox) SupportsProjects() bool { return true }

func TestWithAdmissionNoBudgetIsPassthrough(t *testing.T) {
	inner := &blockingSandbox{}
	got, err := WithAdmission(inner, AdmissionConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if got != Sandbox(inner) {
		t.Fatalf("an empty config should return inner unchanged, got %T", got)
	}
}

func TestAdmissionShedsOnConcurrency(t *testing.T) {
	inner := &blockingSandbox{enter: make(chan struct{}), block: make(chan struct{})}
	sb, err := WithAdmission(inner, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = sb.RunJavaScript(context.Background(), Request{}) }()
	<-inner.enter // the first run now holds the only slot

	if _, err := sb.RunJavaScript(context.Background(), Request{}); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("second concurrent run err = %v, want ErrAtCapacity", err)
	}
	close(inner.block) // let the first finish
	wg.Wait()

	// Slot freed: a fresh run is admitted again.
	inner2 := &blockingSandbox{enter: make(chan struct{}, 1), block: make(chan struct{})}
	close(inner2.block)
	sb2, err := WithAdmission(inner2, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sb2.RunJavaScript(context.Background(), Request{}); err != nil {
		t.Fatalf("run after slot freed should succeed, got %v", err)
	}
}

func TestAdmissionShedsOnMemoryBudget(t *testing.T) {
	inner := &blockingSandbox{enter: make(chan struct{}), block: make(chan struct{})}
	// 512 MiB budget, 256 MiB per run -> exactly 2 concurrent, 3rd sheds.
	sb, err := WithAdmission(inner, AdmissionConfig{TotalMemoryMB: 512, PerRunMemoryMB: 256})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _, _ = sb.RunJavaScript(context.Background(), Request{}) }()
		<-inner.enter
	}
	if _, err := sb.RunJavaScript(context.Background(), Request{}); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("third run (over memory budget) err = %v, want ErrAtCapacity", err)
	}
	close(inner.block)
	wg.Wait()
}

func TestAdmissionRejectsImpossibleIsolationBeforeReservingCapacity(t *testing.T) {
	inner := &blockingSandbox{
		enter:     make(chan struct{}, 1),
		block:     make(chan struct{}),
		isolation: IsolationProcess,
	}
	sb, err := WithAdmission(inner, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	for _, run := range []func() error{
		func() error {
			_, err := sb.RunJavaScript(context.Background(), Request{MinimumIsolation: IsolationKernel})
			return err
		},
		func() error {
			_, err := sb.RunProject(context.Background(), ProjectRequest{MinimumIsolation: IsolationVM})
			return err
		},
	} {
		if err := run(); !errors.Is(err, ErrInsufficientIsolation) {
			t.Fatalf("error = %v, want ErrInsufficientIsolation", err)
		}
		select {
		case <-inner.enter:
			t.Fatal("isolation-rejected request reached the provider")
		default:
		}
	}

	// No capacity was consumed by either rejection: a matching request enters.
	done := make(chan struct{})
	go func() {
		_, _ = sb.RunJavaScript(context.Background(), Request{MinimumIsolation: IsolationProcess})
		close(done)
	}()
	<-inner.enter
	close(inner.block)
	<-done
}

func TestWithAdmissionRejectsInvalidSafetyConfig(t *testing.T) {
	inner := &blockingSandbox{}
	for _, cfg := range []AdmissionConfig{
		{TotalMemoryMB: 512},
		{PerRunMemoryMB: 256},
		{TotalMemoryMB: 128, PerRunMemoryMB: 256},
		{MaxConcurrent: -1},
	} {
		if _, err := WithAdmission(inner, cfg); err == nil {
			t.Errorf("WithAdmission(%+v) succeeded, want configuration error", cfg)
		}
	}
}
