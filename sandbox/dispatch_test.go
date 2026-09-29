package sandbox

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
)

func wantRefusal(t *testing.T, name string, err error, want Refusal, sentinel error) {
	t.Helper()
	got, ok := NotDispatchedReason(err)
	if !ok || got != want {
		t.Errorf("%s: NotDispatchedReason(%v) = %v, %v; want %v, true", name, err, got, ok, want)
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("%s: marking hid the sentinel: errors.Is(%v, %v) = false", name, err, sentinel)
	}
}

// Every refusal the sandbox package raises before dispatch carries the mark and
// its reason, and still matches its sentinel.
func TestPreDispatchRefusalsAreMarked(t *testing.T) {
	ctx := context.Background()

	wantRefusal(t, "empty snippet", ValidateRequest(Request{}), RefusalRequest, ErrInvalidRequest)
	wantRefusal(t, "empty project", ValidateProjectRequest(ProjectRequest{}), RefusalRequest, ErrInvalidRequest)
	wantRefusal(t, "empty module", ValidateModuleRequest(ModuleRequest{}), RefusalRequest, ErrInvalidRequest)
	wantRefusal(t, "unparseable floor", CheckMinimumIsolation(IsolationVM, IsolationClass(99)), RefusalRequest, ErrInvalidRequest)
	wantRefusal(t, "floor above evidence", CheckMinimumIsolation(IsolationContainer, IsolationVM), RefusalIsolation, ErrInsufficientIsolation)

	_, err := Disabled{}.RunJavaScript(ctx, Request{Code: "1"})
	wantRefusal(t, "disabled snippet", err, RefusalUnsupported, ErrDisabled)
	_, err = Disabled{}.RunProject(ctx, ProjectRequest{})
	wantRefusal(t, "disabled project", err, RefusalUnsupported, ErrDisabled)
	_, err = Disabled{}.RunModule(ctx, ModuleRequest{})
	wantRefusal(t, "disabled module", err, RefusalUnsupported, ErrDisabled)

	w := &WasmSandbox{}
	_, err = w.RunProject(ctx, ProjectRequest{Steps: []string{"node x.js"}})
	wantRefusal(t, "wasm project", err, RefusalUnsupported, ErrUnsupported)

	d := &DockerSandbox{}
	_, err = d.RunModule(ctx, ModuleRequest{Model: "m", Rows: [][]float64{{1}}, EndTime: 1, Step: 1})
	wantRefusal(t, "docker without module image", err, RefusalUnsupported, ErrUnsupported)
}

func TestAdmissionRefusalsAreMarked(t *testing.T) {
	inner := &blockingSandbox{enter: make(chan struct{}), block: make(chan struct{}), isolation: IsolationContainer}
	sb, err := WithAdmission(inner, AdmissionConfig{MaxConcurrent: 1})
	if err != nil {
		t.Fatal(err)
	}
	_, err = sb.RunJavaScript(context.Background(), Request{MinimumIsolation: IsolationVM})
	wantRefusal(t, "admission floor", err, RefusalIsolation, ErrInsufficientIsolation)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = sb.RunJavaScript(context.Background(), Request{}) }()
	<-inner.enter
	_, err = sb.RunJavaScript(context.Background(), Request{})
	wantRefusal(t, "admission shed", err, RefusalCapacity, ErrAtCapacity)
	close(inner.block)
	wg.Wait()
}

// The mark is opt-in: an error that may follow execution stays unmarked, and so
// does anything refused() does not recognize.
func TestUnmarkedErrorsMayHaveRun(t *testing.T) {
	for name, err := range map[string]error{
		"result evidence":  CheckResultIsolation(IsolationContainer, IsolationVM),
		"infrastructure":   refused(errors.New("docker: connection reset")),
		"wrapped sentinel": fmt.Errorf("%w: worker refused the table", ErrInvalidRequest),
	} {
		if r, ok := NotDispatchedReason(err); ok {
			t.Errorf("%s: %v is marked %v; an error that may follow execution must not be", name, err, r)
		}
	}
	if NotDispatched(RefusalRequest, nil) != nil || refused(nil) != nil {
		t.Fatal("marking nil must stay nil")
	}
	// The mark survives further wrapping by callers.
	wrapped := fmt.Errorf("rpc: %w", ValidateRequest(Request{}))
	wantRefusal(t, "wrapped", wrapped, RefusalRequest, ErrInvalidRequest)
}
