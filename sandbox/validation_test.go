package sandbox

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestValidateRequest(t *testing.T) {
	if err := ValidateRequest(Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	for _, code := range []string{"", "a\x00b", string([]byte{0xff}), strings.Repeat("x", MaxCodeBytes+1)} {
		if err := ValidateRequest(Request{Code: code}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("code bytes=%d: err=%v, want ErrInvalidRequest", len(code), err)
		}
	}
	for _, minimum := range []IsolationClass{IsolationNone, IsolationClass(99)} {
		if err := ValidateRequest(Request{Code: "1", MinimumIsolation: minimum}); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("minimum isolation %v: err=%v, want ErrInvalidRequest", minimum, err)
		}
	}
}

func TestValidateProjectRequest(t *testing.T) {
	valid := ProjectRequest{
		Files:     []File{{Path: "src/a.js", Content: "1"}},
		Steps:     []string{"node src/a.js"},
		Artifacts: []string{"out/result.json"},
	}
	if err := ValidateProjectRequest(valid); err != nil {
		t.Fatalf("valid project rejected: %v", err)
	}
	invalidMinimum := valid
	invalidMinimum.MinimumIsolation = IsolationNone
	if err := ValidateProjectRequest(invalidMinimum); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("none minimum isolation err=%v, want ErrInvalidRequest", err)
	}
	invalidPaths := []string{"", ".", "./a", "../a", "/a", "a//b", "a\\b", "a\x00b", "a\nb"}
	for _, name := range invalidPaths {
		req := valid
		req.Files = []File{{Path: name}}
		if err := ValidateProjectRequest(req); !errors.Is(err, ErrInvalidRequest) {
			t.Errorf("file path %q: err=%v, want ErrInvalidRequest", name, err)
		}
	}
	tooMany := make([]string, MaxProjectArtifacts+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("a-%d", i)
	}
	req := valid
	req.Artifacts = tooMany
	if err := ValidateProjectRequest(req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized artifact list err=%v, want ErrInvalidRequest", err)
	}
	req = valid
	req.Files = []File{{Path: "a", Content: strings.Repeat("x", MaxProjectBytes+1)}}
	if err := ValidateProjectRequest(req); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized project err=%v, want ErrInvalidRequest", err)
	}
	for _, mutate := range []func(*ProjectRequest){
		func(r *ProjectRequest) { r.Steps = []string{"echo\x00bad"} },
		func(r *ProjectRequest) { r.Steps = []string{string([]byte{0xff})} },
		func(r *ProjectRequest) { r.Files = []File{{Path: "a", Content: string([]byte{0xff})}} },
		func(r *ProjectRequest) { r.Files = []File{{Path: string([]byte{0xff}), Content: "x"}} },
	} {
		req = valid
		mutate(&req)
		if err := ValidateProjectRequest(req); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("invalid UTF-8/NUL project err=%v, want ErrInvalidRequest", err)
		}
	}
}

func TestCheckMinimumIsolation(t *testing.T) {
	if err := CheckMinimumIsolation(IsolationKernel, IsolationContainer); err != nil {
		t.Fatalf("kernel should meet container: %v", err)
	}
	if err := CheckMinimumIsolation(IsolationProcess, IsolationUnknown); err != nil {
		t.Fatalf("unknown means no requested floor: %v", err)
	}
	if err := CheckMinimumIsolation(IsolationContainer, IsolationKernel); !errors.Is(err, ErrInsufficientIsolation) {
		t.Fatalf("container vs kernel err=%v, want ErrInsufficientIsolation", err)
	}
	if err := CheckMinimumIsolation(IsolationUnknown, IsolationProcess); !errors.Is(err, ErrInsufficientIsolation) {
		t.Fatalf("unknown actual err=%v, want ErrInsufficientIsolation", err)
	}
}

func TestCheckResultIsolationUsesPostDispatchSentinel(t *testing.T) {
	err := CheckResultIsolation(IsolationContainer, IsolationKernel)
	if !errors.Is(err, ErrIsolationEvidenceMismatch) {
		t.Fatalf("error = %v, want ErrIsolationEvidenceMismatch", err)
	}
	if errors.Is(err, ErrInsufficientIsolation) {
		t.Fatalf("post-dispatch mismatch was misclassified as safe pre-dispatch rejection: %v", err)
	}
	if err := CheckResultIsolation(IsolationKernel, IsolationKernel); err != nil {
		t.Fatalf("matching evidence: %v", err)
	}
}
