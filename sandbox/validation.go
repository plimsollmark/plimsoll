package sandbox

import (
	"errors"
	"fmt"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"
)

var ErrInvalidRequest = errors.New("invalid sandbox request")

const (
	MaxCodeBytes        = 256 << 10
	MaxProjectBytes     = 4 << 20
	MaxProjectFiles     = 200
	MaxProjectSteps     = 20
	MaxProjectArtifacts = 100
	MaxProjectPathBytes = 1024
	MaxProjectStepBytes = 16 << 10
)

func ValidateRequest(req Request) error {
	if err := validateMinimumIsolation(req.MinimumIsolation); err != nil {
		return err
	}
	if req.Code == "" {
		return fmt.Errorf("%w: code is required", ErrInvalidRequest)
	}
	if !utf8.ValidString(req.Code) || strings.ContainsRune(req.Code, '\x00') {
		return fmt.Errorf("%w: code must be valid UTF-8 without NUL bytes", ErrInvalidRequest)
	}
	if len(req.Code) > MaxCodeBytes {
		return fmt.Errorf("%w: code exceeds %d bytes", ErrInvalidRequest, MaxCodeBytes)
	}
	return nil
}

func ValidateProjectRequest(req ProjectRequest) error {
	if err := validateMinimumIsolation(req.MinimumIsolation); err != nil {
		return err
	}
	if len(req.Steps) == 0 {
		return fmt.Errorf("%w: at least one step is required", ErrInvalidRequest)
	}
	if len(req.Steps) > MaxProjectSteps {
		return fmt.Errorf("%w: too many steps (max %d)", ErrInvalidRequest, MaxProjectSteps)
	}
	for i, step := range req.Steps {
		if !utf8.ValidString(step) || strings.ContainsRune(step, '\x00') {
			return fmt.Errorf("%w: step %d must be valid UTF-8 without NUL bytes", ErrInvalidRequest, i)
		}
		if len(step) > MaxProjectStepBytes {
			return fmt.Errorf("%w: step %d exceeds %d bytes", ErrInvalidRequest, i, MaxProjectStepBytes)
		}
	}
	if len(req.Files) > MaxProjectFiles {
		return fmt.Errorf("%w: too many files (max %d)", ErrInvalidRequest, MaxProjectFiles)
	}
	total := 0
	seenFiles := make(map[string]struct{}, len(req.Files))
	for _, file := range req.Files {
		if err := validateProjectPath("file", file.Path); err != nil {
			return err
		}
		if !utf8.ValidString(file.Content) {
			return fmt.Errorf("%w: file %q content must be valid UTF-8", ErrInvalidRequest, file.Path)
		}
		if _, duplicate := seenFiles[file.Path]; duplicate {
			return fmt.Errorf("%w: duplicate file path %q", ErrInvalidRequest, file.Path)
		}
		seenFiles[file.Path] = struct{}{}
		if len(file.Content) > MaxProjectBytes-total {
			return fmt.Errorf("%w: project exceeds %d bytes", ErrInvalidRequest, MaxProjectBytes)
		}
		total += len(file.Content)
	}
	if len(req.Artifacts) > MaxProjectArtifacts {
		return fmt.Errorf("%w: too many artifacts (max %d)", ErrInvalidRequest, MaxProjectArtifacts)
	}
	seenArtifacts := make(map[string]struct{}, len(req.Artifacts))
	for _, artifact := range req.Artifacts {
		if err := validateProjectPath("artifact", artifact); err != nil {
			return err
		}
		if _, duplicate := seenArtifacts[artifact]; duplicate {
			return fmt.Errorf("%w: duplicate artifact path %q", ErrInvalidRequest, artifact)
		}
		seenArtifacts[artifact] = struct{}{}
	}
	return nil
}

func validateMinimumIsolation(minimum IsolationClass) error {
	if minimum == IsolationUnknown {
		return nil
	}
	if minimum < IsolationProcess || minimum > IsolationVM {
		return fmt.Errorf("%w: minimum isolation must be process, container, kernel, or vm", ErrInvalidRequest)
	}
	return nil
}

// CheckMinimumIsolation verifies a validated request-specific isolation floor
// against the provider's current evidence. Call it immediately before admission
// and dispatch so a stale discovery/readiness result can never authorize a run.
func CheckMinimumIsolation(actual, minimum IsolationClass) error {
	if err := validateMinimumIsolation(minimum); err != nil {
		return err
	}
	if minimum == IsolationUnknown {
		return nil
	}
	if !actual.Meets(minimum) {
		return fmt.Errorf("%w: provider isolation %s is below requested minimum %s", ErrInsufficientIsolation, actual, minimum)
	}
	return nil
}

// CheckResultIsolation verifies evidence attached to a completed remote result.
// A failure is deliberately distinct from CheckMinimumIsolation: the backend may
// already have executed code before returning false/weak evidence.
func CheckResultIsolation(actual, minimum IsolationClass) error {
	if err := validateMinimumIsolation(minimum); err != nil {
		return err
	}
	if minimum == IsolationUnknown {
		return nil
	}
	if !actual.Meets(minimum) {
		return fmt.Errorf("%w: result isolation %s is below requested minimum %s; execution may have occurred", ErrIsolationEvidenceMismatch, actual, minimum)
	}
	return nil
}

func validateProjectPath(kind, name string) error {
	if len(name) > MaxProjectPathBytes {
		return fmt.Errorf("%w: %s path exceeds %d bytes", ErrInvalidRequest, kind, MaxProjectPathBytes)
	}
	clean := path.Clean(name)
	if !utf8.ValidString(name) || name == "" || clean != name || clean == "." || strings.HasPrefix(name, "/") || clean == ".." || strings.HasPrefix(clean, "../") || strings.IndexFunc(name, unicode.IsControl) >= 0 || strings.Contains(name, "\\") {
		return fmt.Errorf("%w: unsafe %s path %q", ErrInvalidRequest, kind, name)
	}
	return nil
}
