package sandbox

import "context"

// Disabled is the default provider: it refuses to run anything. This makes
// "safe" the zero-configuration state — code execution is opt-in via
// SANDBOX_PROVIDER, never on by accident.
type Disabled struct{}

func (Disabled) Name() string { return "disabled" }

// SupportsProjects is false: the provider refuses to run anything.
func (Disabled) SupportsProjects() bool { return false }

func (Disabled) SupportsJavaScriptGrants() bool { return false }
func (Disabled) SupportsProjectGrants() bool    { return false }

// IsolationClass is None: the provider refuses to run code, so there is no
// boundary to speak of.
func (Disabled) IsolationClass() IsolationClass { return IsolationNone }

func (Disabled) RunJavaScript(context.Context, Request) (Result, error) {
	return Result{Sandbox: "disabled", Isolation: IsolationNone}, ErrDisabled
}

func (Disabled) RunProject(context.Context, ProjectRequest) (ProjectResult, error) {
	return ProjectResult{Sandbox: "disabled", Isolation: IsolationNone}, ErrDisabled
}
