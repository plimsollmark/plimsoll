package server

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/plimsollmark/plimsoll/client"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A server installed with a grant (Config.GrantProfile and GrantDescription) gives
// run_code without a sandbox the one web API the operator's profile allows: every such
// call carries the profile, and its code calls the API's routes through plimsoll's
// broker outside the sandbox, which holds and adds the credential. A call in a sandbox
// from open_sandbox never carries it (a session's interpreter outlives the call, and
// its code with it, so the daemon gives a cell no grant), and run_code's description
// says so. The profile is the installer's; no tool argument names one.

const (
	// MaxGrantDescriptionChars bounds the API's description: run_code's description,
	// which every tool list carries, holds it (about 8,000 tokens).
	MaxGrantDescriptionChars = 32_000
	maxGrantProfileBytes     = 128
)

// grantPlan is what the daemon's Describe said the grant can do, read once in New.
type grantPlan struct {
	profile, description, provider string
	// languages are those whose code can call the API on the daemon: JavaScript wherever
	// a granted project or snippet runs, Python too where every project step gets the
	// broker's socket (sandbox.PythonGrantProviders).
	languages []sandbox.Language
	// snippets: the daemon runs snippets only (wasm), so a granted call is a snippet.
	snippets bool
}

// planGrant reads the daemon's Describe for a grant, and refuses one it cannot carry.
func planGrant(info client.Info, profile, description string) (*grantPlan, error) {
	p := &grantPlan{profile: profile, description: description, provider: info.Sandbox}
	switch {
	case !info.SupportsProject && info.SupportsJavaScriptGrants:
		p.languages, p.snippets = []sandbox.Language{sandbox.LanguageJavaScript}, true
	case !info.SupportsProject:
		return nil, fmt.Errorf("the daemon's provider (%s) runs no projects and grants no snippet, so no run_code call can carry grant profile %q", info.Sandbox, profile)
	case !info.SupportsProjectGrants:
		return nil, fmt.Errorf("the daemon's provider (%s) cannot give a project run a grant, so no run_code call can carry grant profile %q", info.Sandbox, profile)
	default:
		for _, l := range []sandbox.Language{sandbox.LanguageJavaScript, sandbox.LanguagePython} {
			if slices.Contains(info.Environments.Project.Languages, l) && (l != sandbox.LanguagePython || sandbox.PythonCarriesGrant(info.Sandbox)) {
				p.languages = append(p.languages, l)
			}
		}
		if len(p.languages) == 0 {
			return nil, fmt.Errorf("no language of the daemon's project image (provider %s) can call the API from a granted run", info.Sandbox)
		}
	}
	return p, nil
}

// refusal is why code in l cannot call the API on this daemon, and what to write instead.
func (p *grantPlan) refusal(l sandbox.Language) string {
	var others []string
	for _, o := range p.languages {
		others = append(others, languageName(o))
	}
	why := fmt.Sprintf("its provider (%s) gives a Python step no way to reach plimsoll's broker", p.provider)
	switch {
	case l == sandbox.LanguagePython && p.snippets:
		why = fmt.Sprintf("the daemon (provider %s) runs JavaScript snippets only", p.provider)
	case l != sandbox.LanguagePython:
		why = fmt.Sprintf("the daemon's project image (provider %s) states no %s interpreter", p.provider, languageName(l))
	}
	return fmt.Sprintf("%s code cannot call the API without a sandbox here: %s. Write the program in %s, or run it in a sandbox from open_sandbox, which cannot call the API", languageName(l), why, strings.Join(others, " or "))
}

func languageName(l sandbox.Language) string {
	if l == sandbox.LanguagePython {
		return "Python"
	}
	return "JavaScript"
}

// apiText is what run_code tells the model about the API: in the Python and TypeScript
// kits' words (plimsoll_client._code_tool.api_text), for the languages this server
// offers, then the API's description as the installer gave it.
func (p *grantPlan) apiText(offered []sandbox.Language) string {
	lines := []string{
		"Without sandbox, this tool's code can call one web API, described below, from inside the sandbox. Only its routes listed below " +
			"(each a method and a path) are sent to it: any other request is refused before it leaves, and so is a call " +
			"past the run's call budget (status 429). plimsoll adds the API's key outside the sandbox; the code never needs " +
			"one. A call that changes data takes effect even if the program fails afterwards, and a run is never retried. " +
			"Code run in a sandbox from open_sandbox cannot call the API: kept state is not available to a call that can.",
	}
	if slices.Contains(offered, sandbox.LanguageJavaScript) && slices.Contains(p.languages, sandbox.LanguageJavaScript) {
		// In a granted project's cell form top-level await works; in the snippet form of a
		// daemon that runs snippets only (sandbox.SnippetCell, evaluated as a script) it
		// does not, and a final promise is printed once it settles.
		js := "In JavaScript, call it through the global client the description names, as it shows; each call returns a promise, so await it."
		if p.snippets {
			js = "In JavaScript, call it through the global client the description names, as it shows; each call returns a promise. " +
				"Top-level await does not work in this sandbox: put the calls in an async function and end the code with its call, " +
				"(async () => { ... return value; })(), whose value is printed once it settles."
		}
		lines = append(lines, js)
	}
	if slices.Contains(offered, sandbox.LanguagePython) {
		if slices.Contains(p.languages, sandbox.LanguagePython) {
			lines = append(lines, "In Python, import plimsoll_host and call plimsoll_host.get(path), post(path, body), put(path, body), "+
				"patch(path, body), delete(path) or call(method, path, body) with a route's method and path from the "+
				"list below; each returns the answer's parsed JSON and raises plimsoll_host.HostAPIError, which has "+
				".status and .body, for any other status.")
		} else {
			lines = append(lines, fmt.Sprintf("Python code cannot call the API on this daemon (its provider, %s, gives a Python step no way to reach it); run Python without the API in a sandbox from open_sandbox.", p.provider))
		}
	}
	return strings.Join(append(lines, "The API:\n"+p.description), "\n")
}

// runGranted runs one run_code call without a sandbox, carrying the grant: the fresh
// cell's form in a granted project (sandbox.GrantedCellProject: the final expression's
// value printed, and for Python the plimsoll_host module), or on a daemon that runs
// snippets only a granted snippet. Its ends are read as a cell run by itself reads them
// (sandbox.RunCellFresh).
func (s *Server) runGranted(ctx context.Context, lang sandbox.Language, code string, files []sandbox.File) (runOutput, *failure) {
	p := s.plan
	// An omitted language is the server's first, as run_code's schema says, never another
	// one the code may not be written in; on a daemon that runs snippets only it is
	// JavaScript, as for a call without a grant (runFresh).
	if lang == "" {
		lang = s.cfg.Languages[0]
		if p.snippets && slices.Contains(s.cfg.Languages, sandbox.LanguageJavaScript) {
			lang = sandbox.LanguageJavaScript
		}
	}
	if !slices.Contains(p.languages, lang) {
		return runOutput{}, refused(sandbox.RefusalUnsupported, "%s", p.refusal(lang))
	}
	if p.snippets {
		if len(files) > 0 {
			return runOutput{}, refused(sandbox.RefusalUnsupported, "the daemon (%s) runs JavaScript snippets only, without files", clipRunes(p.provider, 100))
		}
		r, err := s.clientsFor(s.shareOfCall(ctx)).granted.RunJavaScript(ctx, sandbox.Request{Code: sandbox.SnippetCell(code), Timeout: s.cfg.RunTimeout, MinimumIsolation: s.cfg.MinimumIsolation, Software: s.cfg.Software})
		if !answered(err, r.Record) {
			return runOutput{}, s.grantFailed(ctx, err)
		}
		exit := r.ExitCode
		if r.TimedOut {
			exit = 124
		}
		out := s.output(ctx, lang, exit, r.TimedOut, r.Stdout, r.Stderr, r.StdoutTruncated || r.StderrTruncated, r.Isolation, r.SoftwareIdentity, r.Record)
		out.Receipt = s.receiptFor(r.Record, err)
		out.granted = true
		summarize(&out, "")
		return out, nil
	}
	all, step := sandbox.GrantedCellProject(sandbox.CellRequest{Language: lang, Code: code, Files: files})
	r, err := s.clientsFor(s.shareOfCall(ctx)).granted.RunProject(ctx, sandbox.ProjectRequest{Files: all, Steps: []string{step}, Timeout: s.cfg.RunTimeout, MinimumIsolation: s.cfg.MinimumIsolation, Software: s.cfg.Software})
	if !answered(err, r.Record) {
		return runOutput{}, s.grantFailed(ctx, err)
	}
	var exit int
	var timedOut, cut bool
	var stdout, stderr string
	switch {
	case len(r.Steps) > 0:
		st := r.Steps[0]
		exit, timedOut, stdout, stderr, cut = st.ExitCode, st.TimedOut || r.Outcome == sandbox.ProjectOutcomeTimedOut, st.Stdout, st.Stderr, st.StdoutTruncated || st.StderrTruncated
	case r.Outcome == sandbox.ProjectOutcomeTimedOut:
		timedOut = true
	case r.Outcome == sandbox.ProjectOutcomeSetupFailed:
		s.keep(ctx, r.Record)
		return runOutput{}, refused(sandbox.RefusalRequest, "the call's files could not be set up, so none of its code ran: %s", clipRunes(r.Detail, 300))
	default:
		s.keep(ctx, r.Record)
		f := s.grantFailed(ctx, fmt.Errorf("the run ended %s without a step report (%s); the code may have run", r.Outcome, clipRunes(r.Detail, 300)))
		f.RecordSHA256 = r.Record.SHA256
		return runOutput{}, f
	}
	if timedOut {
		exit = 124
	}
	out := s.output(ctx, lang, exit, timedOut, stdout, stderr, cut, r.Isolation, r.SoftwareIdentity, r.Record)
	out.Receipt = s.receiptFor(r.Record, err)
	out.granted = true
	summarize(&out, "")
	return out, nil
}

// grantFailed is failed for a granted call, with what a granted call adds: a permission
// refusal is the operator's to fix, and a call that may have run may have called the API.
func (s *Server) grantFailed(ctx context.Context, err error) *failure {
	// A refusal that says the daemon changed makes the next Describe read afresh, as after
	// a fresh run's (runFresh); a granted run reads its plan, not Describe, but open_sandbox
	// and a fresh call read Describe (hunt-quality-49, 2026-11-20).
	s.forgetDescribeOn(err)
	f := s.failed(ctx, err)
	switch {
	case f.Ran == "no" && f.Refusal == sandbox.RefusalPermission.String():
		f.Summary += " " + grantPermissionNote
	case f.Ran == "maybe":
		f.Summary += " It may have called the API too, as many times as the run's call budget allows."
	}
	return f
}

const grantPermissionNote = "The API this server is set up to call is not available to it, so nothing ran: the grant profile is unknown to the daemon, or this server's caller is not on it. That is the operator's to fix; do not retry, and tell the user the API could not be reached."

// describeGrant reads the daemon's Describe for New, bounded by the call timeout, and
// plans the grant: a server whose grant the daemon cannot carry does not start, since
// the tool list it would serve could not say what run_code can call.
func describeGrant(remote *client.Remote, cfg Config) (*grantPlan, error) {
	ctx, cancel := context.WithTimeout(context.Background(), cfg.CallTimeout)
	defer cancel()
	info, err := remote.Describe(ctx)
	if err != nil {
		return nil, fmt.Errorf("grant profile %q: the daemon's Describe, which decides what run_code can call: %w", cfg.GrantProfile, err)
	}
	p, err := planGrant(info, cfg.GrantProfile, cfg.GrantDescription)
	if err != nil {
		return nil, errors.New("PLIMSOLL_GRANT_PROFILE: " + err.Error())
	}
	return p, nil
}
