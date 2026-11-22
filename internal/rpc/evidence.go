package rpc

import (
	"errors"
	"runtime/debug"
	"sync"

	"connectrpc.com/connect"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// qualification is the sentence the provider states beside its tier (sandbox.Qualifier),
// "" when it states none. Every answer and its record state it beside the run's tier, so
// one that record.ValidQualification refuses (over-long, a control character) is refused
// here, before anything runs, marked not dispatched: the answer could not carry it, and a
// tier without the sentence its provider requires would state less than it must.
// plimsolld refuses to start on such a provider (cmd/plimsolld), so this is a backstop.
// So is a provider whose name no record can carry (record.ValidText): every client's record
// check refuses an answer naming it, after the code ran, so it is refused here instead,
// before anything runs. plimsolld's providers have fixed names; an embedder's may not.
func (s *SandboxService) qualification() (string, error) {
	if !record.ValidText(s.Sandbox.Name()) {
		return "", refuse(connect.CodeFailedPrecondition, sandbox.RefusalEnvironment,
			errors.New("the provider's name cannot be stated in a run record (not UTF-8, or a control or bidirectional format character); nothing ran"))
	}
	q, ok := s.Sandbox.(sandbox.Qualifier)
	if !ok {
		return "", nil
	}
	v := q.Qualification()
	if !record.ValidQualification(v) {
		return "", refuse(connect.CodeFailedPrecondition, sandbox.RefusalEnvironment,
			errors.New("the provider's isolation qualification cannot be stated in a run record (over 1024 bytes, not UTF-8, or a control or bidirectional format character); nothing ran"))
	}
	return v, nil
}

// plimsollModule is the module whose version a daemon states.
const plimsollModule = "github.com/plimsollmark/plimsoll"

// daemonVersion is the version every answer and its record state for this daemon
// (RunResponse.daemon_version), read once from the build information.
var daemonVersion = sync.OnceValue(func() string {
	bi, ok := debug.ReadBuildInfo()
	return moduleVersion(bi, ok)
})

// moduleVersion is plimsoll's module version in bi: the main module's when the binary
// is plimsoll's own (plimsolld), else the dependency's, its replacement's when replaced.
// A build that states no version for it (a test binary, a directory replacement, a
// binary whose build information lists no plimsoll module) is "(devel)", stated as such;
// no build information at all, or a version outside record.ValidDaemonVersion, is "" (the
// daemon states none rather than a malformed one).
func moduleVersion(bi *debug.BuildInfo, ok bool) string {
	if !ok || bi == nil {
		return ""
	}
	v, found := "", false
	if bi.Main.Path == plimsollModule {
		v, found = bi.Main.Version, true
	}
	for _, d := range bi.Deps {
		if found {
			break
		}
		if d.Path == plimsollModule {
			v, found = d.Version, true
			if d.Replace != nil {
				v = d.Replace.Version
			}
		}
	}
	switch {
	case !found, v == "":
		return "(devel)"
	case !record.ValidDaemonVersion(v):
		return ""
	}
	return v
}
