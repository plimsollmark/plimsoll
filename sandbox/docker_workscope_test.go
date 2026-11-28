package sandbox

import (
	"slices"
	"testing"
)

// TestWorkScopeAnswerReadsTheHelpersKernelRefusal holds smokeRunner's reading of its work scope
// step (review finding session-files-23): exit 0 states the work scope, the helper's refusal of
// a kernel without mount ids or openat2 (exit 1, ENOSYS first on stderr) states the sandbox
// scope alone, and any other answer, the work folder's own mount refused among them, refuses
// startup.
func TestWorkScopeAnswerReadsTheHelpersKernelRefusal(t *testing.T) {
	for _, c := range []struct {
		step    StepResult
		work    bool
		refused bool
	}{
		{StepResult{ExitCode: 0}, true, false},
		{StepResult{ExitCode: 1, Stderr: "ENOSYS: function not implemented, statx 'the work scope needs Linux 5.8 or later, or gVisor: this kernel's statx states no mount id'\n"}, false, false},
		{StepResult{ExitCode: 1, Stderr: "ENOSYS: function not implemented, openat2 'the work scope needs Linux 5.8 or later, or gVisor: this kernel has no openat2'\n"}, false, false},
		{StepResult{ExitCode: 1, Stderr: "EXDEV: invalid cross-device link, statx 'the work folder is not a mount of its own'\n"}, false, true},
		{StepResult{ExitCode: 1, Stderr: "sh: plimsoll-helper: not found\n"}, false, true},
		{StepResult{ExitCode: 86}, false, true},
		{StepResult{ExitCode: 127}, false, true},
	} {
		work, err := workScopeAnswer(c.step)
		if work != c.work || (err != nil) != c.refused {
			t.Errorf("exit %d, stderr %q: work scope %v, error %v; want %v, refused %v", c.step.ExitCode, c.step.Stderr, work, err, c.work, c.refused)
		}
	}
}

// TestDockerSessionsStateTheWorkScopeOnlyOnceTheSmokeTestSawIt: before a SmokeTest has seen
// the work scope answer, and where it saw the kernel refused, the provider, its sessions and
// each payload kind state the sandbox scope alone; once it saw it, both.
func TestDockerSessionsStateTheWorkScopeOnlyOnceTheSmokeTestSawIt(t *testing.T) {
	d := &DockerSandbox{ProjectImage: "p"}
	s := &dockerSession{d: d}
	for _, work := range []bool{false, true} {
		d.stateMu.Lock()
		d.workScope = work
		d.stateMu.Unlock()
		want := FilesScopesSandboxOnly()
		if work {
			want = FilesScopesBoth()
		}
		env := d.SessionEnvironments()
		for name, got := range map[string][]FilesScope{
			"provider project": env.Project.FileScopes, "provider javascript": env.JavaScript.FileScopes,
			"session": s.FileScopes(),
		} {
			if !slices.Equal(got, want) {
				t.Errorf("work scope seen %v: %s states %v, want %v", work, name, got, want)
			}
		}
	}
}
