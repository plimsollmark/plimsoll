package sandbox

import (
	"fmt"
	"strings"
	"testing"
)

// TestDockerExitDetailNamesTheMemoryLimit chooses a docker session's end explanation from
// every combination of runtime, exit status and a recorded out-of-memory kill: the recorded
// kill is named as certain on every runtime; under runsc alone a 137 with no kill recorded is
// named as probable (docker can miss the kill under gVisor, the outside fact
// docker-oomkilled-under-runsc); everything else is the bare state.
func TestDockerExitDetailNamesTheMemoryLimit(t *testing.T) {
	const memory = "256m"
	for _, runtime := range []string{"", "runc", "runsc"} {
		for _, exitCode := range []int{0, 1, 2, 137, 139, 143} {
			for _, oom := range []bool{false, true} {
				t.Run(fmt.Sprintf("%q/%d/%v", runtime, exitCode, oom), func(t *testing.T) {
					got := dockerExitDetail(runtime, "exited", exitCode, oom, memory)
					recorded := strings.Contains(got, dockerOOMRecorded)
					likely := strings.Contains(got, dockerOOMLikely)
					switch {
					case oom:
						want := "the container is exited: it ran out of memory (the sandbox's limit is 256m)"
						if got != want {
							t.Fatalf("got %q, want %q", got, want)
						}
					case runtime == "runsc" && exitCode == 137:
						if recorded || !likely || !strings.Contains(got, memory) || !strings.Contains(got, "gVisor") ||
							!strings.Contains(got, "any other forced kill also gives 137") {
							t.Fatalf("got %q; want the limit named as probable, not certain, with the reason", got)
						}
						if !strings.HasPrefix(got, "the container is exited") {
							t.Fatalf("got %q; want it to start with the container's state", got)
						}
					default:
						if got != "the container is exited" {
							t.Fatalf("got %q, want the bare state", got)
						}
					}
				})
			}
		}
	}
}

// TestDockerExitDetailIsFromTrustedValuesOnly: the explanation carries docker's state and the
// configured limit and nothing else, so a status string is echoed as docker gave it and the
// exit status is never formatted from the value read back.
func TestDockerExitDetailIsFromTrustedValuesOnly(t *testing.T) {
	got := dockerExitDetail("runsc", "dead", 137, false, "512m")
	want := "the container is dead with status 137, a forced kill: probably by its memory limit (the sandbox's limit is 512m), " +
		"since under gVisor docker can miss a kill by the memory limit; any other forced kill also gives 137"
	if got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}
