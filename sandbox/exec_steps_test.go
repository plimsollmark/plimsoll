package sandbox

import (
	"slices"
	"testing"
	"time"
)

// The artifact selection is believed only for whole pairs naming a requested path and
// an absolute real path: a guest that prints into it cannot add a path, and a cut
// answer's last pair is dropped, not read as a shorter path.
func TestSelectedArtifactsKeepsOnlyWholeRequestedPairs(t *testing.T) {
	out := "a.txt\x00/w/a.txt\x00" + "evil\x00/etc/passwd\x00" + "b.txt\x00relative\x00" + "c.txt\x00/w/c"
	got := selectedArtifacts(out, []string{"a.txt", "b.txt", "c.txt"})
	if want := []artifactFile{{path: "a.txt", real: "/w/a.txt"}}; !slices.Equal(got, want) {
		t.Fatalf("selected %+v, want %+v", got, want)
	}
	if got := selectedArtifacts("", []string{"a.txt"}); len(got) != 0 {
		t.Fatalf("an empty answer selected %+v", got)
	}
}

// The artifacts get their whole grace even when what came after the steps (a session's
// grant ending on a slow network update) ran past the run's deadline (review,
// 2026-10-24); before, they got whatever was left of deadline plus grace.
func TestArtifactsGetTheirGraceAfterASlowGrantEnd(t *testing.T) {
	passed := time.Now().Add(-6 * time.Second) // the deadline, six seconds gone
	if got := time.Until(artifactDeadline(passed)); got < projectArtifactGrace-time.Second {
		t.Fatalf("%v left for the artifacts after a slow grant end; want about %v", got, projectArtifactGrace)
	}
	ahead := time.Now().Add(time.Minute)
	if got := artifactDeadline(ahead); !got.Equal(ahead.Add(projectArtifactGrace)) {
		t.Fatalf("a deadline still ahead: %v, want it plus the grace", got)
	}
}
