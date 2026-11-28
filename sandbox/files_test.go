package sandbox

import (
	"context"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// SessionFiles asks for the sweep after an answered call exactly when the call can add to the
// sandbox's disk, a write or a make_dir (review finding session-files-17: the sweep is what
// holds a session of file calls alone to its disk budget), and never after an answered read,
// stat, listing, readmany, removal or rename, whose helper has exited and left nothing. A call
// the helper did not answer is swept whatever its operation.
func TestSessionFilesSweepsAfterWhatCanGrowTheDisk(t *testing.T) {
	t.Parallel()
	grows := map[FilesOp]bool{FilesWrite: true, FilesMakeDir: true}
	for _, op := range []FilesOp{FilesStat, FilesRead, FilesWrite, FilesList, FilesReadMany, FilesMakeDir, FilesRemove, FilesRename} {
		req := FilesRequest{FilesCall: FilesCall{Scope: FilesScopeWork, Op: op, Path: []byte("a")}}
		for _, c := range []struct {
			name      string
			res       sessionkit.ExecResult
			wantSweep bool
		}{
			// 81, not found: an error of the contract, so the helper answered.
			{"answered", sessionkit.ExecResult{Exited: true, ExitCode: 81}, grows[op]},
			// 92: a write's outcome unknown, read as no answer.
			{"no answer", sessionkit.ExecResult{Exited: true, ExitCode: sessionkit.HelperExitUnknown}, true},
			{"unreadable", sessionkit.ExecResult{Exited: true, ExitCode: sessionkit.HelperExitMalformed}, true},
		} {
			exec := func(context.Context, []string, []byte, int, int) (sessionkit.ExecResult, error) { return c.res, nil }
			ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			_, sweep, err := SessionFiles(ctx, req, FilesResult{}, exec,
				func() error { return nil }, func() error { return nil }, func(err error) error { return err })
			cancel()
			if err != nil {
				t.Fatalf("%s %s: %v", op, c.name, err)
			}
			if sweep != c.wantSweep {
				t.Errorf("%s %s: sweep %t, want %t", op, c.name, sweep, c.wantSweep)
			}
		}
	}
}
