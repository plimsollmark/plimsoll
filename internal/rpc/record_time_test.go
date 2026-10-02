package rpc

import (
	"testing"
	"time"
)

// A record's end is its start plus the elapsed time, so it never lands before the
// start, whatever the wall clock did during the run. Go's time API cannot step the
// wall clock under a monotonic reading, so the test hands recordEnd an end with no
// monotonic reading whose wall time is a second early: the clock-stepped case at its
// worst. With monotonic readings on both, as the daemon has, the difference is
// monotonic and cannot be negative.
func TestRecordEndNeverPrecedesTheStart(t *testing.T) {
	started := time.Now()
	stepped := started.Add(-time.Second).Round(0) // wall clock stepped back, no monotonic reading
	if got := recordEnd(started, stepped); got.UnixMilli() < started.UnixMilli() {
		t.Fatalf("a stepped clock put the end %v before the start %v", got, started)
	}
	later := started.Add(1500 * time.Millisecond)
	if got := recordEnd(started, later); got.Sub(started) != 1500*time.Millisecond {
		t.Fatalf("the end is %v after the start, want 1.5s", got.Sub(started))
	}
}
