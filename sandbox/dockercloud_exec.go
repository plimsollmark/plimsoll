package sandbox

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- guest execution ----

type dcExecOutput struct {
	stdout          string
	stderr          string
	stdoutTruncated bool
	stderrTruncated bool
	exitCode        int
	timedOut        bool
}

// execGuarded runs argv under dcExecWrapper with an in-guest time limit derived
// from the remaining run budget.
//
// A step is reported as timed out when the in-guest `timeout` killed it: exit 137
// (or 124) AND the command ran at least the in-guest limit, as the wrapper measured it
// inside the VM (dcTrailer). Guest code cannot change that measurement (it is the
// wrapper's own, written after anything the guest can write) or shorten its run, so a
// user program that merely exits 137 is not misread as a timeout, and neither is one
// whose answer was slow to arrive. When the trailer states no time (a guest with no
// readable /proc/uptime), the elapsed time around the call stands in, as it did
// before. The trailer itself is always there: the wrapper writes it last whatever the
// guest wrote, so a guest line in its shape is never read as it.
func (d *DockerCloud) execGuarded(ctx context.Context, vm dcVM, argv []string, cwd string) (dcExecOutput, error) {
	return d.execGuardedCap(ctx, vm, argv, cwd, d.maxOutput())
}

// execGuardedCap is execGuarded keeping max bytes of each stream: a project step keeps
// ProjectStepOutputCap, as on every provider.
func (d *DockerCloud) execGuardedCap(ctx context.Context, vm dcVM, argv []string, cwd string, max int) (dcExecOutput, error) {
	limit := remainingBudget(ctx, clampRunTimeout(0, d.DefaultTimeout, d.MaxTimeout)) - dcGuestMargin
	secs := int(limit / time.Second)
	if secs < 1 {
		secs = 1
	}
	return d.execLimited(ctx, vm, argv, cwd, secs, max)
}

// execLimited is execGuarded with an explicit in-guest limit in whole seconds and max
// bytes kept of each stream.
func (d *DockerCloud) execLimited(ctx context.Context, vm dcVM, argv []string, cwd string, secs, max int) (dcExecOutput, error) {
	cmd := append([]string{"sh", "-c", dcExecWrapper, "plimsoll-exec", strconv.Itoa(secs), strconv.Itoa(max + 1)}, argv...)
	start := time.Now()
	raw, flooded, err := d.wire().exec(ctx, vm, cmd, cwd, dcExecResponseLimit(max+1))
	elapsed := time.Since(start)
	if err != nil {
		return dcExecOutput{}, err
	}
	if flooded {
		// The response outgrew what the in-guest caps allow, which only guest code
		// working around them can cause: a failed user run, never infrastructure.
		return dcExecOutput{stdoutTruncated: true, stderrTruncated: true, exitCode: exitOutputFlooded}, nil
	}
	out := dcExecOutput{exitCode: int(raw.ExitCode)}
	stderr, ran, measured, streamFlooded := splitDCTrailer(raw.Stderr)
	if !measured {
		ran = elapsed
	}
	out.stdout, out.stdoutTruncated = capStream(raw.Stdout, max)
	out.stderr, out.stderrTruncated = capStream(stderr, max)
	if streamFlooded {
		// A stream passed the transfer budget and stopped being read: a flood, as the
		// runner and E2B report it, whatever the command's own exit.
		out.stdoutTruncated, out.stderrTruncated, out.exitCode = true, true, exitOutputFlooded
		return out, nil
	}
	// /proc/uptime counts in centiseconds, so the limit is met within one of them.
	if (out.exitCode == 137 || out.exitCode == 124) && ran >= time.Duration(secs)*time.Second-10*time.Millisecond {
		out.timedOut, out.exitCode = true, 124
	}
	return out, nil
}

// splitDCTrailer separates the wrapper's trailer from the guest's stderr and returns the
// time the command ran inside the VM. measured is false when the stream does not end with
// the trailer (a wrapper that never ran: the stream is returned whole), or when the
// trailer states no time ("-": the guest could not read /proc/uptime; the trailer is
// still stripped and its flood flag read).
func splitDCTrailer(b []byte) (stderr []byte, ran time.Duration, measured, flooded bool) {
	m := dcTrailerForm.FindSubmatchIndex(b)
	if m == nil {
		return b, 0, false, false
	}
	flooded = b[m[4]] == '1'
	field := string(b[m[2]:m[3]])
	if field == "-" {
		return b[:m[0]], 0, false, flooded
	}
	cs, err := strconv.ParseInt(field, 10, 64)
	if err != nil {
		return b[:m[0]], 0, false, flooded
	}
	return b[:m[0]], time.Duration(cs) * 10 * time.Millisecond, true, flooded
}

var dcTrailerForm = regexp.MustCompile("\\n" + dcTrailer + " (-?[0-9]{1,15}|-) ([01])\\n$")

func capStream(b []byte, max int) (string, bool) {
	if len(b) > max {
		return string(b[:max]), true
	}
	return string(b), false
}

// dcExecResponseLimit is the largest Exec response the wrapper's caps allow: both
// streams base64-encoded in JSON, plus room for the envelope.
func dcExecResponseLimit(perStream int) int64 {
	return 2*int64(base64.StdEncoding.EncodedLen(perStream)) + 64<<10
}

// mkdirs creates the project directories with one `mkdir -p` in the guest.
// Assumption (live probe): FileService.Upload does not create parent directories,
// so they are created explicitly rather than relied on.
func (d *DockerCloud) mkdirs(ctx context.Context, vm dcVM, dirs map[string]struct{}) error {
	list := make([]string, 0, len(dirs))
	for dir := range dirs {
		list = append(list, dir)
	}
	sort.Strings(list)
	out, flooded, err := d.wire().exec(ctx, vm, append([]string{"mkdir", "-p", "--"}, list...), "", dcExecResponseLimit(4<<10))
	if err != nil {
		return err
	}
	if flooded || out.ExitCode != 0 {
		return fmt.Errorf("mkdir exited %d: %s", out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}
