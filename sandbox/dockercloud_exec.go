package sandbox

import (
	"context"
	"encoding/base64"
	"fmt"
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
// (or 124) AND the call took at least the in-guest limit. The elapsed-time half
// cannot be forged by guest code (it would have to actually run that long), so a
// user program that merely exits 137 is not misread as a timeout.
func (d *DockerCloud) execGuarded(ctx context.Context, vm dcVM, argv []string, cwd string) (dcExecOutput, error) {
	limit := remainingBudget(ctx, clampRunTimeout(0, d.DefaultTimeout, d.MaxTimeout)) - dcGuestMargin
	secs := int(limit / time.Second)
	if secs < 1 {
		secs = 1
	}
	return d.execLimited(ctx, vm, argv, cwd, secs)
}

// execLimited is execGuarded with an explicit in-guest limit in whole seconds.
func (d *DockerCloud) execLimited(ctx context.Context, vm dcVM, argv []string, cwd string, secs int) (dcExecOutput, error) {
	max := d.maxOutput()
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
	out.stdout, out.stdoutTruncated = capStream(raw.Stdout, max)
	out.stderr, out.stderrTruncated = capStream(raw.Stderr, max)
	if (out.exitCode == 137 || out.exitCode == 124) && elapsed >= time.Duration(secs)*time.Second {
		out.timedOut, out.exitCode = true, 124
	}
	return out, nil
}

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
