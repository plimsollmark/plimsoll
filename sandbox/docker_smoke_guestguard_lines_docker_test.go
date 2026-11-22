package sandbox

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/boundary"
	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

// putGuardFile puts content in the place of the guard file at path for the calls that follow,
// as TestDockerSmokeRefusesAProgramWithoutTheGuardsFilter does: the refusing point lets a run
// mount only that file at the guard's path.
func putGuardFile(t *testing.T, path string, content []byte) {
	t.Helper()
	tmp := path + ".test"
	if err := os.WriteFile(tmp, content, guestGuardFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(tmp, guestGuardFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// TestDockerSmokeRequiresProcess1BehindTheGuardUnderGVisor (finding guest-guard-18): the guard
// check also reads process 1's Seccomp line and the guest program's, and under gVisor refuses
// to serve unless both read 2. The stand-in at the guard's path stays process 1 without any
// filter and starts the command from a child that puts the guard's own filter on itself first,
// so the guest-started check gets every answer the guard's filter gives and only process 1's
// Seccomp line tells the two apart: under gVisor it reads 0, and smokeGuestGuard refuses and
// proves nothing; under runc the host profile makes it 2 whatever runs, so the lines are not
// required there and the check passes. A second stand-in leaves process 1 without a filter in a
// session's shape only (finding guest-guard-10): under gVisor the check's run in that shape
// refuses. Then the real guard passes under both runtimes.
//
// It changes the guard file every docker run of this process mounts, so it does not run in
// parallel, as TestDockerSmokeRefusesAProgramWithoutTheGuardsFilter does not.
func TestDockerSmokeRequiresProcess1BehindTheGuardUnderGVisor(t *testing.T) {
	d := testDocker()
	d.ProjectImage = pythonProjectImage
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	if _, err := guestguard.Program(runtime.GOARCH); err != nil {
		t.Skipf("%v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	state, err := d.verifiedState()
	if err != nil {
		t.Fatal(err)
	}
	filter, err := guestguard.Filter(runtime.GOARCH, "")
	if err != nil {
		t.Fatal(err)
	}
	guard, err := os.ReadFile(state.guard)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { putGuardFile(t, state.guard, guard) })
	// The child sets no_new_privs and installs the filter as the guard does (prctl), then
	// becomes the command; the shell, process 1, waits for it and exits with its status. It
	// takes the guard's process-1 word too, which the check's run in a session's shape passes.
	child := fmt.Sprintf(`import ctypes, os, sys
libc = ctypes.CDLL(None, use_errno=True)
f = bytes.fromhex("%s")
class P(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]
b = ctypes.create_string_buffer(f, len(f))
p = P(len(f) // 8, ctypes.cast(b, ctypes.c_void_p))
u = ctypes.c_ulong
if libc.prctl(ctypes.c_int(38), u(1), u(0), u(0), u(0)) or libc.prctl(ctypes.c_int(22), u(2), ctypes.byref(p), u(0), u(0)):
    sys.exit(122)
os.execv(sys.argv[1], sys.argv[1:])
`, hex.EncodeToString(filter))
	python := "/usr/bin/python3 -I -c '" + child + "' \"$@\""
	image := state.projectImageID
	for _, c := range []struct {
		what, standIn, want string
	}{
		// Process 1 without a filter in both of the check's shapes: the ordinary run's fails.
		{"process 1 unfiltered", "#!/bin/sh\n[ \"$1\" = " + guestGuardPID1 + " ] && shift\n[ \"$1\" = -- ] && shift\n" + python + "\n", `the Seccomp line of process 1 reads "0", not 2`},
		// Finding guest-guard-10 (decision 10 B): in the ordinary shape the stand-in becomes the
		// filtered program, as the guard does, so that run passes everywhere; only in a session's
		// shape does process 1 stay without a filter, as docker's --init did. Only the check's run in
		// a session's shape tells them apart, under gVisor.
		{"process 1 unfiltered in a session's shape only", "#!/bin/sh\nif [ \"$1\" = " + guestGuardPID1 + " ]; then shift; shift; " + python + "; exit $?; fi\nshift\nexec " + python + "\n", `in a session's shape (the guest guard as process 1): under gVisor the Seccomp line of process 1 reads "0", not 2`},
	} {
		putGuardFile(t, state.guard, []byte(c.standIn))
		proof := dockerClaims.Start()
		err = d.smokeGuestGuard(ctx, state, image, true, proof)
		putGuardFile(t, state.guard, guard)
		t.Logf("behind the stand-in with %s under %q: %v", c.what, d.Runtime, err)
		if d.Runtime == "runsc" {
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("under gVisor, %s: %v; want the refusal naming process 1's Seccomp line (%s)", c.what, err, c.want)
			}
			if perr := proof.Done(); perr == nil || !strings.Contains(perr.Error(), string(boundary.GuestGuard)) {
				t.Fatalf("%s: a refused check left the proof %v; want guest-guard unproved", c.what, perr)
			}
		} else if err != nil {
			t.Fatalf("under runc, where the lines are not required, %s: %v", c.what, err)
		}
	}
	if err := d.smokeGuestGuard(ctx, state, image, true, dockerClaims.Start()); err != nil {
		t.Fatalf("behind the real guard under %q: %v", d.Runtime, err)
	}
}

// TestDockerSmokeChecksTheGuardUnderTheSDKVariant (finding guest-guard-26): smokeGuestGuard also
// runs its check under the seccomp profile variant a run whose grant sets sdk_env gets, when one
// is configured and the runtime applies it. An operator's variant that ends a process for
// unshare, instead of refusing it, ends the guard at its self-check, so every granted run would
// fail; under runc the startup check refuses with it, naming the variant, and proves nothing.
// Under gVisor no host profile applies to any run, so the same variant changes nothing and the
// check passes. The derived variant passes under both.
func TestDockerSmokeChecksTheGuardUnderTheSDKVariant(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	shippedSeccomp(t, d)
	var variant map[string]any
	if err := json.Unmarshal(derivedSeccompBytes(t), &variant); err != nil {
		t.Fatal(err)
	}
	variant["syscalls"] = append(variant["syscalls"].([]any), map[string]any{"names": []any{"unshare"}, "action": "SCMP_ACT_KILL_PROCESS"})
	raw, err := json.Marshal(variant)
	if err != nil {
		t.Fatal(err)
	}
	killing := filepath.Join(t.TempDir(), "sdk-kills-unshare.json")
	if err := os.WriteFile(killing, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	for _, sdk := range []string{killing, SeccompSDKDerived} {
		d.SeccompSDK = sdk
		if err := d.Preflight(ctx); err != nil {
			t.Fatalf("Preflight with the variant %s: %v", sdk, err)
		}
		state, err := d.verifiedState()
		if err != nil {
			t.Fatal(err)
		}
		if n := len(state.guestGuardProfiles()); (d.Runtime == "runsc") != (n == 1) {
			t.Fatalf("under %q the check runs under %d profiles; want 1 under gVisor and 2 under runc", d.Runtime, n)
		}
		for _, image := range []string{state.imageID, state.projectImageID} {
			proof := dockerClaims.Start()
			err := d.smokeGuestGuard(ctx, state, image, image == state.projectImageID, proof)
			if sdk == killing && d.Runtime != "runsc" {
				if err == nil || !strings.Contains(err.Error(), "under the seccomp profile variant a run whose grant sets sdk_env gets") {
					t.Fatalf("image %s, a variant that kills unshare, under runc: %v; want the check refused under the variant", shortImageID(image), err)
				}
				if perr := proof.Done(); perr == nil || !strings.Contains(perr.Error(), string(boundary.GuestGuard)) {
					t.Fatalf("image %s: a refused check left the proof %v; want guest-guard unproved", shortImageID(image), perr)
				}
				t.Logf("image %s, the variant that kills unshare, under runc: %v", shortImageID(image), err)
				continue
			}
			if err != nil {
				t.Fatalf("image %s, variant %s, runtime %q: %v", shortImageID(image), filepath.Base(sdk), d.Runtime, err)
			}
		}
	}
}
