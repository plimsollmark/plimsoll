package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/internal/boundary"
)

// TestDockerSmokeProvesTheGuestGuard runs the real smoke test under the configured runtime
// (runc, or gVisor with SANDBOX_DOCKER_RUNTIME=runsc): it passes, which it does only when the
// guard check (smokeGuestGuard) got the guard's answers in every image; the provider then states
// the guard proven with the word every policy it states ends with: Describe's, and the record of
// a snippet and of a project.
//
// The deletion check for the smoke step: with smokeGuestGuard's call removed from SmokeTest,
// SmokeTest fails here (the guest-guard claim is declared checked, and Proof.Done finds it
// unproved), and GuestGuard states nothing proven.
func TestDockerSmokeProvesTheGuestGuard(t *testing.T) {
	t.Parallel()
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if word, proven := d.GuestGuard(); proven || word != "" {
		t.Fatalf("before any smoke test the guard is stated proven (%q)", word)
	}
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest under runtime %q: %v", d.Runtime, err)
	}
	word, proven := d.GuestGuard()
	if !proven || !strings.HasPrefix(word, GuestGuardPolicyPrefix) || len(word) != len(GuestGuardPolicyPrefix)+64 {
		t.Fatalf("after the smoke test the guard is stated %q, proven %v", word, proven)
	}
	if p := d.Environments().Policy; !strings.HasSuffix(p, " "+word) {
		t.Fatalf("Describe's policy %q does not end with the guest guard's word %q", p, word)
	}
	res, err := d.RunJavaScript(ctx, Request{Code: `console.log("ran")`, Timeout: 20 * time.Second})
	if err != nil || res.ExitCode != 0 || !strings.HasSuffix(res.Policy, " "+word) {
		t.Fatalf("a snippet: exit %d, policy %q, %v; want its policy to end with %q", res.ExitCode, res.Policy, err, word)
	}
	if d.Runtime == "runsc" && res.Policy != seccompPolicySkippedRunsc+" "+word {
		t.Fatalf("under gVisor a snippet's policy is %q, want %q", res.Policy, seccompPolicySkippedRunsc+" "+word)
	}
	proj, err := d.RunProject(ctx, ProjectRequest{Steps: []string{"true"}, Timeout: 20 * time.Second})
	if err != nil || proj.Outcome != ProjectOutcomeCompleted || proj.Policy != res.Policy {
		t.Fatalf("a project: %s, policy %q, %v; want %q, the snippet's", proj.Outcome, proj.Policy, err, res.Policy)
	}
}

// TestDockerSmokeRefusesAProgramWithoutTheGuardsFilter starts the guard check exactly as the smoke
// test does, but behind a stand-in at the guard's path that starts the command without putting
// any filter on it, as a guard whose install did nothing, or a runtime that ignored it, would. The
// check stops at its first request, the self-check (which asks the kernel for nothing it would
// do: unshare with every flag bit set is refused as invalid), so no request that could make a
// namespace is made without the guard; smokeGuestGuard refuses, saying which protection is
// missing, and proves nothing. Then the same call behind the real guard proves both its claims.
//
// The refusing point lets a run mount only the guard file writeGuestGuard writes at the guard's
// path (finding guest-guard-20), so the stand-in is put in that file's place for the unguarded
// call and the real guard put back before the guarded one. That changes a file every docker run
// of this process mounts, so this test does not run in parallel: Go starts the package's parallel
// tests only after its sequential ones have ended.
func TestDockerSmokeRefusesAProgramWithoutTheGuardsFilter(t *testing.T) {
	d := testDocker()
	requireSnippetImage(t, d)
	requireProjectImage(t, d)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	state, err := d.verifiedState()
	if err != nil {
		t.Fatal(err)
	}
	// The stand-in is a shell script; docker reads it through the same read-only bind mount, at
	// the path of the guard file Preflight verified (state.guard), which it replaces for one call.
	guard, err := os.ReadFile(state.guard)
	if err != nil {
		t.Fatal(err)
	}
	put := func(content []byte) {
		t.Helper()
		tmp := state.guard + ".test"
		if err := os.WriteFile(tmp, content, guestGuardFileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(tmp, guestGuardFileMode); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, state.guard); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { put(guard) })
	standIn := []byte("#!/bin/sh\n[ \"$1\" = -- ] && shift\nexec \"$@\"\n")
	for _, image := range []string{state.imageID, state.projectImageID} {
		put(standIn)
		proof := dockerClaims.Start()
		err := d.smokeGuestGuard(ctx, state, image, image == state.projectImageID, proof)
		put(guard)
		if err == nil {
			t.Fatalf("image %s: the guard check passed behind a stand-in that puts no filter on it", shortImageID(image))
		}
		for _, want := range []string{"is not behind the guest guard's filter", "the self-check request did not get the answer only that filter gives", "exit 10"} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("image %s: %v\nwant it to say %q", shortImageID(image), err, want)
			}
		}
		if perr := proof.Done(); perr == nil || !strings.Contains(perr.Error(), string(boundary.GuestGuard)) {
			t.Fatalf("image %s: a refused check left the proof %v; want guest-guard unproved", shortImageID(image), perr)
		}
		guarded := dockerClaims.Start()
		if err := d.smokeGuestGuard(ctx, state, image, image == state.projectImageID, guarded); err != nil {
			t.Fatalf("image %s behind the real guard under runtime %q: %v", shortImageID(image), d.Runtime, err)
		}
		// The two claims the step records are proved; the rest, which other steps prove, are not.
		perr := guarded.Done()
		if perr == nil || strings.Contains(perr.Error(), string(boundary.GuestGuard)+" is declared") || strings.Contains(perr.Error(), string(boundary.WritablePlaces)+" is declared") {
			t.Fatalf("image %s: after the guarded check the proof says %v; want guest-guard and writable-places proved", shortImageID(image), perr)
		}
	}
}
