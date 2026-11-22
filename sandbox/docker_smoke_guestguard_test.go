package sandbox

import (
	"strings"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

// TestSDKVariantMatchesSeccompFor holds sdkVariant, the profile smokeGuestGuard checks beside the
// default (finding guest-guard-26), to seccompFor, the profile a run gets: for every runtime and
// configuration, sdkVariant names the profile a run whose grant sets sdk_env gets exactly when it
// is another than an ordinary run's, and "" otherwise.
func TestSDKVariantMatchesSeccompFor(t *testing.T) {
	sdk := &HostAPIGrant{SDKEnv: map[string]string{"PLIMSOLL_TEST": "1"}}
	for _, s := range []dockerSeccomp{
		{defaultPath: "/p/default.json", defaultID: "d", sdkPath: "/p/sdk.json", sdkID: "s"},
		{defaultPath: "/p/default.json", defaultID: "d"},
		{defaultPath: "", defaultID: seccompPolicyDockerDefault},
		{defaultPath: "unconfined", defaultID: seccompPolicyUnconfined},
	} {
		for _, rt := range []string{"", "runc", "runsc"} {
			plain, _, err := s.seccompFor(nil, rt)
			if err != nil {
				t.Fatal(err)
			}
			want := ""
			if granted, _, err := s.seccompFor(sdk, rt); err == nil && granted != plain {
				want = granted
			}
			if got := s.sdkVariant(rt); got != want {
				t.Errorf("%+v under %q: sdkVariant %q, want %q (seccompFor's)", s, rt, got, want)
			}
		}
	}
	st := dockerExecutionState{runtime: "runc", seccomp: dockerSeccomp{defaultPath: "/p/default.json", sdkPath: "/p/sdk.json"}}
	if p := st.guestGuardProfiles(); len(p) != 2 || p[0].path != "/p/default.json" || p[0].what != "" || p[1].path != "/p/sdk.json" || !strings.Contains(p[1].what, "sdk_env") {
		t.Errorf("profiles under runc with a variant: %+v; want the default, then the variant", p)
	}
	st.runtime = "runsc"
	if p := st.guestGuardProfiles(); len(p) != 1 {
		t.Errorf("profiles under runsc: %+v; want the default alone, since gVisor applies no host profile", p)
	}
}

// TestCheckSmokeSeccomp: the guard check's Seccomp lines (finding guest-guard-18), as
// smokeSeccompScript writes them, are split from the check's own line, and under gVisor both
// must read 2; under runc they are not required.
func TestCheckSmokeSeccomp(t *testing.T) {
	lines, out := smokeSeccompLines("plimsoll seccomp 1 2\nplimsoll seccomp guest 2\n" + guestguard.CheckOK)
	if out != guestguard.CheckOK || lines["1"] != "2" || lines["guest"] != "2" {
		t.Fatalf("split %v and %q", lines, out)
	}
	if err := checkSmokeSeccomp("runsc", lines); err != nil {
		t.Fatalf("both lines 2 under gVisor: %v", err)
	}
	for _, c := range []struct{ stdout, want string }{
		{"plimsoll seccomp 1 0\nplimsoll seccomp guest 2\n", `process 1 reads "0"`},
		{"plimsoll seccomp 1 2\nplimsoll seccomp guest 0\n", `the guest's program reads "0"`},
		{"plimsoll seccomp 1 none\nplimsoll seccomp guest 2\n", `process 1 reads "none"`},
		{"plimsoll seccomp guest 2\n", "did not read the Seccomp line of process 1"},
		{"", "did not read the Seccomp line of process 1"},
		{"plimsoll seccomp 1 2\nplimsoll seccomp 1 2\n", "did not read the Seccomp line of the guest's program"},
	} {
		lines, out := smokeSeccompLines(c.stdout + guestguard.CheckOK)
		if !strings.HasSuffix(out, guestguard.CheckOK) {
			t.Errorf("%q: the check's line was not left whole: %q", c.stdout, out)
		}
		if err := checkSmokeSeccomp("runsc", lines); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%q under gVisor: %v; want a refusal saying %q", c.stdout, err, c.want)
		}
		if err := checkSmokeSeccomp("runc", lines); err != nil {
			t.Errorf("%q under runc: %v; the lines are not required there", c.stdout, err)
		}
	}
}
