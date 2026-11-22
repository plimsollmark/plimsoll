package sandbox

import (
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

// listingWithProcessOne is a lister's output whose process 1 has the command line argv.
func listingWithProcessOne(t *testing.T, argv []string) []byte {
	t.Helper()
	raw := strings.Join(argv, "\x00") + "\x00"
	b, err := json.Marshal(map[string]any{"ptrace": "1", "procs": []map[string]any{
		{"pid": 1, "ppid": 0, "state": "S", "start": "1", "uid": 1000, "cmd": strings.TrimSpace(strings.Join(argv, " ")), "cmdHex": hex.EncodeToString([]byte(raw))},
		{"pid": 7, "ppid": 1, "state": "S", "start": "2", "uid": 1000, "cmd": "sleep 2147483647", "cmdHex": hex.EncodeToString([]byte("sleep\x002147483647\x00"))},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestProcessOneIs: a session's open keeps its container only when process 1 is the guard in its
// process-1 mode exactly as plimsoll started it (finding guest-guard-10); docker's init, the
// guard in its ordinary mode, a command line that differs in one byte, and a listing without
// process 1 are refused.
func TestProcessOneIs(t *testing.T) {
	t.Parallel()
	main, err := dockerSessionMain("plimsoll-session-main:0123456789abcdef\n")
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{guestGuardTarget, guestGuardPID1, "--"}, main...)
	other, err := dockerSessionMain("plimsoll-session-main:fedcba9876543210\n")
	if err != nil {
		t.Fatal(err)
	}
	if err := processOneIs(listingWithProcessOne(t, want), want); err != nil {
		t.Fatalf("the guard as plimsoll started it: %v", err)
	}
	for what, got := range map[string][]string{
		"docker's init":                  append([]string{"/sbin/docker-init", "--"}, main...),
		"the guard in its ordinary mode": append([]string{guestGuardTarget, "--"}, main...),
		"another marker":                 append([]string{guestGuardTarget, guestGuardPID1, "--"}, other...),
	} {
		if err := processOneIs(listingWithProcessOne(t, got), want); err == nil || !strings.Contains(err.Error(), "not the guest guard as plimsoll started it") {
			t.Errorf("process 1 is %s: %v; want the refusal", what, err)
		}
	}
	if err := processOneIs([]byte(`{"ptrace":"1","procs":[]}`), want); err == nil || !strings.Contains(err.Error(), "no process 1") {
		t.Errorf("a listing without process 1: %v; want the refusal", err)
	}
}

// TestVerifyAtOpenRefusesDockersInit: a session container that docker started with its own init
// (HostConfig.Init true) is refused at open; one without it, as the session's docker run now
// starts it, is not.
func TestVerifyAtOpenRefusesDockersInit(t *testing.T) {
	t.Parallel()
	base := func(init *bool) dockerInspect {
		var i dockerInspect
		i.Image = "sha256:img"
		i.State.Running = true
		i.hostConfig.NetworkMode = "none"
		i.hostConfig.ReadonlyRootfs = true
		i.hostConfig.Init = init
		return i
	}
	yes, no := true, false
	for _, ok := range []*bool{nil, &no} {
		if err := base(ok).verifyAtOpen("sha256:img"); err != nil {
			t.Errorf("Init %v: %v; want no refusal", ok, err)
		}
	}
	if err := base(&yes).verifyAtOpen("sha256:img"); err == nil || !strings.Contains(err.Error(), "docker's init") {
		t.Errorf("Init true: %v; want the refusal naming docker's init", err)
	}
}
