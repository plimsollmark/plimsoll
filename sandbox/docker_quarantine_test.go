package sandbox

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// A run's container whose removal cannot be confirmed keeps the capacity admitted for
// its call until a retry confirms it gone, so the concurrency and memory limits still
// bound it (review, 2026-10-23). An unpinned daemon endpoint is a
// removal that can never be confirmed, and needs no daemon.
func TestDockerTeardownHoldsCapacityUntilRemovalIsConfirmed(t *testing.T) {
	d := &DockerSandbox{}
	released := make(chan struct{})
	ctx, returned := WithCapacity(context.Background(), func() { close(released) })
	d.removeOrHold(ctx, "", "plsm-run-unconfirmed")
	returned()
	select {
	case <-released:
		t.Fatal("the call's capacity came back while its container was not confirmed gone")
	default:
	}
	if !d.quarantine.Held("plsm-run-unconfirmed") {
		t.Fatal("the container was not quarantined")
	}
	if n, err := d.quarantine.Retry(func(string) error { return errors.New("still there") }); n != 0 || err == nil {
		t.Fatalf("a failed retry: %d, %v", n, err)
	}
	select {
	case <-released:
		t.Fatal("a failed retry gave the capacity back")
	default:
	}
	if n, err := d.quarantine.Retry(func(string) error { return nil }); n != 1 || err != nil {
		t.Fatalf("a confirmed retry: %d, %v", n, err)
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Fatal("the capacity did not come back once the container was confirmed gone")
	}
}

// One deadline bounds a removal: the absence checks and the pauses between attempts
// share it, so a daemon that never answers holds removeContainer no longer than its
// context. Before, each absence check had a budget of its own (review, 2026-10-23).
func TestDockerRemovalKeepsToOneDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := removeContainer(ctx, "unix:///nonexistent/plimsoll-test/docker.sock", "plsm-run-unreachable")
	if err == nil {
		t.Fatal("a removal through an unreachable daemon was reported confirmed")
	}
	if took := time.Since(start); took > 3*time.Second {
		t.Fatalf("the removal took %v against a 1.5 s deadline", took)
	}
	if dockerRemoveBudget != 33*time.Second {
		t.Fatalf("dockerRemoveBudget is %v; the docs and the session lease test state 33 s", dockerRemoveBudget)
	}
}

// The session's read-back compares values, not docker's bytes: fields in another order,
// or a field a newer daemon adds at its zero value, are the same configuration; a value
// that changes, appears or disappears is not (review, 2026-10-23).
func TestTheSessionReadBackComparesValuesNotBytes(t *testing.T) {
	snapshot := func(hostConfig, mounts string) string {
		return dockerInspect{Image: "sha256:aa", HostConfig: json.RawMessage(hostConfig), Mounts: json.RawMessage(mounts)}.securitySnapshot()
	}
	m1, m2 := `{"Type":"tmpfs","Destination":"/work"}`, `{"Type":"bind","Source":"/s","Destination":"/run/host"}`
	base := snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, "["+m1+","+m2+"]")
	for name, same := range map[string]string{
		"keys reordered":              snapshot(`{"Runtime":"runsc","ReadonlyRootfs":true,"CapDrop":["ALL"],"Memory":268435456}`, "["+m1+","+m2+"]"),
		"a field added at zero":       snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc","CgroupnsMode":"","OomScoreAdj":0,"Devices":[]}`, "["+m1+","+m2+"]"),
		"mounts listed the other way": snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, "["+m2+","+m1+"]"),
		"a mount's keys reordered":    snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, `[{"Destination":"/work","Type":"tmpfs"},`+m2+"]"),
	} {
		if same != base {
			t.Errorf("%s reads as a changed configuration", name)
		}
	}
	for name, changed := range map[string]string{
		"memory raised":      snapshot(`{"Memory":536870912,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, "["+m1+","+m2+"]"),
		"root made writable": snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"Runtime":"runsc"}`, "["+m1+","+m2+"]"),
		"a capability added": snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"CapAdd":["SYS_ADMIN"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, "["+m1+","+m2+"]"),
		"a mount added":      snapshot(`{"Memory":268435456,"CapDrop":["ALL"],"ReadonlyRootfs":true,"Runtime":"runsc"}`, "["+m1+","+m2+`,{"Type":"bind","Source":"/","Destination":"/host"}]`),
	} {
		if changed == base {
			t.Errorf("%s reads as the same configuration", name)
		}
	}
}

// A pool member whose removal is not confirmed keeps its place in the pool until the
// orphan pass confirms it gone, so failing removals cannot let the filler make
// containers past the pool's size (review, 2026-10-24). Before, the place came back at
// once, the container still quarantined.
func TestPoolHoldsAMemberPlaceUntilItsRemovalIsConfirmed(t *testing.T) {
	d := &DockerSandbox{}
	broker, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	s := &dockerSession{d: d, life: testLife(), name: "plsm-pool-unconfirmed", broker: broker}
	p := &dockerPool{d: d, size: 1, wake: make(chan struct{}, 1)}
	p.discard = p.remove
	p.mu.Lock()
	p.retiring = 1
	p.mu.Unlock()
	p.drop(s)
	waitRemovals := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.sessions.WaitRemovals(ctx); err != nil {
			t.Fatal(err)
		}
	}
	waitRemovals()
	if !d.quarantine.Held("plsm-pool-unconfirmed") || p.short() {
		t.Fatalf("held %v, short %v: the member's place came back before its container was confirmed gone", d.quarantine.Held("plsm-pool-unconfirmed"), p.short())
	}
	if n, err := d.quarantine.Retry(func(string) error { return nil }); n != 1 || err != nil {
		t.Fatalf("a confirmed retry: %d, %v", n, err)
	}
	for deadline := time.Now().Add(5 * time.Second); !p.short(); time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the place did not come back once the container was confirmed gone")
		}
	}
}

// A member that failed to start holds its place the same way: add abandons it under a
// hold of the pool's, so the place comes back only once its container is confirmed gone
// (review, 2026-10-24).
func TestPoolHoldsAFailedMemberPlaceUntilItsRemovalIsConfirmed(t *testing.T) {
	d := &DockerSandbox{}
	broker, err := startDockerSessionBroker()
	if err != nil {
		t.Fatal(err)
	}
	s := &dockerSession{d: d, life: testLife(), name: "plsm-pool-failed-start", broker: broker}
	p := &dockerPool{d: d, size: 1, wake: make(chan struct{}, 1)}
	p.mu.Lock()
	p.making = 1
	p.mu.Unlock()
	ctx, made := WithCapacity(context.Background(), p.made)
	s.abandon(ctx) // as add does when an interpreter will not start
	made()
	if !d.quarantine.Held("plsm-pool-failed-start") || p.short() {
		t.Fatalf("held %v, short %v: the failed member's place came back before its container was confirmed gone", d.quarantine.Held("plsm-pool-failed-start"), p.short())
	}
	if n, err := d.quarantine.Retry(func(string) error { return nil }); n != 1 || err != nil {
		t.Fatalf("a confirmed retry: %d, %v", n, err)
	}
	if !p.short() {
		t.Fatal("the place did not come back once the container was confirmed gone")
	}
}
