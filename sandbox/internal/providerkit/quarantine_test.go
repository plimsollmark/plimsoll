package providerkit

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

func TestQuarantineReleasesOnlyOnceConfirmedGone(t *testing.T) {
	var q Quarantine
	var released atomic.Int32
	release := func() { released.Add(1) }

	if err := q.Destroy("a", release, func() error { return nil }); err != nil || released.Load() != 1 || q.Held("a") {
		t.Fatalf("a destroy that succeeded: err %v, released %d, held %v", err, released.Load(), q.Held("a"))
	}

	failing := errors.New("daemon unreachable")
	if err := q.Destroy("b", release, func() error { return failing }); !errors.Is(err, failing) {
		t.Fatalf("Destroy returned %v", err)
	}
	if released.Load() != 1 || !q.Held("b") {
		t.Fatalf("a failed destroy released its capacity (%d) or forgot the name (held %v)", released.Load(), q.Held("b"))
	}
	gone, err := q.Retry(func(string) error { return failing })
	if gone != 0 || !errors.Is(err, failing) || released.Load() != 1 {
		t.Fatalf("a failed retry: gone %d, err %v, released %d", gone, err, released.Load())
	}
	gone, err = q.Retry(func(name string) error {
		if name != "b" {
			t.Errorf("retried %q", name)
		}
		return nil
	})
	if gone != 1 || err != nil || released.Load() != 2 || q.Held("b") || len(q.Names()) != 0 {
		t.Fatalf("a successful retry: gone %d, err %v, released %d, names %v", gone, err, released.Load(), q.Names())
	}
}

func TestQuarantineRetrySkipsADestroyInProgress(t *testing.T) {
	var q Quarantine
	q.Hold("busy", nil)
	gone, err := q.Retry(func(string) error {
		t.Fatal("retried a name whose destroy is in progress")
		return nil
	})
	if gone != 0 || err != nil {
		t.Fatalf("gone %d, err %v", gone, err)
	}
	if q.Begin("busy") {
		t.Fatal("a second destroyer claimed a name being destroyed")
	}
	q.Done("busy", false)
	if !q.Begin("busy") {
		t.Fatal("a name whose destroy failed could not be claimed for a retry")
	}
}

func TestDestroyAndWaitReturnsOnlyOnceARetryConfirmsGone(t *testing.T) {
	var q Quarantine
	returned := make(chan struct{})
	go func() {
		q.DestroyAndWait("s", func() error { return errors.New("removal failed") })
		close(returned)
	}()
	for !q.Held("s") || q.Begin("s") == false {
		time.Sleep(time.Millisecond)
	}
	q.Done("s", false) // give the claim taken above back unconfirmed
	select {
	case <-returned:
		t.Fatal("DestroyAndWait returned while the sandbox was not confirmed gone")
	case <-time.After(50 * time.Millisecond):
	}
	if gone, err := q.Retry(func(string) error { return nil }); gone != 1 || err != nil {
		t.Fatalf("retry: gone %d, err %v", gone, err)
	}
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("DestroyAndWait did not return once the sandbox was confirmed gone")
	}
}
