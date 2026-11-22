package providerkit

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDeleteRetriesThenGivesUp(t *testing.T) {
	calls := 0
	n, err := Delete(10*time.Second, func(context.Context) error {
		calls++
		if calls == 2 {
			return nil
		}
		return errors.New("busy")
	})
	if n != 2 || err != nil {
		t.Fatalf("second try: %d, %v", n, err)
	}
	if testing.Short() {
		return
	}
	n, err = Delete(10*time.Second, func(context.Context) error { return errors.New("down") })
	if n != deleteAttempts || err == nil {
		t.Fatalf("all fail: %d, %v", n, err)
	}
}

func TestCheckIsCached(t *testing.T) {
	c := &Check{TTL: time.Hour, Err: errors.New("not yet")}
	calls := 0
	for range 3 {
		if err := c.Run(context.Background(), time.Second, func(context.Context) error { calls++; return nil }); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatalf("%d checks", calls)
	}
}
