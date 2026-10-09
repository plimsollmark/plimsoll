package main

import (
	"net"
	"runtime"
	"testing"
	"time"
)

func TestRPCConnectionCapLeavesHalfTheDescriptors(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no descriptor limit to read")
	}
	limit := descriptorLimit()
	if limit == 0 {
		t.Fatal("descriptor limit unreadable")
	}
	if got := uint64(rpcConnectionCap()); got == 0 || got > limit/2 {
		t.Fatalf("cap %d with a descriptor limit of %d, want at most half", got, limit)
	}
}

// At the cap a new connection is not accepted until an open one closes.
func TestLimitConnectionsHoldsTheExtraConnection(t *testing.T) {
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln := limitConnections(raw, 2)
	defer ln.Close()
	accepted := make(chan net.Conn, 3)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			accepted <- c
		}
	}()
	for range 3 {
		c, err := net.Dial("tcp", raw.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	first := <-accepted
	<-accepted
	select {
	case <-accepted:
		t.Fatal("a third connection was accepted past a cap of two")
	case <-time.After(300 * time.Millisecond):
	}
	_ = first.Close()
	select {
	case c := <-accepted:
		_ = c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting connection was not accepted once one closed")
	}
}
