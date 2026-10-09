//go:build !unix

package main

// descriptorLimit is unknown off unix, so the RPC listener is not capped there.
func descriptorLimit() uint64 { return 0 }
