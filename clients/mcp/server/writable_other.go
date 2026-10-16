//go:build !unix

package server

// writable cannot be asked here, so it answers yes: a directory that refused to open is
// then never taken for one this user made no entry in. (Receipts are refused on Windows.)
func writable(string) bool { return true }
