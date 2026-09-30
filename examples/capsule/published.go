package main

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// publishedImportedAt is the import time docs/examples/capsule states. It is the
// default for -imported-at, so running this program with no flags reproduces
// every published capsule ID; only the signatures differ, since each run makes
// its own key.
const publishedImportedAt = "2026-09-30T16:22:00Z"

// publishedIDs are the capsule IDs on that page, one per call, in order.
var publishedIDs = []string{
	"037e038a991b3a8f961ba685088e843a852d43dbac57c3107f63839ce1faf8a5",
	"f7990e8deba2296b7a2816f20bfcd1b5428064bc87a529403a63ce07db801340",
	"e2c95aa2c898714b80eb045c4b103bf7d7de1d10e380af1302fb1ae709d514cc",
	"0be34118e88388f80e146b2645251088f31304057a184a219994608fcb7862e3",
	"1c1bac6a701df435dc0d722c4935862856412804343f6a7ccc73a3240ddb2aaf",
}

const (
	defaultOperator  = "plimsoll examples/sessions"
	defaultDeveloper = "github.com/plimsollmark/plimsoll/examples/sessions"
)

// publishedSource is the source an import of bundle at time at states, with the
// default operator and developer. The batch is the bundle's own digest, so every
// capsule names the exact bytes it was stated from.
func publishedSource(bundle []byte, at time.Time) source {
	sum := sha256.Sum256(bundle)
	return source{
		operator:   defaultOperator,
		developer:  defaultDeveloper,
		batch:      "plimsoll-bundle:sha256:" + hex.EncodeToString(sum[:]),
		importedAt: at,
	}
}
