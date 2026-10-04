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
const publishedImportedAt = "2026-10-04T06:41:00Z"

// publishedIDs are the capsule IDs on that page, one per call, in order.
var publishedIDs = []string{
	"9cafc675aadf33c5e2603c1ec8624d185b0d0f15a3a0e8a578426b6306645009",
	"74b3dc02ec74e981709c398d8a71992c3e6019dbf50a55981f5bdf858b1a8133",
	"4c00419e12e5ec4fb5d2ce8a186e7b7936b3bae98fce7e4d15fbe6d29ac1edcb",
	"ef380fe374f1993a5979dd7d2a474967939449156cbc3f4743b8fd1c95d7a825",
	"da9d36e7a1c93dd52f6512dbd0032d860cd37709dd78be8c1af301f26fc163b3",
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
