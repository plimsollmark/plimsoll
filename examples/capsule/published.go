package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// publishedBundleSHA256 is the SHA-256 of the bundle the published page states,
// docs/examples/sessions/bundle.jsonl as it was at that import. The published
// defaults below belong to that bundle and no other: a different bundle is
// someone else's records, and stating the published operator, or an import time
// days in the past, on it would be false.
const publishedBundleSHA256 = "89af007222df5048b40625238c04230b92bbfc23476a66bb0e88af1e8fc73ed6"

// publishedImportedAt is the import time docs/examples/capsule states. It is the
// default for -imported-at on the published bundle, so running this program with
// no flags reproduces every published capsule ID; only the signatures differ,
// since each run makes its own key.
const publishedImportedAt = "2026-10-13T00:17:00Z"

// publishedIDs are the capsule IDs on that page, one per call, in order.
var publishedIDs = []string{
	"ae90012e0af88bc1b6caea920eebabc83513c51b901cc3d0a8046c21e7cd895a",
	"a653ffc2c9771419a0814c854c062318fac6d532b482ef90ff21e90af41bbead",
	"e4cca5c95e7714b56e655d126fba2d98f33f2eed7306bb1ebce1f919fe96102e",
	"017fd7640249f686dfb534f28558c2877c7c142cfa375ac6316d1cf345905216",
	"42074f54273cf341d130a17a622a171765eeb222562af963991659262aa5abaa",
}

const (
	defaultOperator  = "plimsoll examples/sessions"
	defaultDeveloper = "github.com/plimsollmark/plimsoll/examples/sessions"
)

// publishedSource is the source an import of bundle at time at states with the
// published operator and developer. The batch is the bundle's own digest, so
// every capsule names the exact bytes it was stated from.
func publishedSource(bundle []byte, at time.Time) source {
	sum := sha256.Sum256(bundle)
	return source{
		operator:   defaultOperator,
		developer:  defaultDeveloper,
		batch:      "plimsoll-bundle:sha256:" + hex.EncodeToString(sum[:]),
		importedAt: at,
	}
}

// sourceFor is the source an import of bundle states, from the flags. The
// published bundle takes the published defaults for whatever is not given; any
// other bundle must name all three, and is refused otherwise.
func sourceFor(bundle []byte, operator, developer, importedAt string) (source, error) {
	sum := sha256.Sum256(bundle)
	digest := hex.EncodeToString(sum[:])
	if digest != publishedBundleSHA256 && (operator == "" || developer == "" || importedAt == "") {
		return source{}, fmt.Errorf("the bundle (sha256 %s) is not the published one, so -operator, -developer and -imported-at must say who is stating these capsules and when; the published defaults belong to the published bundle alone", digest)
	}
	if importedAt == "" {
		importedAt = publishedImportedAt
	}
	at, err := time.Parse(time.RFC3339, importedAt)
	if err != nil {
		return source{}, fmt.Errorf("-imported-at: %w", err)
	}
	src := publishedSource(bundle, at.UTC())
	if operator != "" {
		src.operator = operator
	}
	if developer != "" {
		src.developer = developer
	}
	return src, nil
}
