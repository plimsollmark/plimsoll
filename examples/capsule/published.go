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
const publishedBundleSHA256 = "01e636707978a70f2c0cce87e30d886794ed02f30b1529f7f6b706379f571a94"

// publishedImportedAt is the import time docs/examples/capsule states. It is the
// default for -imported-at on the published bundle, so running this program with
// no flags reproduces every published capsule ID; only the signatures differ,
// since each run makes its own key.
const publishedImportedAt = "2026-10-23T19:36:00Z"

// publishedIDs are the capsule IDs on that page, one per call, in order.
var publishedIDs = []string{
	"6cdc9bc448a9c151e2ac66c26b242d1ab4b6ac0f7744d43a52a809fe8ee4b1e9",
	"dcd26519d4def30d94c06338fa7988e89d6d529d683ffd17f9677772d3170df5",
	"b9752b577c12a0ce210350120d26cce0fa24d2aac02115d0a58b62dad1530bb8",
	"c2a12785dd9b8938180db2653f88cf57603ab4e15132f7b789da58e3dcaca6e8",
	"f2384a70785ad3f90a07d589fb959cc6f8446e209b4ab739ac2b4f118cdb63a8",
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
	src.published = digest == publishedBundleSHA256
	if operator != "" {
		src.operator = operator
	}
	if developer != "" {
		src.developer = developer
	}
	return src, nil
}
