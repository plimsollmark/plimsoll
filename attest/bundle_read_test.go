package attest

import (
	"errors"
	"strings"
	"testing"
)

// A line without its signed link is refused as it is read, not after the whole file is
// held in memory (round-3 review: a file of "{}" lines amplified memory many times).
func TestReadBundleRefusesALinelessLineAtOnce(t *testing.T) {
	_, err := ReadBundle(strings.NewReader(strings.Repeat("{}\n", 1000)))
	if !errors.Is(err, ErrLink) || !strings.Contains(err.Error(), "bundle line 1:") {
		t.Fatalf("ReadBundle of link-less lines = %v; want ErrLink on line 1", err)
	}
}
