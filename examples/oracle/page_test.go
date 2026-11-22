package main

import (
	"path/filepath"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/pagetest"
)

// The committed docs/examples/oracle/index.html carries every literal run of page.html, the
// template a run writes it from, in the template's order (internal/pagetest says why).
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	pagetest.CarriesTemplate(t, pageTemplate, filepath.Join("..", "..", "docs", "examples", "oracle", "index.html"),
		"go run ./examples/oracle")
}
