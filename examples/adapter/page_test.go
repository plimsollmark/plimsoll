package main

import (
	"path/filepath"
	"testing"

	"github.com/plimsollmark/plimsoll/internal/pagetest"
)

// The committed docs/examples/adapter/index.html carries every literal run of page.html, the
// template a run writes it from, in the template's order (internal/pagetest says why).
func TestCommittedPageCarriesEveryLineOfItsTemplate(t *testing.T) {
	pagetest.CarriesTemplate(t, pageTemplate, filepath.Join("..", "..", "docs", "examples", "adapter", "index.html"),
		"go run ./examples/adapter")
}
