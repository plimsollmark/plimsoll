package main

// The popups on the underlined terms.
//
// A term the pages define in passing is marked <dfn data-gloss="ID">, and a dotted underline
// promises the reader an explanation on hover, so each one gets it from one source: the entry
// with that id in the public glossary (docs/trainers/glossary.html, generated from terms.json).
// The render reads the glossary, writes the entry's definition and link onto the <dfn>, and
// fails when a <dfn> names no entry or names none at all, so a new underlined term cannot ship
// without a definition. The in-sentence definitions stay as written: the popup is for meeting
// the term again later on the page.

import (
	_ "embed"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

//go:embed glossary_popup.html
var glossaryPopup string

const glossaryRelPath = "docs/trainers/glossary.html"

// glossaryHref is where a page under docs/examples/<name>/ finds the glossary.
const glossaryHref = "../../trainers/glossary.html"

var (
	glossEntryRE = regexp.MustCompile(`(?s)<div class="entry" id="([a-z0-9-]+)">\s*<dt>(.*?)</dt>\s*<dd>(.*?)</dd>\s*</div>`)
	glossTagRE   = regexp.MustCompile(`<[^>]*>`)
	dfnRE        = regexp.MustCompile(`<dfn(\s[^>]*)?>`)
	dfnIDRE      = regexp.MustCompile(`^\s+data-gloss="([a-z0-9-]+)"\s*$`)
)

// glossaryDefinitions maps each entry id of the glossary page to its definition as plain text.
func glossaryDefinitions(page string) map[string]string {
	defs := map[string]string{}
	for _, m := range glossEntryRE.FindAllStringSubmatch(page, -1) {
		text := glossTagRE.ReplaceAllString(m[3], "")
		defs[m[1]] = strings.Join(strings.Fields(html.UnescapeString(text)), " ")
	}
	return defs
}

// loadGlossary finds the glossary by walking up from the working directory, so the render
// command (run from the repository root) and the tests (run in this package) read the same file.
func loadGlossary() (map[string]string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	for {
		raw, err := os.ReadFile(filepath.Join(dir, glossaryRelPath))
		if err == nil {
			defs := glossaryDefinitions(string(raw))
			if len(defs) == 0 {
				return nil, fmt.Errorf("%s has no entries this program can read", glossaryRelPath)
			}
			return defs, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil, fmt.Errorf("no %s found above the working directory", glossaryRelPath)
		}
		dir = parent
	}
}

// applyGlossary gives every <dfn> of a rendered page its definition and glossary link, and adds
// the popup's style and script. A <dfn> with no data-gloss, or one whose entry is missing, fails.
func applyGlossary(page []byte) ([]byte, error) {
	defs, err := loadGlossary()
	if err != nil {
		return nil, err
	}
	return applyGlossaryWith(page, defs)
}

func applyGlossaryWith(page []byte, defs map[string]string) ([]byte, error) {
	var problems []string
	n := 0
	out := dfnRE.ReplaceAllFunc(page, func(tag []byte) []byte {
		attrs := dfnRE.FindSubmatch(tag)[1]
		m := dfnIDRE.FindSubmatch(attrs)
		if m == nil {
			problems = append(problems, fmt.Sprintf("%s names no glossary entry (write <dfn data-gloss=\"id\">)", tag))
			return tag
		}
		id := string(m[1])
		def, ok := defs[id]
		if !ok {
			problems = append(problems, fmt.Sprintf("<dfn data-gloss=%q> has no entry in %s", id, glossaryRelPath))
			return tag
		}
		n++
		return []byte(fmt.Sprintf(`<dfn tabindex="0" data-gloss="%s" data-def="%s" data-href="%s">`,
			id, html.EscapeString(def), glossaryHref+"#"+id))
	})
	if len(problems) > 0 {
		return nil, fmt.Errorf("underlined terms without a definition:\n  %s", strings.Join(problems, "\n  "))
	}
	if n == 0 {
		return out, nil
	}
	if i := strings.LastIndex(string(out), "</body>"); i >= 0 {
		out = append(out[:i:i], append([]byte(glossaryPopup), out[i:]...)...)
	} else {
		return nil, fmt.Errorf("a page with underlined terms has no </body> to carry the popup")
	}
	return out, nil
}
