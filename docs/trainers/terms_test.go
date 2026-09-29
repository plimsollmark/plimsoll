package trainers

// The term registry and the first-use rule.
//
// Why this file exists. On 2026-09-29 the project's owner said the public docs read
// like an AI "spitting out things it assumes i would understand", naming "manifest",
// "provenance" and "admission policy" as words that lose him. Jargon got in because
// every doc change is written fast and nothing checked it, so rewriting pages alone
// would drift back. The mechanism here is data plus a test:
//
//   - terms.json is the registry: each term, the other forms it takes, one plain
//     sentence defining it, and its glossary anchor. It also lists the enforced pages.
//   - glossary.html is generated from it, and so are the definitions the Plain English
//     decoder shows. TestGeneratedBlocks fails when a generated block and the registry
//     disagree; run `go test ./docs/trainers -run TestGeneratedBlocks -update` to
//     rewrite the blocks after editing terms.json.
//   - TestRegisteredTermsAreDefinedAtFirstUse holds each enforced page to one rule: the
//     first time a registered term appears in that page's prose, it is either a marked
//     definition or a link to its glossary entry. Replacing the word with plain words is
//     the third way to pass, and often the best one.
//
// The marking convention:
//
//   - HTML: <dfn>broker</dfn>, followed in the same sentence by a plain definition.
//   - Markdown: <dfn>*broker*</dfn>. GitHub strips the <dfn> tag and keeps the
//     emphasis inside it (checked against GitHub's own renderer on 2026-09-29), so a
//     reader on GitHub sees the term in italics, the usual typographic mark of a term
//     being defined, and the tag stays in the source for this test to find.
//   - A link counts when its href ends in glossary.html#<anchor> for that term.
//
// What counts as prose: the page body, without code (<code>, <pre>, backticks, fenced
// blocks), headings, SVG drawings, scripts, styles, image alt text, HTML comments, link
// text that is a bare file path, and a generated glossary list. An HTML element marked
// data-terms="off" is skipped too; use it only where a registered word appears in its
// everyday sense, such as the security guard in the glossary's housing analogy, and say
// why in a comment beside it. Headings are skipped because a definition cannot
// sit inside one; the first sentence under the heading defines the term instead. Text a
// page builds in its script is not checked, which is a known gap.

import (
	"encoding/json"
	"flag"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the page blocks generated from terms.json")

const (
	registryFile = "terms.json"
	repoRoot     = "../.."
)

type termRegistry struct {
	About         []string          `json:"about"`
	EnforcedPages []string          `json:"enforced_pages"`
	Chapters      []glossaryChapter `json:"chapters"`
	Terms         []registeredTerm  `json:"terms"`
}

// glossaryChapter is a section of glossary.html that explains a group of related terms
// with a picture; a term that names it gets a link back to it in the A to Z list.
type glossaryChapter struct {
	Anchor string `json:"anchor"`
	Title  string `json:"title"`
}

type registeredTerm struct {
	Term          string   `json:"term"`
	Anchor        string   `json:"anchor"`
	Variants      []string `json:"variants"`
	Definition    string   `json:"definition"`
	CaseSensitive bool     `json:"case_sensitive,omitempty"`
	// Assumed marks a term the reader is expected to know (a container, a process).
	// It is listed in the glossary, but its first use on a page is not enforced.
	Assumed bool `json:"assumed,omitempty"`
	// Chapter is the anchor of the glossary chapter that explains the term at length.
	Chapter string `json:"chapter,omitempty"`
}

func loadRegistry(t *testing.T) termRegistry {
	t.Helper()
	raw := readFile(t, registryFile)
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	var reg termRegistry
	if err := dec.Decode(&reg); err != nil {
		t.Fatalf("parse %s: %v", registryFile, err)
	}
	if len(reg.Terms) == 0 || len(reg.EnforcedPages) == 0 {
		t.Fatalf("%s has no terms or no enforced pages; every check below would pass vacuously", registryFile)
	}
	return reg
}

// forms is the term and its variants, longest first so an alternation prefers the
// longer form at the same position ("isolation tiers" before "tier").
func (rt registeredTerm) forms() []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range append([]string{rt.Term}, rt.Variants...) {
		key := f
		if !rt.CaseSensitive {
			key = strings.ToLower(f)
		}
		if f == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool { return len(out[i]) > len(out[j]) })
	return out
}

func (rt registeredTerm) alternation() string {
	var alts []string
	for _, f := range rt.forms() {
		words := strings.Fields(f)
		for i, w := range words {
			words[i] = regexp.QuoteMeta(w)
		}
		alt := strings.Join(words, `\s+`)
		if isWordByte(f[0]) {
			alt = `\b` + alt
		}
		if isWordByte(f[len(f)-1]) {
			alt += `\b`
		}
		alts = append(alts, alt)
	}
	flags := "(?i)"
	if rt.CaseSensitive {
		flags = ""
	}
	return flags + "(?:" + strings.Join(alts, "|") + ")"
}

// pattern finds the term anywhere in prose; whole matches only a complete string, which
// is how a <dfn> is tied to the term it defines.
func (rt registeredTerm) pattern() *regexp.Regexp { return regexp.MustCompile(rt.alternation()) }
func (rt registeredTerm) whole() *regexp.Regexp {
	return regexp.MustCompile(`^` + rt.alternation() + `$`)
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

var anchorShape = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)

// TestTermRegistryIsWellFormed keeps the registry usable as a single source: one entry
// per anchor, no form claimed by two terms, alphabetical order so a reader can scan the
// glossary, and definitions that are one plain sentence with no dash punctuation.
func TestTermRegistryIsWellFormed(t *testing.T) {
	reg := loadRegistry(t)
	anchors := map[string]string{}
	owner := map[string]string{}
	twoSentences := regexp.MustCompile(`[.!?]\s+[A-Z]`)
	for i, rt := range reg.Terms {
		if rt.Term == "" || rt.Definition == "" {
			t.Errorf("entry %d has an empty term or definition: %+v", i, rt)
			continue
		}
		if !anchorShape.MatchString(rt.Anchor) {
			t.Errorf("%q: anchor %q is not lower-case words joined by hyphens", rt.Term, rt.Anchor)
		}
		if prev, dup := anchors[rt.Anchor]; dup {
			t.Errorf("%q and %q share the anchor %q", prev, rt.Term, rt.Anchor)
		}
		anchors[rt.Anchor] = rt.Term
		if i > 0 && strings.ToLower(reg.Terms[i-1].Term) >= strings.ToLower(rt.Term) {
			t.Errorf("%q is out of alphabetical order after %q", rt.Term, reg.Terms[i-1].Term)
		}
		for _, f := range rt.forms() {
			key := strings.ToLower(f)
			if prev, dup := owner[key]; dup && prev != rt.Term {
				t.Errorf("the form %q belongs to both %q and %q", f, prev, rt.Term)
			}
			owner[key] = rt.Term
		}
		if !rt.whole().MatchString(rt.Term) {
			t.Errorf("%q: its own pattern does not match the term", rt.Term)
		}
		d := rt.Definition
		if !strings.HasSuffix(d, ".") {
			t.Errorf("%q: the definition does not end with a full stop", rt.Term)
		}
		if twoSentences.MatchString(strings.TrimSuffix(d, ".")) {
			t.Errorf("%q: the definition is more than one sentence: %q", rt.Term, d)
		}
		for _, dash := range []string{"—", "–", " -- "} {
			if strings.Contains(d, dash) {
				t.Errorf("%q: the definition uses dash punctuation %q; use a comma, colon or parentheses", rt.Term, dash)
			}
		}
	}
	for _, page := range reg.EnforcedPages {
		if _, err := os.Stat(filepath.Join(repoRoot, page)); err != nil {
			t.Errorf("enforced page %s: %v", page, err)
		}
	}
	glossary := readFile(t, "glossary.html")
	chapters := map[string]bool{}
	for _, c := range reg.Chapters {
		if !anchorShape.MatchString(c.Anchor) || c.Title == "" {
			t.Errorf("chapter %+v needs a lower-case hyphenated anchor and a title", c)
		}
		if _, clash := anchors[c.Anchor]; clash {
			t.Errorf("chapter anchor %q is also a term's anchor", c.Anchor)
		}
		if !strings.Contains(glossary, `id="`+c.Anchor+`"`) {
			t.Errorf("chapter %q has no element with id=%q in glossary.html", c.Title, c.Anchor)
		}
		chapters[c.Anchor] = true
	}
	for _, rt := range reg.Terms {
		if rt.Chapter != "" && !chapters[rt.Chapter] {
			t.Errorf("%q names chapter %q, which the registry does not list", rt.Term, rt.Chapter)
		}
	}
}

// --- generated blocks ---------------------------------------------------------------

var (
	glossaryBegin = regexp.MustCompile(`(?m)^([ \t]*)<!-- glossary:begin[^\n]*-->\n`)
	glossaryEnd   = regexp.MustCompile(`(?m)^[ \t]*<!-- glossary:end -->`)
	termsBegin    = regexp.MustCompile(`(?m)^([ \t]*)// terms:begin ([a-z0-9 -]+)\n`)
	termsEnd      = regexp.MustCompile(`(?m)^[ \t]*// terms:end`)
)

// textEscaper escapes what HTML text content needs and nothing more, so apostrophes
// stay readable in the generated source.
var textEscaper = strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")

// glossaryBlock renders every registered term as one entry of a definition list, with
// the anchor as the entry's id so any page can link straight to it.
func glossaryBlock(reg termRegistry, indent string) string {
	titles := map[string]string{}
	for _, c := range reg.Chapters {
		titles[c.Anchor] = c.Title
	}
	var b strings.Builder
	b.WriteString(indent + "<dl class=\"glossary\">\n")
	for _, rt := range reg.Terms {
		more := ""
		if rt.Chapter != "" {
			more = fmt.Sprintf(` <a class="more" href="#%s">More: %s ↑</a>`, rt.Chapter, textEscaper.Replace(titles[rt.Chapter]))
		}
		fmt.Fprintf(&b, "%s  <div class=\"entry\" id=\"%s\">\n", indent, rt.Anchor)
		fmt.Fprintf(&b, "%s    <dt>%s</dt>\n", indent, textEscaper.Replace(rt.Term))
		fmt.Fprintf(&b, "%s    <dd>%s%s</dd>\n", indent, textEscaper.Replace(rt.Definition), more)
		b.WriteString(indent + "  </div>\n")
	}
	b.WriteString(indent + "</dl>\n")
	return b.String()
}

// definitionsBlock renders the named terms' definitions as a script object, for a page
// whose script shows a definition (the Plain English decoder). The anchors come from
// the begin marker, so the page states which terms it needs.
func definitionsBlock(t *testing.T, reg termRegistry, indent, anchors string) string {
	t.Helper()
	byAnchor := map[string]registeredTerm{}
	for _, rt := range reg.Terms {
		byAnchor[rt.Anchor] = rt
	}
	var b strings.Builder
	b.WriteString(indent + "// Generated from terms.json; edit that file, not these lines.\n")
	b.WriteString(indent + "var DEFINED = {\n")
	names := strings.Fields(anchors)
	for i, a := range names {
		rt, ok := byAnchor[a]
		if !ok {
			t.Errorf("a terms:begin marker names %q, which is not a registered anchor", a)
			continue
		}
		def, err := json.Marshal(rt.Definition)
		if err != nil {
			t.Fatal(err)
		}
		sep := ","
		if i == len(names)-1 {
			sep = ""
		}
		fmt.Fprintf(&b, "%s  %q: %s%s\n", indent, a, def, sep)
	}
	b.WriteString(indent + "};\n")
	return b.String()
}

// regenerate returns src with every generated block rebuilt from the registry.
func regenerate(t *testing.T, reg termRegistry, src string) string {
	t.Helper()
	if m := glossaryBegin.FindStringSubmatchIndex(src); m != nil {
		end := glossaryEnd.FindStringIndex(src[m[1]:])
		if end == nil {
			t.Fatal("glossary:begin without glossary:end")
		}
		src = src[:m[1]] + glossaryBlock(reg, src[m[2]:m[3]]) + src[m[1]+end[0]:]
	}
	if m := termsBegin.FindStringSubmatchIndex(src); m != nil {
		indent, anchors := src[m[2]:m[3]], src[m[4]:m[5]]
		end := termsEnd.FindStringIndex(src[m[1]:])
		if end == nil {
			t.Fatal("terms:begin without terms:end")
		}
		src = src[:m[1]] + definitionsBlock(t, reg, indent, anchors) + src[m[1]+end[0]:]
	}
	return src
}

// TestGeneratedBlocks is the single-source guard: the glossary page and every page that
// embeds definitions must say exactly what terms.json says. With -update it rewrites
// them instead of failing.
func TestGeneratedBlocks(t *testing.T) {
	reg := loadRegistry(t)
	pages, err := filepath.Glob("*.html")
	if err != nil {
		t.Fatal(err)
	}
	var found int
	for _, page := range pages {
		src := readFile(t, page)
		if !glossaryBegin.MatchString(src) && !termsBegin.MatchString(src) {
			continue
		}
		found++
		want := regenerate(t, reg, src)
		if want == src {
			continue
		}
		if *update {
			if err := os.WriteFile(page, []byte(want), 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("rewrote the generated blocks in %s", page)
			continue
		}
		t.Errorf("%s: a block generated from terms.json is out of date; run "+
			"go test ./docs/trainers -run TestGeneratedBlocks -update", page)
	}
	if found < 2 {
		t.Errorf("found generated blocks in %d pages, want the glossary and the Plain English decoder", found)
	}
	glossary := readFile(t, "glossary.html")
	if !glossaryBegin.MatchString(glossary) {
		t.Error("glossary.html has no glossary:begin block")
	}
	checkPlainPage(t, "glossary.html", glossary)
}

// --- prose extraction ---------------------------------------------------------------

// prose is a page's readable text flattened into one string, with the definition and
// link each byte sits in, so a match can be traced back to its markup.
type prose struct {
	text  strings.Builder
	dfnAt []int    // per byte: 1-based index into dfns, 0 outside a <dfn>
	href  []string // per byte: the enclosing link's href, "" outside a link
	dfns  []string // the text of each <dfn>, in order
}

func (p *prose) write(s string, dfn int, href string) {
	p.text.WriteString(s)
	for range len(s) {
		p.dfnAt = append(p.dfnAt, dfn)
		p.href = append(p.href, href)
	}
}

// pathLike is link text that is a file path or URL rather than words.
func pathLike(s string) bool {
	s = strings.TrimSpace(s)
	return s != "" && !strings.ContainsAny(s, " \t\n") && strings.ContainsAny(s, "/.")
}

var (
	htmlTag   = regexp.MustCompile(`^<(/?)([a-zA-Z][a-zA-Z0-9]*)([^>]*)>`)
	hrefAttr  = regexp.MustCompile(`\bhref="([^"]*)"`)
	termsOff  = regexp.MustCompile(`\bdata-terms="off"`)
	htmlSkips = map[string]bool{"code": true, "pre": true, "svg": true, "h1": true, "h2": true, "h3": true, "h4": true, "h5": true, "h6": true, "title": true}
)

func htmlProse(src string) *prose {
	if i := strings.Index(src, "<body"); i >= 0 {
		src = src[i:]
	}
	// A generated glossary list is the definitions themselves, not prose that uses the
	// terms, so the page that holds it is checked on everything around it.
	if m := glossaryBegin.FindStringIndex(src); m != nil {
		if end := glossaryEnd.FindStringIndex(src[m[1]:]); end != nil {
			src = src[:m[0]] + src[m[1]+end[1]:]
		}
	}
	p := &prose{}
	skip, dfn := 0, 0
	// offTag and offDepth track an element marked data-terms="off": text is skipped
	// until the matching close tag of the same name.
	offTag, offDepth := "", 0
	var links []string
	var dfnText strings.Builder
	link := func() string {
		if len(links) == 0 {
			return ""
		}
		return links[len(links)-1]
	}
	for len(src) > 0 {
		lt := strings.IndexByte(src, '<')
		if lt < 0 {
			lt = len(src)
		}
		if lt > 0 {
			text := html.UnescapeString(src[:lt])
			if skip == 0 && !(link() != "" && pathLike(text)) {
				p.write(text, dfn, link())
				if dfn > 0 {
					dfnText.WriteString(text)
				}
			}
			src = src[lt:]
			continue
		}
		if strings.HasPrefix(src, "<!--") {
			end := strings.Index(src, "-->")
			if end < 0 {
				break
			}
			src = src[end+3:]
			continue
		}
		m := htmlTag.FindStringSubmatch(src)
		if m == nil {
			p.write("<", dfn, link())
			src = src[1:]
			continue
		}
		src = src[len(m[0]):]
		closing, name := m[1] == "/", strings.ToLower(m[2])
		if !closing && (name == "script" || name == "style") {
			end := strings.Index(strings.ToLower(src), "</"+name)
			if end < 0 {
				break
			}
			src = src[end:]
			continue
		}
		p.write(" ", 0, "")
		if offDepth > 0 && name == offTag {
			if closing {
				offDepth--
			} else {
				offDepth++
			}
			if offDepth == 0 {
				skip--
			}
		} else if offDepth == 0 && !closing && termsOff.MatchString(m[3]) {
			offTag, offDepth = name, 1
			skip++
		}
		switch {
		case htmlSkips[name]:
			if closing {
				skip--
			} else {
				skip++
			}
		case name == "a":
			if closing {
				if len(links) > 0 {
					links = links[:len(links)-1]
				}
			} else {
				href := "#"
				if h := hrefAttr.FindStringSubmatch(m[3]); h != nil {
					href = html.UnescapeString(h[1])
				}
				links = append(links, href)
			}
		case name == "dfn":
			if closing {
				p.dfns = append(p.dfns, dfnText.String())
				dfnText.Reset()
				dfn = 0
			} else {
				dfn = len(p.dfns) + 1
			}
		}
	}
	return p
}

var (
	mdFence   = regexp.MustCompile("^\\s*(```|~~~)")
	mdHeading = regexp.MustCompile(`^\s{0,3}#{1,6}\s`)
	mdAutoURL = regexp.MustCompile(`^<https?://[^>]*>`)
	mdAnyTag  = regexp.MustCompile(`^</?[a-zA-Z][^>]*>`)
)

func markdownProse(src string) *prose {
	var kept []string
	fenced, comment := false, false
	for _, line := range strings.Split(src, "\n") {
		switch {
		case mdFence.MatchString(line):
			fenced = !fenced
			continue
		case fenced || mdHeading.MatchString(line):
			continue
		}
		if comment || strings.Contains(line, "<!--") {
			start := strings.Index(line, "<!--")
			end := strings.Index(line, "-->")
			switch {
			case comment && end >= 0:
				comment, line = false, line[end+3:]
			case comment:
				continue
			case end > start:
				line = line[:start] + line[end+3:]
			default:
				comment, line = true, line[:start]
			}
		}
		kept = append(kept, line)
	}
	p := &prose{}
	mdInline(p, strings.Join(kept, "\n"), "")
	return p
}

// mdInline walks markdown inline syntax: code spans, images and bare tags are dropped,
// a link's text is kept with its URL, and <dfn> marks what it wraps.
func mdInline(p *prose, s, href string) {
	dfn := 0
	var dfnText strings.Builder
	for i := 0; i < len(s); {
		rest := s[i:]
		switch {
		case rest[0] == '`':
			n := len(rest) - len(strings.TrimLeft(rest, "`"))
			end := strings.Index(rest[n:], rest[:n])
			if end < 0 {
				i += n
				continue
			}
			i += n + end + n
			p.write(" ", 0, "")
		case strings.HasPrefix(rest, "!["), rest[0] == '[':
			text, url, n := mdLink(rest)
			if n == 0 {
				p.write("[", dfn, href)
				i++
				continue
			}
			if !strings.HasPrefix(rest, "!") && !pathLike(text) {
				mdInline(p, text, url)
			}
			i += n
		case strings.HasPrefix(rest, "<dfn>"):
			dfn = len(p.dfns) + 1
			i += len("<dfn>")
		case strings.HasPrefix(rest, "</dfn>"):
			p.dfns = append(p.dfns, dfnText.String())
			dfnText.Reset()
			dfn = 0
			i += len("</dfn>")
		case mdAutoURL.MatchString(rest):
			i += len(mdAutoURL.FindString(rest))
		case mdAnyTag.MatchString(rest):
			i += len(mdAnyTag.FindString(rest))
			p.write(" ", 0, "")
		default:
			p.write(rest[:1], dfn, href)
			if dfn > 0 {
				dfnText.WriteByte(rest[0])
			}
			i++
		}
	}
}

// mdLink parses "[text](url)" or "![alt](url)" at the start of s, allowing nested
// brackets (a badge is an image inside a link), and returns the text, the URL and the
// bytes consumed, or n == 0 if s does not start a link.
func mdLink(s string) (text, url string, n int) {
	start := strings.IndexByte(s, '[')
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth > 0 {
				continue
			}
			if i+1 >= len(s) || s[i+1] != '(' {
				return "", "", 0
			}
			end := strings.IndexByte(s[i+2:], ')')
			if end < 0 {
				return "", "", 0
			}
			target := strings.Fields(s[i+2 : i+2+end])
			if len(target) > 0 {
				url = target[0]
			}
			return s[start+1 : i], url, i + 2 + end + 1
		case '\n':
			if i+1 < len(s) && s[i+1] == '\n' {
				return "", "", 0
			}
		}
	}
	return "", "", 0
}

func pageProse(t *testing.T, page string) *prose {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot, page))
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(page, ".md") {
		return markdownProse(string(raw))
	}
	return htmlProse(string(raw))
}

func cleanDfn(s string) string {
	return strings.Join(strings.Fields(strings.Trim(strings.TrimSpace(s), "*_")), " ")
}

// --- the first-use rule -------------------------------------------------------------

// TestRegisteredTermsAreDefinedAtFirstUse is the rule the registry exists for: on an
// enforced page, a registered term's first appearance is a marked definition of that
// term or a link to its glossary entry.
func TestRegisteredTermsAreDefinedAtFirstUse(t *testing.T) {
	reg := loadRegistry(t)
	for _, page := range reg.EnforcedPages {
		p := pageProse(t, page)
		text := p.text.String()
		for _, rt := range reg.Terms {
			if rt.Assumed {
				continue
			}
			loc := rt.pattern().FindStringIndex(text)
			if loc == nil {
				continue
			}
			if definedAt(p, rt, loc) {
				continue
			}
			from, to := max(0, loc[0]-50), min(len(text), loc[1]+50)
			context := strings.Join(strings.Fields(text[from:to]), " ")
			t.Errorf("%s: %q is first used without a definition, in %q; define it there "+
				"(<dfn>%s</dfn> in HTML, <dfn>*%s*</dfn> in markdown, then a plain clause), "+
				"link it to glossary.html#%s, or use plain words instead",
				page, text[loc[0]:loc[1]], context, rt.Term, rt.Term, rt.Anchor)
		}
	}
}

func definedAt(p *prose, rt registeredTerm, loc []int) bool {
	first, last := loc[0], loc[1]-1
	if d := p.dfnAt[first]; d > 0 && p.dfnAt[last] == d && rt.whole().MatchString(cleanDfn(p.dfns[d-1])) {
		return true
	}
	h := p.href[first]
	return h != "" && p.href[last] == h && strings.HasSuffix(h, "glossary.html#"+rt.Anchor)
}

// TestDefinitionsNameRegisteredTerms closes the loop from the other side: a page may
// only mark as a definition a term the registry holds, so every definition a page
// writes has a glossary entry, and it marks each term once.
func TestDefinitionsNameRegisteredTerms(t *testing.T) {
	reg := loadRegistry(t)
	for _, page := range reg.EnforcedPages {
		count := map[string]int{}
		for _, d := range pageProse(t, page).dfns {
			term := cleanDfn(d)
			var owner string
			for _, rt := range reg.Terms {
				if rt.whole().MatchString(term) {
					owner = rt.Term
					break
				}
			}
			if owner == "" {
				t.Errorf("%s: <dfn>%s</dfn> defines a term that is not in %s; register it there", page, term, registryFile)
				continue
			}
			if count[owner]++; count[owner] == 2 {
				t.Errorf("%s: %q is marked as a definition more than once; keep the first", page, owner)
			}
		}
	}
}

// TestProseExtraction pins what the first-use rule reads, so a change to the extractor
// that starts reading code or headings, or stops seeing a definition, fails here first.
func TestProseExtraction(t *testing.T) {
	h := htmlProse(`<head><title>broker</title></head><body><h2>broker</h2>` +
		`<p>A <dfn>broker</dfn> x <code>grant</code></p><svg><text>tier</text></svg>` +
		`<!-- mint --><p data-terms="off">guard <b>guard</b></p><p>after ` +
		`<a href="glossary.html#floor">floor</a></p><script>var escape = 1;</script></body>`)
	text := h.text.String()
	for _, absent := range []string{"grant", "tier", "mint", "guard", "escape", "title"} {
		if strings.Contains(text, absent) {
			t.Errorf("html prose kept %q: %q", absent, text)
		}
	}
	if strings.Count(text, "broker") != 1 || !strings.Contains(text, "after") {
		t.Errorf("html prose lost text it should keep: %q", text)
	}
	if len(h.dfns) != 1 || h.dfns[0] != "broker" {
		t.Errorf("html definitions = %q, want [broker]", h.dfns)
	}
	if i := strings.Index(text, "floor"); i < 0 || h.href[i] != "glossary.html#floor" {
		t.Errorf("html link target not recorded for %q", text)
	}

	m := markdownProse("# broker\n\nA <dfn>*grant*</dfn> and `tier` " +
		"[the floor](https://example.com/glossary.html#floor) ![a mint](x.png) " +
		"[docs/escape.md](docs/escape.md)\n\n```\nguard\n```\n<!-- session -->\nend\n")
	text = m.text.String()
	for _, absent := range []string{"broker", "tier", "mint", "escape", "guard", "session"} {
		if strings.Contains(text, absent) {
			t.Errorf("markdown prose kept %q: %q", absent, text)
		}
	}
	if len(m.dfns) != 1 || cleanDfn(m.dfns[0]) != "grant" {
		t.Errorf("markdown definitions = %q, want [*grant*]", m.dfns)
	}
	if i := strings.Index(text, "floor"); i < 0 || !strings.HasSuffix(m.href[i], "glossary.html#floor") {
		t.Errorf("markdown link target not recorded for %q", text)
	}
	if !strings.Contains(text, "end") {
		t.Errorf("markdown prose lost the text after a comment: %q", text)
	}
}
