package trainers

// Every trainer page carries Open Graph tags so that a link to it renders with a
// picture wherever it is shared. The tags and the card image are generated from the
// page's own <title> and description by docs/social/gen-cards.mjs, which is the whole
// point: there is no second copy of the text to maintain, and this test fails if
// somebody edits a title without regenerating.
//
// The card image referenced by each page must also exist in the tree, so a rename
// cannot leave a published page pointing at a 404.

import (
	"fmt"
	"html"
	"os"
	"regexp"
	"strings"
	"testing"
)

const socialCardBase = "https://plimsollmark.github.io/plimsoll/social/cards/"

var (
	titlePattern       = regexp.MustCompile(`(?s)<title>(.*?)</title>`)
	descriptionPattern = regexp.MustCompile(`<meta name="description" content="(.*?)">`)
	ogPattern          = regexp.MustCompile(`<meta property="og:([a-z:_]+)" content="(.*?)">`)
)

// socialPages is every page that ships: the lessons, the catalog, and the quick start.
func socialPages() []string {
	return append(append([]string{}, trainerPages...), "index.html", "quick-start.html")
}

func ogTags(t *testing.T, page, doc string) map[string]string {
	t.Helper()
	tags := map[string]string{}
	for _, m := range ogPattern.FindAllStringSubmatch(doc, -1) {
		tags[m[1]] = html.UnescapeString(m[2])
	}
	if len(tags) == 0 {
		t.Fatalf("%s: no og: tags; regenerate with docs/social/gen-cards.mjs", page)
	}
	return tags
}

// TestSocialTagsMatchThePage is the drift guard: og:title and og:description must say
// exactly what the page's own head says, entities decoded on both sides.
func TestSocialTagsMatchThePage(t *testing.T) {
	for _, page := range socialPages() {
		doc := readFile(t, page)
		tags := ogTags(t, page, doc)

		title := titlePattern.FindStringSubmatch(doc)
		if title == nil {
			t.Fatalf("%s: no <title>", page)
		}
		if want, got := html.UnescapeString(title[1]), tags["title"]; want != got {
			t.Errorf("%s: og:title is %q, page title is %q; regenerate the cards", page, got, want)
		}

		description := descriptionPattern.FindStringSubmatch(doc)
		if description == nil {
			t.Fatalf("%s: no meta description", page)
		}
		if want, got := html.UnescapeString(description[1]), tags["description"]; want != got {
			t.Errorf("%s: og:description does not match the page description; regenerate the cards", page)
		}
	}
}

// TestSocialCardsExist keeps every published og:image pointing at a file that is
// actually in the tree, at the size the tags promise.
func TestSocialCardsExist(t *testing.T) {
	for _, page := range socialPages() {
		doc := readFile(t, page)
		tags := ogTags(t, page, doc)

		slug := strings.TrimSuffix(page, ".html")
		want := socialCardBase + slug + ".png"
		if tags["image"] != want {
			t.Errorf("%s: og:image is %q, want %q", page, tags["image"], want)
			continue
		}
		card := fmt.Sprintf("../social/cards/%s.png", slug)
		if _, err := os.Stat(card); err != nil {
			t.Errorf("%s: og:image names a card that is not in the tree: %v", page, err)
		}
		for key, want := range map[string]string{"image:width": "1280", "image:height": "640"} {
			if tags[key] != want {
				t.Errorf("%s: og:%s is %q, want %q", page, key, tags[key], want)
			}
		}
	}
}

// TestSocialCardsAreLargeSummary guards the one tag that decides whether the picture
// renders full width or as a thumbnail next to the text.
func TestSocialCardsAreLargeSummary(t *testing.T) {
	for _, page := range socialPages() {
		doc := readFile(t, page)
		if !strings.Contains(doc, `<meta name="twitter:card" content="summary_large_image">`) {
			t.Errorf("%s: missing twitter:card summary_large_image", page)
		}
	}
}
