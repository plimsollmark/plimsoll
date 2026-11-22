package python

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// lostCallWordFiles are the files that tell a caller, or the model through the PydanticAI
// kit, what the record of a lost call shows: a call sent to a kept session whose answer
// never reached the worker that sent it. Paths are from the repository root.
var lostCallWordFiles = []string{
	"client/session.go",
	"client/checkpoint.go",
	"clients/python/src/plimsoll_client/client.py",
	"clients/python/src/plimsoll_client/errors.py",
	"clients/python/src/plimsoll_client/pydantic_ai.py",
	"clients/python/README.md",
	"clients/python/pydantic-ai-plimsoll/README.md",
	"clients/python/examples/pydantic_ai_crash.py",
	"clients/typescript/src/client.ts",
	"clients/typescript/src/errors.ts",
	"clients/typescript/README.md",
	"docs/sessions.md",
}

// lostCallOverclaims are words a sentence about a lost call must not use, each claiming more
// than the record shows. A result digest shows the daemon answered, not that the command ran
// to its end (finding release-80); an unanswered code shows the call was dispatched and ended
// without an answer, not that the command started (release-79); the first-call limit lets a
// lost call be sent again, and a pending record shows a dispatch, not a run (release-81); and
// the refusal's errors are named for a call already sent, not one that ran (release-82).
var lostCallOverclaims = []string{
	"when the daemon finished it",
	"when the daemon finished the call",
	"says whether it finished",
	"says whether the call finished",
	"it started and ended",
	"may have done part or all",
	"never run again",
	"never runs again",
	"if it ran",
	"or it ran",
	"it ran and",
	"ran once",
	"alreadyran",
}

// lostCallWords reads a file as one lowercase line of prose: each line's comment marker
// ("//", "*", "#") dropped and every run of spaces made one, so a phrase wrapped across
// lines of a comment or a paragraph still matches.
func lostCallWords(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(path)))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(b), "\n")
	for i, l := range lines {
		l = strings.TrimSpace(l)
		for _, marker := range []string{"//", "*", "#"} {
			l = strings.TrimSpace(strings.TrimPrefix(l, marker))
		}
		lines[i] = l
	}
	return strings.ToLower(strings.Join(strings.Fields(strings.Join(lines, " ")), " "))
}

// TestLostCallSentencesClaimNoMoreThanTheRecord holds the clients, the PydanticAI kit and
// docs/sessions.md to what a lost call's record shows: each says the record tells whether
// the daemon answered the call, and none uses a word that claims the call finished,
// started, ran, or can never run again.
func TestLostCallSentencesClaimNoMoreThanTheRecord(t *testing.T) {
	for _, path := range lostCallWordFiles {
		text := lostCallWords(t, path)
		if !strings.Contains(text, "says whether the daemon answered") {
			t.Errorf("%s does not say that a lost call's record says whether the daemon answered it", path)
		}
		for _, claim := range lostCallOverclaims {
			// A word boundary before each phrase: "for it ran out of time" is not "or it ran".
			if strings.Contains(" "+text, " "+claim) {
				t.Errorf("%s says %q about a lost call, more than its record shows", path, claim)
			}
		}
	}
}
