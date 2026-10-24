package sandbox

import (
	"slices"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/sessionkit"
)

// Every language LanguageSpecs names can be started in a session, and a session starts
// no other: a language added to one and not the other was offered and failed, or never
// offered (review, 2026-10-23).
func TestEveryLanguageHasALaunchAndNoLaunchIsUnnamed(t *testing.T) {
	var named []string
	for _, l := range Languages {
		named = append(named, string(l))
	}
	slices.Sort(named)
	if got := sessionkit.LaunchLanguages(); !slices.Equal(got, named) {
		t.Fatalf("sessionkit launches %v; LanguageSpecs names %v", got, named)
	}
	if Languages[0] != LanguageJavaScript {
		t.Fatal("JavaScript, which the runner needs, is not the first language")
	}
}

// The shared probe names exactly the languages whose probes answered, once each.
func TestProbedLanguagesReadsTheProbe(t *testing.T) {
	if got := ProbedLanguages("javascript\npython\nruby\njavascript\n"); !slices.Equal(got, []Language{LanguageJavaScript, LanguagePython}) {
		t.Fatalf("ProbedLanguages = %v", got)
	}
	if got := ProbedLanguages("javascript\n"); !slices.Equal(got, []Language{LanguageJavaScript}) {
		t.Fatalf("ProbedLanguages = %v", got)
	}
}
