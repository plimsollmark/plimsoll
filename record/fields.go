package record

import (
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/plimsollmark/plimsoll/internal/printable"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// MaxQualificationBytes bounds an isolation qualification: the longest plimsoll states,
// the WSL per-run mode's with gVisor, is 571 bytes.
const MaxQualificationBytes = 1024

// ValidText reports whether s is text a record may state where a reader is shown it as it
// is: valid UTF-8 holding no control character (U+0000 to U+001F, U+007F to U+009F) and
// none of the format characters that reorder or break displayed text (U+061C, U+200E,
// U+200F, U+2028, U+2029, U+202A to U+202E, U+2066 to U+2069: Unicode's bidirectional
// controls and the line and paragraph separators). It is the one character rule of the
// three fields a reader is shown as the run's evidence (ShownFields): the provider's name,
// the tier and the isolation qualification. The Python and TypeScript clients apply the
// same rule, from the table internal/wiretables writes for them.
func ValidText(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsFunc(s, printable.Escaped)
}

// ShownFields are a record's fields a reader is shown as the run's evidence, each with the
// name a refusal gives it, in the order the check reads them: each must pass ValidText. The
// tier must also be one of the five names, and the qualification at most
// MaxQualificationBytes.
func ShownFields(r sandbox.RunRecord) [3][2]string {
	return [3][2]string{{"provider", r.Provider}, {"isolation", r.Isolation}, {"isolation qualification", r.IsolationQualification}}
}

// ValidQualification reports whether s is an isolation qualification a record may state:
// "" (the provider states none), or at most MaxQualificationBytes of text ValidText
// accepts. It is a sentence a reader is shown beside the tier, so it may not carry a line
// break or text that displays in another order than it reads. examples/sbom/check.js
// applies the same rule.
func ValidQualification(s string) bool {
	return len(s) <= MaxQualificationBytes && ValidText(s)
}

// QualificationForbidden returns the inclusive code point ranges ValidText refuses, in the
// order docs/run-records.md lists them, for the generator that writes the other readers'
// copies. They are the set internal/printable escapes wherever plimsoll prints text from
// outside: one set, so no field a reader is shown holds what a terminal would show as an
// escape. The name is the qualification's, the first field the set was written for.
func QualificationForbidden() [][2]rune { return printable.Ranges() }

// DaemonVersionPattern is the grammar of a daemon version: a Go module version (a release
// tag or a pseudo-version, with optional pre-release and build parts) or "(devel)".
const DaemonVersionPattern = `^(?:\(devel\)|v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$`

var daemonVersionForm = regexp.MustCompile(DaemonVersionPattern)

// MaxDaemonVersionBytes bounds a daemon version.
const MaxDaemonVersionBytes = 128

// ValidDaemonVersion reports whether s is a daemon version a record may state: "" (the
// daemon read no build information), "(devel)", or a module version such as "v0.28.0"
// or a pseudo-version, at most MaxDaemonVersionBytes.
func ValidDaemonVersion(s string) bool {
	return s == "" || len(s) <= MaxDaemonVersionBytes && daemonVersionForm.MatchString(s)
}
