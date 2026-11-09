package withheld

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unicode/utf8"
)

// The known-unreadable list: for each image, the files its scan could not read whole,
// each with why and its whole size. The startup scan of a provider's images refuses to
// serve while an image holds an unreadable file that is not on its image's list
// (cmd/plimsolld), because withheld material inside such a file would not be found.
// A list entry acknowledges the bytes the scan did not read; it does not show they are
// free of withheld material. The list is keyed by the image's content ID, so a rebuilt
// image (a new ID) needs a new list, and a file whose reason or size differs from its
// entry is not known.

// KnownVersion is the known-unreadable list's format version.
const KnownVersion = 1

// MaxKnownFileBytes bounds the list file the daemon and the command read.
const MaxKnownFileBytes = 16 << 20

// maxKnownPathBytes bounds one entry's path.
const maxKnownPathBytes = 64 << 10

// Unreadable is a file of an image the scan could not read whole.
type Unreadable struct {
	// Key names the file unambiguously: the layer's name in the image archive and the
	// file's path in it, each escaped (KnownPath), joined by ":".
	Key string
	// Where is the file in the scan's own display form (CleanWhere), for messages.
	Where string
	// Reason is the bound the scan reached or the format it does not read.
	Reason Bound
	// Size is the whole file's size in bytes, from its header, also when the scan read
	// only part of it.
	Size int64
}

type unreadableID struct {
	key    string
	reason Bound
}

// KnownPath escapes one name (a layer's, a file's path) so that two different names never
// give the same text: CleanWhere's escapes for control and non-UTF-8 bytes, a backslash
// written twice and ":" (the separator of a layer and a path) as \x3a. CleanWhere alone
// would give a name that holds the text \x1b the same output as a name holding ESC.
func KnownPath(name string) string {
	var b strings.Builder
	for i := 0; i < len(name); {
		r, n := utf8.DecodeRuneInString(name[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, name[i])
		case r == '\\':
			b.WriteString(`\\`)
		case r == ':':
			b.WriteString(`\x3a`)
		case needsEscape(r) && r < 0x100:
			fmt.Fprintf(&b, `\x%02x`, r)
		case needsEscape(r):
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(name[i : i+n])
		}
		i += n
	}
	return b.String()
}

// unreadableKey is the key of a file: its names, escaped, joined by ":".
func unreadableKey(names ...string) string {
	parts := make([]string, len(names))
	for i, n := range names {
		parts[i] = KnownPath(n)
	}
	return strings.Join(parts, ":")
}

// ValidImageID reports whether id is an image content ID as Docker writes it:
// "sha256:" and 64 lowercase hexadecimal digits.
func ValidImageID(id string) bool {
	hexPart, ok := strings.CutPrefix(id, "sha256:")
	if !ok || len(hexPart) != 64 {
		return false
	}
	for _, c := range hexPart {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// Known is the known-unreadable lists of any number of images.
type Known struct {
	images map[string]map[unreadableID]int64
}

// NewKnown is a list with no image on it: every unreadable file is unknown.
func NewKnown() *Known { return &Known{images: map[string]map[unreadableID]int64{}} }

// Images is the number of images the list holds.
func (k *Known) Images() int { return len(k.images) }

// Unknown returns the files in found that image id's list does not hold with the same
// reason and size, in the order given.
func (k *Known) Unknown(id string, found []Unreadable) []Unreadable {
	var out []Unreadable
	list := k.images[id]
	for _, u := range found {
		if size, ok := list[unreadableID{u.Key, u.Reason}]; !ok || size != u.Size {
			out = append(out, u)
		}
	}
	return out
}

// Set replaces image id's list with found and leaves every other image's alone.
func (k *Known) Set(id string, found []Unreadable) error {
	if !ValidImageID(id) {
		return fmt.Errorf("image ID %q is not sha256: and 64 lowercase hexadecimal digits", CleanWhere(id))
	}
	list := map[unreadableID]int64{}
	for _, u := range found {
		e := unreadableID{u.Key, u.Reason}
		if err := checkKnownEntry(u.Key, u.Reason, u.Size); err != nil {
			return err
		}
		if _, dup := list[e]; dup {
			return fmt.Errorf("the scan listed %s (%s) twice", CleanWhere(u.Key), u.Reason)
		}
		list[e] = u.Size
	}
	k.images[id] = list
	return nil
}

func checkKnownEntry(path string, reason Bound, size int64) error {
	switch {
	case path == "":
		return errors.New("an entry has an empty path")
	case len(path) > maxKnownPathBytes:
		return fmt.Errorf("an entry's path is longer than %d bytes", maxKnownPathBytes)
	case !utf8.ValidString(path) || strings.ContainsFunc(path, needsEscape):
		return fmt.Errorf("path %q holds a control character or invalid UTF-8; the list writes them as \\x escapes", CleanWhere(path))
	}
	if _, ok := boundText[reason]; !ok {
		return fmt.Errorf("%s: unknown reason %q", CleanWhere(path), CleanWhere(string(reason)))
	}
	if size < 0 {
		return fmt.Errorf("%s: negative size", CleanWhere(path))
	}
	return nil
}

type knownFileJSON struct {
	Path   string `json:"path"`
	Reason Bound  `json:"reason"`
	Size   int64  `json:"size"`
}

type knownImageJSON struct {
	ID    string          `json:"image_id"`
	Files []knownFileJSON `json:"files"`
}

type knownJSON struct {
	Version int              `json:"version"`
	Images  []knownImageJSON `json:"images"`
}

// Marshal writes the list in its one format, images by ID and files by path and reason, so
// the same list is the same bytes.
func (k *Known) Marshal() ([]byte, error) {
	out := knownJSON{Version: KnownVersion, Images: []knownImageJSON{}}
	ids := make([]string, 0, len(k.images))
	for id := range k.images {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		img := knownImageJSON{ID: id, Files: []knownFileJSON{}}
		for e, size := range k.images[id] {
			img.Files = append(img.Files, knownFileJSON{Path: e.key, Reason: e.reason, Size: size})
		}
		slices.SortFunc(img.Files, func(a, b knownFileJSON) int {
			if c := strings.Compare(a.Path, b.Path); c != 0 {
				return c
			}
			return strings.Compare(string(a.Reason), string(b.Reason))
		})
		out.Images = append(out.Images, img)
	}
	raw, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	raw = append(raw, '\n')
	if len(raw) > MaxKnownFileBytes {
		return nil, errors.New("known-unreadable list exceeds its 16 MiB bound")
	}
	if _, err := ParseKnown(raw); err != nil { // what the daemon would refuse to load is never written
		return nil, err
	}
	return raw, nil
}

// LoadKnown reads the list at path. An empty path is the empty list.
func LoadKnown(path string) (*Known, error) {
	if path == "" {
		return NewKnown(), nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, cleanKnownIO(err)
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, MaxKnownFileBytes+1))
	if err != nil {
		return nil, cleanKnownIO(err)
	}
	if len(raw) > MaxKnownFileBytes {
		return nil, fmt.Errorf("%s is larger than %d MiB", CleanWhere(path), MaxKnownFileBytes>>20)
	}
	k, err := ParseKnown(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", CleanWhere(path), err)
	}
	return k, nil
}

// ParseKnown reads a list strictly: the version, every field of every image and file
// present and of its type, no field it does not define (matched exactly, case included),
// no field twice, no image ID malformed or twice, no path twice with the same reason, no
// reason it does not know, and nothing after the JSON value.
func ParseKnown(raw []byte) (*Known, error) {
	top, err := knownObject(raw, "version", "images")
	if err != nil {
		return nil, err
	}
	var version int
	if err := knownScalar(top, "version", &version); err != nil {
		return nil, err
	}
	if version != KnownVersion {
		return nil, fmt.Errorf("version %d, want %d", version, KnownVersion)
	}
	images, err := knownArray(top, "images")
	if err != nil {
		return nil, err
	}
	k := NewKnown()
	for i, rawImg := range images {
		img, err := knownObject(rawImg, "image_id", "files")
		if err != nil {
			return nil, fmt.Errorf("images[%d]: %w", i, err)
		}
		var id string
		if err := knownScalar(img, "image_id", &id); err != nil {
			return nil, fmt.Errorf("images[%d]: %w", i, err)
		}
		if !ValidImageID(id) {
			return nil, fmt.Errorf("images[%d]: image_id %q is not sha256: and 64 lowercase hexadecimal digits", i, CleanWhere(id))
		}
		if _, dup := k.images[id]; dup {
			return nil, fmt.Errorf("images[%d]: image %s is listed twice", i, id)
		}
		files, err := knownArray(img, "files")
		if err != nil {
			return nil, fmt.Errorf("images[%d]: %w", i, err)
		}
		list := map[unreadableID]int64{}
		for j, rawFile := range files {
			at := fmt.Sprintf("images[%d].files[%d]", i, j)
			f, err := knownObject(rawFile, "path", "reason", "size")
			if err != nil {
				return nil, fmt.Errorf("%s: %w", at, err)
			}
			var (
				path, reason string
				size         int64
			)
			for _, step := range []error{knownScalar(f, "path", &path), knownScalar(f, "reason", &reason), knownScalar(f, "size", &size)} {
				if step != nil {
					return nil, fmt.Errorf("%s: %w", at, step)
				}
			}
			if err := checkKnownEntry(path, Bound(reason), size); err != nil {
				return nil, fmt.Errorf("%s: %w", at, err)
			}
			e := unreadableID{path, Bound(reason)}
			if _, dup := list[e]; dup {
				return nil, fmt.Errorf("%s: %s is listed twice for %s", at, CleanWhere(path), reason)
			}
			list[e] = size
		}
		k.images[id] = list
	}
	return k, nil
}

// knownObject splits one JSON object into its fields, requiring every one of want, no
// other, none twice (in any letter case), and no data after the object.
func knownObject(raw []byte, want ...string) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("not JSON: %w", err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	folded := map[string]bool{}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := keyTok.(string)
		if folded[strings.ToLower(key)] {
			return nil, fmt.Errorf("field %q appears twice", CleanWhere(key))
		}
		folded[strings.ToLower(key)] = true
		if !slices.Contains(want, key) {
			return nil, fmt.Errorf("unknown field %q", CleanWhere(key))
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, err
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("data after the JSON value")
	}
	for _, w := range want {
		if _, ok := out[w]; !ok {
			return nil, fmt.Errorf("field %q is missing", w)
		}
	}
	return out, nil
}

func knownArray(obj map[string]json.RawMessage, name string) ([]json.RawMessage, error) {
	raw := bytes.TrimSpace(obj[name])
	if len(raw) == 0 || raw[0] != '[' {
		return nil, fmt.Errorf("field %q is not an array", name)
	}
	var out []json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("field %q: %w", name, err)
	}
	return out, nil
}

// knownScalar decodes a field that must be a string or an integer: never null, never a
// number with a fraction (json would refuse it for an integer) or a string for a number.
func knownScalar[T string | int | int64](obj map[string]json.RawMessage, name string, dst *T) error {
	raw := bytes.TrimSpace(obj[name])
	if bytes.Equal(raw, []byte("null")) {
		return fmt.Errorf("field %q is null", name)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("field %q: %w", name, err)
	}
	return nil
}

// Keep a configured filename from injecting terminal controls through PathError,
// while preserving errors.Is for the command's create-on-not-exist case.
func cleanKnownIO(err error) error {
	var pe *os.PathError
	if errors.As(err, &pe) {
		return fmt.Errorf("%s %s: %w", pe.Op, CleanWhere(pe.Path), pe.Err)
	}
	return err
}
