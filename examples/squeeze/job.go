package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
)

// Job is what one squeeze run does: for each course, the loop whose score is in question, the
// rebuild groups, and the two sealed sets every controller is graded on.
type Job struct {
	Name    string      `json:"name"`
	About   string      `json:"about"`
	Fresh   int         `json:"fresh"` // flights in the fresh set, drawn at random by -seal
	Courses []CourseJob `json:"courses"`
	Rebuild Rebuild     `json:"rebuild"`
}

// CourseJob is one course: its practice set (the loop's own validation flights, which no
// rebuild sees), the loops, and the groups of rebuilds.
type CourseJob struct {
	ID       string   `json:"id"`    // "easy" or "hard": the course's files
	Label    string   `json:"label"` // as the page names it
	Tag      string   `json:"tag"`   // the hackathon's code for the run, shown as a small grey tag
	Practice []uint32 `json:"practice"`
	Loops    []Loop   `json:"loops"`
	Groups   []Group  `json:"groups"`
}

// Loop is the loop whose score the squeeze questions: its own controller, graded like every
// rebuild, and the recipe it was squeezed into.
type Loop struct {
	ID           string `json:"id"`
	Label        string `json:"label"`
	Artifact     string `json:"artifact"` // the loop's controller, under -import; "" if there is none to grade
	Recipe       string `json:"recipe"`
	RecipeTokens int    `json:"recipe_tokens"`
	Tokenizer    string `json:"tokenizer"` // how RecipeTokens was counted
}

// Group is one set of rebuilds: from a loop's recipe, or from no recipe at all (the control).
// Build rebuilds are made here by the caller's model; Import ones were made elsewhere and are
// only graded here (their sandboxes were not plimsoll's, so the leak scan says nothing of them).
type Group struct {
	ID     string   `json:"id"`
	Label  string   `json:"label"`
	From   string   `json:"from"` // a loop's ID, or "" for no recipe
	Build  int      `json:"build"`
	Import []string `json:"import"` // controllers under -import; a missing file is a rebuild that produced none
}

// Rebuild is how a built rebuild works.
type Rebuild struct {
	Turns         int `json:"turns"`           // model turns per rebuild at most
	FlightsPerFly int `json:"flights_per_fly"` // new flights a fly call may ask for at most
}

var idPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,15}$`)

func loadJob(path string) (*Job, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var j Job
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &j, j.check()
}

func (j *Job) check() error {
	if j.Fresh < 8 || j.Fresh > 512 {
		return fmt.Errorf("fresh: %d flights; use 8 to 512", j.Fresh)
	}
	if len(j.Courses) == 0 {
		return errors.New("the job has no course")
	}
	seen := map[string]bool{}
	for _, c := range j.Courses {
		if _, ok := courseIDs[c.ID]; !ok {
			return fmt.Errorf("course %q: no such course (easy or hard)", c.ID)
		}
		if seen[c.ID] {
			return fmt.Errorf("course %q twice", c.ID)
		}
		seen[c.ID] = true
		if len(c.Practice) < 4 {
			return fmt.Errorf("course %s: %d practice flights; the squeeze compares scores on at least 4", c.ID, len(c.Practice))
		}
		loops := map[string]bool{}
		for _, l := range c.Loops {
			if !idPattern.MatchString(l.ID) || l.ID == "none" || l.ID == "loop" {
				return fmt.Errorf("course %s: loop id %q", c.ID, l.ID)
			}
			loops[l.ID] = true
		}
		groups := map[string]bool{}
		for _, g := range c.Groups {
			if !idPattern.MatchString(g.ID) || groups[g.ID] {
				return fmt.Errorf("course %s: group id %q", c.ID, g.ID)
			}
			groups[g.ID] = true
			if g.From != "" && !loops[g.From] {
				return fmt.Errorf("course %s: group %s rebuilds from loop %q, which the course does not list", c.ID, g.ID, g.From)
			}
			if g.Build < 0 || g.Build > 64 || g.Build+len(g.Import) == 0 {
				return fmt.Errorf("course %s: group %s builds %d and imports %d; give it 1 to 64 rebuilds", c.ID, g.ID, g.Build, len(g.Import))
			}
		}
	}
	if j.builds() > 0 && (j.Rebuild.Turns < 1 || j.Rebuild.Turns > 200 || j.Rebuild.FlightsPerFly < 1 || j.Rebuild.FlightsPerFly > 64) {
		return fmt.Errorf("rebuild: %d turns and %d flights per fly call; use 1 to 200 and 1 to 64", j.Rebuild.Turns, j.Rebuild.FlightsPerFly)
	}
	return nil
}

// builds is how many rebuilds the caller's model makes in this job.
func (j *Job) builds() int {
	n := 0
	for _, c := range j.Courses {
		for _, g := range c.Groups {
			n += g.Build
		}
	}
	return n
}

func (c CourseJob) loop(id string) (Loop, bool) {
	for _, l := range c.Loops {
		if l.ID == id {
			return l, true
		}
	}
	return Loop{}, false
}

// SealedSet is a set of flights committed to by the SHA-256 of its file before any rebuild: the
// file is what every grading run receives, byte for byte, so its digest in a signed request is
// the commitment. The nonce makes the digest unguessable from the seeds' distribution alone.
type SealedSet struct {
	Name  string   `json:"name"`
	About string   `json:"about"`
	Nonce string   `json:"nonce,omitempty"`
	Seeds []uint32 `json:"seeds"`
}

// encode is the set's file, the bytes its digest is taken over.
func (s SealedSet) encode() []byte {
	b, err := json.MarshalIndent(s, "", " ")
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

func digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// practiceSet is a course's practice flights as the file grading runs receive.
func practiceSet(c CourseJob) SealedSet {
	return SealedSet{Name: "practice", About: "The loop's own validation flights on the " + c.ID + " course: the loop was graded on these every round; no rebuild sees them.", Seeds: slices.Clone(c.Practice)}
}

// loopsOnly is the job without its rebuild groups: the loops' own controllers alone
// (-loops-only), for flying them on another set of flights without grading every rebuild again.
func (j *Job) loopsOnly() *Job {
	c := *j
	c.Name = j.Name + "-loops"
	c.Courses = slices.Clone(j.Courses)
	for i := range c.Courses {
		c.Courses[i].Groups = nil
	}
	return &c
}

// givenFresh names a fresh set a run flies instead of drawing one (-fresh and -fresh-sha256): a
// file an earlier run published, and the SHA-256 that run committed to.
type givenFresh struct{ path, sha256 string }

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// loadFresh reads a given fresh set, so a run can fly its controllers on the flights of an
// earlier run: reproducing a published score, or flying a loop on another run's set. The file's
// SHA-256 must be the one named; it must be exactly the file encode writes for the set it holds,
// so grading runs receive those bytes and the digest stays the earlier run's commitment; and it
// must hold the job's number of flights under the rules sealFresh draws by (nine- or ten-digit
// seeds, none twice, none in avoid).
func loadFresh(g givenFresh, n int, avoid map[uint32]bool) (SealedSet, []byte, error) {
	if !sha256Hex.MatchString(g.sha256) {
		return SealedSet{}, nil, fmt.Errorf("-fresh-sha256 %q: give the set's SHA-256, 64 lowercase hex digits", g.sha256)
	}
	raw, err := os.ReadFile(g.path)
	if err != nil {
		return SealedSet{}, nil, err
	}
	if d := digest(raw); d != g.sha256 {
		return SealedSet{}, nil, fmt.Errorf("%s has SHA-256 %s, not %s", g.path, d, g.sha256)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s SealedSet
	if err := dec.Decode(&s); err != nil {
		return SealedSet{}, nil, fmt.Errorf("%s: %w", g.path, err)
	}
	if !bytes.Equal(s.encode(), raw) {
		return SealedSet{}, nil, fmt.Errorf("%s is not a sealed set file as this program writes one", g.path)
	}
	if s.Name != "fresh" {
		return SealedSet{}, nil, fmt.Errorf("%s is the %q set, not a fresh set", g.path, s.Name)
	}
	if len(s.Seeds) != n {
		return SealedSet{}, nil, fmt.Errorf("%s holds %d flights; the job's fresh set has %d", g.path, len(s.Seeds), n)
	}
	seen := map[uint32]bool{}
	for _, seed := range s.Seeds {
		if seed < 100_000_000 || avoid[seed] || seen[seed] {
			return SealedSet{}, nil, fmt.Errorf("%s: seed %d is under nine digits, listed twice, or a practice or smoke flight", g.path, seed)
		}
		seen[seed] = true
	}
	return s, raw, nil
}

// sealFresh draws n flights nobody has flown, from crypto/rand, refusing any seed in avoid.
func sealFresh(n int, avoid map[uint32]bool) (SealedSet, error) {
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return SealedSet{}, err
	}
	s := SealedSet{Name: "fresh", About: "Flights drawn at random for this run, sealed by the SHA-256 of this file before any controller flew them.", Nonce: hex.EncodeToString(nonce)}
	have := map[uint32]bool{}
	var b [4]byte
	for len(s.Seeds) < n {
		if _, err := rand.Read(b[:]); err != nil {
			return SealedSet{}, err
		}
		seed := binary.BigEndian.Uint32(b[:])
		// A seed below 100,000,000 is drawn again, so every sealed seed is a nine- or ten-digit
		// number: one the leak scan cannot mistake for a constant in a controller's code.
		if seed < 100_000_000 || avoid[seed] || have[seed] {
			continue
		}
		have[seed] = true
		s.Seeds = append(s.Seeds, seed)
	}
	return s, nil
}
