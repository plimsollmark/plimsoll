package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// Receipts signs every exchange the client checked into files under one directory,
// with plimsoll's attest harness. Each process writes only files it created: its own
// run segments (runs-<process>-<n>.jsonl, a new one every runsPerSegment runs or after
// a failed write, each ending in a checkpoint after every run, so it verifies whole at
// any moment) and one file per session it opened (session-<fingerprint>-<process>.jsonl,
// whole once the session's close is signed and checkpointed). One writer per file needs
// no lock, and an append never re-reads its file.
//
// A session's file holds its calls from the first, without a gap, or it is incomplete
// for good: a call whose receipt could not be stored is not in it, so no later close
// can make it whole. A close is signed into it only when the daemon's checked count and
// last record are those of the calls it holds.
//
// What a receipt proves: this harness checked the exchange against its record and
// signed it with the user's key. It is not an independent audit, and it says nothing
// of whether what the guest printed is true. A line verifies on its own with
// plimsoll-attest verify-entry; a whole file with plimsoll-attest verify.
type Receipts struct {
	dir      string
	signer   *attest.Signer
	keyID    string
	maxBytes int64
	process  string

	mu    sync.Mutex
	ended bool // Close was called: no new file is opened
	// used is what the directory held at measuredAt, as this process's own writes have
	// changed it since: each counted as it lands, a partial line or a cut back included.
	used       int64
	measuredAt time.Time        // when the walk behind used began
	measureErr error            // why the last walk failed, until one succeeds
	now        func() time.Time // time.Now; a test moves it
	walks      atomic.Int64     // walks finished, read before waiting for mu
	segment    int
	runs       *receiptFile
	sessions   map[string]*receiptFile // by session fingerprint, until settled
	index      map[string]*kept        // by record digest
	order      []string

	// For tests: the next write writes half its line and fails; the next file
	// creation fails; the next rollback's cut back fails; the write after the next
	// blockSkip closes blocking and waits for block to be closed, as a slow disk's sync
	// would.
	failNext, failCreate, failRollback bool
	block, blocking                    chan struct{}
	blockSkip                          int
}

// runsPerSegment bounds a run segment, so a verifier never reads one huge file.
const runsPerSegment = 500

type receiptFile struct {
	name   string
	f      *os.File // nil once ended
	w      *lineWriter
	h      *attest.Harness
	state  string // runs: "none"; a session's: "open", "closed" or "incomplete"
	calls  uint64 // a session's: the sequence of the last call stored
	last   string // a session's: the record digest of the last call stored
	note   string // set when a later failure leaves this file's tail uncertain
	reason string // why a session's receipts are incomplete
}

// fail ends a session's file as incomplete for good, keeping the first reason.
func (rf *receiptFile) fail(reason string) {
	rf.end("incomplete")
	if rf.reason == "" {
		rf.reason = reason
	}
}

// end closes the file, once, and sets its final state ("" keeps it).
func (rf *receiptFile) end(state string) {
	if rf.f != nil {
		_ = rf.f.Close()
		rf.f = nil
	}
	if state != "" {
		rf.state = state
	}
}

type kept struct {
	file *receiptFile
	line int
	sum  string
}

// lineWriter passes each line the harness writes to the file and remembers it.
type lineWriter struct {
	f     *os.File
	r     *Receipts
	lines int
	last  []byte
}

func (w *lineWriter) Write(p []byte) (int, error) {
	if ch := w.r.block; ch != nil && w.r.blockSkip > 0 {
		w.r.blockSkip--
	} else if ch != nil {
		w.r.block = nil
		close(w.r.blocking)
		<-ch
	}
	if w.r.failNext {
		// As a disk that fills mid-line: half the line lands, then the write fails.
		w.r.failNext = false
		n, _ := w.f.Write(p[:len(p)/2])
		return n, errors.New("the receipt write failed (test)")
	}
	n, err := w.f.Write(p)
	if err == nil {
		w.lines++
		w.last = append(w.last[:0], p...)
	}
	return n, err
}

// Receipt is what a result or get_record says of a run's record.
type Receipt struct {
	// Status is stored (the signed line is written and synced) or failed (keeping the
	// record failed: Reason; a checked result is still returned).
	Status string `json:"status"`
	// Scope is what a check of the line establishes: "entry", the line on its own.
	Scope string `json:"scope,omitempty"`
	// Session is "none" for a fresh run; for a sandbox call "open" until its session's
	// close is signed, then "closed", or "incomplete" if this server lost the chance or
	// a call of the session could not be stored.
	Session    string `json:"session,omitempty"`
	File       string `json:"file,omitempty"`
	Line       int    `json:"line,omitempty"`
	LineSHA256 string `json:"lineSha256,omitempty"`
	KeyID      string `json:"keyId,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

// OpenReceipts opens dir (created owner-only if absent) for this process's receipts,
// signing with the Ed25519 key in keyFile. It refuses a directory or key file that
// other users can read, and a directory that is a symbolic link: receipts hold the code
// and its output in full, and the key forges receipts. On Windows it refuses outright:
// file access there is a matter of access-control lists, which this does not yet set
// or check, so the confidentiality it promises could not be kept.
func OpenReceipts(dir, keyFile string, maxBytes int64) (*Receipts, error) {
	if runtime.GOOS == "windows" {
		return nil, errors.New("receipts are not supported on Windows yet: access-control lists that keep the key and the receipts private are neither set nor checked")
	}
	if err := ownerOnly(keyFile, false); err != nil {
		return nil, err
	}
	pemBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return nil, err
	}
	key, err := attest.ParsePrivateKey(pemBytes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	if err := mkdirPrivate(dir); err != nil {
		return nil, err
	}
	if err := ownerOnly(dir, true); err != nil {
		return nil, err
	}
	// The directory's name, and its parents', must be on disk before any receipt in it
	// is called stored: synced up the whole chain on every start, so a sync that failed
	// before, at any level, or a directory another process made, is made durable now.
	// The walk stops at a directory this user may neither open nor write, where no
	// process of this user's can have made the entry below it; one it may write but not
	// open could hold an entry this user made, which cannot be synced, so it refuses.
	for d := filepath.Clean(dir); ; {
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
		if err := syncDir(parent); err != nil {
			if errors.Is(err, fs.ErrPermission) && !writable(parent) {
				break
			}
			if errors.Is(err, fs.ErrPermission) {
				return nil, fmt.Errorf("syncing %s, a parent of the receipts directory: this user may make entries there but not open it, so an entry made there cannot be made durable; let it read the directory, or choose another receipts directory: %w", parent, err)
			}
			return nil, fmt.Errorf("syncing %s, a parent of the receipts directory: %w", parent, err)
		}
		d = parent
	}
	var id [4]byte
	_, _ = rand.Read(id[:])
	r := &Receipts{
		dir:      dir,
		signer:   attest.NewSigner(key),
		keyID:    attest.KeyID(key.Public().(ed25519.PublicKey)),
		maxBytes: maxBytes,
		process:  fmt.Sprintf("%s-%x", time.Now().UTC().Format("20060102T150405Z"), id),
		sessions: map[string]*receiptFile{},
		index:    map[string]*kept{},
		now:      time.Now,
	}
	start := r.now()
	used, err := r.measure()
	if err != nil {
		return nil, err
	}
	r.used, r.measuredAt = used, start
	return r, nil
}

// mkdirPrivate creates dir and any missing parents, each owner-only, syncing each new
// one's parent so the names survive a crash of the host.
func mkdirPrivate(dir string) error {
	dir = filepath.Clean(dir)
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(dir)
	if parent != dir {
		if err := mkdirPrivate(parent); err != nil {
			return err
		}
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := syncDir(parent); err != nil {
		return fmt.Errorf("syncing %s, where %s was made: %w", parent, filepath.Base(dir), err)
	}
	return nil
}

// ownerOnly refuses a path its group or others can access, and (for a directory) a
// symbolic link or a non-directory.
func ownerOnly(path string, dir bool) error {
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if dir && st.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symbolic link; give the receipts directory itself", path)
	}
	if dir && !st.IsDir() {
		return fmt.Errorf("%s is not a directory", path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s is open to other users (mode %v); it holds what receipts must keep private: chmod %s it", path, st.Mode().Perm(), map[bool]string{true: "700", false: "600"}[dir])
	}
	return nil
}

// syncDir syncs a directory, so an entry made in it survives a crash of the host (a
// variable, so a test can make it fail).
var syncDir = func(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// measure is the directory's size now, every writer's files included.
func (r *Receipts) measure() (int64, error) {
	var used int64
	err := filepath.WalkDir(r.dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, ierr := d.Info()
		switch {
		case errors.Is(ierr, fs.ErrNotExist): // removed since it was listed
		case ierr != nil:
			return ierr // a size it cannot read is not a size of zero
		case info.Mode().IsRegular():
			used += info.Size()
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return used, nil
}

// quotaRefresh is how old the directory's measurement may get before Full measures it
// again, for the files of other writers (another server sharing the directory) and any
// the user moved away; this process's own writes count as they land. A walk costs about
// 1.4 us a file (ext4, warm cache): 143 ms at 100,000 files, so one every 30 s is under
// 0.5% of a core with calls back to back, and 30 s is under one run's 50 s timeout, so
// another process's receipts are seen within about one of its calls. A variable, so a
// test can move it.
var quotaRefresh = 30 * time.Second

// Full refuses new work, before anything runs, once the directory holds maxBytes;
// checked at admission and again at dispatch. This process's own writes count as they
// land. The directory is measured again (every writer's files, and none the user moved
// away) once its last measurement is quotaRefresh old, and on every check at or past the
// limit, so deleting receipts lets work in at once. It is a threshold, not a
// reservation: work admitted under the limit may take the directory past it, and
// another writer's files can go unseen for up to quotaRefresh.
func (r *Receipts) Full() error {
	seen := r.walks.Load()
	if quotaJoin != nil {
		quotaJoin()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	due := now.Sub(r.measuredAt) >= quotaRefresh || r.used >= r.maxBytes || r.measureErr != nil
	// A check that waited while another walked takes that walk's answer, so checks at
	// once share one walk; a check after it walks again, so receipts moved away let
	// work in. Measured under mu: none of this process's writes lands during the walk,
	// so each is in the measurement or counted after it, never both.
	if due && r.walks.Load() == seen {
		used, err := r.measure()
		r.walks.Add(1)
		r.measureErr = err
		if err == nil {
			// Its age counts from when it began: a file it read early may have grown since.
			r.used, r.measuredAt = used, now
		}
	}
	if r.measureErr != nil {
		return fmt.Errorf("measuring the receipts directory: %w", r.measureErr)
	}
	if r.used >= r.maxBytes {
		return fmt.Errorf("the receipts directory holds %d MB, its limit (PLIMSOLL_RECEIPTS_MAX_MB); move or delete old receipts", r.used>>20)
	}
	return nil
}

// quotaJoin, when set, is called by a check after it has noted the walks so far and
// before it waits for mu; a test uses it to line checks up.
var quotaJoin func()

// count adds what an append changed rf's size by, a partial line or a cut back included;
// when the size cannot be read, the next check measures the directory instead.
func (r *Receipts) count(rf *receiptFile, before int64) {
	st, err := rf.f.Stat()
	if err != nil {
		r.measuredAt = time.Time{}
		return
	}
	r.used += st.Size() - before
}

var errEnded = errors.New("the receipt store has ended: the server is shutting down")

func (r *Receipts) create(name, state string) (*receiptFile, error) {
	if r.failCreate {
		r.failCreate = false
		return nil, errors.New("the receipt file could not be created (test)")
	}
	path := filepath.Join(r.dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syncDir(r.dir); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, err
	}
	w := &lineWriter{f: f, r: r}
	return &receiptFile{name: name, f: f, w: w, h: attest.NewHarness(r.signer, w), state: state}, nil
}

// append writes one entry through rf, ends it with a checkpoint when the file must
// verify whole after every entry, and syncs. On failure the file is cut back to where
// it was and the caller ends it; a cut back that fails or cannot be synced is reported,
// and marked on the file's earlier receipts.
func (r *Receipts) append(rf *receiptFile, record func(*attest.Harness) error, checkpoint bool) (line int, sum string, err error) {
	before, serr := rf.f.Seek(0, 1) // the file's size: it is only ever appended to
	if serr != nil {
		return 0, "", serr
	}
	defer r.count(rf, before)
	err = record(rf.h)
	if err == nil {
		line = rf.w.lines
		sum = lineSum(rf.w.last)
		if checkpoint {
			err = rf.h.Checkpoint()
		}
	}
	if err == nil {
		err = rf.f.Sync()
	}
	if err == nil {
		return line, sum, nil
	}
	var terr error
	if r.failRollback {
		r.failRollback = false
		terr = errors.New("the cut back failed (test)")
	} else {
		terr = rf.f.Truncate(before)
	}
	switch {
	case terr != nil:
		err = fmt.Errorf("%w; cutting %s back failed too (%v), so it may hold part of a line", err, rf.name, terr)
		rf.note = "a later write to this file failed and could not be cut back: check the file with plimsoll-attest verify"
	default:
		if serr := rf.f.Sync(); serr != nil {
			err = fmt.Errorf("%w; the cut back of %s could not be synced (%v), so after a crash it may hold part of a line", err, rf.name, serr)
			rf.note = "a later write to this file failed and its cut back could not be synced: after a crash, check the file with plimsoll-attest verify"
		}
	}
	return 0, "", err
}

func lineSum(line []byte) string {
	h := sha256.Sum256(bytes.TrimSuffix(line, []byte{'\n'}))
	return hex.EncodeToString(h[:])
}

func (r *Receipts) keep(recordSHA256 string, rf *receiptFile, line int, sum string) {
	if _, ok := r.index[recordSHA256]; !ok {
		r.order = append(r.order, recordSHA256)
	}
	r.index[recordSHA256] = &kept{file: rf, line: line, sum: sum}
	for len(r.order) > KeptRecords {
		delete(r.index, r.order[0])
		r.order = r.order[1:]
	}
}

// Record signs a checked exchange: a single run into this process's run segment, a
// session call into its session's file. It is the client.Recorder.
func (r *Receipts) Record(req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return errEnded
	}
	rec := resp.GetRecord()
	if fp := rec.GetSession(); fp != "" {
		return r.sessionAppend(fp, rec.GetSequence(), rec.GetRecordSha256(), func(h *attest.Harness) error { return h.Record(req, resp) })
	}
	if r.runs == nil || r.runs.w.lines >= 2*runsPerSegment {
		if r.runs != nil {
			r.runs.end("")
		}
		r.segment++
		rf, err := r.create(fmt.Sprintf("runs-%s-%04d.jsonl", r.process, r.segment), "none")
		if err != nil {
			r.runs = nil
			return err
		}
		r.runs = rf
	}
	rf := r.runs
	line, sum, err := r.append(rf, func(h *attest.Harness) error { return h.Record(req, resp) }, true)
	if err != nil {
		rf.end("") // the next run starts a new segment
		r.runs = nil
		return err
	}
	r.keep(rec.GetRecordSha256(), rf, line, sum)
	return nil
}

// sessionAppend stores call seq of session fp, which must follow the last call stored.
func (r *Receipts) sessionAppend(fp string, seq uint64, digest string, record func(*attest.Harness) error) error {
	rf, err := r.sessionFile(fp, seq == 1)
	if err != nil {
		return err
	}
	if seq != rf.calls+1 {
		err := fmt.Errorf("session %s…'s receipts are incomplete: call %d follows call %d", prefix(fp), seq, rf.calls)
		rf.fail(err.Error())
		return err
	}
	line, sum, err := r.append(rf, record, false)
	if err != nil {
		rf.fail(fmt.Sprintf("call %d's receipt could not be stored: %v", seq, err))
		return err
	}
	rf.calls, rf.last = seq, digest
	r.keep(digest, rf, line, sum)
	return nil
}

// sessionFile returns fp's open file, creating it when allowed (a session's first call,
// or a close of a session that ran none). A session whose file could not be created is
// remembered as incomplete, so nothing later makes a file that skips its first calls.
func (r *Receipts) sessionFile(fp string, mayCreate bool) (*receiptFile, error) {
	rf := r.sessions[fp]
	if rf == nil {
		if !mayCreate {
			err := fmt.Errorf("session %s…'s receipts are incomplete: its earlier calls are in no file", prefix(fp))
			r.sessions[fp] = &receiptFile{state: "incomplete", reason: err.Error()}
			return nil, err
		}
		created, err := r.create(fmt.Sprintf("session-%s-%s.jsonl", prefix(fp), r.process), "open")
		if err != nil {
			r.sessions[fp] = &receiptFile{state: "incomplete", reason: fmt.Sprintf("the session's receipt file could not be created: %v", err)}
			return nil, err
		}
		r.sessions[fp] = created
		return created, nil
	}
	if rf.state != "open" {
		return nil, fmt.Errorf("session %s…'s receipts are %s: %s", prefix(fp), rf.state, rf.reason)
	}
	return rf, nil
}

func prefix(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// RecordUnanswered signs the record of a session call that may have run.
func (r *Receipts) RecordUnanswered(req *plimsollv1.RunRequest, rec *plimsollv1.RunRecord) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return errEnded
	}
	return r.sessionAppend(rec.GetSession(), rec.GetSequence(), rec.GetRecordSha256(), func(h *attest.Harness) error { return h.RecordUnanswered(req, rec) })
}

// RecordClose signs a session's close and checkpoints its file, which is then whole,
// but only when the close's count and last record are those of the calls stored.
func (r *Receipts) RecordClose(session string, calls uint64, last string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ended {
		return errEnded
	}
	rf, err := r.sessionFile(session, calls == 0)
	if err != nil {
		return err
	}
	if calls != rf.calls || last != rf.last {
		err := fmt.Errorf("session %s…'s close counts %d calls, its file holds %d: the receipts are incomplete", prefix(session), calls, rf.calls)
		rf.fail(err.Error())
		return err
	}
	if _, _, err := r.append(rf, func(h *attest.Harness) error {
		if err := h.RecordClose(session, calls, last); err != nil {
			return err
		}
		return h.Checkpoint()
	}, false); err != nil {
		rf.fail(fmt.Sprintf("the session's signed close could not be stored: %v", err))
		return err
	}
	rf.end("closed") // kept until settle reports it
	return nil
}

// unseen ends a session's receipts as incomplete when its close counted calls this
// server never saw answered: their records are in no file. A session none of whose calls
// was stored has no file to fail, and would otherwise settle as closed.
func (r *Receipts) unseen(fingerprint string) {
	if r == nil || fingerprint == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	reason := fmt.Sprintf("session %s…'s close counts calls this server never saw answered, so their records are in no file", prefix(fingerprint))
	if rf := r.sessions[fingerprint]; rf != nil {
		rf.fail(reason)
		return
	}
	r.sessions[fingerprint] = &receiptFile{state: "incomplete", reason: reason}
}

// settle lets a session go once this server has, and says how its receipts ended:
// closed (its signed close is stored), or incomplete with the reason; a file still open
// (its close never signed) is incomplete, whatever became of the sandbox. A session that
// ran no call and was never closed has nothing to keep: closed. The store forgets the
// session; its receipts keep their state.
func (r *Receipts) settle(fingerprint string) (state, reason string) {
	if r == nil || fingerprint == "" {
		return "", ""
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	rf := r.sessions[fingerprint]
	if rf == nil {
		return "closed", ""
	}
	if rf.state == "open" {
		rf.fail("the session ended without a signed close")
	} else {
		rf.end("")
	}
	delete(r.sessions, fingerprint)
	return rf.state, rf.reason
}

// Close ends the store: the run segment (whole after each run) and every session file
// still open, which is then incomplete. Nothing is written or created after it.
func (r *Receipts) Close() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ended = true
	if r.runs != nil {
		r.runs.end("")
		r.runs = nil
	}
	for fp, rf := range r.sessions {
		if rf.state == "open" {
			rf.fail("the server shut down before the session's close was signed")
		} else {
			rf.end("")
		}
		delete(r.sessions, fp)
	}
}

// receiptOf is the receipt of a checked record, given the error that came with its
// result (nil, or one wrapping ErrNotRecorded).
func (r *Receipts) receiptOf(recordSHA256 string, err error) *Receipt {
	if err != nil {
		return &Receipt{Status: "failed", Reason: shown(err)}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	k := r.index[recordSHA256]
	if k == nil {
		return &Receipt{Status: "failed", Reason: "this server has no receipt for the record"}
	}
	// A session that ended incomplete says why here too: a model that never closed the
	// sandbox (the host ended the server, the sandbox expired) has no other answer saying so.
	reason := k.file.note
	if k.file.state == "incomplete" && k.file.reason != "" {
		reason = strings.TrimSuffix(k.file.reason+"; "+reason, "; ")
	}
	return &Receipt{Status: "stored", Scope: "entry", Session: k.file.state, File: k.file.name, Line: k.line, LineSHA256: k.sum, KeyID: r.keyID, Reason: reason}
}
