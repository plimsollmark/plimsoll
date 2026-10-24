// Package runsclog reads the log gVisor's runsc writes outside a sandbox when it runs with
// --debug --strace --debug-log-format=json, and returns what the programs inside attempted:
// the programs started, the files opened for writing and written, the files made, renamed,
// linked and removed, and the network calls with their destinations.
//
// The log is written by gVisor's kernel, outside the sandbox, so the package under
// observation cannot remove an entry or add one. It does choose some of the text inside
// entries: file names, process names, the paths it passes. The reader is built so that no
// such text can add an event, remove one or change one's kind:
//
//   - Only the JSON form is read. The text form prints paths raw, so a newline in a file name
//     writes what looks like a whole entry of its own (measured on runsc release-20260907.0).
//     In JSON every entry is one object with the package's text escaped inside it.
//   - Each syscall entry is read against the argument layout gVisor prints for that call, and
//     every way of splitting it into those arguments is tried. An entry is used only when
//     exactly one split fits; otherwise it is listed as unclear, never guessed.
//   - A program counts as started only when gVisor's loader logs a new stack for the thread
//     after its execve: the exit line of an execve reads 0 even when the file does not exist.
//   - A written file is named by the path gVisor resolves for the descriptor (a write through
//     a symlink names the file it reached), not by the path the program passed to open.
//
// A log is refused whole (Read returns an error) when it is not JSON, ends inside an entry,
// lacks runsc's closing line, carries anything between entries (gVisor's lost-lines marker
// is written there), or names a runsc release this reader has not been checked against.
package runsclog

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Supported lists the runsc releases whose log this reader has been checked against. The
// entries it relies on (the strace layout, the loader's stack line, the closing line) are
// debug output with no stability promise, so another release is refused until it is checked.
var Supported = []string{"release-20260907.0"}

// Errors that refuse a log whole.
var (
	ErrNotJSON     = errors.New("not runsc's JSON log (start runsc with --debug-log-format=json)")
	ErrIncomplete  = errors.New("the log is incomplete")
	ErrUnsupported = errors.New("the log names a runsc release this reader has not been checked against")
)

// Trace is what a log shows the programs in the sandbox attempted.
type Trace struct {
	// Runsc is the release the log names.
	Runsc string `json:"runsc"`
	// Processes lists every process that made a call the reader follows, in order of first
	// appearance.
	Processes []*Process `json:"processes"`
	// Written lists the files written, by process, named where each write landed.
	Written []*Written `json:"written"`
	// Opened lists the opens that asked to write, create or truncate, with the path as the
	// program passed it.
	Opened []*Opened `json:"opened"`
	// Changes lists directories made and removed and files renamed, linked, removed and
	// truncated, with paths as the program passed them.
	Changes []Change `json:"changes"`
	// Network lists sockets made, connections tried, addresses bound and data sent.
	Network []Net `json:"network"`
	// Unclear lists entries of calls this reader follows that it could not read as exactly
	// one event, with why.
	Unclear []Unclear `json:"unclear"`
	// Entries counts the log's entries; Calls counts the syscall entries among them.
	Entries int `json:"entries"`
	Calls   int `json:"calls"`
}

// Process is one process seen in the log.
type Process struct {
	// PID is the process's ID in its container's PID namespace, as the program saw it.
	PID int `json:"pid"`
	// Parent is the PID of the process that made it, or 0 when the log does not show it.
	Parent int `json:"parent,omitempty"`
	// Programs lists the programs gVisor loaded into it, in order.
	Programs []Program `json:"programs,omitempty"`
	// Exit is the status it passed to exit_group, when the log shows one.
	Exit *int `json:"exit,omitempty"`

	key int // the thread group's ID in the sandbox's root namespace, unique in a log
	cwd string
}

// Program is one program gVisor loaded into a process: its execve, then the loader's new
// stack. The loader logs the stack before mapping it, so a start that fails while the stack
// is mapped (under a tiny memory limit the program sets on itself) also shows here; the
// attempt is real either way, and no start that succeeded is missing. The environment the
// program was given is not kept: it is logged in full and can hold secrets. Its arguments
// are kept, and can hold whatever the program passed on its command line.
type Program struct {
	Path string   `json:"path"`
	Argv []string `json:"argv,omitempty"`
	// ByRunsc marks the container's first program, which runsc starts without an execve.
	ByRunsc bool `json:"by_runsc,omitempty"`
	// Unclear marks a start whose execve entry the reader could not read (Trace.Unclear
	// holds it): a program was loaded, and the log does not say plainly which.
	Unclear bool `json:"unclear,omitempty"`
}

// Written is the bytes one process wrote to one file, as the calls returned them. Path is
// gVisor's name for the descriptor at the write: a write through a symlink names the file
// it reached.
type Written struct {
	Path  string `json:"path"`
	PID   int    `json:"pid"`
	Bytes int64  `json:"bytes"`
}

// Opened is one open that asked to write, create or truncate. Path is the path the program
// passed, joined to the directory it was relative to where the log names one, and not
// cleaned: a symlink in it can make the open land elsewhere, and ".." after a symlink
// leaves a different directory than its text suggests.
type Opened struct {
	Path string `json:"path"`
	// Reached is gVisor's name for the file the open reached, when a later entry of the
	// same thread names the descriptor and no thread in the sandbox freed that descriptor
	// number in between; "" when the log does not tie them that safely.
	Reached  string `json:"reached,omitempty"`
	PID      int    `json:"pid"`
	Create   bool   `json:"create,omitempty"`
	Truncate bool   `json:"truncate,omitempty"`
	Result   string `json:"result"` // "ok", or the error: attempted, not done
}

// Change is a directory made or removed, or a file renamed, linked, removed or truncated.
// Paths are as the program passed them (see Opened.Path), except a truncate through a
// descriptor, which gVisor names.
type Change struct {
	Kind   string `json:"kind"` // mkdir, rmdir, unlink, rename, link, symlink, truncate, memfd
	Path   string `json:"path"`
	Path2  string `json:"path2,omitempty"` // the new name of a rename or link; the link of a symlink
	PID    int    `json:"pid"`
	Result string `json:"result"` // "ok", or the error
}

// Net is one network call.
type Net struct {
	Kind   string `json:"kind"` // socket, connect, bind, listen, send
	PID    int    `json:"pid"`
	Family string `json:"family,omitempty"`
	Type   string `json:"type,omitempty"`
	Addr   string `json:"addr,omitempty"`
	Port   int    `json:"port,omitempty"`
	Result string `json:"result"` // "ok", the error, or "unknown" when the call never returned
	Note   string `json:"note,omitempty"`
}

// Unclear is an entry the reader could not read as exactly one event. Entry is the entry's
// text, cut to maxEntry bytes; an execve entry's text is withheld, since it holds the
// program's environment.
type Unclear struct {
	PID   int    `json:"pid"`
	Call  string `json:"call"`
	Entry string `json:"entry"`
	Why   string `json:"why"`
}

// Read reads one runsc boot log in its JSON form.
func Read(r io.Reader) (*Trace, error) {
	dec := json.NewDecoder(bufio.NewReaderSize(r, 1<<20))
	st := newState()
	closed := false
	for {
		var e struct {
			Msg *string `json:"msg"`
		}
		err := dec.Decode(&e)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			var syn *json.SyntaxError
			switch {
			case st.t.Entries == 0:
				return nil, ErrNotJSON
			case errors.Is(err, io.ErrUnexpectedEOF):
				return nil, fmt.Errorf("%w: it ends inside an entry, after %d entries", ErrIncomplete, st.t.Entries)
			case errors.As(err, &syn):
				return nil, fmt.Errorf("%w: text that is not an entry at byte %d (gVisor writes its lost-lines marker between entries)", ErrIncomplete, syn.Offset)
			}
			return nil, err
		}
		if e.Msg == nil {
			return nil, fmt.Errorf("%w: entry %d has no msg", ErrNotJSON, st.t.Entries+1)
		}
		st.t.Entries++
		if done, err := st.entry(*e.Msg); err != nil {
			return nil, err
		} else if done {
			closed = true
		}
	}
	if st.t.Entries == 0 {
		return nil, ErrNotJSON
	}
	if st.t.Runsc == "" {
		return nil, fmt.Errorf("%w: no Version line", ErrUnsupported)
	}
	if !closed {
		return nil, fmt.Errorf("%w: no closing line (runsc's \"Exiting with status\"), after %d entries", ErrIncomplete, st.t.Entries)
	}
	st.finish()
	return st.t, nil
}

var (
	locRE     = regexp.MustCompile(`(?s)^([A-Za-z0-9_]+\.go):\d+\] (.*)$`)
	versionRE = regexp.MustCompile(`^Version (\S+), `)
	idsRE     = regexp.MustCompile(`(?s)^\[\s*(\d+)(?:\(\s*(\d+)\))?:\s*(\d+)(?:\(\s*(\d+)\))?\] (.*)$`)
	stackRE   = regexp.MustCompile(`^Allocating stack with size of \d+ bytes$`)
	callRE    = regexp.MustCompile(` ([EX]) ([a-z0-9_]+)\(`)
	retRE     = regexp.MustCompile(`\) = (?:(-?\d+) \(0x[0-9a-f]+\)|-1 errno=(\d+) \(([^()]*)\)) \([^()]*\)$`)
)

// maxComm is the most runes a process name can take: Linux keeps 15 bytes, and JSON shows an
// invalid byte as one replacement rune.
const maxComm = 15

// maxEntry is the most bytes of an unclear entry's text the trace keeps.
const maxEntry = 2048

type ids struct{ tgRoot, tgNS, tidRoot int }

type thrFD struct{ tid, fd int }

type writeKey struct {
	proc int
	path string
}

// tie is an open waiting for a later entry of its own thread to name its descriptor.
type tie struct {
	o     *Opened
	since int // the entry index of the open's entry line
}

type pending struct {
	call string
	args []string
	proc *Process
	at   int // the entry index
}

type state struct {
	t        *Trace
	procs    map[int]*Process
	children map[int][]int // child PID in the caller's namespace -> the keys of every caller that got it
	exec     map[int]*Program
	ties     map[thrFD]*tie
	freed    map[int]int // descriptor number -> the last entry index any thread freed it at
	freedAll int         // the last entry index a close_range freed too many numbers to list
	execAt   map[int]int // thread-group root id -> last exec attempt, which may close descriptors
	written  map[writeKey]*Written
	inflight map[int]pending // a thread's entry line, until its exit line
}

func newState() *state {
	return &state{
		t: &Trace{Processes: []*Process{}, Written: []*Written{}, Opened: []*Opened{}, Changes: []Change{},
			Network: []Net{}, Unclear: []Unclear{}},
		procs:    map[int]*Process{},
		children: map[int][]int{},
		exec:     map[int]*Program{},
		ties:     map[thrFD]*tie{},
		freed:    map[int]int{},
		execAt:   map[int]int{},
		written:  map[writeKey]*Written{},
		inflight: map[int]pending{},
	}
}

// entry reads one log entry and reports whether it is runsc's closing line.
func (st *state) entry(msg string) (bool, error) {
	m := locRE.FindStringSubmatch(msg)
	if m == nil {
		return false, nil
	}
	file, body := m[1], m[2]
	if file == "cli.go" {
		if v := versionRE.FindStringSubmatch(body); v != nil {
			if st.t.Runsc != "" && st.t.Runsc != v[1] {
				return false, fmt.Errorf("%w: two releases, %s and %s", ErrUnsupported, st.t.Runsc, v[1])
			}
			if !slices.Contains(Supported, v[1]) {
				return false, fmt.Errorf("%w: %s", ErrUnsupported, v[1])
			}
			st.t.Runsc = v[1]
		}
		return strings.HasPrefix(body, "Exiting with status: "), nil
	}
	im := idsRE.FindStringSubmatch(body)
	if im == nil {
		return false, nil
	}
	id := ids{tgRoot: atoi(im[1]), tidRoot: atoi(im[3])}
	id.tgNS = id.tgRoot
	if im[2] != "" {
		id.tgNS = atoi(im[2])
	}
	rest := im[5]
	if file == "strace.go" {
		st.call(id, rest)
		return false, nil
	}
	if stackRE.MatchString(rest) {
		p := st.proc(id)
		if prog := st.exec[id.tidRoot]; prog != nil {
			p.Programs = append(p.Programs, *prog)
			delete(st.exec, id.tidRoot)
		} else {
			p.Programs = append(p.Programs, Program{ByRunsc: true})
		}
	}
	return false, nil
}

func (st *state) proc(id ids) *Process {
	if p := st.procs[id.tgRoot]; p != nil {
		return p
	}
	p := &Process{PID: id.tgNS, key: id.tgRoot}
	if parents := st.children[id.tgNS]; len(parents) == 1 {
		// The parent's fork line came first, as it usually does: inherit its directory now.
		// finish links the rest, since a child can be logged before its parent's fork returns.
		if pp := st.procs[parents[0]]; pp != nil {
			p.Parent = pp.PID
			p.cwd = pp.cwd
		}
	}
	st.procs[id.tgRoot] = p
	st.t.Processes = append(st.t.Processes, p)
	return p
}

// call reads one syscall entry: the process name, E or X, the call and its arguments.
// gVisor's own marker (" E name(" or " X name(") follows the process name, which is at
// most maxComm runes; a second marker inside that window can only come from the name, so
// the entry is unclear rather than read either way.
func (st *state) call(id ids, rest string) {
	var marks [][]int
	for _, loc := range callRE.FindAllStringSubmatchIndex(rest, -1) {
		if runeCount(rest[:loc[0]]) > maxComm {
			break
		}
		marks = append(marks, loc)
	}
	followed := ""
	for _, loc := range marks {
		if _, ok := specs[rest[loc[4]:loc[5]]]; ok {
			followed = rest[loc[4]:loc[5]]
		}
	}
	if followed == "" {
		return // a call this reader does not follow
	}
	st.t.Calls++
	p := st.proc(id)
	if len(marks) > 1 {
		st.unclearOn(id, p, followed, rest, "the process name holds a call marker")
		return
	}
	loc := marks[0]
	exit := rest[loc[2]:loc[3]] == "X"
	tail := rest[loc[1]:]
	var args, ret string
	if exit {
		rm := retRE.FindStringSubmatchIndex(tail)
		if rm == nil {
			st.unclearOn(id, p, followed, rest, "no return value where gVisor prints one")
			return
		}
		args = tail[:rm[0]]
		if rm[2] >= 0 {
			ret = tail[rm[2]:rm[3]]
		} else {
			ret = "errno=" + tail[rm[4]:rm[5]] + " (" + tail[rm[6]:rm[7]] + ")"
		}
	} else {
		if !strings.HasSuffix(tail, ")") {
			st.unclearOn(id, p, followed, rest, "the entry line does not close")
			return
		}
		args = tail[:len(tail)-1]
	}
	readings := split(specs[followed], args)
	switch {
	case len(readings) == 0:
		st.unclearOn(id, p, followed, rest, "no reading of its arguments fits the layout gVisor prints for it")
		return
	case len(readings) > 1:
		st.unclearOn(id, p, followed, rest, "more than one reading of its arguments fits")
		return
	}
	f := readings[0]
	if !exit {
		st.entering(id, p, followed, f)
		st.inflight[id.tidRoot] = pending{call: followed, args: f, proc: p, at: st.t.Entries}
		return
	}
	pe, ok := st.inflight[id.tidRoot]
	delete(st.inflight, id.tidRoot)
	if !ok || pe.call != followed {
		pe = pending{at: st.t.Entries}
	}
	st.exit(id, p, followed, f, ret, pe)
}

// entering acts on an entry line for what must be read before the call runs: a descriptor
// its own thread names, and descriptor numbers the call frees, which another thread can be
// given before this call's exit line is logged.
func (st *state) entering(id ids, p *Process, call string, f []string) {
	switch call {
	case "execve", "execveat":
		// Exec may close O_CLOEXEC descriptors and replaces the thread group. A later
		// descriptor name must not resolve an open from before this attempt.
		st.execAt[id.tgRoot] = st.t.Entries
	case "close":
		fd, name := fdArg(f[0])
		st.resolve(id, fd, name)
		st.free(fd)
	case "dup2", "dup3":
		fd, name := fdArg(f[0])
		st.resolve(id, fd, name)
		newfd, _ := fdArg(f[1])
		st.free(newfd)
	case "close_range":
		first, _ := fdArg(f[0])
		last, _ := fdArg(f[1])
		if first < 0 || last < first || last-first > 4096 {
			st.freedAll = st.t.Entries
			return
		}
		for n := first; n <= last; n++ {
			st.free(n)
		}
	}
}

func (st *state) free(fd int) {
	if fd >= 0 {
		st.freed[fd] = st.t.Entries
	}
}

// resolve ties an open of this thread to gVisor's name for its descriptor, unless any
// thread freed that descriptor number since the open's entry line: the number may then
// name another file.
func (st *state) resolve(id ids, fd int, name string) {
	k := thrFD{id.tidRoot, fd}
	t := st.ties[k]
	if t == nil {
		return
	}
	delete(st.ties, k)
	if !strings.HasPrefix(name, "/") || st.freed[fd] > t.since || st.freedAll > t.since || st.execAt[id.tgRoot] > t.since {
		return
	}
	t.o.Reached = name
}

func (st *state) unclear(p *Process, call, raw, why string) {
	if call == "execve" || call == "execveat" {
		st.execAt[p.key] = st.t.Entries
		raw = fmt.Sprintf("(%d bytes withheld: an execve entry holds the program's environment)", len(raw))
	} else if len(raw) > maxEntry {
		cut := maxEntry
		for cut > 0 && !utf8.RuneStart(raw[cut]) {
			cut--
		}
		raw = raw[:cut] + "..."
	}
	st.t.Unclear = append(st.t.Unclear, Unclear{PID: p.PID, Call: call, Entry: raw, Why: why})
}

// unclearOn records an unclear entry of a thread, so that a program it starts next is marked
// unclear instead of passing for runsc's own first program.
func (st *state) unclearOn(id ids, p *Process, call, raw, why string) {
	st.unclear(p, call, raw, why)
	if call == "execve" || call == "execveat" {
		st.exec[id.tidRoot] = &Program{Unclear: true}
	}
}

// exit turns one call that returned into events; ret is the value, or "errno=N (text)", and
// pe is the call's entry line when the log shows it.
func (st *state) exit(id ids, p *Process, call string, f []string, ret string, pe pending) {
	ok := !strings.HasPrefix(ret, "errno=")
	result := "ok"
	if !ok {
		result = ret
	}
	n, _ := strconv.ParseInt(ret, 10, 64)
	switch call {
	case "fork", "vfork", "clone", "clone3":
		if ok && n > 0 && !(call == "clone" && strings.Contains(f[0], "CLONE_THREAD")) {
			st.children[int(n)] = append(st.children[int(n)], p.key)
		}
	case "execve", "execveat":
		i := 0
		if call == "execveat" {
			i = 1
		}
		path := st.abs(p, pathArg(f[i]), dirArg(f, call))
		st.exec[id.tidRoot] = &Program{Path: path, Argv: vector(f[i+1])}
	case "exit_group":
		code := int(hexValue(f[0]))
		p.Exit = &code
	case "open", "creat", "openat", "openat2":
		st.opened(id, p, call, f, ok, n, result, pe.at)
	case "write", "pwrite64", "writev", "pwritev", "pwritev2":
		fd, name := fdArg(f[0])
		st.resolve(id, fd, name)
		if ok && strings.HasPrefix(name, "/") {
			k := writeKey{p.key, name}
			w := st.written[k]
			if w == nil {
				w = &Written{Path: name, PID: p.PID}
				st.written[k] = w
				st.t.Written = append(st.t.Written, w)
			}
			w.Bytes += n
		}
	case "ftruncate":
		fd, name := fdArg(f[0])
		st.resolve(id, fd, name)
		st.change(p, "truncate", name, "", result)
	case "fchdir":
		fd, name := fdArg(f[0])
		st.resolve(id, fd, name)
		if ok && strings.HasPrefix(name, "/") {
			p.cwd = name
		}
	case "chdir":
		if ok {
			p.cwd = st.abs(p, pathArg(f[0]), "")
		}
	case "truncate":
		st.change(p, "truncate", st.abs(p, pathArg(f[0]), ""), "", result)
	case "mkdir", "rmdir", "unlink":
		st.change(p, call, st.abs(p, pathArg(f[0]), ""), "", result)
	case "mkdirat":
		st.change(p, "mkdir", st.abs(p, pathArg(f[1]), dirName(f[0])), "", result)
	case "unlinkat":
		kind := "unlink"
		if hexValue(f[2])&0x200 != 0 { // AT_REMOVEDIR
			kind = "rmdir"
		}
		st.change(p, kind, st.abs(p, pathArg(f[1]), dirName(f[0])), "", result)
	case "rename", "link", "symlink":
		from := pathArg(f[0])
		if call != "symlink" { // a symlink's target is stored as written
			from = st.abs(p, from, "")
		}
		st.change(p, call, from, st.abs(p, pathArg(f[1]), ""), result)
	case "renameat", "renameat2", "linkat":
		// gVisor prints the second directory as a number, so a relative new name stays relative.
		kind := strings.TrimSuffix(strings.TrimSuffix(call, "at2"), "at")
		st.change(p, kind, st.abs(p, pathArg(f[1]), dirName(f[0])), st.abs(p, pathArg(f[3]), "?"), result)
	case "symlinkat":
		st.change(p, "symlink", pathArg(f[0]), st.abs(p, pathArg(f[2]), dirName(f[1])), result)
	case "socket":
		st.t.Network = append(st.t.Network, Net{Kind: "socket", PID: p.PID, Family: f[0], Type: f[1], Result: result})
	case "connect", "bind":
		st.t.Network = append(st.t.Network, sockNet(call, p.PID, f[1], result))
	case "listen":
		_, name := fdArg(f[0])
		st.t.Network = append(st.t.Network, Net{Kind: "listen", PID: p.PID, Result: result, Note: name})
	case "sendto":
		if f[4] != "null" {
			st.t.Network = append(st.t.Network, sockNet("send", p.PID, f[4], result))
		}
	case "sendmsg":
		// gVisor reads the message header again for the exit line, so another thread can
		// change it during the call; the entry line's copy is the one the call was given.
		hdr := f[1]
		note := "sendmsg: the destination is not in the log"
		if pe.call == "sendmsg" {
			if pe.args[1] != hdr {
				note += "; the message header changed during the call"
			}
			hdr = pe.args[1]
		}
		if !strings.Contains(hdr, "namelen=0,") || strings.Contains(note, "changed") {
			st.t.Network = append(st.t.Network, Net{Kind: "send", PID: p.PID, Result: result, Note: note})
		}
	case "sendmmsg":
		st.t.Network = append(st.t.Network, Net{Kind: "send", PID: p.PID, Result: result, Note: "sendmmsg: the destinations are not in the log"})
	case "memfd_create":
		st.t.Changes = append(st.t.Changes, Change{Kind: "memfd", Path: pathArg(f[0]), PID: p.PID, Result: result})
	case "io_uring_setup":
		if ok {
			st.unclear(p, call, "io_uring_setup", "io_uring was set up: the file and network work it does is not in this log")
		}
	}
}

func (st *state) change(p *Process, kind, a, b, result string) {
	st.t.Changes = append(st.t.Changes, Change{Kind: kind, Path: a, Path2: b, PID: p.PID, Result: result})
}

// opened records an open that asks to write, create or truncate.
func (st *state) opened(id ids, p *Process, call string, f []string, ok bool, fd int64, result string, since int) {
	var passed, flags, dir string
	switch call {
	case "open":
		passed, flags = pathArg(f[0]), f[1]
	case "creat":
		passed, flags = pathArg(f[0]), "O_WRONLY|O_CREAT|O_TRUNC"
	case "openat":
		dir, passed, flags = dirName(f[0]), pathArg(f[1]), f[2]
	case "openat2":
		dir, passed = dirName(f[0]), pathArg(f[1])
		if m := howRE.FindStringSubmatch(f[2]); m != nil {
			flags = m[1]
		}
	}
	if ok {
		// A read-only reopen can reuse a descriptor too. It terminates an older
		// association even though it creates no write-intent observation itself.
		delete(st.ties, thrFD{id.tidRoot, int(fd)})
	}
	if !writeIntent(flags) {
		return
	}
	o := &Opened{Path: st.abs(p, passed, dir), PID: p.PID, Result: result,
		Create: strings.Contains(flags, "O_CREAT"), Truncate: strings.Contains(flags, "O_TRUNC")}
	st.t.Opened = append(st.t.Opened, o)
	if ok {
		st.ties[thrFD{id.tidRoot, int(fd)}] = &tie{o: o, since: since}
	}
}

// finish links children whose first entry came before their parent's fork line, and turns
// calls that never returned into events with an unknown result. A PID that more than one
// fork returned (a reused number) links no parent.
func (st *state) finish() {
	for _, p := range st.t.Processes {
		if parents := st.children[p.PID]; p.Parent == 0 && len(parents) == 1 && parents[0] != p.key {
			if pp := st.procs[parents[0]]; pp != nil {
				p.Parent = pp.PID
			}
		}
	}
	tids := make([]int, 0, len(st.inflight))
	for tid := range st.inflight {
		tids = append(tids, tid)
	}
	slices.Sort(tids)
	for _, tid := range tids {
		pe := st.inflight[tid]
		switch pe.call {
		case "connect":
			st.t.Network = append(st.t.Network, sockNet("connect", pe.proc.PID, pe.args[1], "unknown"))
		case "sendto":
			if pe.args[4] != "null" {
				st.t.Network = append(st.t.Network, sockNet("send", pe.proc.PID, pe.args[4], "unknown"))
			}
		case "sendmsg":
			if !strings.Contains(pe.args[1], "namelen=0,") {
				st.t.Network = append(st.t.Network, Net{Kind: "send", PID: pe.proc.PID, Result: "unknown", Note: "sendmsg: the destination is not in the log"})
			}
		}
	}
}

// abs joins a path a program passed to the directory it names ("" for the process's own
// directory, "?" for one the log does not name). It never cleans the result: ".." after a
// symlink leaves the directory the symlink reaches, not the one its text names.
func (st *state) abs(p *Process, passed, dir string) string {
	if passed == "" || strings.HasPrefix(passed, "/") || strings.HasPrefix(passed, "(error decoding ") {
		return passed
	}
	if dir == "" {
		dir = p.cwd
	}
	if dir == "" || dir == "?" || !strings.HasPrefix(dir, "/") {
		return passed
	}
	return strings.TrimSuffix(dir, "/") + "/" + passed
}

func sockNet(kind string, pid int, addr, result string) Net {
	n := Net{Kind: kind, PID: pid, Result: result}
	if m := inetRE.FindStringSubmatch(addr); m != nil {
		n.Family, n.Addr, n.Port = m[1], m[2], atoi(m[3])
	} else if m := unixRE.FindStringSubmatch(addr); m != nil {
		n.Family = "AF_UNIX"
		if s, err := strconv.Unquote(m[1]); err == nil {
			n.Addr = s
		}
	} else if m := familyRE.FindStringSubmatch(addr); m != nil {
		n.Family = m[1]
	}
	return n
}

var (
	inetRE   = regexp.MustCompile(`^0x[0-9a-f]+ \{Family: (AF_INET6?|AF_PACKET), Addr: ([^,{}]*), Port: (\d+)\}$`)
	unixRE   = regexp.MustCompile(`^0x[0-9a-f]+ \{Family: AF_UNIX, Addr: ("(?:[^"\\]|\\.)*")\}$`)
	familyRE = regexp.MustCompile(`^0x[0-9a-f]+ \{Family: ([A-Z0-9_]+)`)
)

// writeIntent reports whether open flags ask to write, create or truncate.
func writeIntent(flags string) bool {
	for _, f := range strings.Split(flags, "|") {
		switch f {
		case "O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND":
			return true
		}
	}
	return false
}

func atoi(s string) int { n, _ := strconv.Atoi(s); return n }

func hexValue(s string) int64 {
	n, _ := strconv.ParseUint(strings.TrimPrefix(s, "0x"), 16, 64)
	return int64(n)
}

func runeCount(s string) int { return len([]rune(s)) }

// pathArg is the text after the address of a Path argument ("0xADDR path"): the path, or
// gVisor's "(error decoding path: ...)" when it could not read one; "" for a null pointer.
func pathArg(f string) string {
	if f == "<null>" {
		return ""
	}
	_, s, _ := strings.Cut(f, " ")
	return s
}

// fdArg is a descriptor argument's number and gVisor's name for it; -1 for AT_FDCWD or a
// bad descriptor.
func fdArg(f string) (int, string) {
	num, name, _ := strings.Cut(f, " ")
	if num == "AT_FDCWD" || name == "(bad FD)" {
		return -1, name
	}
	return int(hexValue(num)), name
}

// dirName is the directory a descriptor argument of an *at call names.
func dirName(f string) string {
	_, name := fdArg(f)
	if strings.HasPrefix(name, "/") {
		return name
	}
	return "?"
}

func dirArg(f []string, call string) string {
	if call == "execveat" {
		return dirName(f[0])
	}
	return ""
}

// vector decodes an ExecveStringVector argument ("0xADDR [\"a\", \"b\"]").
func vector(f string) []string {
	_, list, _ := strings.Cut(f, " ")
	if !strings.HasPrefix(list, "[") {
		return nil
	}
	var out []string
	rest := strings.TrimSuffix(strings.TrimPrefix(list, "["), "]")
	for rest != "" {
		n := quoted(rest)
		if n <= 0 {
			return out
		}
		s, err := strconv.Unquote(rest[:n])
		if err != nil {
			return out
		}
		out = append(out, s)
		rest = strings.TrimPrefix(rest[n:], ", ")
	}
	return out
}
