package sessionkit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// The file driver: one operation on a session's files, carried out inside the sandbox by
// plimsoll's native helper (docs/session-files.md is the helper's contract). Every provider
// that carries file calls runs them here and supplies only how to start one argv as the
// guest, in the session's work folder, with one stdin (FileExec): the driver builds the
// helper's command, writes its words and input to stdin, reads its frames strictly and maps
// its exit code. Package sandbox names these types (FilesRequest, FilesResult) and turns a
// call's end into a result or a refusal.

// FileScope is how a file call's paths resolve; the numbers are the wire's (FilesScope).
type FileScope int

const (
	FileScopeUnspecified FileScope = 0
	// FileScopeWork: a relative path from the work folder, each part opened by itself
	// without following a link.
	FileScopeWork FileScope = 1
	// FileScopeSandbox: an absolute path, resolved as the guest's own shell resolves it.
	FileScopeSandbox FileScope = 2
)

// word is the scope's word on the helper's command line.
func (s FileScope) word() string {
	if s == FileScopeSandbox {
		return "sandbox"
	}
	return "work"
}

// FileOp is one operation, named by the word the record encoding uses for it.
type FileOp string

const (
	FileStat     FileOp = "stat"
	FileRead     FileOp = "read"
	FileWrite    FileOp = "write"
	FileList     FileOp = "list"
	FileReadMany FileOp = "read_many"
	FileMakeDir  FileOp = "make_dir"
	FileRemove   FileOp = "remove"
	FileRename   FileOp = "rename"
)

// FileOps are every operation, in the wire's order.
var FileOps = []FileOp{FileStat, FileRead, FileWrite, FileList, FileReadMany, FileMakeDir, FileRemove, FileRename}

// FileWriteMode is how a write treats a file already there; the numbers are the wire's.
type FileWriteMode int

const (
	FileWriteUnspecified FileWriteMode = 0
	FileWriteReplace     FileWriteMode = 1
	FileWriteCreateOnly  FileWriteMode = 2
	FileWriteAppend      FileWriteMode = 3
)

// FileError is the closed set of a file call's errors; the numbers are the wire's
// (FilesError), and FileErrorNone (0) is no error.
type FileError int

const (
	FileErrorNone             FileError = 0
	FileErrorNotFound         FileError = 1
	FileErrorIsDir            FileError = 2
	FileErrorNotDir           FileError = 3
	FileErrorExists           FileError = 4
	FileErrorSymlink          FileError = 5
	FileErrorNotRegular       FileError = 6
	FileErrorPermissionDenied FileError = 7
	FileErrorTooLarge         FileError = 8
	FileErrorNoSpace          FileError = 9
	FileErrorReadOnly         FileError = 10
	FileErrorNotEmpty         FileError = 11
	FileErrorScanLimit        FileError = 12
	FileErrorOther            FileError = 13
)

var fileErrorNames = map[FileError]string{
	FileErrorNone: "none", FileErrorNotFound: "not_found", FileErrorIsDir: "is_dir", FileErrorNotDir: "not_dir",
	FileErrorExists: "exists", FileErrorSymlink: "symlink", FileErrorNotRegular: "not_regular",
	FileErrorPermissionDenied: "permission_denied", FileErrorTooLarge: "too_large", FileErrorNoSpace: "no_space",
	FileErrorReadOnly: "read_only", FileErrorNotEmpty: "not_empty", FileErrorScanLimit: "scan_limit", FileErrorOther: "other",
}

// String is the error's word on an audit line and a metric's label.
func (e FileError) String() string {
	if n, ok := fileErrorNames[e]; ok {
		return n
	}
	return "file_error(" + strconv.Itoa(int(e)) + ")"
}

// helperExit is one of the helper's exit codes that names an error: the error, and the errno
// name the result states for it. The errno is the one the contract names first: the helper
// answers EACCES and EPERM both with 86, and ENOSPC and EDQUOT both with 89, and says nothing
// more, so the result states the first (the call's errno is not known to be it). 85 and 91
// have no errno of their own.
type helperExit struct {
	err   FileError
	errno string
}

// HelperExits maps each exit code of the helper's (docs/session-files.md, "Exit codes") to
// exactly one FileError: every code but 0 (done) and 2 (a malformed command, which the daemon's
// own check refuses before the helper starts, so a 2 is a disagreement between the two and the
// call's outcome is a protocol error, with no FileError). Exit 1 is FileErrorOther, its errno
// read from the helper's own first word on stderr (exitOtherErrno). TestHelperExitsMatchTheEnum
// holds this table, the contract's table and the wire's enum to one another.
var HelperExits = map[int]helperExit{
	80: {FileErrorSymlink, "ELOOP"},
	81: {FileErrorNotFound, "ENOENT"},
	82: {FileErrorIsDir, "EISDIR"},
	83: {FileErrorNotDir, "ENOTDIR"},
	84: {FileErrorExists, "EEXIST"},
	85: {FileErrorNotRegular, ""},
	86: {FileErrorPermissionDenied, "EACCES"},
	87: {FileErrorTooLarge, "EFBIG"},
	88: {FileErrorNotEmpty, "ENOTEMPTY"},
	89: {FileErrorNoSpace, "ENOSPC"},
	90: {FileErrorReadOnly, "EROFS"},
	91: {FileErrorScanLimit, ""},
	1:  {FileErrorOther, ""},
}

// HelperExitMalformed is the helper's exit for a malformed command.
const HelperExitMalformed = 2

// HelperExitUnknown is the helper's exit for a write that failed after a change it could not
// undo (an append cut short it could not cut back, a staging name another process swapped):
// what the file holds is unknown, so the call is read as one that gave no answer
// (FileNoAnswer), never as an error that left the file as it was.
const HelperExitUnknown = 92

// HelperErrnoNames are the errno names the helper writes first on stderr when it exits 1
// (its errno.rs name table; TestHelperErrnoNamesAreTheHelpers reads that file). A first word
// outside it is not the helper's, and the call's errno is left empty.
var HelperErrnoNames = []string{
	"EPERM", "ENOENT", "ESRCH", "EINTR", "EIO", "ENXIO", "E2BIG", "ENOEXEC", "EBADF", "ECHILD",
	"EAGAIN", "ENOMEM", "EACCES", "EFAULT", "EBUSY", "EEXIST", "EXDEV", "ENODEV", "ENOTDIR", "EISDIR",
	"EINVAL", "ENFILE", "EMFILE", "ENOTTY", "ETXTBSY", "EFBIG", "ENOSPC", "ESPIPE", "EROFS", "EMLINK",
	"EPIPE", "ENAMETOOLONG", "ENOSYS", "ENOTEMPTY", "ELOOP", "EOVERFLOW", "EOPNOTSUPP", "ENOBUFS", "ETIMEDOUT", "EDQUOT",
}

// exitOtherErrno is the errno a helper exit 1 states: its stderr's first word, the helper's
// `CODE: description, call 'path'`, when CODE is one of HelperErrnoNames. ok is false when
// stderr does not start that way, so the exit is not the helper's own failure (a docker exec
// that failed exits 1 too). Nothing else of stderr is kept: it names the path, and it is the
// guest's text as much as the helper's.
func exitOtherErrno(stderr string) (errno string, ok bool) {
	code, _, found := strings.Cut(stderr, ": ")
	if !found || !slices.Contains(HelperErrnoNames, code) {
		return "", false
	}
	return code, true
}

// FileType is what a path names; the numbers are the wire's (FilesEntryType).
type FileType int

const (
	FileTypeUnspecified FileType = 0
	FileTypeFile        FileType = 1
	FileTypeDir         FileType = 2
	FileTypeLink        FileType = 3
	FileTypeOther       FileType = 4
	// FileTypeUnreadable is a folder a recursive listing could not enter (the guest may not
	// read or search it): a listing's entry alone, never a stat's answer. Its entries are not
	// listed, and the listing goes on after it.
	FileTypeUnreadable FileType = 5
)

var fileTypeOfKind = map[string]FileType{"f": FileTypeFile, "d": FileTypeDir, "l": FileTypeLink, "o": FileTypeOther, "u": FileTypeUnreadable}

// The bounds of a file call, the helper's own (docs/session-files.md).
const (
	MaxFilePath     = 4096    // bytes of one path
	MaxFileRead     = 8 << 20 // bytes of one read, and of one readmany file
	MaxFileWrite    = 4 << 20 // bytes of one write
	MinFileBudget   = 8192    // bytes of a list or readmany answer, at least: room for its largest entry
	MaxFileBudget   = 8 << 20 // and at most
	MaxFileReadMany = 16384   // paths of one readmany; its budget, not the count, bounds its answer
	// fileOutCap bounds what the driver keeps of the helper's stdout: the largest answer
	// (a whole budget, or a read of MaxFileRead with its two frames) and room for the rest.
	fileOutCap = MaxFileBudget + 4096
	// fileErrCap bounds its stderr, of which only the first word is read.
	fileErrCap = 4096
)

// FileCall is one file operation. Which fields an operation reads:
//
//   - stat: Path. read: Path, Offset, MaxBytes. write: Path, Content, Mode, Parents.
//   - list: Path (the folder), Recursive, Match, After, Budget.
//   - read_many: Paths, MaxBytes (each), Budget.
//   - make_dir: Path, Parents. remove: Path, Dir. rename: Path (from), To, Replace.
type FileCall struct {
	Scope     FileScope
	Op        FileOp
	Path      []byte
	To        []byte
	Paths     [][]byte
	Offset    uint64
	MaxBytes  uint32
	Content   []byte
	Mode      FileWriteMode
	Parents   bool
	Recursive bool
	Match     []byte
	After     []byte
	Budget    uint32
	Dir       bool
	Replace   bool
}

// ErrFileRequest is a file call the helper would refuse as malformed: the daemon checks it
// before anything starts.
var ErrFileRequest = errors.New("a malformed file call")

func fileRequestErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrFileRequest, fmt.Sprintf(format, args...))
}

// Check refuses what the helper would refuse as malformed (its exit 2), with plimsoll's own
// words: a path out of its scope, a number out of its bounds, a malformed glob or cursor. The
// error never repeats the caller's path.
func (c FileCall) Check() error {
	if c.Scope != FileScopeWork && c.Scope != FileScopeSandbox {
		return fileRequestErr("the scope is WORK or SANDBOX")
	}
	path := func(what string, p []byte, folder bool) error {
		if err := checkFilePath(c.Scope, p, folder); err != nil {
			return fileRequestErr("%s: %v", what, err)
		}
		return nil
	}
	switch c.Op {
	case FileStat:
		return path("stat's path", c.Path, true)
	case FileRead:
		if c.MaxBytes < 1 || c.MaxBytes > MaxFileRead {
			return fileRequestErr("a read's max_bytes is 1 to %d", MaxFileRead)
		}
		if c.Offset > 1<<63-1 {
			return fileRequestErr("a read's offset is at most %d", uint64(1<<63-1))
		}
		return path("read's path", c.Path, false)
	case FileWrite:
		if len(c.Content) > MaxFileWrite {
			return fileRequestErr("a write carries at most %d bytes", MaxFileWrite)
		}
		if c.Mode < FileWriteReplace || c.Mode > FileWriteAppend {
			return fileRequestErr("a write's mode is replace, create only or append")
		}
		return path("write's path", c.Path, false)
	case FileList:
		if err := checkFileBudget(c.Budget); err != nil {
			return err
		}
		if err := path("list's folder", c.Path, true); err != nil {
			return err
		}
		if len(c.Match) > 0 {
			if err := CheckGlob(c.Match); err != nil {
				return fileRequestErr("list's match: %v", err)
			}
		}
		return checkFileCursor(c.After, c.Recursive)
	case FileReadMany:
		if len(c.Paths) < 1 || len(c.Paths) > MaxFileReadMany {
			return fileRequestErr("a read_many asks 1 to %d paths", MaxFileReadMany)
		}
		if c.MaxBytes < 1 || c.MaxBytes > MaxFileRead {
			return fileRequestErr("a read_many's max_bytes_each is 1 to %d", MaxFileRead)
		}
		if err := checkFileBudget(c.Budget); err != nil {
			return err
		}
		for i, p := range c.Paths {
			if err := path(fmt.Sprintf("read_many's paths[%d]", i), p, false); err != nil {
				return err
			}
		}
		return nil
	case FileMakeDir:
		return path("make_dir's path", c.Path, false)
	case FileRemove:
		return path("remove's path", c.Path, false)
	case FileRename:
		if err := path("rename's from_path", c.Path, false); err != nil {
			return err
		}
		return path("rename's to_path", c.To, false)
	}
	return fileRequestErr("the operation is one of %v", FileOps)
}

func checkFileBudget(b uint32) error {
	if b < MinFileBudget || b > MaxFileBudget {
		return fileRequestErr("a budget is %d to %d bytes", MinFileBudget, MaxFileBudget)
	}
	return nil
}

// checkFilePath is the helper's rule for a path in its scope: in WORK relative, in SANDBOX
// absolute, at most MaxFilePath bytes, no part empty, "." or "..", no NUL; "." (WORK) or "/"
// (SANDBOX) alone only where a folder is meant (folder).
func checkFilePath(scope FileScope, p []byte, folder bool) error {
	if len(p) > MaxFilePath {
		return fmt.Errorf("a path is at most %d bytes", MaxFilePath)
	}
	rel := p
	if scope == FileScopeSandbox {
		if len(p) == 0 || p[0] != '/' {
			return errors.New("a SANDBOX path is absolute")
		}
		if len(p) == 1 {
			if folder {
				return nil
			}
			return errors.New("a file's path is not the root")
		}
		rel = p[1:]
	} else {
		if folder && string(p) == "." {
			return nil
		}
		if len(p) == 0 || p[0] == '/' {
			return errors.New("a WORK path is relative and not empty")
		}
	}
	return checkParts(rel)
}

func checkParts(rel []byte) error {
	if bytes.IndexByte(rel, 0) >= 0 {
		return errors.New("a path holds no NUL")
	}
	for part := range bytes.SplitSeq(rel, []byte{'/'}) {
		if len(part) == 0 || string(part) == "." || string(part) == ".." {
			return errors.New(`no part of a path is empty, "." or ".."`)
		}
	}
	return nil
}

// checkFileCursor is the helper's rule for a listing's cursor: empty, or a path of plain parts
// at most MaxFilePath bytes, one part for a flat listing.
func checkFileCursor(after []byte, recursive bool) error {
	if len(after) == 0 {
		return nil
	}
	if len(after) > MaxFilePath || checkParts(after) != nil {
		return fileRequestErr("list's after is the last path of the page before")
	}
	if !recursive && bytes.IndexByte(after, '/') >= 0 {
		return fileRequestErr("a flat listing's after is one name")
	}
	return nil
}

// CheckGlob is the helper's rule for a glob (docs/session-files.md, "Glob"): not empty, no
// empty part, "**" only as a whole part, every "[" closed, no trailing "\", at most
// MaxFilePath bytes and no NUL (it travels as one of the helper's words).
func CheckGlob(p []byte) error {
	if len(p) == 0 {
		return errors.New("a glob is not empty")
	}
	if len(p) > MaxFilePath || bytes.IndexByte(p, 0) >= 0 {
		return fmt.Errorf("a glob is at most %d bytes and holds no NUL", MaxFilePath)
	}
	for part := range bytes.SplitSeq(p, []byte{'/'}) {
		if len(part) == 0 {
			return errors.New("a glob's part is not empty")
		}
		if string(part) != "**" && bytes.Contains(part, []byte("**")) {
			return errors.New(`"**" is a whole part`)
		}
		for i := 0; i < len(part); {
			switch part[i] {
			case '\\':
				if i+1 == len(part) {
					return errors.New(`a glob ends with no "\"`)
				}
				i += 2
			case '[':
				end, ok := globSetEnd(part, i)
				if !ok {
					return errors.New(`every "[" is closed`)
				}
				i = end + 1
			default:
				i++
			}
		}
	}
	return nil
}

// globSetEnd is the index of the "]" closing the set that opens at start, as the helper finds
// it: a "!" or "^" first negates, a "]" first is a member, "\" makes the next byte plain.
func globSetEnd(p []byte, start int) (int, bool) {
	i := start + 1
	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		i++
	}
	if i < len(p) && p[i] == ']' {
		i++
	}
	for i < len(p) {
		switch p[i] {
		case ']':
			return i, true
		case '\\':
			i += 2
		default:
			i++
		}
	}
	return 0, false
}

// words are the helper's command and its arguments for c.
func (c FileCall) words() [][]byte {
	b := func(v bool) []byte {
		if v {
			return []byte("1")
		}
		return []byte("0")
	}
	n := func(v uint64) []byte { return strconv.AppendUint(nil, v, 10) }
	switch c.Op {
	case FileStat:
		return [][]byte{[]byte("stat"), c.Path}
	case FileRead:
		return [][]byte{[]byte("read"), c.Path, n(c.Offset), n(uint64(c.MaxBytes))}
	case FileWrite:
		mode := map[FileWriteMode]string{FileWriteReplace: "replace", FileWriteCreateOnly: "create-only", FileWriteAppend: "append"}[c.Mode]
		return [][]byte{[]byte("write"), c.Path, []byte(mode), b(c.Parents)}
	case FileList:
		w := [][]byte{[]byte("list"), c.Path, b(c.Recursive), n(uint64(c.Budget))}
		if len(c.Match) > 0 {
			w = append(w, c.Match)
		}
		return w
	case FileReadMany:
		return [][]byte{[]byte("readmany"), n(uint64(c.MaxBytes)), n(uint64(c.Budget))}
	case FileMakeDir:
		return [][]byte{[]byte("mkdir"), c.Path, b(c.Parents)}
	case FileRemove:
		return [][]byte{[]byte("remove"), c.Path, b(c.Dir)}
	case FileRename:
		return [][]byte{[]byte("rename"), c.Path, c.To, b(c.Replace)}
	}
	return nil
}

// Argv is the helper's command line for c: the words come on stdin (Stdin), since an exec's
// arguments reach a sandbox as UTF-8 text and a path need not be UTF-8. A provider starts it
// under ControlArgv, as the guest, in the work folder.
func (c FileCall) Argv() []string {
	return append(slices.Clone(nativehelper.Files), c.Scope.word(), "-")
}

// Stdin is what the helper reads: the count of words, ":", each word ended by a NUL, then the
// command's own input (a write's content, a listing's cursor, read_many's paths each ended by
// a NUL).
func (c FileCall) Stdin() []byte {
	words := c.words()
	in := strconv.AppendInt(nil, int64(len(words)), 10)
	in = append(in, ':')
	for _, w := range words {
		in = append(append(in, w...), 0)
	}
	switch c.Op {
	case FileWrite:
		in = append(in, c.Content...)
	case FileList:
		in = append(in, c.After...)
	case FileReadMany:
		for _, p := range c.Paths {
			in = append(append(in, p...), 0)
		}
	}
	return in
}

// FileEntry is one entry of a listing.
type FileEntry struct {
	Path []byte
	Type FileType
	Size uint64
}

// FileItem is one path's answer in a read_many: its bytes, or its error.
type FileItem struct {
	Error      FileError
	Errno      string
	Content    []byte
	SizeAtOpen uint64
}

// FileAnswer is what the helper answered: an error (with the errno it came from), or the
// operation's answer, which names its operation (Op; empty with an error).
type FileAnswer struct {
	Error FileError
	Errno string
	Op    FileOp
	// stat
	Type FileType
	Size uint64
	Mode uint32
	// read
	Content    []byte
	SizeAtOpen uint64
	// write
	Written uint64
	// list and read_many
	Entries []FileEntry
	Items   []FileItem
	More    bool
}

// FileEnd is how a file call's helper ended, when it ended with an exit status.
type FileEnd int

const (
	// FileAnswered: the helper exited with an answer or an error of the contract.
	FileAnswered FileEnd = iota
	// FileUnreadable: it exited 0 with an answer the driver could not parse, or 2 (a
	// command the daemon's check passed and the helper refused): a protocol error.
	FileUnreadable
	// FileNoAnswer: it exited with no answer and no code of the contract (killed, or an
	// exec that never started it), or with HelperExitUnknown.
	FileNoAnswer
)

// FileExec starts argv as the guest, in the session's work folder, with stdin, keeping at
// most outCap and errCap bytes of output.
type FileExec func(ctx context.Context, argv []string, stdin []byte, outCap, errCap int) (ExecResult, error)

// RunFile runs c through exec. err is exec's own (the command delivered no exit status: the
// deadline, or the exec failed); otherwise end says how the helper ended and, when it
// answered, ans is its answer. c must have passed Check.
func RunFile(ctx context.Context, exec FileExec, c FileCall) (ans FileAnswer, end FileEnd, res ExecResult, err error) {
	res, err = exec(ctx, c.Argv(), c.Stdin(), fileOutCap, fileErrCap)
	if err != nil || !res.Exited {
		return FileAnswer{}, FileNoAnswer, res, err
	}
	ans, end = ReadFileAnswer(c, res)
	return ans, end, res, nil
}

// ReadFileAnswer reads the helper's exit and stdout for c.
func ReadFileAnswer(c FileCall, res ExecResult) (FileAnswer, FileEnd) {
	switch code := res.ExitCode; {
	case code == 0:
		if res.StdoutTruncated {
			return FileAnswer{}, FileUnreadable
		}
		ans, err := parseFileAnswer(c, []byte(res.Stdout))
		if err != nil {
			return FileAnswer{}, FileUnreadable
		}
		return ans, FileAnswered
	case code == HelperExitMalformed:
		return FileAnswer{}, FileUnreadable
	case code == HelperExitUnknown:
		if res.Stdout != "" {
			return FileAnswer{}, FileUnreadable
		}
		return FileAnswer{}, FileNoAnswer
	case code == 1:
		errno, ok := exitOtherErrno(res.Stderr)
		if !ok {
			return FileAnswer{}, FileNoAnswer
		}
		return FileAnswer{Error: FileErrorOther, Errno: errno}, FileAnswered
	default:
		if res.Stdout != "" {
			return FileAnswer{}, FileUnreadable
		}
		if e, ok := HelperExits[code]; ok {
			return FileAnswer{Error: e.err, Errno: e.errno}, FileAnswered
		}
		return FileAnswer{}, FileNoAnswer
	}
}

type fileFrame struct {
	tag     byte
	payload []byte
}

// readFrames reads an answer's frames strictly: each a tag byte, its length in decimal (no
// sign, no leading zero), ":", that many bytes; the last frame, and only the last, "." or "+",
// whose payload is the count of entries of group frames before it. It returns the entries and
// whether the answer is whole (".").
func readFrames(out []byte, group int) ([][]fileFrame, bool, error) {
	var all []fileFrame
	for i := 0; i < len(out); {
		colon := bytes.IndexByte(out[i+1:], ':')
		if colon < 1 || colon > 20 {
			return nil, false, errors.New("a frame without a length")
		}
		n, err := plainNumber(out[i+1 : i+1+colon])
		if err != nil {
			return nil, false, err
		}
		start := i + 1 + colon + 1
		if n > uint64(len(out)-start) {
			return nil, false, errors.New("a frame past the answer's end")
		}
		all = append(all, fileFrame{out[i], out[start : start+int(n)]})
		i = start + int(n)
	}
	if len(all) == 0 {
		return nil, false, errors.New("no end frame")
	}
	last := all[len(all)-1]
	body := all[:len(all)-1]
	if last.tag != '.' && last.tag != '+' {
		return nil, false, errors.New("no end frame")
	}
	count, err := plainNumber(last.payload)
	// count is bounded first, so its product cannot wrap around to the frames' number.
	if err != nil || count > uint64(len(body)) || count*uint64(group) != uint64(len(body)) {
		return nil, false, errors.New("the end frame's count is not the entries'")
	}
	entries := make([][]fileFrame, 0, count)
	for k := 0; k < len(body); k += group {
		for _, f := range body[k : k+group] {
			if f.tag == '.' || f.tag == '+' {
				return nil, false, errors.New("an end frame inside the answer")
			}
		}
		entries = append(entries, body[k:k+group])
	}
	return entries, last.tag == '.', nil
}

// plainNumber is a decimal number with no sign and no leading zero that fits 64 bits.
func plainNumber(s []byte) (uint64, error) {
	if len(s) == 0 || len(s) > 20 || (len(s) > 1 && s[0] == '0') {
		return 0, errors.New("not a plain number")
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, errors.New("not a plain number")
		}
	}
	return strconv.ParseUint(string(s), 10, 64)
}

// tags checks that an entry's frames carry exactly the tags given, in order.
func tags(entry []fileFrame, want string) error {
	for i, f := range entry {
		if f.tag != want[i] {
			return fmt.Errorf("frame %d is %q, not %q", i, f.tag, want[i])
		}
	}
	return nil
}

func fileType(kind []byte) (FileType, error) {
	t, ok := fileTypeOfKind[string(kind)]
	if !ok {
		return 0, errors.New("an unknown kind")
	}
	return t, nil
}

// parseFileAnswer reads the answer of a helper that exited 0.
func parseFileAnswer(c FileCall, out []byte) (FileAnswer, error) {
	ans := FileAnswer{Op: c.Op}
	switch c.Op {
	case FileMakeDir, FileRemove, FileRename:
		if len(out) != 0 {
			return ans, errors.New("an answer to an operation that answers nothing")
		}
		return ans, nil
	}
	group := map[FileOp]int{FileStat: 4, FileRead: 2, FileWrite: 1, FileList: 3, FileReadMany: 3}[c.Op]
	entries, whole, err := readFrames(out, group)
	if err != nil {
		return ans, err
	}
	one := func(t string) ([]fileFrame, error) {
		if len(entries) != 1 || !whole {
			return nil, errors.New("not one whole entry")
		}
		return entries[0], tags(entries[0], t)
	}
	switch c.Op {
	case FileStat:
		e, err := one("ksmt")
		if err != nil {
			return ans, err
		}
		if ans.Type, err = fileType(e[0].payload); err != nil {
			return ans, err
		}
		if ans.Type == FileTypeUnreadable {
			return ans, errors.New("a stat answered a listing's kind")
		}
		if ans.Size, err = plainNumber(e[1].payload); err != nil {
			return ans, err
		}
		mode, err := plainNumber(e[2].payload)
		if err != nil || mode > 0o7777 {
			return ans, errors.New("not permission bits")
		}
		ans.Mode = uint32(mode)
		// e[3], the modification time, is not part of a file call's answer.
		if _, err := plainNumber(e[3].payload); err != nil {
			return ans, err
		}
	case FileRead:
		e, err := one("sb")
		if err != nil {
			return ans, err
		}
		if ans.SizeAtOpen, err = plainNumber(e[0].payload); err != nil {
			return ans, err
		}
		if len(e[1].payload) > int(c.MaxBytes) {
			return ans, errors.New("more bytes than asked")
		}
		ans.Content = e[1].payload
	case FileWrite:
		e, err := one("n")
		if err != nil {
			return ans, err
		}
		if ans.Written, err = plainNumber(e[0].payload); err != nil {
			return ans, err
		}
		if ans.Written != uint64(len(c.Content)) {
			return ans, errors.New("a count of bytes written other than the content's")
		}
	case FileList:
		ans.More = !whole
		for _, e := range entries {
			if err := tags(e, "pks"); err != nil {
				return ans, err
			}
			t, err := fileType(e[1].payload)
			if err != nil {
				return ans, err
			}
			size, err := plainNumber(e[2].payload)
			if err != nil {
				return ans, err
			}
			// Only a recursive listing enters folders, so only it can meet one it may not
			// enter; such an entry, like every one but a regular file's, has no size.
			if t == FileTypeUnreadable && (!c.Recursive || size != 0) {
				return ans, errors.New("an unreadable folder where none can be")
			}
			if len(e[0].payload) == 0 {
				return ans, errors.New("an entry with no path")
			}
			ans.Entries = append(ans.Entries, FileEntry{Path: e[0].payload, Type: t, Size: size})
		}
	case FileReadMany:
		ans.More = !whole
		if len(entries) > len(c.Paths) || (whole && len(entries) != len(c.Paths)) {
			return ans, errors.New("not the paths asked")
		}
		for i, e := range entries {
			if e[0].tag != 'p' || !bytes.Equal(e[0].payload, c.Paths[i]) {
				return ans, errors.New("not the path asked, in order")
			}
			if e[1].tag != 's' {
				return ans, errors.New("an item without its size at open")
			}
			size, err := plainNumber(e[1].payload)
			if err != nil {
				return ans, err
			}
			switch e[2].tag {
			case 'b':
				if len(e[2].payload) > int(c.MaxBytes) {
					return ans, errors.New("more bytes than asked")
				}
				ans.Items = append(ans.Items, FileItem{Content: e[2].payload, SizeAtOpen: size})
			case 'e':
				if size != 0 {
					return ans, errors.New("an item not read with a size")
				}
				code, err := plainNumber(e[2].payload)
				if err != nil {
					return ans, err
				}
				// A code of the contract; 1 (any other failure) states no errno, since an item
				// carries no stderr.
				x, ok := HelperExits[int(min(code, 1<<16))]
				if !ok {
					return ans, errors.New("an item's code is not one of the contract")
				}
				ans.Items = append(ans.Items, FileItem{Error: x.err, Errno: x.errno})
			default:
				return ans, errors.New("an item that is neither bytes nor an error")
			}
		}
	}
	return ans, nil
}
