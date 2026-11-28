package sessionkit

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// Every exit code of the helper's contract maps to exactly one FilesError, and every FilesError
// of the wire's closed set is some code's: the contract's table (docs/session-files.md, "Exit
// codes"), HelperExits and the proto enum are held to one another. 0 (done) is no error; 2 (a
// malformed command, which the daemon's own check refuses before the helper starts) is the
// call's protocol error, not a FilesError. An enum value no code maps to would need its reason
// here, in unusedErrors, which this test reads; there is none.
func TestHelperExitsMatchTheEnum(t *testing.T) {
	unusedErrors := map[plimsollv1.FilesError]string{}
	doc, err := os.ReadFile("../../../docs/session-files.md")
	if err != nil {
		t.Fatal(err)
	}
	row := regexp.MustCompile("(?m)^\\| ([0-9]+) \\| ")
	var docCodes []int
	for _, m := range row.FindAllSubmatch(doc[bytes.Index(doc, []byte("## Exit codes")):], -1) {
		n, _ := strconv.Atoi(string(m[1]))
		docCodes = append(docCodes, n)
	}
	if len(docCodes) < 14 {
		t.Fatalf("read %d exit codes from the contract's table: %v", len(docCodes), docCodes)
	}
	for _, code := range docCodes {
		_, mapped := HelperExits[code]
		switch {
		case code == 0 || code == HelperExitMalformed || code == HelperExitUnknown:
			if mapped {
				t.Errorf("exit %d maps to a FilesError; it is no error (0), a protocol error (2) or no answer (92)", code)
			}
		case !mapped:
			t.Errorf("the contract's exit %d maps to no FilesError", code)
		}
	}
	for code := range HelperExits {
		if !slices.Contains(docCodes, code) {
			t.Errorf("HelperExits maps exit %d, which the contract's table does not name", code)
		}
	}
	seen := map[FileError]int{}
	for code, x := range HelperExits {
		if prev, dup := seen[x.err]; dup {
			t.Errorf("exits %d and %d both map to %v", prev, code, x.err)
		}
		seen[x.err] = code
	}
	for n, name := range plimsollv1.FilesError_name {
		e := plimsollv1.FilesError(n)
		if e == plimsollv1.FilesError_FILES_ERROR_UNSPECIFIED {
			continue
		}
		want := "FILES_ERROR_" + strings.ToUpper(FileError(n).String())
		if name != want {
			t.Errorf("wire value %d is %s, the driver's %s", n, name, want)
		}
		if _, ok := seen[FileError(n)]; !ok {
			if why, ok := unusedErrors[e]; !ok || why == "" {
				t.Errorf("%s is no exit code's error and says why nowhere", name)
			}
		}
	}
	if len(plimsollv1.FilesError_name)-1 != len(fileErrorNames)-1 {
		t.Errorf("the wire has %d errors, the driver %d", len(plimsollv1.FilesError_name)-1, len(fileErrorNames)-1)
	}
}

// The errno names an exit 1 may state are the helper's own table (errno.rs), so a name the
// helper learns is not dropped and nothing else is taken from stderr.
func TestHelperErrnoNamesAreTheHelpers(t *testing.T) {
	src, err := os.ReadFile("../nativehelper/program/src/errno.rs")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range regexp.MustCompile(`=> "(E[A-Z0-9]+)",`).FindAllSubmatch(src, -1) {
		names = append(names, string(m[1]))
	}
	if !slices.Equal(names, HelperErrnoNames) {
		t.Fatalf("errno.rs names %v\nthe driver takes %v", names, HelperErrnoNames)
	}
	for _, c := range []struct {
		stderr, errno string
		ok            bool
	}{
		{"EIO: input/output error, read 'x'\n", "EIO", true},
		{"ENAMETOOLONG: file name too long, open 'x'", "ENAMETOOLONG", true},
		{"errno 200: unknown, open 'x'", "", false},
		{"Error response from daemon: container is paused", "", false},
		{"EVIL: x", "", false},
		{"", "", false},
	} {
		if errno, ok := exitOtherErrno(c.stderr); errno != c.errno || ok != c.ok {
			t.Errorf("%q: %q, %v; want %q, %v", c.stderr, errno, ok, c.errno, c.ok)
		}
	}
}

// The helper's own copy of the exit table, read from its source as text (files.rs: the exit
// constants, its errno numbers and code_of, which maps an errno to an exit), is held to
// HelperExits, so the Go table and the helper cannot drift apart silently: every exit the
// helper defines is HelperExits' (92 and 2 are the two constants of their own), every errno
// code_of maps lands on the exit whose errno HelperExits states first, and every errno
// HelperExits states is one code_of maps to that exit. The errno numbers are held to Go's
// tables for x86-64 and aarch64 (syscall's zerrors files, generated from the kernel's
// headers), as TestSysConstantsMatchGo holds sys.rs's. Nothing here builds the helper.
func TestHelperExitsAreTheHelpersFilesRS(t *testing.T) {
	b, err := os.ReadFile("../nativehelper/program/src/files.rs")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// The exits are the public constants and the two private ones (USAGE, FAILED); the
	// errnos are the private constants named E....
	exits, errnos := map[string]int{}, map[string]int{}
	for _, m := range regexp.MustCompile(`(?m)^(pub )?const ([A-Z][A-Z0-9_]*): i32 = ([0-9]+);`).FindAllStringSubmatch(src, -1) {
		n, _ := strconv.Atoi(m[3])
		into := exits
		if m[1] == "" && m[2] != "USAGE" && m[2] != "FAILED" {
			if !strings.HasPrefix(m[2], "E") {
				t.Fatalf("files.rs's private constant %s is neither an exit nor an errno: say which here", m[2])
			}
			into = errnos
		}
		if _, dup := into[m[2]]; dup {
			t.Fatalf("files.rs defines %s twice", m[2])
		}
		into[m[2]] = n
	}
	if len(exits) < 15 || len(errnos) < 10 {
		t.Fatalf("read %d exit constants (%v) and %d errno constants (%v) from files.rs", len(exits), exits, len(errnos), errnos)
	}
	if exits["USAGE"] != HelperExitMalformed || exits["UNKNOWN"] != HelperExitUnknown {
		t.Errorf("files.rs's USAGE is %d and UNKNOWN %d; the driver's are %d and %d", exits["USAGE"], exits["UNKNOWN"], HelperExitMalformed, HelperExitUnknown)
	}
	if x, ok := HelperExits[exits["FAILED"]]; !ok || x.err != FileErrorOther {
		t.Errorf("files.rs's FAILED (%d) is not the driver's FileErrorOther", exits["FAILED"])
	}
	byValue := map[int]string{}
	for name, v := range exits {
		if prev, dup := byValue[v]; dup {
			t.Errorf("files.rs's %s and %s are both exit %d", prev, name, v)
		}
		byValue[v] = name
		if v == HelperExitMalformed || v == HelperExitUnknown {
			continue
		}
		if _, ok := HelperExits[v]; !ok {
			t.Errorf("files.rs's %s is exit %d, which HelperExits does not map", name, v)
		}
	}
	for code := range HelperExits {
		if _, ok := byValue[code]; !ok {
			t.Errorf("HelperExits maps exit %d, which files.rs defines no constant for", code)
		}
	}

	// code_of's arms: "ERRNO | ERRNO => EXIT,", up to its catch-all.
	start := strings.Index(src, "fn code_of(")
	end := strings.Index(src[max(start, 0):], "_ => return None")
	if start < 0 || end < 0 {
		t.Fatal("files.rs has no code_of ending in `_ => return None`")
	}
	arms := regexp.MustCompile(`(?m)^\s*([A-Z][A-Z0-9_]*(?:\s*\|\s*[A-Z][A-Z0-9_]*)*)\s*=>\s*([A-Z][A-Z0-9_]*),\s*$`).FindAllStringSubmatch(src[start:start+end], -1)
	if len(arms) < 9 {
		t.Fatalf("read %d arms of code_of: %v", len(arms), arms)
	}
	// An exit HelperExits states no errno for: its first errno in code_of is not the one
	// the call states, because the exit is reached another way too (85 mostly from fstat's
	// kind, 91 from a listing's bounds), so the result names none.
	noErrnoOfItsOwn := map[int]bool{85: true, 91: true}
	mapped := map[int][]string{}
	for _, a := range arms {
		code, ok := exits[a[2]]
		if !ok {
			t.Errorf("code_of maps to %s, which is no exit constant of files.rs", a[2])
			continue
		}
		var names []string
		for _, e := range strings.Split(a[1], "|") {
			e = strings.TrimSpace(e)
			if _, ok := errnos[e]; !ok {
				t.Errorf("code_of maps %s, which files.rs defines no errno constant for", e)
			}
			names = append(names, e)
		}
		if _, dup := mapped[code]; dup {
			t.Errorf("code_of has two arms for %s", a[2])
		}
		mapped[code] = names
		x, ok := HelperExits[code]
		switch {
		case !ok:
			t.Errorf("code_of maps %v to exit %d, which HelperExits does not map", names, code)
		case x.errno == "" && !noErrnoOfItsOwn[code]:
			t.Errorf("code_of maps %v to exit %d, for which HelperExits states no errno", names, code)
		case x.errno != "" && x.errno != names[0]:
			t.Errorf("code_of maps %v to exit %d; HelperExits states %s for it, which must be the arm's first", names, code, x.errno)
		}
	}
	// An exit HelperExits states an errno for that code_of never answers: the helper raises it
	// by a check of its own, and the errno names what the check found.
	// None today: since file contract 8 a kernel EFBIG maps to 87 as the helper's own size caps do.
	ownCheck := map[int]string{}
	for code, x := range HelperExits {
		if _, own := ownCheck[code]; own {
			if len(mapped[code]) > 0 {
				t.Errorf("exit %d is listed here as raised by the helper's own check, but code_of maps %v to it: drop it from ownCheck", code, mapped[code])
			}
			continue
		}
		if x.errno != "" && !slices.Contains(mapped[code], x.errno) {
			t.Errorf("HelperExits states %s for exit %d, which code_of does not map there (it maps %v)", x.errno, code, mapped[code])
		}
	}

	for _, arch := range []string{"amd64", "arm64"} {
		table, err := os.ReadFile(filepath.Join(runtime.GOROOT(), "src", "syscall", "zerrors_linux_"+arch+".go"))
		if err != nil {
			t.Fatalf("Go's errno table for %s: %v", arch, err)
		}
		for name, v := range errnos {
			m := regexp.MustCompile(`(?m)^\s*` + name + `\s+= Errno\((0x[0-9a-f]+)\)\s*$`).FindSubmatch(table)
			if m == nil {
				t.Errorf("Go's errno table for %s has no %s", arch, name)
				continue
			}
			if w, _ := strconv.ParseInt(string(m[1]), 0, 64); int(w) != v {
				t.Errorf("files.rs's %s is %d; Go's table for %s says %d", name, v, arch, w)
			}
		}
	}
}

// The words go on stdin, never in argv, so a name of any bytes reaches the helper whole.
func TestFileCallWordsTravelOnStdin(t *testing.T) {
	c := FileCall{Scope: FileScopeWork, Op: FileWrite, Path: []byte("d\xff\n/f"), Content: []byte("body"), Mode: FileWriteCreateOnly, Parents: true}
	argv := c.Argv()
	if want := []string{"/usr/local/libexec/plimsoll-helper", "files", "work", "-"}; !slices.Equal(argv, want) {
		t.Fatalf("argv %q, want %q", argv, want)
	}
	if got, want := c.Stdin(), []byte("4:write\x00d\xff\n/f\x00create-only\x001\x00body"); !bytes.Equal(got, want) {
		t.Fatalf("stdin %q, want %q", got, want)
	}
	l := FileCall{Scope: FileScopeSandbox, Op: FileList, Path: []byte("/"), Recursive: true, Budget: 4096, Match: []byte("**/*.py"), After: []byte("a/b")}
	if got, want := l.Stdin(), []byte("5:list\x00/\x001\x004096\x00**/*.py\x00a/b"); !bytes.Equal(got, want) || l.Argv()[2] != "sandbox" {
		t.Fatalf("list stdin %q, argv %q", got, l.Argv())
	}
	r := FileCall{Scope: FileScopeWork, Op: FileReadMany, Paths: [][]byte{[]byte("a"), []byte("b\n")}, MaxBytes: 10, Budget: MinFileBudget}
	if got, want := r.Stdin(), []byte("3:readmany\x0010\x008192\x00a\x00b\n\x00"); !bytes.Equal(got, want) {
		t.Fatalf("read_many stdin %q", got)
	}
}

// Check refuses what the helper would refuse as malformed.
func TestFileCallCheck(t *testing.T) {
	ok := []FileCall{
		{Scope: FileScopeWork, Op: FileStat, Path: []byte(".")},
		{Scope: FileScopeSandbox, Op: FileStat, Path: []byte("/")},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a\xff/b c"), MaxBytes: 1},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: MaxFileRead, Offset: 1<<63 - 1},
		{Scope: FileScopeWork, Op: FileWrite, Path: []byte("a"), Mode: FileWriteAppend, Content: make([]byte, MaxFileWrite)},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: MinFileBudget, Recursive: true, After: []byte("x/y"), Match: []byte("[]a]")},
		{Scope: FileScopeWork, Op: FileReadMany, Paths: [][]byte{[]byte("a")}, MaxBytes: 1, Budget: MaxFileBudget},
		{Scope: FileScopeWork, Op: FileReadMany, Paths: manyPaths(MaxFileReadMany), MaxBytes: 1, Budget: MinFileBudget},
		{Scope: FileScopeSandbox, Op: FileRename, Path: []byte("/a"), To: []byte("/b")},
		{Scope: FileScopeWork, Op: FileMakeDir, Path: []byte(strings.Repeat("a", MaxFilePath))},
	}
	for _, c := range ok {
		if err := c.Check(); err != nil {
			t.Errorf("%+v: %v", c, err)
		}
	}
	bad := []FileCall{
		{Op: FileStat, Path: []byte("a")},
		{Scope: FileScopeWork, Path: []byte("a")},
		{Scope: FileScopeWork, Op: "chmod", Path: []byte("a")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("/a")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("a/../b")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("a//b")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("a/")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("a\x00b")},
		{Scope: FileScopeWork, Op: FileStat, Path: []byte(strings.Repeat("a", MaxFilePath+1))},
		{Scope: FileScopeSandbox, Op: FileStat, Path: []byte("a")},
		{Scope: FileScopeSandbox, Op: FileRemove, Path: []byte("/")},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("."), MaxBytes: 1},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: 0},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: MaxFileRead + 1},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: 1, Offset: 1 << 63},
		{Scope: FileScopeWork, Op: FileWrite, Path: []byte("a"), Mode: FileWriteReplace, Content: make([]byte, MaxFileWrite+1)},
		{Scope: FileScopeWork, Op: FileWrite, Path: []byte("a")},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: MinFileBudget - 1},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: MaxFileBudget + 1},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: 100, After: []byte("x/y")},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: 100, Recursive: true, After: []byte("x/../y")},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: 100, Match: []byte("a**")},
		{Scope: FileScopeWork, Op: FileReadMany, MaxBytes: 1, Budget: 100},
		{Scope: FileScopeWork, Op: FileReadMany, Paths: manyPaths(MaxFileReadMany + 1), MaxBytes: 1, Budget: MinFileBudget},
		{Scope: FileScopeWork, Op: FileReadMany, Paths: [][]byte{[]byte("a"), []byte("/b")}, MaxBytes: 1, Budget: 100},
		{Scope: FileScopeWork, Op: FileRename, Path: []byte("a"), To: []byte("")},
	}
	for _, c := range bad {
		if err := c.Check(); err == nil {
			t.Errorf("%+v passed", c)
		} else if bytes.Contains([]byte(err.Error()), []byte("a\x00b")) {
			t.Errorf("the refusal repeats the path: %v", err)
		}
	}
}

// manyPaths is n distinct valid work-scope paths.
func manyPaths(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte("d/f" + strconv.Itoa(i))
	}
	return out
}

// CheckGlob refuses exactly the patterns the shared vectors mark invalid.
func TestCheckGlobAgainstTheSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../nativehelper/testdata/glob-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Pattern string `json:"pattern"`
			Invalid bool   `json:"invalid"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	invalid := 0
	for _, c := range v.Cases {
		err := CheckGlob([]byte(c.Pattern))
		if c.Invalid {
			invalid++
		}
		if (err != nil) != c.Invalid {
			t.Errorf("%q: %v, want invalid %v", c.Pattern, err, c.Invalid)
		}
	}
	if invalid == 0 || invalid == len(v.Cases) {
		t.Fatalf("%d of %d vectors invalid", invalid, len(v.Cases))
	}
	for _, p := range []string{"[a\\]", "a\\", "x/[!", "a\x00b"} {
		if CheckGlob([]byte(p)) == nil {
			t.Errorf("%q passed", p)
		}
	}
}

func answer(t *testing.T, c FileCall, code int, stdout, stderr string) (FileAnswer, FileEnd) {
	t.Helper()
	return ReadFileAnswer(c, ExecResult{Stdout: stdout, Stderr: stderr, ExitCode: code, Exited: true})
}

// Each operation's answer is read by its frames alone, strictly; anything else is unreadable.
func TestReadFileAnswer(t *testing.T) {
	stat := FileCall{Scope: FileScopeWork, Op: FileStat, Path: []byte("a")}
	if a, end := answer(t, stat, 0, "k1:fs1:5m3:420t10:1700000000.1:1", ""); end != FileAnswered || a.Type != FileTypeFile || a.Size != 5 || a.Mode != 0o644 || a.Op != FileStat {
		t.Fatalf("stat: %+v %v", a, end)
	}
	read := FileCall{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: 4}
	if a, end := answer(t, read, 0, "s1:9b4:ab\nc.1:1", ""); end != FileAnswered || string(a.Content) != "ab\nc" || a.SizeAtOpen != 9 {
		t.Fatalf("read: %+v %v", a, end)
	}
	write := FileCall{Scope: FileScopeWork, Op: FileWrite, Path: []byte("a"), Content: []byte("xyz"), Mode: FileWriteReplace}
	if a, end := answer(t, write, 0, "n1:3.1:1", ""); end != FileAnswered || a.Written != 3 {
		t.Fatalf("write: %+v %v", a, end)
	}
	list := FileCall{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: 4096}
	a, end := answer(t, list, 0, "p1:xk1:ds1:0p3:x/fk1:fs1:5+1:2", "")
	if end != FileAnswered || len(a.Entries) != 2 || !a.More || string(a.Entries[1].Path) != "x/f" || a.Entries[1].Size != 5 {
		t.Fatalf("list: %+v %v", a, end)
	}
	// A recursive listing names a folder it could not enter "u", with no size, and goes on.
	deep := FileCall{Scope: FileScopeSandbox, Op: FileList, Path: []byte("/"), Recursive: true, Budget: MinFileBudget}
	a, end = answer(t, deep, 0, "p4:rootk1:us1:0p3:tmpk1:ds1:0.1:2", "")
	if end != FileAnswered || len(a.Entries) != 2 || a.More || a.Entries[0].Type != FileTypeUnreadable || a.Entries[1].Type != FileTypeDir {
		t.Fatalf("a recursive list with an unreadable folder: %+v %v", a, end)
	}
	many := FileCall{Scope: FileScopeWork, Op: FileReadMany, Paths: [][]byte{[]byte("a"), []byte("b"), []byte("c")}, MaxBytes: 8, Budget: MinFileBudget}
	a, end = answer(t, many, 0, "p1:as1:5b2:hip1:bs1:0e2:81+1:2", "")
	if end != FileAnswered || len(a.Items) != 2 || !a.More || string(a.Items[0].Content) != "hi" || a.Items[0].SizeAtOpen != 5 ||
		a.Items[1].Error != FileErrorNotFound || a.Items[1].Errno != "ENOENT" {
		t.Fatalf("read_many: %+v %v", a, end)
	}
	done := FileCall{Scope: FileScopeWork, Op: FileMakeDir, Path: []byte("d")}
	if a, end := answer(t, done, 0, "", ""); end != FileAnswered || a.Op != FileMakeDir {
		t.Fatalf("make_dir: %+v %v", a, end)
	}
	for _, c := range []struct {
		call FileCall
		out  string
	}{
		{stat, ""},
		{stat, "k1:f.1:1"},
		{stat, "k1:xs1:5m3:420t1:1.1:1"},
		{stat, "k1:fs1:5m5:99999t1:1.1:1"},
		{stat, "k1:fs02:5m3:420t1:1.1:1"},
		{stat, "k1:fs1:5m3:420t1:1+1:1"},
		{stat, "k1:fs1:5m3:420t1:1.1:1x"},
		{read, "s1:9b5:abcde.1:1"},
		{read, "s1:9b4:ab\ncd.1:1"},
		{read, "s1:9b9999999999999999999:ab.1:1"},
		{write, "n1:2.1:1"},
		{list, "p0:k1:fs1:0.1:1"},
		{list, "p1:xk1:fs1:0.1:2"},
		{list, "p1:x.1:0k1:fs1:0.1:1"},
		// "u" only in a recursive listing, and with no size; never a stat's answer.
		{list, "p1:xk1:us1:0.1:1"},
		{deep, "p1:xk1:us1:4.1:1"},
		{stat, "k1:us1:0m3:493t1:1.1:1"},
		// A count whose product with the frames per entry wraps around to the frames read.
		// (2^62+1)*4 is 4 modulo 2^64: before the bound, a make of that capacity panicked.
		{stat, "k1:fs1:5m3:420t1:1.19:4611686018427387905"},
		{many, "p1:bs1:2b2:hi+1:1"},
		{many, "p1:as1:9b9:123456789+1:1"},
		{many, "p1:ab2:hi+1:1"},
		{many, "p1:as1:0e2:79+1:1"},
		{many, "p1:as1:2e2:81+1:1"},
		{many, "p1:as1:0z1:x+1:1"},
		{done, ".1:0"},
	} {
		if a, end := answer(t, c.call, 0, c.out, ""); end != FileUnreadable {
			t.Errorf("%s %q: %+v %v; want unreadable", c.call.Op, c.out, a, end)
		}
	}
	if _, end := ReadFileAnswer(list, ExecResult{Stdout: "p1:x", StdoutTruncated: true, Exited: true}); end != FileUnreadable {
		t.Error("a truncated answer was read")
	}
	// Exits: a code of the contract is an error, 1 with the helper's own words OTHER, 2 a
	// protocol error, anything else no answer; output with an error code is unreadable.
	if a, end := answer(t, read, 86, "", ""); end != FileAnswered || a.Error != FileErrorPermissionDenied || a.Errno != "EACCES" || a.Op != "" {
		t.Errorf("86: %+v %v", a, end)
	}
	if a, end := answer(t, read, 1, "", "EIO: input/output error, read 'a'"); end != FileAnswered || a.Error != FileErrorOther || a.Errno != "EIO" {
		t.Errorf("1: %+v %v", a, end)
	}
	if _, end := answer(t, read, 1, "", "OCI runtime exec failed"); end != FileNoAnswer {
		t.Errorf("docker's exit 1: %v", end)
	}
	if _, end := answer(t, read, 2, "", "plimsoll-helper files: x"); end != FileUnreadable {
		t.Errorf("2: %v", end)
	}
	for _, code := range []int{126, 127, 137, 79, 92, 255} {
		if _, end := answer(t, read, code, "", ""); end != FileNoAnswer {
			t.Errorf("%d: %v", code, end)
		}
	}
	if _, end := answer(t, read, 81, "s1:0", ""); end != FileUnreadable {
		t.Errorf("81 with output: %v", end)
	}
}

// The driver's entry types are the wire's, number for number and name for name, and every
// kind the helper frames is one of them.
func TestFileTypesMatchTheEnum(t *testing.T) {
	names := map[FileType]string{FileTypeFile: "FILE", FileTypeDir: "DIR", FileTypeLink: "LINK", FileTypeOther: "OTHER", FileTypeUnreadable: "UNREADABLE"}
	if len(plimsollv1.FilesEntryType_name)-1 != len(names) || len(fileTypeOfKind) != len(names) {
		t.Fatalf("the wire has %d entry types, the driver names %d and frames %d", len(plimsollv1.FilesEntryType_name)-1, len(names), len(fileTypeOfKind))
	}
	for ft, name := range names {
		if got := plimsollv1.FilesEntryType_name[int32(ft)]; got != "FILES_ENTRY_TYPE_"+name {
			t.Errorf("entry type %d is %s on the wire, %s in the driver", ft, got, name)
		}
	}
	for kind, ft := range fileTypeOfKind {
		if _, ok := names[ft]; !ok || len(kind) != 1 {
			t.Errorf("the helper's kind %q maps to %d, no entry type", kind, ft)
		}
	}
}

// RunFile hands the provider the helper's argv and stdin and caps, and returns an exec that
// delivered no exit status as exec's own error.
func TestRunFileHandsTheExecItsCommand(t *testing.T) {
	c := FileCall{Scope: FileScopeWork, Op: FileStat, Path: []byte("a")}
	var gotArgv []string
	var gotIn []byte
	exec := func(_ context.Context, argv []string, stdin []byte, outCap, errCap int) (ExecResult, error) {
		gotArgv, gotIn = argv, stdin
		if outCap < MaxFileBudget || errCap <= 0 {
			t.Errorf("caps %d and %d", outCap, errCap)
		}
		return ExecResult{Stdout: "k1:ds1:0m3:493t1:0.1:1", Exited: true}, nil
	}
	a, end, _, err := RunFile(context.Background(), exec, c)
	if err != nil || end != FileAnswered || a.Type != FileTypeDir || !slices.Equal(gotArgv, c.Argv()) || !bytes.Equal(gotIn, c.Stdin()) {
		t.Fatalf("%+v %v %v; argv %q stdin %q", a, end, err, gotArgv, gotIn)
	}
	cut := func(context.Context, []string, []byte, int, int) (ExecResult, error) {
		return ExecResult{}, context.DeadlineExceeded
	}
	if _, end, _, err := RunFile(context.Background(), cut, c); err != context.DeadlineExceeded || end != FileNoAnswer {
		t.Fatalf("a cut exec: %v %v", end, err)
	}
}

// Fuzzing the reader: it never panics, and whatever it reads as answered holds to its bounds.
func FuzzReadFileAnswer(f *testing.F) {
	f.Add("p1:xk1:ds1:0p3:x/fk1:fs1:5.1:2", uint8(3))
	f.Add("k1:fs1:5m3:420t1:1.1:1", uint8(0))
	f.Add("p1:as1:2b2:hip1:bs1:0e2:81+1:2", uint8(4))
	ops := []FileCall{
		{Scope: FileScopeWork, Op: FileStat, Path: []byte("a")},
		{Scope: FileScopeWork, Op: FileRead, Path: []byte("a"), MaxBytes: 4},
		{Scope: FileScopeWork, Op: FileWrite, Path: []byte("a"), Content: []byte("xy"), Mode: FileWriteReplace},
		{Scope: FileScopeWork, Op: FileList, Path: []byte("."), Budget: MinFileBudget},
		{Scope: FileScopeWork, Op: FileReadMany, Paths: [][]byte{[]byte("a"), []byte("b")}, MaxBytes: 4, Budget: MinFileBudget},
		{Scope: FileScopeWork, Op: FileRename, Path: []byte("a"), To: []byte("b")},
	}
	f.Fuzz(func(t *testing.T, out string, which uint8) {
		c := ops[int(which)%len(ops)]
		a, end := ReadFileAnswer(c, ExecResult{Stdout: out, Exited: true})
		if end != FileAnswered {
			return
		}
		if len(a.Content) > int(c.MaxBytes) && c.Op == FileRead {
			t.Fatalf("read %d bytes past %d", len(a.Content), c.MaxBytes)
		}
		if len(a.Items) > len(c.Paths) {
			t.Fatalf("%d items for %d paths", len(a.Items), len(c.Paths))
		}
	})
}
