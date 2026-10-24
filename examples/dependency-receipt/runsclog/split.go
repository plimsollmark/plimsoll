package runsclog

import (
	"regexp"
	"slices"
	"strings"
)

// kind is one argument layout gVisor's strace prints (pkg/sentry/strace: the format table in
// linux64_amd64.go and the formatters in strace.go and socket.go).
type kind int

const (
	kHex   kind = iota // %#x
	kFlags             // decoded flags or a name: O_WRONLY|O_CREAT, CLONE_VM|..., AF_INET
	kMode              // a file mode: 0o644, or with type and extra bits, S_IFREG|S_ISUID|0o755
	kOct               // a plain octal number: 0o4755
	kPath              // "0xADDR path": the path as the program passed it, printed raw
	kFD                // "0xN name" or "AT_FDCWD dir": gVisor's name for the file, printed raw
	kVec               // "0xADDR [\"a\", \"b\"]": quoted strings
	kBuf               // written data: "0xADDR \"...\"", quoted; "..." on a successful exit
	kIOV               // written iovecs: "0xADDR {base=..., len=N, \"...\"}, ..."; "..." on exit
	kAddr              // a socket address: "null" or "0xADDR {Family: ...}"
	kBrace             // a structure gVisor decodes: "0xADDR {...}"
	kHow               // openat2's open_how: "0xADDR flags F mode M resolve R"
)

// specs holds the layout of every call the reader follows, as gVisor prints it on amd64.
var specs = map[string][]kind{
	"execve":         {kPath, kVec, kVec},
	"execveat":       {kFD, kPath, kVec, kVec, kHex},
	"fork":           {},
	"vfork":          {},
	"clone":          {kFlags, kHex, kHex, kHex, kHex},
	"clone3":         {kHex, kHex},
	"exit_group":     {kHex},
	"open":           {kPath, kFlags, kMode},
	"openat":         {kFD, kPath, kFlags, kMode},
	"openat2":        {kFD, kPath, kHow, kHex},
	"creat":          {kPath, kOct},
	"close":          {kFD},
	"write":          {kFD, kBuf, kHex},
	"pwrite64":       {kFD, kBuf, kHex, kHex},
	"writev":         {kFD, kIOV, kHex},
	"pwritev":        {kFD, kIOV, kHex, kHex},
	"pwritev2":       {kFD, kIOV, kHex, kHex, kHex},
	"truncate":       {kPath, kHex},
	"ftruncate":      {kFD, kHex},
	"mkdir":          {kPath, kOct},
	"mkdirat":        {kFD, kPath, kHex},
	"rmdir":          {kPath},
	"unlink":         {kPath},
	"unlinkat":       {kFD, kPath, kHex},
	"rename":         {kPath, kPath},
	"renameat":       {kFD, kPath, kHex, kPath},
	"renameat2":      {kFD, kPath, kHex, kPath, kHex},
	"link":           {kPath, kPath},
	"linkat":         {kFD, kPath, kHex, kPath, kHex},
	"symlink":        {kPath, kPath},
	"symlinkat":      {kPath, kFD, kPath},
	"chdir":          {kPath},
	"fchdir":         {kFD},
	"dup":            {kFD},
	"dup2":           {kFD, kFD},
	"dup3":           {kFD, kFD, kHex},
	"close_range":    {kFD, kFD, kFlags},
	"socket":         {kFlags, kFlags, kFlags},
	"connect":        {kFD, kAddr, kHex},
	"bind":           {kFD, kAddr, kHex},
	"listen":         {kFD, kHex},
	"sendto":         {kFD, kHex, kHex, kHex, kAddr, kHex},
	"sendmsg":        {kFD, kBrace, kHex},
	"sendmmsg":       {kFD, kHex, kHex, kHex},
	"memfd_create":   {kPath, kHex},
	"io_uring_setup": {kHex, kHex},
}

// Syscalls is the list to give runsc's --strace-syscalls so that it logs the calls this
// reader follows and no others.
func Syscalls() []string {
	out := make([]string, 0, len(specs))
	for name := range specs {
		out = append(out, name)
	}
	slices.Sort(out)
	return out
}

// budget bounds the work one entry may cost: a path full of ", " multiplies the ways to
// split an entry with two raw arguments.
const budget = 20000

// split returns every way args can be read as the fields of spec, stopping at two (two are
// enough to call it ambiguous). A raw field (a path or a descriptor's name) may hold any
// text, so every ", " after it is a place it might end; every other field is read exactly.
func split(spec []kind, args string) [][]string {
	var out [][]string
	steps := 0
	var rec func(i int, s string, acc []string)
	rec = func(i int, s string, acc []string) {
		steps++
		if len(out) > 1 || steps > budget {
			return
		}
		acc = acc[:len(acc):len(acc)]
		if i == len(spec) {
			if s == "" {
				out = append(out, acc)
			}
			return
		}
		last := i == len(spec)-1
		if spec[i] == kPath || spec[i] == kFD {
			if last {
				if rawOK(spec[i], s) {
					rec(i+1, "", append(acc, s))
				}
				return
			}
			for j := 0; ; {
				k := strings.Index(s[j:], ", ")
				if k < 0 {
					return
				}
				e := j + k
				if rawOK(spec[i], s[:e]) {
					rec(i+1, s[e+2:], append(acc, s[:e]))
				}
				j = e + 1
			}
		}
		n := token(spec[i], s)
		if n < 0 {
			return
		}
		if last {
			if n == len(s) {
				rec(i+1, "", append(acc, s))
			}
			return
		}
		if strings.HasPrefix(s[n:], ", ") {
			rec(i+1, s[n+2:], append(acc, s[:n]))
		}
	}
	rec(0, args, nil)
	if steps > budget {
		return [][]string{nil, nil} // too many ways to read it: unclear
	}
	return out
}

var (
	hexRE   = regexp.MustCompile(`^0x[0-9a-f]+`)
	flagsRE = regexp.MustCompile(`^[A-Za-z0-9_|]+`)
	modeRE  = regexp.MustCompile(`^(?:[A-Za-z0-9_]+\|)*0o[0-7]+`)
	octRE   = regexp.MustCompile(`^0o[0-7]+`)
	addrRE  = regexp.MustCompile(`^0x[0-9a-f]+ `)
	errRE   = regexp.MustCompile(`^0x[0-9a-f]+ \(error decoding [A-Za-z]+: [^()]*\)`)
	howRE   = regexp.MustCompile(`^0x[0-9a-f]+ flags ([A-Za-z0-9_|]+) mode 0o[0-7]+ resolve [A-Za-z0-9_|]+`)
)

// rawOK says whether s can be a raw field: a path or a descriptor's name after its number.
func rawOK(k kind, s string) bool {
	if k == kPath && s == "<null>" {
		return true
	}
	if k == kFD && strings.HasPrefix(s, "AT_FDCWD ") {
		return true
	}
	return addrRE.MatchString(s)
}

// token returns the length of the field of kind k at the start of s, or -1.
func token(k kind, s string) int {
	switch k {
	case kHex:
		return match(hexRE, s)
	case kFlags:
		return match(flagsRE, s)
	case kMode:
		return match(modeRE, s)
	case kOct:
		return match(octRE, s)
	case kVec:
		if n := match(addrRE, s); n > 0 && n < len(s) && s[n] == '[' {
			if m := balanced(s[n:]); m > 0 {
				return n + m
			}
		}
		return braced(s)
	case kBuf:
		if strings.HasPrefix(s, "...") {
			return 3
		}
		if strings.HasPrefix(s, ", ") || s == "" {
			return 0 // gVisor prints nothing for an empty write
		}
		if n := match(errRE, s); n > 0 {
			return n
		}
		if n := match(addrRE, s); n > 0 && n < len(s) && s[n] == '"' {
			if m := quoted(s[n:]); m > 0 {
				n += m
				if strings.HasPrefix(s[n:], "...") {
					n += 3
				}
				return n
			}
		}
		return -1
	case kIOV:
		if strings.HasPrefix(s, "...") {
			return 3
		}
		if n := match(errRE, s); n > 0 {
			return n
		}
		n := match(addrRE, s)
		if n < 0 {
			return -1
		}
		for n < len(s) && s[n] == '{' {
			m := balanced(s[n:])
			if m < 0 {
				return -1
			}
			n += m
			if !strings.HasPrefix(s[n:], ", {") {
				break
			}
			n += 2
		}
		return n
	case kAddr:
		if strings.HasPrefix(s, "null") {
			return 4
		}
		return braced(s)
	case kHow:
		if strings.HasPrefix(s, "<null>") {
			return 6
		}
		if strings.HasPrefix(s, "<invalid size>") {
			return 14
		}
		if n := match(errRE, s); n > 0 {
			return n
		}
		return match(howRE, s)
	case kBrace:
		if n := match(errRE, s); n > 0 {
			return n
		}
		return braced(s)
	}
	return -1
}

func match(re *regexp.Regexp, s string) int {
	if loc := re.FindStringIndex(s); loc != nil {
		return loc[1]
	}
	return -1
}

// braced is the length of "0xADDR {...}" at the start of s, or -1.
func braced(s string) int {
	n := match(addrRE, s)
	if n < 0 || n >= len(s) || s[n] != '{' {
		return -1
	}
	m := balanced(s[n:])
	if m < 0 {
		return -1
	}
	return n + m
}

// balanced is the length of the bracketed group at the start of s ({...} or [...]), with
// quoted strings skipped whole, or -1 when it does not close.
func balanced(s string) int {
	depth := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			n := quoted(s[i:])
			if n < 0 {
				return -1
			}
			i += n - 1
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1
			}
		}
	}
	return -1
}

// quoted is the length of the Go-quoted string at the start of s, or -1.
func quoted(s string) int {
	if s == "" || s[0] != '"' {
		return -1
	}
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i + 1
		}
	}
	return -1
}
