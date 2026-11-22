package guestguard

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The tests run the generated filter as data: a small interpreter for the five classic BPF
// instructions the filter uses, fed a seccomp_data built here, with no process installing
// anything. The kernel's and gVisor's own interpreters run the same bytes; the docker check
// (sandbox/guestguard_docker_test.go) holds a real one to the same answers.

const (
	auditI386    = 0x40000003 // AUDIT_ARCH_I386: the 32-bit x86 entry of an x86-64 kernel
	auditARM     = 0x40000028 // AUDIT_ARCH_ARM: the 32-bit ARM entry of an aarch64 kernel
	auditX86_64  = 0xc000003e
	auditAArch64 = 0xc00000b7
	maxInsns     = 4096 // BPF_MAXINSNS
	seccompData  = 64   // sizeof(struct seccomp_data)
)

// data is a struct seccomp_data on a little-endian machine. nr is cut to its low 32 bits, as
// the kernel and gVisor hand a 64-bit request number to a filter.
func data(arch uint32, nr uint64, args ...uint64) []byte {
	b := make([]byte, seccompData)
	binary.LittleEndian.PutUint32(b[0:], uint32(nr))
	binary.LittleEndian.PutUint32(b[4:], arch)
	for i, a := range args {
		binary.LittleEndian.PutUint64(b[16+8*i:], a)
	}
	return b
}

// interpret runs p on d as the kernel's classic BPF interpreter would, for the instructions
// the filter may use; any other instruction, a load outside seccomp_data or unaligned, a jump
// past the end and running off the end are errors.
func interpret(p []Instruction, d []byte) (uint32, error) {
	var acc uint32
	for pc, steps := 0, 0; ; steps++ {
		if pc >= len(p) {
			return 0, fmt.Errorf("ran off the end at %d", pc)
		}
		if steps > len(p) {
			return 0, fmt.Errorf("more steps than instructions: a jump went backwards")
		}
		i := p[pc]
		switch i.Code {
		case opLdAbsW:
			if i.K%4 != 0 || i.K+4 > uint32(len(d)) {
				return 0, fmt.Errorf("instruction %d loads offset %d, outside or unaligned in seccomp_data", pc, i.K)
			}
			acc = binary.LittleEndian.Uint32(d[i.K:])
			pc++
		case opJeqK, opJgtK, opJsetK:
			var c bool
			switch i.Code {
			case opJeqK:
				c = acc == i.K
			case opJgtK:
				c = acc > i.K
			default:
				c = acc&i.K != 0
			}
			if c {
				pc += 1 + int(i.Jt)
			} else {
				pc += 1 + int(i.Jf)
			}
		case opRetK:
			return i.K, nil
		default:
			return 0, fmt.Errorf("instruction %d has code 0x%x, which the filter does not use", pc, i.Code)
		}
	}
}

// answer names a return value.
func answer(ret uint32) string {
	switch ret {
	case retAllow:
		return Allow
	case retErrno | 1:
		return EPERM
	case retErrno | 38:
		return ENOSYS
	case retErrno | 133:
		return "EHWPOISON"
	case retKillProcess:
		return Kill
	}
	return fmt.Sprintf("unknown 0x%08x", ret)
}

func mustLoad(t *testing.T) *Table {
	t.Helper()
	tb, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	return tb
}

// committedProgram is the committed bytes of v, decoded.
func committedProgram(t *testing.T, v Variant) []Instruction {
	t.Helper()
	b, err := Filter(v.Arch.GOARCH, v.Suffix)
	if err != nil {
		t.Fatalf("%s: %v (run go run ./sandbox/internal/guestguard/gen)", v.FileName(), err)
	}
	p, err := Decode(b)
	if err != nil {
		t.Fatalf("%s: %v", v.FileName(), err)
	}
	return p
}

func run(t *testing.T, p []Instruction, d []byte) string {
	t.Helper()
	ret, err := interpret(p, d)
	if err != nil {
		t.Fatal(err)
	}
	return answer(ret)
}

// TestGeneratedFilesAreCurrent: the committed filter files and C header are what the table
// makes, byte for byte, and no filter file is left that the table no longer makes.
func TestGeneratedFilesAreCurrent(t *testing.T) {
	files, err := mustLoad(t).Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range FileNames(files) {
		got, err := os.ReadFile(name)
		if err != nil {
			t.Errorf("%s: %v (run go run ./sandbox/internal/guestguard/gen)", name, err)
			continue
		}
		if !bytes.Equal(got, files[name]) {
			t.Errorf("%s is not what refused.json makes; edit the table, not the file, and run go run ./sandbox/internal/guestguard/gen", name)
		}
	}
	on, err := filepath.Glob("filter_*.bin")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range on {
		if _, ok := files[name]; !ok {
			t.Errorf("%s is committed and the table makes no such filter; go run ./sandbox/internal/guestguard/gen removes it", name)
		}
	}
}

// decidedRow is one refused request as the design and its review decided it, written here a
// second time on purpose: a row taken out of refused.json, or an answer or number changed
// there, fails TestEveryDecidedRowIsRefused even after the filter is regenerated.
type decidedRow struct {
	name            string
	x86_64, aarch64 uint64
	answer          string
	tracing         bool // decision 137's rows
}

var decided = []decidedRow{
	{"unshare", 272, 97, EPERM, false},
	{"clone", 56, 220, EPERM, false}, // with a namespace flag; TestCloneFlags holds the rest
	{"clone3", 435, 435, ENOSYS, false},
	{"setns", 308, 268, EPERM, false},
	{"mount", 165, 40, EPERM, false},
	{"umount2", 166, 39, EPERM, false},
	{"pivot_root", 155, 41, EPERM, false},
	{"chroot", 161, 51, EPERM, false},
	{"open_tree", 428, 428, EPERM, false},
	{"move_mount", 429, 429, EPERM, false},
	{"fsopen", 430, 430, EPERM, false},
	{"fsconfig", 431, 431, EPERM, false},
	{"fsmount", 432, 432, EPERM, false},
	{"fspick", 433, 433, EPERM, false},
	{"mount_setattr", 442, 442, EPERM, false},
	{"open_tree_attr", 467, 467, EPERM, false},
	{"fchroot", 472, 472, EPERM, false},
	{"ptrace", 101, 117, EPERM, true},
	{"process_vm_writev", 311, 271, EPERM, true},
}

func (r decidedRow) number(a Arch) uint64 {
	if a.Name == "aarch64" {
		return r.aarch64
	}
	return r.x86_64
}

// The clone flags that make a namespace, each alone in the tests.
var namespaceFlags = map[string]uint64{
	"CLONE_NEWNS": 0x00020000, "CLONE_NEWCGROUP": 0x02000000, "CLONE_NEWUTS": 0x04000000,
	"CLONE_NEWIPC": 0x08000000, "CLONE_NEWUSER": 0x10000000, "CLONE_NEWPID": 0x20000000,
	"CLONE_NEWNET": 0x40000000,
}

// TestEveryDecidedRowIsRefused: the table lists exactly the decided requests, and each
// committed filter answers each one as decided on its machine (a tracing row only in a
// filter decision 137 puts it in, and allowed in the others).
func TestEveryDecidedRowIsRefused(t *testing.T) {
	tb := mustLoad(t)
	var want, got []string
	for _, r := range decided {
		want = append(want, r.name)
	}
	for _, r := range tb.Requests {
		got = append(got, r.Name)
	}
	slices.Sort(want)
	slices.Sort(got)
	if !slices.Equal(want, got) {
		t.Errorf("refused.json lists %v; the decided rows are %v", got, want)
	}
	for _, v := range tb.Variants() {
		p := committedProgram(t, v)
		for _, r := range decided {
			arg0 := uint64(0)
			if r.name == "clone" {
				arg0 = namespaceFlags["CLONE_NEWUSER"] | 17 // SIGCHLD
			}
			w := r.answer
			if r.tracing && !v.Tracing {
				w = Allow
			}
			if a := run(t, p, data(v.Arch.audit, r.number(v.Arch), arg0)); a != w {
				t.Errorf("%s: %s (%d) answered %s, want %s", v.FileName(), r.name, r.number(v.Arch), a, w)
			}
		}
	}
}

// TestCloneFlags: clone is refused with any namespace flag, alone or together, and allowed
// without one: a fork's flags, a thread's flags, a namespace flag in the upper half of the
// 64-bit argument (Linux and gVisor read only the low 32 bits of clone's flags), and
// CLONE_NEWTIME, which clone reads as part of the exit signal (only clone3 and unshare carry
// it, and both are refused whole).
func TestCloneFlags(t *testing.T) {
	tb := mustLoad(t)
	for _, v := range tb.Variants() {
		p := committedProgram(t, v)
		nr := uint64(220)
		if v.Arch.Name == "x86_64" {
			nr = 56
		}
		all := uint64(0)
		for name, f := range namespaceFlags {
			all |= f
			if a := run(t, p, data(v.Arch.audit, nr, f)); a != EPERM {
				t.Errorf("%s: clone with %s answered %s, want EPERM", v.FileName(), name, a)
			}
			if a := run(t, p, data(v.Arch.audit, nr, f|17|0x3d0f00)); a != EPERM {
				t.Errorf("%s: clone with %s and a thread's flags answered %s, want EPERM", v.FileName(), name, a)
			}
			if a := run(t, p, data(v.Arch.audit, nr, f<<32|17)); a != Allow {
				t.Errorf("%s: clone with %s only in the upper half answered %s, want allowed (the kernel ignores that half)", v.FileName(), name, a)
			}
		}
		if a := run(t, p, data(v.Arch.audit, nr, all)); a != EPERM {
			t.Errorf("%s: clone with every namespace flag answered %s", v.FileName(), a)
		}
		for name, flags := range map[string]uint64{
			"no flags": 0, "a fork (SIGCHLD)": 17,
			"a thread (CLONE_VM|FS|FILES|SIGHAND|THREAD|SYSVSEM|SETTLS|PARENT_SETTID|CHILD_CLEARTID)": 0x3d0f00,
			"vfork (CLONE_VM|CLONE_VFORK|SIGCHLD)":                                                    0x4111, "CLONE_NEWTIME (0x80)": 0x80,
			"every bit outside the mask": 0xffffffff &^ 0x7e020000, "the upper half set": 0xffffffff00000011,
		} {
			if a := run(t, p, data(v.Arch.audit, nr, flags)); a != Allow {
				t.Errorf("%s: clone with %s answered %s, want allowed", v.FileName(), name, a)
			}
		}
	}
}

// TestFixedRules: an ordinary request is allowed; request -1 and every number above the
// ceiling get Function not implemented; the x32 bit is killed on x86-64 and is only a large
// number on aarch64; a number with bits above 32 is read by its low half; every other entry
// is killed.
func TestFixedRules(t *testing.T) {
	tb := mustLoad(t)
	ordinary := map[string]map[string]uint64{
		"x86_64":  {"read": 0, "write": 1, "mmap": 9, "getpid": 39, "execve": 59, "openat": 257, "listns": 470, "rseq_slice_yield": 471},
		"aarch64": {"read": 63, "write": 64, "mmap": 222, "getpid": 172, "execve": 221, "openat": 56, "listns": 470, "rseq_slice_yield": 471},
	}
	for _, v := range tb.Variants() {
		p := committedProgram(t, v)
		audit := v.Arch.audit
		expect := func(what string, d []byte, w string) {
			t.Helper()
			if a := run(t, p, d); a != w {
				t.Errorf("%s: %s answered %s, want %s", v.FileName(), what, a, w)
			}
		}
		for name, nr := range ordinary[v.Arch.Name] {
			expect(name, data(audit, nr), Allow)
		}
		expect("request -1", data(audit, 0xFFFFFFFF), ENOSYS)
		expect("request -1 as a 64-bit -1", data(audit, ^uint64(0)), ENOSYS)
		expect("the ceiling itself (fchroot)", data(audit, uint64(tb.Ceiling)), EPERM)
		expect("just above the ceiling", data(audit, uint64(tb.Ceiling)+1), ENOSYS)
		expect("1000", data(audit, 1000), ENOSYS)
		expect("0x3fffffff", data(audit, 0x3fffffff), ENOSYS)
		expect("0x80000000", data(audit, 0x80000000), ENOSYS)
		getpid, unshare := ordinary[v.Arch.Name]["getpid"], uint64(272)
		if v.Arch.Name == "aarch64" {
			unshare = 97
		}
		expect("unshare with bit 32 set", data(audit, 1<<32|unshare), EPERM)
		expect("getpid with every upper bit set", data(audit, 0xffffffff<<32|getpid), Allow)
		if v.Arch.Name == "x86_64" {
			expect("x32 getpid", data(audit, 0x40000000|getpid), Kill)
			expect("x32 unshare", data(audit, 0x40000000|unshare), Kill)
			expect("the x32 bit alone", data(audit, 0x40000000), Kill)
		} else {
			expect("bit 30 on aarch64", data(audit, 0x40000000|getpid), ENOSYS)
		}
		others := []uint32{auditI386, auditARM, 0, ^uint32(0)}
		if v.Arch.Name == "x86_64" {
			others = append(others, auditAArch64)
		} else {
			others = append(others, auditX86_64)
		}
		for _, other := range others {
			expect(fmt.Sprintf("getpid through entry 0x%08x", other), data(other, getpid), Kill)
			expect(fmt.Sprintf("request -1 through entry 0x%08x", other), data(other, 0xFFFFFFFF), Kill)
		}
	}
}

// TestSelfCheck: the self-check request (refused.json, self_check) is answered with its own errno
// by every committed filter, through the machine's own entry only, and the same request with any
// other first argument keeps its row's answer; the C header names the same request, argument and
// errno the filter answers, so the guard asks exactly what the filter answers.
func TestSelfCheck(t *testing.T) {
	tb := mustLoad(t)
	sc := tb.SelfCheck
	if sc.Request != "unshare" || sc.Errno != 133 || sc.ErrnoName != "EHWPOISON" || sc.Arg0() != 0xffffffff {
		t.Fatalf("self_check is %+v; this test, guard.c and the docker tests read unshare(0xffffffff) answered EHWPOISON (133)", sc)
	}
	header, err := os.ReadFile("guest_filter.h")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"#define GUEST_SELF_CHECK_ARG0 0xffffffffUL\n", "#define GUEST_SELF_CHECK_ERRNO 133\n",
		"#define GUEST_SELF_CHECK_NR 272 /* unshare */\n", "#define GUEST_SELF_CHECK_NR 97 /* unshare */\n"} {
		if !bytes.Contains(header, []byte(want)) {
			t.Errorf("guest_filter.h lacks %q", want)
		}
	}
	for _, v := range tb.Variants() {
		p := committedProgram(t, v)
		nr := uint64(272)
		if v.Arch.Name == "aarch64" {
			nr = 97
		}
		for _, c := range []struct {
			what string
			arg0 uint64
			want string
		}{
			{"the self-check", 0xffffffff, "EHWPOISON"},
			{"the self-check with upper bits set", 0xffffffff_ffffffff, "EHWPOISON"},
			{"flags 0", 0, EPERM},
			{"a user namespace", 0x10000000, EPERM},
			{"all but one low bit", 0xfffffffe, EPERM},
		} {
			if a := run(t, p, data(v.Arch.audit, nr, c.arg0)); a != c.want {
				t.Errorf("%s: unshare, %s: %s, want %s", v.FileName(), c.what, a, c.want)
			}
		}
		if a := run(t, p, data(auditI386, nr, 0xffffffff)); a != Kill {
			t.Errorf("%s: the self-check through another entry: %s, want it killed", v.FileName(), a)
		}
	}
}

// TestFilterMatchesTable: over every number up to well past the ceiling, the special ones,
// each entry and a set of first arguments, both the committed filter and a freshly generated
// one answer what Decide reads from the table.
func TestFilterMatchesTable(t *testing.T) {
	tb := mustLoad(t)
	args := []uint64{0, 17, 0x3d0f00, 0x10000000, 0x7e020000, 0x80, 0xffffffffffffffff, 0x10000000 << 32, 0xffffffff, 0xfffffffe}
	for _, v := range tb.Variants() {
		fresh, err := tb.Program(v)
		if err != nil {
			t.Fatal(err)
		}
		progs := map[string][]Instruction{"committed": committedProgram(t, v), "generated": fresh}
		var nrs []uint32
		for n := uint32(0); n <= tb.Ceiling+64; n++ {
			nrs = append(nrs, n)
		}
		nrs = append(nrs, 0xFFFFFFFF, 0xFFFFFFFE, 0x40000000, 0x40000027, 0x7fffffff, 0x80000000, 0xc0000110)
		for _, arch := range []uint32{v.Arch.audit, auditI386, auditARM, auditX86_64, auditAArch64} {
			for _, nr := range nrs {
				for _, a0 := range args {
					w := tb.Decide(v, arch, nr, a0)
					for which, p := range progs {
						ret, err := interpret(p, data(arch, uint64(nr), a0))
						if err != nil {
							t.Fatalf("%s %s: %v", v.FileName(), which, err)
						}
						if a := answer(ret); a != w {
							t.Fatalf("%s %s: arch 0x%08x nr %d arg0 0x%x answered %s; the table says %s", v.FileName(), which, arch, nr, a0, a, w)
						}
					}
				}
			}
		}
	}
}

// TestFilterIsWellFormed: what the kernel's seccomp_check_filter asks of a classic program,
// checked on the committed bytes: at most BPF_MAXINSNS instructions, only the five used
// codes, loads aligned inside seccomp_data, no jump past the end, the last instruction a
// return, and only the four answers this filter gives.
func TestFilterIsWellFormed(t *testing.T) {
	tb := mustLoad(t)
	for _, v := range tb.Variants() {
		p := committedProgram(t, v)
		if len(p) == 0 || len(p) > maxInsns {
			t.Fatalf("%s: %d instructions", v.FileName(), len(p))
		}
		if p[len(p)-1].Code != opRetK {
			t.Errorf("%s: the last instruction is not a return", v.FileName())
		}
		for pc, i := range p {
			switch i.Code {
			case opLdAbsW:
				if i.K%4 != 0 || i.K+4 > seccompData || i.Jt != 0 || i.Jf != 0 {
					t.Errorf("%s: %d: load of offset %d", v.FileName(), pc, i.K)
				}
			case opJeqK, opJgtK, opJsetK:
				if pc+1+int(i.Jt) >= len(p) || pc+1+int(i.Jf) >= len(p) {
					t.Errorf("%s: %d: a jump past the end", v.FileName(), pc)
				}
			case opRetK:
				if a := answer(i.K); strings.HasPrefix(a, "unknown") {
					t.Errorf("%s: %d: returns %s", v.FileName(), pc, a)
				}
			default:
				t.Errorf("%s: %d: code 0x%x", v.FileName(), pc, i.Code)
			}
		}
	}
}

// edited is refused.json with edit applied to its decoded form, so a test's change does not
// depend on how the file is laid out.
func edited(t *testing.T, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(refusedJSON, &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// row is request name in a decoded table.
func row(t *testing.T, m map[string]any, name string) map[string]any {
	t.Helper()
	for _, r := range m["requests"].([]any) {
		if r := r.(map[string]any); r["name"] == name {
			return r
		}
	}
	t.Fatalf("refused.json has no row %s", name)
	return nil
}

// TestDecision137IsOneLine: the answer to decision 137 changes one line of the table,
// and nothing else needs editing; TestDecision137 holds what each answer makes.
func TestDecision137IsOneLine(t *testing.T) {
	n := 0
	for _, l := range strings.Split(string(refusedJSON), "\n") {
		if strings.Contains(l, `"tracing_refused":`) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("refused.json has %d lines naming tracing_refused, want 1", n)
	}
}

// TestDecision137 holds what each answer to decision 137 makes: everywhere, the tracing rows
// are in each machine's one filter; nowhere, in none; gvisor, a plain filter without them
// and a _gvisor one with them, both in the header.
func TestDecision137(t *testing.T) {
	cases := map[string]struct {
		files  []string
		traced map[string]string // file to the tracing rows' answer in it
	}{
		TracingEverywhere: {[]string{"filter_amd64.bin", "filter_arm64.bin"}, map[string]string{"filter_amd64.bin": EPERM, "filter_arm64.bin": EPERM}},
		TracingNowhere:    {[]string{"filter_amd64.bin", "filter_arm64.bin"}, map[string]string{"filter_amd64.bin": Allow, "filter_arm64.bin": Allow}},
		TracingGVisor: {[]string{"filter_amd64.bin", "filter_amd64_gvisor.bin", "filter_arm64.bin", "filter_arm64_gvisor.bin"},
			map[string]string{"filter_amd64.bin": Allow, "filter_amd64_gvisor.bin": EPERM, "filter_arm64.bin": Allow, "filter_arm64_gvisor.bin": EPERM}},
	}
	for answerTo, c := range cases {
		tb, err := Parse(edited(t, func(m map[string]any) { m["tracing_refused"] = answerTo }))
		if err != nil {
			t.Fatal(err)
		}
		files, err := tb.Files()
		if err != nil {
			t.Fatal(err)
		}
		var bins []string
		for _, n := range FileNames(files) {
			if strings.HasSuffix(n, ".bin") {
				bins = append(bins, n)
			}
		}
		if !slices.Equal(bins, c.files) {
			t.Errorf("%s: files %v, want %v", answerTo, bins, c.files)
		}
		hasGVisor := bytes.Contains(files["guest_filter.h"], []byte("guest_filter_gvisor[]"))
		if hasGVisor != (answerTo == TracingGVisor) {
			t.Errorf("%s: the header's _gvisor array present: %v", answerTo, hasGVisor)
		}
		for _, v := range tb.Variants() {
			p, err := Decode(files[v.FileName()])
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range decided {
				if !r.tracing {
					continue
				}
				if a := run(t, p, data(v.Arch.audit, r.number(v.Arch))); a != c.traced[v.FileName()] {
					t.Errorf("%s: %s answers %s %s, want %s", answerTo, v.FileName(), r.name, a, c.traced[v.FileName()])
				}
			}
		}
	}
}

// TestParseRefusesABadTable: the mistakes Parse exists to catch.
func TestParseRefusesABadTable(t *testing.T) {
	for what, edit := range map[string]func(m map[string]any){
		"an unknown field":             func(m map[string]any) { m["extra"] = 1 },
		"an unknown field in a row":    func(m map[string]any) { row(t, m, "mount")["flags"] = 1 },
		"a number above the ceiling":   func(m map[string]any) { row(t, m, "fchroot")["x86_64"] = 473 },
		"a number listed twice":        func(m map[string]any) { row(t, m, "umount2")["x86_64"] = 165 },
		"a name listed twice":          func(m map[string]any) { row(t, m, "umount2")["name"] = "mount" },
		"an answer that is not one":    func(m map[string]any) { row(t, m, "chroot")["answer"] = Kill },
		"a missing number":             func(m map[string]any) { delete(row(t, m, "pivot_root"), "aarch64") },
		"a row with no why":            func(m map[string]any) { delete(row(t, m, "setns"), "why") },
		"an unknown decision 137":      func(m map[string]any) { m["tracing_refused"] = "sometimes" },
		"a mask that is not hex":       func(m map[string]any) { row(t, m, "clone")["when_arg0_any"] = "namespaces" },
		"a ceiling in the x32 range":   func(m map[string]any) { m["ceiling"] = 0x40000000 },
		"an x32 bit of two bits":       func(m map[string]any) { m["arches"].([]any)[0].(map[string]any)["x32_bit"] = "0x60000000" },
		"no self-check":                func(m map[string]any) { delete(m, "self_check") },
		"a self-check on no row":       func(m map[string]any) { m["self_check"].(map[string]any)["request"] = "getpid" },
		"a self-check on clone":        func(m map[string]any) { m["self_check"].(map[string]any)["request"] = "clone" },
		"a self-check on ptrace":       func(m map[string]any) { m["self_check"].(map[string]any)["request"] = "ptrace" },
		"a self-check answering EPERM": func(m map[string]any) { m["self_check"].(map[string]any)["errno"] = 1 },
		"a self-check past 4095":       func(m map[string]any) { m["self_check"].(map[string]any)["errno"] = 4096 },
		"a self-check with argument 0": func(m map[string]any) { m["self_check"].(map[string]any)["arg0_low"] = "0" },
	} {
		if _, err := Parse(edited(t, edit)); err == nil {
			t.Errorf("Parse accepted a table with %s", what)
		}
	}
	if _, err := Parse(edited(t, func(map[string]any) {})); err != nil {
		t.Fatalf("the table itself, decoded and encoded again: %v", err)
	}
}
