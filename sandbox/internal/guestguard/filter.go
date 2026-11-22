package guestguard

import (
	"bytes"
	"embed"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// Classic BPF, as seccomp runs it (linux/filter.h, linux/bpf_common.h, linux/seccomp.h).
// The filter uses five instructions and nothing else, written here by hand so the guard needs
// no BPF library: load a 32-bit word of seccomp_data, three conditional jumps against a
// constant, and return a constant.
const (
	opLdAbsW = 0x20 // BPF_LD | BPF_W | BPF_ABS: A = the 32-bit word at offset k of seccomp_data
	opJeqK   = 0x15 // BPF_JMP | BPF_JEQ | BPF_K: A == k ? skip jt : skip jf
	opJgtK   = 0x25 // BPF_JMP | BPF_JGT | BPF_K: A > k (unsigned) ? skip jt : skip jf
	opJsetK  = 0x45 // BPF_JMP | BPF_JSET | BPF_K: A & k != 0 ? skip jt : skip jf
	opRetK   = 0x06 // BPF_RET | BPF_K: stop and answer k

	// struct seccomp_data { int nr; __u32 arch; __u64 instruction_pointer; __u64 args[6]; },
	// in the machine's own byte order; both machines here are little-endian, so the low half
	// of args[0] is at 16.
	offNr      = 0
	offArch    = 4
	offArg0Low = 16

	retKillProcess = 0x80000000 // SECCOMP_RET_KILL_PROCESS: the whole process dies by SIGSYS
	retErrno       = 0x00050000 // SECCOMP_RET_ERRNO: the request fails with the low 16 bits as errno
	retAllow       = 0x7fff0000 // SECCOMP_RET_ALLOW
)

// Instruction is one struct sock_filter, with the line the C header prints beside it.
type Instruction struct {
	Code    uint16
	Jt, Jf  uint8
	K       uint32
	Comment string
}

// InstructionSize is sizeof(struct sock_filter).
const InstructionSize = 8

// asm builds a program with named jump targets, resolved to the forward offsets classic BPF
// takes (a jump skips that many instructions after its own).
type asm struct {
	ins    []Instruction
	jt, jf map[int]string // instruction index to the label it jumps to when true / false
	labels map[string]int
}

func newAsm() *asm {
	return &asm{jt: map[int]string{}, jf: map[int]string{}, labels: map[string]int{}}
}

func (a *asm) emit(i Instruction) { a.ins = append(a.ins, i) }

func (a *asm) label(name string) { a.labels[name] = len(a.ins) }

// jump emits a conditional jump; an empty label means the next instruction.
func (a *asm) jump(code uint16, k uint32, ifTrue, ifFalse, comment string) {
	if ifTrue != "" {
		a.jt[len(a.ins)] = ifTrue
	}
	if ifFalse != "" {
		a.jf[len(a.ins)] = ifFalse
	}
	a.emit(Instruction{Code: code, K: k, Comment: comment})
}

func (a *asm) resolve() ([]Instruction, error) {
	off := func(at int, label string) (uint8, error) {
		to, ok := a.labels[label]
		if !ok {
			return 0, fmt.Errorf("instruction %d jumps to %q, which is not defined", at, label)
		}
		d := to - at - 1
		if d < 0 || d > 255 {
			return 0, fmt.Errorf("instruction %d jumps %d to %q: classic BPF jumps only 0 to 255 forward", at, d, label)
		}
		return uint8(d), nil
	}
	out := append([]Instruction(nil), a.ins...)
	for at, l := range a.jt {
		d, err := off(at, l)
		if err != nil {
			return nil, err
		}
		out[at].Jt = d
	}
	for at, l := range a.jf {
		d, err := off(at, l)
		if err != nil {
			return nil, err
		}
		out[at].Jf = d
	}
	return out, nil
}

// Program is variant v's filter. In order: check the entry (any other is killed), answer
// request -1, kill the x32 bit, answer each refused request, check clone's flags, answer
// every number above the ceiling, allow the rest.
func (t *Table) Program(v Variant) ([]Instruction, error) {
	a := newAsm()
	arch := v.Arch
	label := map[string]string{EPERM: "eperm", ENOSYS: "enosys"}

	a.emit(Instruction{Code: opLdAbsW, K: offArch, Comment: "A = seccomp_data.arch: which entry the request came through"})
	a.jump(opJeqK, arch.audit, "", "kill", fmt.Sprintf("the %s entry goes on; any other entry (32-bit x86 or 32-bit ARM) is killed", arch.Name))
	a.emit(Instruction{Code: opLdAbsW, K: offNr, Comment: "A = seccomp_data.nr: the request's number (its low 32 bits)"})
	a.jump(opJeqK, 0xFFFFFFFF, "enosys", "", "request -1 (a tracer's skip): Function not implemented, as Linux and gVisor answer")
	if arch.x32 != 0 {
		a.jump(opJsetK, arch.x32, "kill", "", fmt.Sprintf("the x32 bit 0x%x: a second entry with the same arch value, killed", arch.x32))
	}
	var conditional []Request
	var selfCheck *Request
	for _, r := range t.Rows(v) {
		to := label[r.Answer]
		what := r.Answer
		if r.mask != 0 {
			to = "cond_" + r.Name
			what = "check its flags"
			conditional = append(conditional, r)
		}
		if r.Name == t.SelfCheck.Request {
			to = "selfcheck"
			what = r.Answer + ", after the guard's self-check"
			selfCheck = &r
		}
		a.jump(opJeqK, r.Number(arch), to, "", fmt.Sprintf("%s (%d): %s", r.Name, r.Number(arch), what))
	}
	a.jump(opJgtK, t.Ceiling, "enosys", "", fmt.Sprintf("above %d, the highest reviewed number: Function not implemented", t.Ceiling))
	a.emit(Instruction{Code: opRetK, K: retAllow, Comment: "every other request is allowed"})
	if selfCheck != nil {
		sc := t.SelfCheck
		a.label("selfcheck")
		a.emit(Instruction{Code: opLdAbsW, K: offArg0Low, Comment: fmt.Sprintf("A = the low 32 bits of %s's first argument", sc.Request)})
		a.jump(opJeqK, sc.arg0, "selfcheck_answer", label[selfCheck.Answer], fmt.Sprintf("0x%08x is the guard's self-check; any other value: %s", sc.arg0, selfCheck.Answer))
		a.label("selfcheck_answer")
		a.emit(Instruction{Code: opRetK, K: retErrno | sc.Errno, Comment: fmt.Sprintf("%s (%d): the answer only this filter gives", sc.ErrnoName, sc.Errno)})
	}
	for _, r := range conditional {
		a.label("cond_" + r.Name)
		a.emit(Instruction{Code: opLdAbsW, K: offArg0Low, Comment: fmt.Sprintf("A = the low 32 bits of %s's first argument, its flags", r.Name)})
		a.jump(opJsetK, r.mask, label[r.Answer], "", fmt.Sprintf("any flag of 0x%08x: %s", r.mask, r.Answer))
		a.emit(Instruction{Code: opRetK, K: retAllow, Comment: fmt.Sprintf("%s without them is allowed", r.Name)})
	}
	a.label("eperm")
	a.emit(Instruction{Code: opRetK, K: retErrno | errnos[EPERM], Comment: "EPERM: Operation not permitted"})
	a.label("enosys")
	a.emit(Instruction{Code: opRetK, K: retErrno | errnos[ENOSYS], Comment: "ENOSYS: Function not implemented"})
	a.label("kill")
	a.emit(Instruction{Code: opRetK, K: retKillProcess, Comment: "kill the process (SIGSYS)"})
	return a.resolve()
}

// Encode is p as the bytes of a struct sock_filter array on a little-endian machine.
func Encode(p []Instruction) []byte {
	b := make([]byte, 0, len(p)*InstructionSize)
	for _, i := range p {
		b = binary.LittleEndian.AppendUint16(b, i.Code)
		b = append(b, i.Jt, i.Jf)
		b = binary.LittleEndian.AppendUint32(b, i.K)
	}
	return b
}

// Decode reads Encode's bytes back, comments empty.
func Decode(b []byte) ([]Instruction, error) {
	if len(b) == 0 || len(b)%InstructionSize != 0 {
		return nil, fmt.Errorf("%d bytes is not a whole number of %d-byte instructions", len(b), InstructionSize)
	}
	p := make([]Instruction, len(b)/InstructionSize)
	for n := range p {
		w := b[n*InstructionSize:]
		p[n] = Instruction{Code: binary.LittleEndian.Uint16(w), Jt: w[2], Jf: w[3], K: binary.LittleEndian.Uint32(w[4:])}
	}
	return p, nil
}

// cMacro is the compiler's macro for each machine, which picks the header's array.
var cMacro = map[string]string{"x86_64": "__x86_64__", "aarch64": "__aarch64__"}

// FileName is the generated bytes' file for variant v.
func (v Variant) FileName() string { return "filter_" + v.Arch.GOARCH + v.Suffix + ".bin" }

// Files is every generated file, by name in this package's directory: each variant's bytes
// and the C header holding them all.
func (t *Table) Files() (map[string][]byte, error) {
	files := map[string][]byte{}
	var h bytes.Buffer
	h.WriteString("/* Code generated by go run ./sandbox/internal/guestguard/gen from refused.json. DO NOT EDIT. */\n\n")
	h.WriteString("/* The guest guard's seccomp filter, one array per machine (and per runtime when decision 137\n")
	h.WriteString(" * says so). Include <linux/filter.h> first; install with prctl(PR_SET_SECCOMP,\n")
	h.WriteString(" * SECCOMP_MODE_FILTER, &prog) after prctl(PR_SET_NO_NEW_PRIVS, 1). The same bytes are\n")
	h.WriteString(" * filter_<goarch>.bin beside this file. */\n\n")
	h.WriteString("#ifndef PLIMSOLL_GUEST_FILTER_H\n#define PLIMSOLL_GUEST_FILTER_H\n\n")
	byArch := map[string][]Variant{}
	var archOrder []string
	for _, v := range t.Variants() {
		if _, ok := byArch[v.Arch.Name]; !ok {
			archOrder = append(archOrder, v.Arch.Name)
		}
		byArch[v.Arch.Name] = append(byArch[v.Arch.Name], v)
	}
	for n, name := range archOrder {
		macro, ok := cMacro[name]
		if !ok {
			return nil, fmt.Errorf("no compiler macro for %s", name)
		}
		if n == 0 {
			fmt.Fprintf(&h, "#if defined(%s)\n", macro)
		} else {
			fmt.Fprintf(&h, "#elif defined(%s)\n", macro)
		}
		for _, v := range byArch[name] {
			p, err := t.Program(v)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", v.FileName(), err)
			}
			files[v.FileName()] = Encode(p)
			fmt.Fprintf(&h, "static const struct sock_filter guest_filter%s[] = {\n", v.Suffix)
			for i, ins := range p {
				fmt.Fprintf(&h, "\t{ 0x%02x, %d, %d, 0x%08x }, /* %2d: %s */\n", ins.Code, ins.Jt, ins.Jf, ins.K, i, strings.ReplaceAll(ins.Comment, "*/", "* /"))
			}
			h.WriteString("};\n")
		}
		nr := -1
		for _, r := range t.Requests {
			if r.Name == t.SelfCheck.Request {
				nr = int(r.Number(byArch[name][0].Arch))
			}
		}
		fmt.Fprintf(&h, "#define GUEST_SELF_CHECK_NR %d /* %s */\n", nr, t.SelfCheck.Request)
	}
	h.WriteString("#else\n#error \"the guest guard's filter is generated for x86-64 and aarch64 only\"\n#endif\n\n")
	h.WriteString("#define GUEST_FILTER_LEN (sizeof guest_filter / sizeof guest_filter[0])\n")
	fmt.Fprintf(&h, "/* The guard's self-check: GUEST_SELF_CHECK_NR with this first argument is answered\n * GUEST_SELF_CHECK_ERRNO (%s) by this filter alone (refused.json, self_check). */\n", t.SelfCheck.ErrnoName)
	fmt.Fprintf(&h, "#define GUEST_SELF_CHECK_ARG0 0x%08xUL\n#define GUEST_SELF_CHECK_ERRNO %d\n", t.SelfCheck.arg0, t.SelfCheck.Errno)
	if t.TracingRefused == TracingGVisor {
		h.WriteString("#define GUEST_FILTER_GVISOR_LEN (sizeof guest_filter_gvisor / sizeof guest_filter_gvisor[0])\n")
	}
	h.WriteString("\n#endif\n")
	files["guest_filter.h"] = h.Bytes()
	return files, nil
}

// FileNames is Files' keys, sorted.
func FileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

//go:embed filter_*.bin
var committed embed.FS

// Filter is the committed bytes of the filter for goarch (amd64, arm64) and suffix ("" or
// "_gvisor"), what a guard embeds. TestGeneratedFilesAreCurrent holds them to the table.
func Filter(goarch, suffix string) ([]byte, error) {
	return committed.ReadFile("filter_" + goarch + suffix + ".bin")
}
