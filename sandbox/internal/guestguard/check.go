package guestguard

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
)

// The guard check: a program of a few dozen machine instructions, written out here one by one,
// that the docker provider's startup smoke test starts the way a guest's program is started
// (behind the guard, then plimsoll's start script), so the smoke test proves from inside a
// guest-started process that the guard's filter is on it (finding guest-guard-18), not only that
// the guard ran. It makes the requests of CheckAttempts in order and requires each answer the
// table gives, the first being the self-check request, whose answer only the guard's filter
// gives; then one ordinary request, a write of CheckOK to its standard output, which must work;
// then it exits 0. On the first answer that differs it writes nothing and exits with that
// attempt's code, so a program without the guard's filter stops at the self-check, before any
// request that could make a namespace: no check runs the road without the guard (finding
// guest-guard-11).
//
// It is not C, so it needs no compiler and no build step, and nothing of an image: no library,
// no loader, no interpreter. Its bytes are made from the table at each start (CheckProgram), so
// it cannot drift from the filter it checks. Built for the machines the guard is installed for
// (amd64 today, as Program).

// CheckOK is the line the check writes when every answer was the table's.
const CheckOK = "plimsoll guest guard check: ok\n"

// The check's exit codes. Each attempt's is its own; CheckExitOrdinary is the ordinary request.
const (
	CheckExitSelfCheck = 10
	CheckExitRefused   = 11
	CheckExitClone3    = 12
	CheckExitTracing   = 13
	CheckExitMount     = 14
	CheckExitOrdinary  = 15
)

// CheckAttempt is one request the check makes and the answer it requires.
type CheckAttempt struct {
	Name    string    // the request, as the table names it
	Nr      uint32    // its number on the machine
	Args    [4]uint32 // its first four arguments (each zero-extended to 64 bits)
	Want    string    // the answer the table gives (Decide): an errno's name
	Errno   uint32    // that errno's number
	Exit    int       // the check's exit code when the answer differs
	Missing string    // the protection missing when the answer differs, in plain words
}

// Check-attempt arguments: CLONE_NEWUSER, the flag that makes a user namespace; PTRACE_TRACEME.
const (
	cloneNewUser  = 0x10000000
	ptraceTraceMe = 0
)

// CheckAttempts is what the check makes through the machine's own entry, for the machine's one
// filter: each answer read from the table (Decide), never written here. An attempt whose request
// the variant allows is an error (the check is only of refusals), and so is a machine with more
// than one filter, since the check would not know which one a run gets.
func (t *Table) CheckAttempts(goarch string) ([]CheckAttempt, error) {
	var vs []Variant
	for _, v := range t.Variants() {
		if v.Arch.GOARCH == goarch {
			vs = append(vs, v)
		}
	}
	if len(vs) != 1 {
		return nil, fmt.Errorf("the guard check is built for one filter per machine, and %s has %d", goarch, len(vs))
	}
	v := vs[0]
	number := func(name string) (uint32, error) {
		for _, r := range t.Requests {
			if r.Name == name {
				return r.Number(v.Arch), nil
			}
		}
		return 0, fmt.Errorf("the guard check makes %s, which is not a row of the table", name)
	}
	type spec struct {
		name    string
		args    [4]uint32
		exit    int
		missing string
	}
	specs := []spec{
		{t.SelfCheck.Request, [4]uint32{t.SelfCheck.arg0}, CheckExitSelfCheck,
			"the guard's filter is not on a program started as a guest's program is started: the self-check request did not get the answer only that filter gives"},
		{"unshare", [4]uint32{cloneNewUser}, CheckExitRefused,
			"a request for a user namespace of its own is not refused"},
		{"clone3", [4]uint32{}, CheckExitClone3,
			"clone3, whose flags a filter cannot read, is not answered not implemented"},
		{"ptrace", [4]uint32{ptraceTraceMe}, CheckExitTracing,
			"a tracing request is not refused"},
		{"mount", [4]uint32{}, CheckExitMount,
			"a mount request is not refused"},
	}
	var out []CheckAttempt
	for _, s := range specs {
		nr, err := number(s.name)
		if err != nil {
			return nil, err
		}
		want := t.Decide(v, v.Arch.audit, nr, uint64(s.args[0]))
		var errno uint32
		switch want {
		case t.SelfCheck.ErrnoName:
			errno = t.SelfCheck.Errno
		case EPERM, ENOSYS:
			errno = errnos[want]
		default:
			return nil, fmt.Errorf("the guard check's %s attempt is answered %s by the table, not refused with an errno", s.name, want)
		}
		out = append(out, CheckAttempt{Name: s.name, Nr: nr, Args: s.args, Want: want, Errno: errno, Exit: s.exit, Missing: s.missing})
	}
	if out[0].Want != t.SelfCheck.ErrnoName {
		return nil, fmt.Errorf("the guard check's first attempt is answered %s, not the self-check's %s", out[0].Want, t.SelfCheck.ErrnoName)
	}
	return out, nil
}

// x86-64 system call numbers the check uses beyond its attempts: write and exit_group.
const (
	amd64Write     = 1
	amd64ExitGroup = 231
)

// checkBase is where the check's one segment is loaded: the address static programs on x86-64
// conventionally start at, far above the lowest address Linux maps (vm.mmap_min_addr).
const checkBase = 0x400000

// CheckProgram is the guard check for goarch, as the bytes of a static ELF program: two program
// headers (the code, loaded read and run, never written; and a stack that cannot be run) and the
// code. An error names a machine it is not built for.
func CheckProgram(goarch string) ([]byte, error) {
	if goarch != "amd64" {
		return nil, fmt.Errorf("no guest guard check is built for %s (the guard is installed for amd64 only)", goarch)
	}
	t, err := Load()
	if err != nil {
		return nil, err
	}
	attempts, err := t.CheckAttempts(goarch)
	if err != nil {
		return nil, err
	}
	const ehdr, phdr, phnum = 64, 56, 2
	code := checkCode(attempts, checkBase+ehdr+phdr*phnum)
	size := uint64(ehdr + phdr*phnum + len(code))

	b := make([]byte, 0, size)
	le := binary.LittleEndian
	// The ELF header.
	b = append(b, 0x7f, 'E', 'L', 'F', byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT), byte(elf.ELFOSABI_NONE))
	b = append(b, make([]byte, 8)...)
	b = le.AppendUint16(b, uint16(elf.ET_EXEC))
	b = le.AppendUint16(b, uint16(elf.EM_X86_64))
	b = le.AppendUint32(b, uint32(elf.EV_CURRENT))
	b = le.AppendUint64(b, checkBase+ehdr+phdr*phnum) // entry: the first instruction
	b = le.AppendUint64(b, ehdr)                      // program headers right after this header
	b = le.AppendUint64(b, 0)                         // no section headers
	b = le.AppendUint32(b, 0)                         // flags
	b = le.AppendUint16(b, ehdr)
	b = le.AppendUint16(b, phdr)
	b = le.AppendUint16(b, phnum)
	b = le.AppendUint16(b, 64) // section header size, though there are none
	b = le.AppendUint16(b, 0)
	b = le.AppendUint16(b, 0)
	// The whole file as one segment, read and run.
	b = le.AppendUint32(b, uint32(elf.PT_LOAD))
	b = le.AppendUint32(b, uint32(elf.PF_R|elf.PF_X))
	b = le.AppendUint64(b, 0)
	b = le.AppendUint64(b, checkBase)
	b = le.AppendUint64(b, checkBase)
	b = le.AppendUint64(b, size)
	b = le.AppendUint64(b, size)
	b = le.AppendUint64(b, 0x1000)
	// The stack: read and write, never run.
	b = le.AppendUint32(b, uint32(elf.PT_GNU_STACK))
	b = le.AppendUint32(b, uint32(elf.PF_R|elf.PF_W))
	b = append(b, make([]byte, 5*8)...)
	b = le.AppendUint64(b, 16)
	return append(b, code...), nil
}

// checkCode is the check's instructions, loaded at address at, followed by CheckOK's bytes. Every
// request is made the same way: its four arguments into rdi, rsi, rdx and r10, its number into
// rax, syscall, then the answer in rax compared with the one required and, when it differs, a jump
// to that attempt's exit. The instructions are all of the forms below, each a fixed encoding:
//
//	BF imm32       mov edi, imm32     (the upper half of rdi is cleared)
//	BE imm32       mov esi, imm32
//	BA imm32       mov edx, imm32
//	41 BA imm32    mov r10d, imm32
//	B8 imm32       mov eax, imm32
//	0F 05          syscall
//	48 3D imm32    cmp rax, imm32     (imm32 sign-extended to 64 bits: -errno fits)
//	0F 85 rel32    jne rel32          (from the end of this instruction)
func checkCode(attempts []CheckAttempt, at uint32) []byte {
	var c []byte
	imm := func(op []byte, v uint32) { c = binary.LittleEndian.AppendUint32(append(c, op...), v) }
	// call returns where its second argument's immediate is, for the one call that patches it.
	call := func(nr uint32, args [4]uint32) int {
		imm([]byte{0xBF}, args[0])
		second := len(c) + 1
		imm([]byte{0xBE}, args[1])
		imm([]byte{0xBA}, args[2])
		imm([]byte{0x41, 0xBA}, args[3])
		imm([]byte{0xB8}, nr)
		c = append(c, 0x0F, 0x05)
		return second
	}
	type jump struct{ at, exit int } // the rel32's offset in c, the exit it goes to
	var jumps []jump
	expect := func(rax uint32, exit int) {
		imm([]byte{0x48, 0x3D}, rax)
		c = append(c, 0x0F, 0x85, 0, 0, 0, 0)
		jumps = append(jumps, jump{len(c) - 4, exit})
	}
	for _, a := range attempts {
		call(a.Nr, a.Args)
		expect(uint32(-int32(a.Errno)), a.Exit)
	}
	// The ordinary request: CheckOK to standard output, all of it. Its address is patched below.
	msgImm := call(amd64Write, [4]uint32{1, 0, uint32(len(CheckOK))})
	expect(uint32(len(CheckOK)), CheckExitOrdinary)
	call(amd64ExitGroup, [4]uint32{0})
	// One exit per code a jump names, in the order first named.
	exits := map[int]int{}
	for _, j := range jumps {
		if _, ok := exits[j.exit]; ok {
			continue
		}
		exits[j.exit] = len(c)
		call(amd64ExitGroup, [4]uint32{uint32(j.exit)})
	}
	for _, j := range jumps {
		binary.LittleEndian.PutUint32(c[j.at:], uint32(int32(exits[j.exit]-(j.at+4))))
	}
	binary.LittleEndian.PutUint32(c[msgImm:], at+uint32(len(c)))
	return append(c, CheckOK...)
}

// CheckExitSays is what the check's exit code says: "" for 0, and for each attempt's code the
// protection it found missing.
func (t *Table) CheckExitSays(goarch string, code int) string {
	if code == 0 {
		return ""
	}
	attempts, err := t.CheckAttempts(goarch)
	if err != nil {
		return err.Error()
	}
	for _, a := range attempts {
		if a.Exit == code {
			return fmt.Sprintf("%s was not answered %s: %s", a.Name, a.Want, a.Missing)
		}
	}
	if code == CheckExitOrdinary {
		return "an ordinary request (a write to standard output) did not work"
	}
	return fmt.Sprintf("the check did not finish (exit %d)", code)
}
