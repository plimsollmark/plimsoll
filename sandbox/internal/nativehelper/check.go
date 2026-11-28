package nativehelper

import (
	"errors"
	"fmt"
	"strings"
)

// Every provider that starts the helper as the project runner checks, at startup and before
// it trusts any run, that the file at InContainer is the helper this plimsolld carries: a
// regular file, root's, writable by no one else, readable by root alone (InstalledMode), with
// no setuid or setgid bit. The check runs inside the sandbox (CheckJS, as root or as the
// guest), so it is as trustworthy as the image: it proves the image is one built with this
// helper (an image from before the helper, or for another plimsoll, is refused with what to
// do), not that a hostile image could not lie. One report shape and one judgment serve every
// provider.
//
// Readable by root alone, because the kernel makes every process that runs a program its user
// cannot read non-dumpable from the exec, before the program's first instruction (would_dump,
// then fs.suid_dumpable). The helper's own first call does the same, but between the exec and
// that call another process of the guest's user could open /proc/<pid>/mem and change the
// answer being made (review finding session-files-14). Measured 2026-11-27 under runc and
// gVisor (sandbox/docker_nativehelper_dumpable_test.go). It follows that a check run as the
// guest cannot read the bytes: where a provider can start the check as root (docker, and the
// root checks of agent-sandbox and WSL containers), Check proves the SHA-256; where every
// command runs as the guest's user (OpenShell's gateway, and the guest-side checks of
// agent-sandbox and WSL containers), CheckUnread proves the file's type, owner, mode and size,
// and that the guest's read of it is refused.
//
// Both also start the file with the helper's identity command and require the line the
// pinned build prints (Identity: the digest of its build's inputs, compiled in), so two builds
// of the same size are told apart where the bytes cannot be read (the builds pinned 1b403142
// and b5effd0c were both 586,400 bytes), and a size match alone never passes. What that line
// proves: the file is the build of this plimsolld's release, not a stale image's or another
// release's. What it does not: a program built to lie can print any line, so against an image
// made to deceive it proves nothing; the image is the operator's.

// InstalledMode is the helper's permission bits wherever plimsoll installs it: every user may
// run it, root alone may read it, no one may write it but root.
const InstalledMode = 0o711

// checkFn is a JavaScript function of a path that returns what the file there is: its type
// (lstat, so a link is reported as one), owner, permission bits and size, then its SHA-256,
// or the code its read failed with (a helper readable by root alone, read as the guest:
// EACCES), or the error code of the lstat, and the machine the sandbox's node runs on
// (process.arch); then, for a regular file, what the file's identity command printed (at
// most 256 bytes, within 10 seconds, no input) or how it failed ("exit N", a signal's name or
// node's code). A file with a set-id bit, or writable by its group or every user, is not started
// (the check refuses it anyway): the root checks start the file as root. It needs the node
// modules fs and cr (node:crypto) bound, and require.
const checkFn = `(p)=>{const out={arch:process.arch};try{const st=fs.lstatSync(p);out.type=st.isFile()?"file":st.isSymbolicLink()?"link":"other";out.uid=st.uid;out.mode=st.mode&0o7777;out.size=st.size;
if(out.type==="file"){try{const b=fs.readFileSync(p);out.size=b.length;out.sha256=cr.createHash("sha256").update(b).digest("hex")}catch(e){out.read=e.code||"unreadable"}
if((st.mode&0o7022)!==0){out.identityError="not run: writable by others, or a set-id bit"}else try{out.identity=require("node:child_process").execFileSync(p,["identity"],{encoding:"latin1",timeout:10000,maxBuffer:256,stdio:["ignore","pipe","ignore"]}).replace(/\n$/,"")}catch(e){out.identityError=e.signal||(typeof e.status==="number"?"exit "+e.status:e.code||"failed")}}}catch(e){out.error=e.code||"unreadable"}return out}`

// CheckJS is a node program that prints, as one JSON object (a FileReport), what the file at
// its first argument is.
const CheckJS = `const fs=require("node:fs"),cr=require("node:crypto");process.stdout.write(JSON.stringify((` + checkFn + `)(process.argv[1])));`

// CheckExpr is a JavaScript expression whose value is the same object for InContainer, for
// a program that reports it among other readings (a smoke test's probe step) and has fs and
// cr (node:crypto) bound.
const CheckExpr = `(` + checkFn + `)("` + InContainer + `")`

// CheckStdinJS is CheckJS for InContainer as a program node reads from its standard input
// (`node -`), for a provider whose command line must carry no program text (WSL containers:
// every argument wslc.exe reads is held to a plain set of bytes).
const CheckStdinJS = `const fs=require("node:fs"),cr=require("node:crypto");process.stdout.write(JSON.stringify(` + CheckExpr + `));`

// FileReport is what CheckJS prints.
type FileReport struct {
	Type   string `json:"type"`
	UID    *int   `json:"uid"`
	Mode   *int   `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Read   string `json:"read"`  // the code the read of a regular file failed with; "" when it was read
	Error  string `json:"error"` // the code lstat failed with
	Arch   string `json:"arch"`  // node's process.arch in the sandbox: "x64" for x86-64
	// Identity is what the file's identity command printed, less a last newline; IdentityError
	// how it failed instead ("exit 2" for a build from before the command).
	Identity      string `json:"identity"`
	IdentityError string `json:"identityError"`
}

// ErrNotTheHelper wraps every refusal Check makes, so a provider can add what its operator
// should do.
var ErrNotTheHelper = errors.New("the image's project runner is not the native helper this plimsolld carries")

// firstLine keeps a reading the sandbox wrote to one bounded line in an error.
func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 120 {
		s = s[:120]
	}
	return s
}

// installed judges what both checks judge: a regular file, root's, writable by no one else,
// with no setuid, setgid or sticky bit, runnable by every user and readable by root alone.
func (r FileReport) installed() error {
	switch {
	case r.Error == "" && r.Type == "":
		return fmt.Errorf("%w: the check reported nothing for %s (a probe from before the native helper?)", ErrNotTheHelper, InContainer)
	case r.Error != "":
		return fmt.Errorf("%w: there is no file at %s (%s)", ErrNotTheHelper, InContainer, firstLine(r.Error))
	case r.Type != "file":
		return fmt.Errorf("%w: %s is not a regular file (lstat: %s)", ErrNotTheHelper, InContainer, firstLine(r.Type))
	case r.UID == nil || r.Mode == nil:
		return fmt.Errorf("%w: the check reported no owner or no mode for %s, so the runner cannot be proven", ErrNotTheHelper, InContainer)
	case *r.UID != 0 || *r.Mode&0o022 != 0:
		return fmt.Errorf("%w: %s is owned by uid %d with mode %04o; it must be root's and writable by no one else, so the guest cannot replace it", ErrNotTheHelper, InContainer, *r.UID, *r.Mode)
	case *r.Mode&0o7000 != 0:
		// A setuid or setgid bit would start the runner, and every step with it, as the
		// file's owner (root) wherever no-new-privileges is not set (WSL containers cannot
		// set it); the sticky bit means nothing on a file and is refused with them, so the
		// rule is one mask (review finding rust-native-helper-47).
		return fmt.Errorf("%w: %s has mode %04o; it must carry no setuid, setgid or sticky bit, so the runner starts as the guest", ErrNotTheHelper, InContainer, *r.Mode)
	case *r.Mode&0o044 != 0 || *r.Mode&0o001 == 0:
		return fmt.Errorf("%w: %s has mode %04o; it must be readable by root alone and runnable by every user (%04o), so the kernel makes the helper non-dumpable from its exec, before another process of the guest's can open its memory",
			ErrNotTheHelper, InContainer, *r.Mode, InstalledMode)
	}
	return nil
}

// reports judges the line the file's identity command printed against want.
func (r FileReport) reports(want string) error {
	switch {
	case want == "":
		return errors.New("nativehelper: no identity to require")
	case r.IdentityError != "":
		return fmt.Errorf("%w: %s did not report which build it is (its identity command: %s); a helper built before that command, or not the helper, so not the build of this plimsolld's release", ErrNotTheHelper, InContainer, firstLine(r.IdentityError))
	case r.Identity != want:
		return fmt.Errorf("%w: %s reports the build %q; this plimsolld's helper is %q", ErrNotTheHelper, InContainer, firstLine(r.Identity), want)
	}
	return nil
}

// Check judges r, read as root, against want (Pinned for this machine, or a test's build):
// installed as it must be, its SHA-256 want's, and its identity command's line want's. Each
// refusal says what is wrong and wraps ErrNotTheHelper.
func (r FileReport) Check(want Want) error {
	if err := r.installed(); err != nil {
		return err
	}
	switch {
	case r.Read != "":
		return fmt.Errorf("%w: the check could not read %s (%s); it is readable by root alone, so the check must read it as root", ErrNotTheHelper, InContainer, firstLine(r.Read))
	case r.SHA256 != want.SHA256:
		return fmt.Errorf("%w: %s has sha256 %s (%d bytes); want %s", ErrNotTheHelper, InContainer, firstLine(r.SHA256), r.Size, want.SHA256)
	}
	return r.reports(want.Identity)
}

// CheckUnread judges r, read as the guest, against the helper built for goarch: installed as
// Check requires it, the guest's read of it refused (EACCES or EPERM: it is readable by root
// alone, which also proves the mode the report states), its size the size of that build, and
// its identity command's line the pinned build's (Identity). It cannot prove the bytes, which
// the guest cannot read; the identity tells this build from another of plimsoll's, which the
// size cannot. Each refusal says what is wrong and wraps ErrNotTheHelper.
func (r FileReport) CheckUnread(goarch string) error {
	prog, err := Program(goarch)
	if err != nil {
		return err
	}
	id, err := Identity()
	if err != nil {
		return err
	}
	if err := r.installed(); err != nil {
		return err
	}
	switch {
	case r.Read == "" || r.SHA256 != "":
		return fmt.Errorf("%w: the guest read %s, which its mode %04o does not allow; it must be readable by root alone", ErrNotTheHelper, InContainer, *r.Mode)
	case r.Read != "EACCES" && r.Read != "EPERM":
		return fmt.Errorf("%w: the guest's read of %s failed with %s, not a refusal of its permission", ErrNotTheHelper, InContainer, firstLine(r.Read))
	case r.Size != int64(len(prog)):
		return fmt.Errorf("%w: %s is %d bytes; this plimsolld's helper is %d", ErrNotTheHelper, InContainer, r.Size, len(prog))
	}
	return r.reports(id)
}

// BuiltMachine is the one machine an image of plimsoll's carries the helper for (Go's name),
// and BuiltMachineNode node's name for it (process.arch).
const (
	BuiltMachine     = "amd64"
	BuiltMachineNode = "x64"
)

// CheckBuilt judges r as CheckUnread does against the helper for BuiltMachine, whatever machine
// plimsolld itself runs on: for a provider whose sandboxes run on another machine (an
// OpenShell gateway, a Kubernetes cluster's nodes), where plimsolld's own machine says
// nothing about the sandbox's, and whose check runs as the guest. A sandbox that reports
// another machine is refused by name, and every refusal names the machine the sandbox
// reported.
func (r FileReport) CheckBuilt() error {
	return r.onBuiltMachine(func() error { return r.CheckUnread(BuiltMachine) })
}

// CheckBuiltAsRoot is CheckBuilt for a check read as root: Check against the helper pinned for
// BuiltMachine (its SHA-256 and its identity line), on a sandbox that reports that machine.
func (r FileReport) CheckBuiltAsRoot() error {
	return r.onBuiltMachine(func() error {
		want, err := Pinned(BuiltMachine)
		if err != nil {
			return err
		}
		return r.Check(want)
	})
}

// onBuiltMachine refuses a sandbox that reports a machine other than BuiltMachine's, then
// judges r by check, naming the reported machine in every refusal.
func (r FileReport) onBuiltMachine(check func() error) error {
	machine := r.Arch
	if machine == "" {
		machine = "not reported"
	}
	if r.Arch != BuiltMachineNode && r.Error == "" && r.Type != "" {
		return fmt.Errorf("%w: the sandbox's machine is %s (node's process.arch); the native helper is built for x86-64 (%s) only", ErrNotTheHelper, firstLine(machine), BuiltMachineNode)
	}
	if err := check(); err != nil {
		return fmt.Errorf("%w (the sandbox's machine: %s)", err, firstLine(machine))
	}
	return nil
}
