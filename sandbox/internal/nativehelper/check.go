package nativehelper

import (
	"errors"
	"fmt"
	"strings"
)

// Every provider that starts the helper as the project runner checks, at startup and before
// it trusts any run, that the file at InContainer is the helper this plimsolld carries: a
// regular file, root's, writable by no one else, whose SHA-256 is SHA256's. The check runs
// inside the sandbox (CheckJS, as the guest or as a control program), so it is as
// trustworthy as the image: it proves the image is one built with this helper (an image
// from before the helper, or for another plimsoll, is refused with what to do), not that a
// hostile image could not lie. One report shape and one judgment serve every provider.

// checkFn is a JavaScript function of a path that returns what the file there is: its type
// (lstat, so a link is reported as one), owner, permission bits, size and SHA-256, or the
// error code, and the machine the sandbox's node runs on (process.arch); it needs the node
// modules fs and cr (node:crypto) bound.
const checkFn = `(p)=>{const out={arch:process.arch};try{const st=fs.lstatSync(p);out.type=st.isFile()?"file":st.isSymbolicLink()?"link":"other";out.uid=st.uid;out.mode=st.mode&0o7777;
if(out.type==="file"){const b=fs.readFileSync(p);out.size=b.length;out.sha256=cr.createHash("sha256").update(b).digest("hex")}}catch(e){out.error=e.code||"unreadable"}return out}`

// CheckJS is a node program that prints, as one JSON object (a FileReport), what the file at
// its first argument is.
const CheckJS = `const fs=require("node:fs"),cr=require("node:crypto");process.stdout.write(JSON.stringify((` + checkFn + `)(process.argv[1])));`

// CheckExpr is a JavaScript expression whose value is the same object for InContainer, for
// a program that reports it among other readings (a smoke test's probe step) and has fs and
// cr (node:crypto) bound.
const CheckExpr = `(` + checkFn + `)("` + InContainer + `")`

// FileReport is what CheckJS prints.
type FileReport struct {
	Type   string `json:"type"`
	UID    *int   `json:"uid"`
	Mode   *int   `json:"mode"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Error  string `json:"error"`
	Arch   string `json:"arch"` // node's process.arch in the sandbox: "x64" for x86-64
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

// Check judges r against want, the SHA-256 required (SHA256 for this machine, or a test's).
// Each refusal says what is wrong and wraps ErrNotTheHelper.
func (r FileReport) Check(want string) error {
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
	case r.SHA256 != want:
		return fmt.Errorf("%w: %s has sha256 %s (%d bytes); want %s", ErrNotTheHelper, InContainer, firstLine(r.SHA256), r.Size, want)
	}
	return nil
}

// BuiltMachine is the one machine an image of plimsoll's carries the helper for (Go's name),
// and BuiltMachineNode node's name for it (process.arch).
const (
	BuiltMachine     = "amd64"
	BuiltMachineNode = "x64"
)

// CheckBuilt judges r as Check does against the helper for BuiltMachine, whatever machine
// plimsolld itself runs on: for a provider whose sandboxes run on another machine (an
// OpenShell gateway, a Kubernetes cluster's nodes), where plimsolld's own machine says
// nothing about the sandbox's. A sandbox that reports another machine is refused by name,
// and every refusal names the machine the sandbox reported.
func (r FileReport) CheckBuilt() error {
	want, err := SHA256(BuiltMachine)
	if err != nil {
		return err
	}
	machine := r.Arch
	if machine == "" {
		machine = "not reported"
	}
	if r.Arch != BuiltMachineNode && r.Error == "" && r.Type != "" {
		return fmt.Errorf("%w: the sandbox's machine is %s (node's process.arch); the native helper is built for x86-64 (%s) only", ErrNotTheHelper, firstLine(machine), BuiltMachineNode)
	}
	if err := r.Check(want); err != nil {
		return fmt.Errorf("%w (the sandbox's machine: %s)", err, firstLine(machine))
	}
	return nil
}
