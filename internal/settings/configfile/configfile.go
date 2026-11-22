// Package configfile reads a file one of plimsolld's settings names (the callers file,
// PLIMSOLL_CLIENTS_FILE; the grants file, PLIMSOLL_GRANTS_FILE; the withheld set,
// PLIMSOLL_WITHHELD_FILE) and judges whether a user other than the daemon's own and root
// could change what the daemon reads from it.
//
// Each of those files decides who may run code and what a run may reach, so a file
// another local user can write, or a directory that lets another user put a file of
// their own in its place, hands that user a caller of their own at the next restart. The
// rule is OpenSSH's for a user's authorized_keys file under StrictModes (sshd(8): "If
// this file, the ~/.ssh directory, or the user's home directory are writable by other
// users, then the file could be modified or replaced by unauthorized users"; safe_path
// in openssh-portable's misc.c), with one difference stated below:
//
//   - The file, read through the descriptor the daemon opened (fstat, never a second
//     lookup of the name), is a regular file, owned by root or by the daemon's effective
//     user, and has neither the group-write bit (0o020) nor the others-write bit (0o002).
//     Read bits are not judged: a group-readable file (a Kubernetes secret mounted with
//     fsGroup is 0o440 or 0o640) is accepted.
//   - Every directory the daemon passes through to reach it, on the path as named and on
//     every symbolic link's target, up to "/", is owned by root or by the daemon's
//     effective user, and has neither write bit for the group or others, unless its
//     sticky bit (0o1000) is set. OpenSSH refuses a sticky directory too; plimsoll
//     accepts one, because in a sticky directory only an entry's owner, the directory's
//     owner and a privileged process may rename or delete the entry (inode(7)), and
//     every entry this walk passes through is itself held to an owner of root or the
//     daemon's user. A Kubernetes secret or config map volume is such a directory (its
//     root is listed as 0o1777, owned by root, in kubernetes/kubernetes issue 34982, and
//     each key is a symbolic link into a timestamped directory through "..data").
//   - A symbolic link is judged by what it points to (the walk continues along its
//     target) and by the directory it sits in; one in a directory others can write
//     (sticky) must itself be owned by root or the daemon's user, or another user could
//     have made it.
//   - The file the walk reaches must be the file the daemon opened (same device and
//     inode); a difference means the path changed while it was read.
//
// What the caller does with a finding is its own: plimsolld refuses to start in hardened
// mode and logs one warning line otherwise. A finding names paths, mode bits and owner
// ids, never the file's content.
package configfile

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// Finding lists what lets another user change the file; nil means nothing does.
type Finding struct {
	Problems []string
}

// String is the problems on one line.
func (f *Finding) String() string {
	if f == nil {
		return ""
	}
	return strings.Join(f.Problems, "; ")
}

// Read opens path, reads it whole from the opened descriptor and judges it by the
// package's rule. A file that cannot be opened or read is an error; a file whose
// permissions let another user change it is read and returned with its Finding.
func Read(path string) ([]byte, *Finding, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	raw, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	problems := judge(path, info)
	if len(problems) == 0 {
		return raw, nil, nil
	}
	return raw, &Finding{Problems: problems}, nil
}

// mode is a permission and sticky bit set printed as an operator would type it to chmod.
func mode(m os.FileMode) string {
	bits := uint32(m.Perm())
	if m&os.ModeSticky != 0 {
		bits |= 0o1000
	}
	return fmt.Sprintf("%04o", bits)
}
