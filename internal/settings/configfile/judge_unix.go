//go:build unix

package configfile

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
)

// maxLinks bounds the symbolic links one walk follows, as the kernel's ELOOP does (40 on
// Linux).
const maxLinks = 40

// writableByOthers is the group-write and others-write bits.
const writableByOthers = 0o022

// owner is a file's owning user id.
func owner(info os.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// daemonUID is the daemon's effective user id; a test replaces it to judge files it
// owns as another user's.
var daemonUID = os.Geteuid

// trusted reports whether uid is root or the daemon's effective user.
func trusted(uid uint32) bool {
	return uid == 0 || uid == uint32(daemonUID())
}

// judge applies the package's rule to the opened file (info, from fstat) and to the
// directories and links on the way to it from path.
func judge(path string, info os.FileInfo) []string {
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	uid, ok := owner(info)
	switch {
	case !info.Mode().IsRegular():
		add("%s is not a regular file", path)
	case !ok:
		add("%s: the owner of the opened file cannot be read", path)
	default:
		if !trusted(uid) {
			add("file %s is owned by uid %d, neither root nor the daemon's user (uid %d)", path, uid, daemonUID())
		}
		if m := info.Mode().Perm(); m&writableByOthers != 0 {
			add("file %s has mode %s, which %s can write", path, mode(info.Mode()), whoWrites(m))
		}
	}

	reached, err := walk(path, add)
	switch {
	case err != nil:
		add("the path to %s cannot be checked: %v", path, err)
	case reached != nil && !os.SameFile(reached, info):
		add("%s changed while it was read: the path now names a different file", path)
	}
	// A link's target can climb back through a directory already judged; each problem is
	// said once.
	slices.Sort(problems)
	return slices.Compact(problems)
}

// whoWrites names the write bits set in m beyond the owner's.
func whoWrites(m os.FileMode) string {
	switch {
	case m&0o020 != 0 && m&0o002 != 0:
		return "its group and every other user"
	case m&0o020 != 0:
		return "its group"
	default:
		return "every other user"
	}
}

// judgeDir applies the directory rule to dir.
func judgeDir(dir string, info os.FileInfo, add func(string, ...any)) {
	uid, ok := owner(info)
	if !ok {
		add("directory %s: its owner cannot be read", dir)
		return
	}
	if !trusted(uid) {
		add("directory %s is owned by uid %d, neither root nor the daemon's user (uid %d), so its owner can replace what it holds", dir, uid, daemonUID())
	}
	if m := info.Mode(); m.Perm()&writableByOthers != 0 && m&os.ModeSticky == 0 {
		add("directory %s has mode %s, which lets %s replace what it holds", dir, mode(m), whoWrites(m.Perm()))
	}
}

// parts splits a path into the names the kernel looks up, dropping empty names and ".".
func parts(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" && s != "." {
			out = append(out, s)
		}
	}
	return out
}

// walk resolves path one name at a time, as the kernel does, judging every directory it
// passes through and every symbolic link it follows, and returns what the last name
// names (Lstat), for the caller to compare with the opened file.
func walk(path string, add func(string, ...any)) (os.FileInfo, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	cur := "/"
	root, err := os.Lstat(cur)
	if err != nil {
		return nil, err
	}
	judgeDir(cur, root, add)
	pending := parts(abs)
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		if name == ".." {
			// cur is a directory already judged; its parent was judged on the way down,
			// or is judged now when a link's target climbed above where the walk began.
			parent := filepath.Dir(cur)
			if parent != cur {
				info, err := os.Lstat(parent)
				if err != nil {
					return nil, err
				}
				judgeDir(parent, info, add)
			}
			cur = parent
			continue
		}
		next := filepath.Join(cur, name)
		info, err := os.Lstat(next)
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if links++; links > maxLinks {
				return nil, fmt.Errorf("more than %d symbolic links", maxLinks)
			}
			// A link's own permission bits mean nothing; what matters is who could have put
			// it where it is. A directory others can write without its sticky bit is already
			// a finding; in a sticky one, only the link's owner, the directory's owner or root
			// can replace it, so its owner must be trusted.
			dir, err := os.Lstat(cur)
			if err != nil {
				return nil, err
			}
			if uid, ok := owner(info); dir.Mode().Perm()&writableByOthers != 0 && (!ok || !trusted(uid)) {
				add("symbolic link %s is owned by uid %d in directory %s, which others can write", next, uid, cur)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return nil, err
			}
			if filepath.IsAbs(target) {
				cur = "/"
			}
			pending = append(parts(target), pending...)
			continue
		}
		if len(pending) == 0 {
			return info, nil
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("%s is not a directory", next)
		}
		judgeDir(next, info, add)
		cur = next
	}
	// The path ended on a directory ("/" or a trailing ".."): the opened file is no
	// regular file, which the caller has already said.
	return nil, nil
}
