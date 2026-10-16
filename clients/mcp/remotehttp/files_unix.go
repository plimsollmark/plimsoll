//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package remotehttp

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

func makeStateDirs(dir string) error {
	if _, err := os.Lstat(dir); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := makeStateDirs(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	return nil
}
func privateDir(dir string) error {
	if err := makeStateDirs(dir); err != nil {
		return err
	}
	for p := dir; ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return errors.New("authorization state path contains a non-directory or symlink")
		}
		stat, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot verify authorization directory owner")
		}
		if p == dir && (st.Mode().Perm() != 0o700 || int(stat.Uid) != os.Geteuid()) {
			return errors.New("authorization directory must be owner-owned with mode 0700")
		}
		if st.Mode().Perm()&0o022 != 0 && !(stat.Uid == 0 && st.Mode()&os.ModeSticky != 0) {
			return errors.New("authorization directory has a writable ancestor")
		}
		// The owner of a directory can rename what is in it, whatever its mode: an
		// ancestor of another user's could move the state directory away under a running
		// server. Only this user's ancestors and root's are trusted.
		if int(stat.Uid) != os.Geteuid() && stat.Uid != 0 {
			return fmt.Errorf("authorization directory has an ancestor owned by another user (%s, uid %d)", p, stat.Uid)
		}
		if filepath.Dir(p) == p {
			break
		}
	}
	return nil
}

func openPrivate(path string, flags int, mode os.FileMode) (*os.File, error) {
	f, err := os.OpenFile(path, flags|syscall.O_NOFOLLOW, mode)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0o600 || !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		_ = f.Close()
		return nil, fmt.Errorf("authorization file %s must be one owner-only regular file", filepath.Base(path))
	}
	return f, nil
}

func lockState(path string) (*os.File, error) {
	f, err := openPrivate(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return nil, errors.New("authorization state already has a writer")
	}
	return f, nil
}
