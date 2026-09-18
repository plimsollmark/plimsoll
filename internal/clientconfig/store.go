package clientconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// ReadRegular is the CLI's file policy. The daemon may read deployment-managed
// symlinks, but a local editor must not silently replace their final component.
func ReadRegular(path string) (File, fs.FileMode, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return File{}, 0, err
	}
	if !info.Mode().IsRegular() {
		return File{}, 0, errors.New("clients: registry must be a regular file, not a symlink or device")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return File{}, 0, err
	}
	f, err := Parse(raw)
	return f, info.Mode().Perm(), err
}

// Update serializes cooperative local edits with an exclusive directory lock.
// A killed editor leaves the lock behind rather than permit a lost update; an
// operator must confirm no edit is active before removing that empty directory.
// The containing directory must be controlled by the operator. External editors
// do not participate in this lock and must not run concurrently with this CLI.
// changed remains true if replacement succeeded but directory sync failed.
func Update(path string, allowCreate bool, edit func(*File) error) (changed bool, err error) {
	lock := path + ".lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return false, fmt.Errorf("clients: registry locked (%s); retry after the other editor finishes; remove a stale lock only after confirming no editor is active", lock)
		}
		return false, fmt.Errorf("clients: acquire registry lock: %w", err)
	}
	defer func() {
		if cleanupErr := os.Remove(lock); cleanupErr != nil {
			err = errors.Join(err, fmt.Errorf("clients: remove registry lock: %w", cleanupErr))
		}
	}()
	f, mode, err := ReadRegular(path)
	if errors.Is(err, fs.ErrNotExist) && allowCreate {
		f, mode, err = File{Clients: []Caller{}}, 0o600, nil
	}
	if err != nil {
		return false, err
	}
	if err := edit(&f); err != nil {
		return false, err
	}
	if err := f.Validate(); err != nil {
		return false, err
	}
	raw, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".plimsoll-clients-*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err = tmp.Write(append(raw, '\n')); err == nil {
		err = tmp.Chmod(mode)
	}
	if err == nil {
		err = tmp.Sync()
	}
	err = errors.Join(err, tmp.Close())
	if err != nil {
		return false, err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return false, err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return true, err
	}
	return true, errors.Join(dir.Sync(), dir.Close())
}
