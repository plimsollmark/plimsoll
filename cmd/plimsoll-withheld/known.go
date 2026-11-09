package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

// knownUnreadable acknowledges the unread bytes in one immutable image. The lock is
// held across read/merge/rename, so two operators cannot silently lose either update.
func knownUnreadable(args []string, stdout, stderr io.Writer) (int, error) {
	fl := flag.NewFlagSet("known-unreadable", flag.ContinueOnError)
	fl.SetOutput(stderr)
	setPath := fl.String("set", "", "the withheld set file used by the daemon")
	knownPath := fl.String("known", "", "the known-unreadable list to create or update")
	if err := fl.Parse(args); err != nil {
		return 2, err
	}
	if *setPath == "" || *knownPath == "" || fl.NArg() != 1 {
		return 2, errors.New("known-unreadable needs -set FILE -known FILE IMAGE")
	}
	set, err := withheld.Load(*setPath)
	if err != nil {
		return 2, err
	}
	// Resolve aliases (including a symlinked parent directory) before locking, and
	// refuse a symlink destination: rename must update the same file that was read.
	parent, err := filepath.EvalSymlinks(filepath.Dir(*knownPath))
	if err != nil {
		return 2, err
	}
	path := filepath.Join(parent, filepath.Base(*knownPath))
	lock := path + ".lock"
	if err := os.Mkdir(lock, 0o700); err != nil {
		return 2, fmt.Errorf("cannot lock %s (another update or a stale .lock directory): %w", withheld.CleanWhere(path), err)
	}
	defer os.Remove(lock)
	if st, err := os.Lstat(path); err == nil {
		if !st.Mode().IsRegular() {
			return 2, fmt.Errorf("%s is not a regular list file", withheld.CleanWhere(path))
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return 2, err
	}
	known, err := withheld.LoadKnown(path)
	if errors.Is(err, os.ErrNotExist) {
		known, err = withheld.NewKnown(), nil
	}
	if err != nil {
		return 2, err
	}
	ctx := context.Background()
	// Resolve the reference once, then save by content ID so a tag moved meanwhile
	// cannot bless different bytes. A user-supplied archive cannot claim an identity.
	ref := fl.Arg(0)
	out, err := exec.CommandContext(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", "--", ref).Output()
	if err != nil {
		return 2, fmt.Errorf("docker image inspect %s: %w", withheld.CleanWhere(ref), err)
	}
	id := strings.TrimSpace(string(out))
	if !withheld.ValidImageID(id) {
		return 2, fmt.Errorf("docker returned invalid image ID %q", withheld.CleanWhere(id))
	}
	save := exec.CommandContext(ctx, "docker", "save", id)
	save.Stderr = stderr
	pipe, err := save.StdoutPipe()
	if err != nil {
		return 2, err
	}
	if err := save.Start(); err != nil {
		return 2, fmt.Errorf("docker save: %w", err)
	}
	res, scanErr := set.ScanImage(ctx, pipe)
	if scanErr == nil {
		_, scanErr = io.Copy(io.Discard, pipe)
	}
	if scanErr != nil {
		_ = save.Process.Kill()
	}
	waitErr := save.Wait()
	if scanErr != nil {
		return 2, scanErr
	}
	if waitErr != nil {
		return 2, fmt.Errorf("docker save: %w", waitErr)
	}
	if err := known.Set(id, res.Unreadable); err != nil {
		return 2, err
	}
	raw, err := known.Marshal()
	if err != nil {
		return 2, err
	}
	if err := writeKnown(path, raw); err != nil {
		return 2, err
	}
	for _, u := range res.Unreadable {
		fmt.Fprintf(stdout, "known unreadable: %s: %s (%d bytes)\n", withheld.CleanWhere(u.Where), u.Reason.Text(), u.Size)
	}
	fmt.Fprintf(stdout, "updated %s for image %s (%s): %d unreadable file/reason entries; %d images retained. This acknowledges unread bytes, not that they are free of withheld material.\n", withheld.CleanWhere(path), withheld.CleanWhere(ref), id, len(res.Unreadable), known.Images())
	return 0, nil
}

func writeKnown(path string, raw []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".known-unreadable-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
