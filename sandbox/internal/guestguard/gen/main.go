// Command gen writes the guest guard's filter from its table: filter_<goarch>.bin, one per
// machine (and a _gvisor one each when decision 137 says "gvisor"), and guest_filter.h, the
// same instructions as a C array with a comment on each, into sandbox/internal/guestguard. It
// removes a filter file the table no longer makes. make generate runs it;
// TestGeneratedFilesAreCurrent fails when a written file is stale.
//
//	go run ./sandbox/internal/guestguard/gen
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/plimsollmark/plimsoll/sandbox/internal/guestguard"
)

func main() {
	dir := flag.String("dir", filepath.Join("sandbox", "internal", "guestguard"), "the package directory, holding refused.json")
	flag.Parse()
	if err := run(*dir); err != nil {
		fmt.Fprintln(os.Stderr, "guestguard/gen:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	b, err := os.ReadFile(filepath.Join(dir, "refused.json"))
	if err != nil {
		return fmt.Errorf("%w (run from the repository root, or pass -dir)", err)
	}
	t, err := guestguard.Parse(b)
	if err != nil {
		return err
	}
	files, err := t.Files()
	if err != nil {
		return err
	}
	old, err := filepath.Glob(filepath.Join(dir, "filter_*.bin"))
	if err != nil {
		return err
	}
	for _, p := range old {
		if _, ok := files[filepath.Base(p)]; !ok {
			if err := os.Remove(p); err != nil {
				return err
			}
			fmt.Println("removed", p)
		}
	}
	for _, name := range guestguard.FileNames(files) {
		p := filepath.Join(dir, name)
		if cur, err := os.ReadFile(p); err == nil && bytes.Equal(cur, files[name]) {
			continue
		}
		if err := os.WriteFile(p, files[name], 0o644); err != nil {
			return err
		}
		fmt.Println("wrote", p)
	}
	return nil
}
