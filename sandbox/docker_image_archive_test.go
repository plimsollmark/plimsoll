package sandbox_test

import (
	"archive/tar"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/dockertest"
)

// ImageArchives hands over each pinned image once, by its content ID, as a tar docker
// save wrote; an error from the reader stops it and is returned.
func TestDockerImageArchivesStreamsEachPinnedImage(t *testing.T) {
	d := dockertest.Sandbox(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := d.Preflight(ctx); err != nil {
		t.Fatalf("Preflight: %v", err)
	}
	seen := map[string]bool{}
	err := d.ImageArchives(ctx, func(ref, id string, archive io.Reader) error {
		if seen[id] {
			t.Errorf("image %s handed over twice", id)
		}
		seen[id] = true
		if ref != d.Image && ref != d.ProjectImage && ref != d.ModuleImage {
			t.Errorf("reference %q is none of the configured images", ref)
		}
		tr := tar.NewReader(archive)
		members := 0
		for {
			if _, err := tr.Next(); err != nil {
				if !errors.Is(err, io.EOF) {
					return err
				}
				break
			}
			members++
		}
		if members == 0 {
			t.Errorf("image %s: an empty archive", id)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ImageArchives: %v", err)
	}
	if len(seen) == 0 {
		t.Fatal("no image handed over")
	}
	stop := errors.New("stop")
	if err := d.ImageArchives(ctx, func(string, string, io.Reader) error { return stop }); !errors.Is(err, stop) {
		t.Fatalf("a reader's error: %v; want it returned", err)
	}
}
