package sandbox

import (
	"context"
	"fmt"
	"io"
	"strings"
)

// ImageArchives hands fn each image the provider runs, as `docker save` writes it, by
// the content ID Preflight pinned (the snippet image, the project image and, when one
// is configured, the module image; an ID shared by two of them once), with the
// configured reference it was pinned from. plimsolld scans them against its withheld set
// at startup (cmd/plimsolld): a harness file baked into an image reaches every sandbox
// without passing through a request, where the ship scan reads payloads. The docker CLI
// starts through dockerCommand, against the pinned daemon. fn reads the archive, or
// returns an error, which stops docker save and is returned.
func (d *DockerSandbox) ImageArchives(ctx context.Context, fn func(ref, id string, archive io.Reader) error) error {
	state, err := d.verifiedState()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, img := range [][2]string{{d.Image, state.imageID}, {d.ProjectImage, state.projectImageID}, {d.ModuleImage, state.moduleImageID}} {
		ref, id := img[0], img[1]
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		if err := saveImage(ctx, state.host, ref, id, fn); err != nil {
			return err
		}
	}
	return nil
}

// saveImage runs docker save for one image and hands its output to fn.
func saveImage(ctx context.Context, host, ref, id string, fn func(ref, id string, archive io.Reader) error) error {
	args, err := dockerArgs(host, "save", id)
	if err != nil {
		return err
	}
	cmd := dockerCommand(ctx, args...)
	var stderr cappedBuffer
	stderr.limit = dockerErrorCap
	cmd.Stderr = &stderr
	// Stdout is streamed, not buffered: an image is as large as it is, and fn holds at
	// most one of its files at a time (withheld.MaxImageFileBytes).
	out, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("docker save %s: %w", id, err)
	}
	ferr := fn(ref, id, out)
	if ferr == nil {
		// What follows the archive's end marker, so docker save is not left blocked
		// writing it.
		_, ferr = io.Copy(io.Discard, out)
	}
	if ferr != nil {
		_ = cmd.Process.Kill()
	}
	werr := cmd.Wait()
	if ferr != nil {
		return ferr
	}
	if werr != nil {
		return fmt.Errorf("docker save %s: %w: %s", id, werr, strings.TrimSpace(stderr.String()))
	}
	return nil
}
