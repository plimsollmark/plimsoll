package wslc

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

// templateDiskBytes is the template's virtual size: the most one run's session can write
// to its disk (the image plus dockerd's own state; a run itself can write only to its tmpfs
// mounts). The file holds only the blocks written, so it is about the image's size; the
// bound keeps one run's session from growing its copy on the Windows drive past 8 GiB.
const templateDiskBytes = 8 << 30

// templateDisk is what the template build left.
type templateDisk struct {
	win   string // storage.vhdx as wslc.exe and powershell.exe take it
	bytes int64
	built time.Duration
}

// buildTemplate makes the per-run mode's template disk from nothing: an empty ext4
// filesystem (mkfs.ext4 on a sparse file here, the formatting WSLC's own Ext4Format does
// for a new store), wrapped in a dynamic VHDX (vhdx.go) in a session-named directory under
// the run root; a session on it; plimsoll's image saved from the default session by its
// ID and loaded into it; a check that the session then holds that image and nothing else
// (no other image, no container, no volume); the session ended at its exit line; and the
// directory renamed to the template's. The user's default session store is never copied:
// only the image, by ID, crosses. On every failure the session, its directory and the
// image archive are deleted.
func (p *Provider) buildTemplate(ctx context.Context, imageID string) (templateDisk, error) {
	start := time.Now()
	if err := p.takeSlot(ctx); err != nil {
		return templateDisk{}, err
	}
	h := p.newHolder()
	h.slot = true
	// The image archive sits beside the session's directory, named like it, so the sweeps
	// know it as this provider's (ownEntryRE) and spare it while the build is live.
	tarWin, tarLinux := h.winDir+".tar", h.dir+".tar"
	fail := func(err error) (templateDisk, error) {
		if tErr := p.endSession(h, false, false); tErr != nil {
			err = errors.Join(err, tErr)
		}
		if rmErr := p.removeOwn(tarLinux); rmErr != nil {
			err = errors.Join(err, rmErr)
		}
		return templateDisk{}, fmt.Errorf("wslc: building the template disk: %w", err)
	}
	if err := os.MkdirAll(p.pr.root.linux, 0o755); err != nil {
		return fail(err)
	}
	if err := os.Mkdir(h.dir, 0o755); err != nil {
		return fail(err)
	}
	if err := p.formatDisk(ctx, path.Join(h.dir, storageFile)); err != nil {
		return fail(err)
	}
	if err := p.startHolder(h); err != nil {
		return fail(err)
	}
	if err := p.waitListed(ctx, h); err != nil {
		return fail(err)
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if _, err := p.output(lctx, "save", "-o", tarWin, imageID); err != nil {
		return fail(err)
	}
	_, err := p.output(lctx, "--session", h.name, "load", "-q", "-i", tarWin)
	if rmErr := p.removeOwn(tarLinux); rmErr != nil && err == nil {
		err = rmErr
	}
	if err != nil {
		return fail(err)
	}
	if p.cfg.GVisor {
		// Streamed in after the image, from the operator's files checked by SHA-512; the
		// template check below reads the digests back from the store.
		if err := p.installGVisor(lctx, h.name); err != nil {
			return fail(err)
		}
	}
	if err := p.checkTemplateContents(lctx, h.name, imageID); err != nil {
		return fail(err)
	}
	if err := p.endSession(h, true, true); err != nil {
		_ = p.removeOwn(h.dir)
		return templateDisk{}, fmt.Errorf("wslc: building the template disk: %w", err)
	}
	// A store whose session was terminated rather than ended at its exit line may lack what
	// was loaded into it: whether terminate lets dockerd write its state out is not
	// measured, so such a store is never a template.
	if h.forced {
		_ = p.removeOwn(h.dir)
		return templateDisk{}, fmt.Errorf("wslc: building the template disk: the session %s did not end at its exit line and was terminated, so its store may not hold the loaded image", h.name)
	}
	// The session has ended; from here a failure only leaves the directory to delete.
	dst := path.Join(p.pr.root.linux, templateDirName)
	if err := p.removeOwn(dst); err != nil {
		_ = p.removeOwn(h.dir)
		return templateDisk{}, fmt.Errorf("wslc: replacing the template disk: %w", err)
	}
	if err := os.Rename(h.dir, dst); err != nil {
		_ = p.removeOwn(h.dir)
		return templateDisk{}, fmt.Errorf("wslc: placing the template disk: %w", err)
	}
	st, err := os.Stat(path.Join(dst, storageFile))
	if err != nil {
		return templateDisk{}, fmt.Errorf("wslc: the template disk: %w", err)
	}
	return templateDisk{win: p.pr.root.win + "/" + templateDirName + "/" + storageFile, bytes: st.Size(), built: time.Since(start)}, nil
}

// formatDisk writes an empty ext4 filesystem of templateDiskBytes, as a VHDX, at dst. The
// raw image is a sparse file in a private temporary directory on the Linux side; the root
// directory is made root's, as a filesystem made inside the VM would be.
func (p *Provider) formatDisk(ctx context.Context, dst string) error {
	dir, err := os.MkdirTemp("", "plimsoll-wslc-template-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	raw := filepath.Join(dir, "raw.ext4")
	f, err := os.OpenFile(raw, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Truncate(templateDiskBytes); err != nil {
		return err
	}
	mctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := hostCommand(mctx, p.cfg.Mkfs, "-q", "-F", "-m", "0", "-L", "plimsoll-wslc",
		"-E", "root_owner=0:0,lazy_itable_init=1,lazy_journal_init=1", raw)
	var out providerkit.Capture
	out.Limit = errorCap
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mkfs.ext4: %w: %s", err, strings.TrimSpace(out.String()))
	}
	vhd, err := os.OpenFile(dst, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := writeVHDX(vhd, f); err != nil {
		vhd.Close()
		return err
	}
	return vhd.Close()
}

// checkTemplateContents refuses a session whose store holds anything but the image, and,
// when gVisor is on, anything but the image and the pinned gVisor files (each file's
// SHA-512 read from the store). The template is built anew at every startup (the startup
// sweep deletes the previous one), so a template built without gVisor is never reused
// when the setting is on.
func (p *Provider) checkTemplateContents(ctx context.Context, session, imageID string) error {
	list := func(args ...string) ([]string, error) {
		out, err := p.output(ctx, append([]string{"--session", session}, args...)...)
		if err != nil {
			return nil, err
		}
		return strings.Fields(string(out)), nil
	}
	images, err := list("image", "list", "--all", "--quiet", "--no-trunc")
	if err != nil {
		return err
	}
	if !slices.Equal(images, []string{imageID}) {
		return fmt.Errorf("the new store lists images %q, want exactly %s", images, imageID)
	}
	containers, err := list("container", "list", "--all", "--quiet")
	if err != nil {
		return err
	}
	volumes, err := list("volume", "list", "--quiet")
	if err != nil {
		return err
	}
	if len(containers) > 0 || len(volumes) > 0 {
		return fmt.Errorf("the new store holds containers %q and volumes %q, want none", containers, volumes)
	}
	if p.cfg.GVisor {
		if _, err := p.verifyGVisorStore(ctx, session); err != nil {
			return err
		}
	}
	return nil
}
