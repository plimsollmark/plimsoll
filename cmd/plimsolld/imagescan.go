package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/internal/withheld"
)

// imageArchives is what the docker provider offers the startup scan: each image it runs,
// as docker save writes it (sandbox.DockerSandbox.ImageArchives).
type imageArchives interface {
	ImageArchives(ctx context.Context, fn func(ref, id string, archive io.Reader) error) error
}

// scanImages scans every image the provider runs against the withheld set, at startup:
// the ship scan reads each call's payload, and a harness file or a hidden answer baked
// into an image would reach every sandbox without passing through one. A refuse-mode
// entry found in an image is an error (the daemon refuses to serve until the image is
// rebuilt without it); an audit-mode one is logged. Files the scan could not read whole
// (an xz or zstd stream, archive-like bytes in a compiled library, a file over 64 MiB:
// any real image has some) must be on the image's known-unreadable list, whatever the
// set's mode: one that is not refuses the start, since withheld material inside it would
// not be found. An unset list means every such file is unknown.
func scanImages(ctx context.Context, src imageArchives, set *withheld.Set) error {
	knownPath := settings.WithheldKnownFile.Get(os.Getenv)
	known, err := withheld.LoadKnown(knownPath)
	if err != nil {
		return fmt.Errorf("loading known-unreadable image files: %w", err)
	}
	var refused, unlisted []string
	var commands []string
	err = src.ImageArchives(ctx, func(ref, id string, archive io.Reader) error {
		ref, id = withheld.CleanWhere(ref), withheld.CleanWhere(id)
		res, err := set.ScanImage(ctx, archive)
		if err != nil {
			return fmt.Errorf("scanning image %s (%s): %w", ref, id, err)
		}
		for _, f := range res.Found {
			attrs := []any{"image", ref, "image_id", id, "entry", f.Label, "mode", string(f.Mode), "where", strings.Join(f.Where, ", ")}
			if f.Mode == withheld.ModeRefuse {
				slog.Error("a withheld entry is in an image this provider runs", attrs...)
				refused = append(refused, f.Label)
			} else {
				slog.Warn("a withheld entry (audit mode) is in an image this provider runs", attrs...)
			}
		}
		unknown := known.Unknown(id, res.Unreadable)
		for _, u := range unknown {
			unlisted = append(unlisted, fmt.Sprintf("image %s (%s): unlisted unreadable file %s (%s, %d bytes)", ref, id, withheld.CleanWhere(u.Where), u.Reason.Text(), u.Size))
		}
		if len(unknown) > 0 {
			setPath := settings.WithheldFile.Get(os.Getenv)
			if setPath == "" {
				setPath = "withheld.json"
			}
			listPath := knownPath
			if listPath == "" {
				listPath = "known-images.json"
			}
			commands = append(commands, fmt.Sprintf("plimsoll-withheld known-unreadable -set %s -known %s %s", scanShellQuote(setPath), scanShellQuote(listPath), scanShellQuote(id)))
		}
		if n := len(res.Incomplete); n > 0 {
			slog.Info("image files the withheld scan could not read whole", "image", ref, "count", n,
				"first", res.Incomplete[0].Where, "why", res.Incomplete[0].Bound.Text())
		}
		slog.Info("image scanned against the withheld set", "image", ref, "image_id", id, "files", res.Files,
			"layers", res.Layers, "found", len(res.Found), "set", set.Digest())
		return nil
	})
	if err != nil {
		return err
	}
	var msgs []string
	if len(refused) > 0 {
		msgs = append(msgs, fmt.Sprintf("the provider's images hold %d withheld refuse-mode entries (%s); rebuild them without, or check with plimsoll-withheld scan-image",
			len(refused), strings.Join(refused, ", ")))
	}
	if len(unlisted) > 0 {
		msgs = append(msgs, strings.Join(unlisted, "; ")+"; after reviewing the unread bytes, list them with: "+strings.Join(commands, "; ")+"; configure PLIMSOLL_WITHHELD_KNOWN_FILE to read that list. Listing acknowledges unread bytes, not that they hold no withheld material")
	}
	if len(msgs) > 0 {
		return fmt.Errorf("%s", strings.Join(msgs, "; "))
	}
	return nil
}

// Names printed in a suggested shell command must neither forge a log line nor
// become shell syntax when copied. CleanWhere also protects the surrounding prose.
func scanShellQuote(s string) string {
	return "'" + strings.ReplaceAll(withheld.CleanWhere(s), "'", "'\\''") + "'"
}
