package wslc

import (
	"errors"
	"fmt"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// FromEnv builds the provider from SANDBOX_WSLC_* and the shared variables, as plimsolld
// does (each is a setting in internal/settings, which -h is printed from).
func FromEnv(getenv func(string) string) (sandbox.Provider, error) {
	res, err := sandbox.ResourcesFromEnv(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	if res.PidsLimit > 0 {
		return sandbox.Provider{}, errors.New("wslc: SANDBOX_PIDS cannot be honored: WSLC has no per-container process limit (no --pids-limit); SANDBOX_WSLC_NPROC sets --ulimit nproc, which counts per uid across the session VM; unset SANDBOX_PIDS")
	}
	pinned, err := settings.RequirePinnedImages.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	nproc, err := settings.WSLCNproc.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	maxSessions, err := settings.WSLCMaxSessions.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	gvisor, err := settings.WSLCGvisor.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	helpers, err := helpersFromEnv(settings.WSLCRunscHelpers.Get(getenv))
	if err != nil {
		return sandbox.Provider{}, err
	}
	// The setting means nothing in the shared mode, so any value fails there, 0 and false
	// included: an operator who set it expected it to change something (finding wslc-32).
	// Config.validate refuses AcceptVMTier there for a caller of New.
	mode := Mode(settings.WSLCMode.Get(getenv))
	if mode == ModeShared && settings.WSLCAcceptVMTier.Set(getenv) {
		return sandbox.Provider{}, errors.New("wslc: " + acceptVMTierPerRunOnly)
	}
	acceptVM, err := settings.WSLCAcceptVMTier.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	p, err := New(Config{
		Mode:               mode,
		MaxSessions:        maxSessions,
		RunRoot:            settings.WSLCRunRoot.Get(getenv),
		Path:               settings.WSLCPath.Get(getenv),
		Image:              settings.WSLCImage.Get(getenv),
		RequirePinnedImage: pinned,
		MemoryMB:           res.MemoryMB,
		CPUs:               res.CPUs,
		DiskMB:             res.DiskMB,
		Nproc:              nproc,
		GVisor:             gvisor,
		RunscPath:          settings.WSLCRunscPath.Get(getenv),
		RunscSHA512:        settings.WSLCRunscSHA512.Get(getenv),
		RunscHelpers:       helpers,
		AcceptVMTier:       acceptVM,
	})
	if err != nil {
		return sandbox.Provider{}, err
	}
	// The envelope as enforced, so Describe states the sizes the defaults filled in.
	res.MemoryMB, res.CPUs, res.DiskMB = p.cfg.MemoryMB, p.cfg.CPUs, 3*smallTmpfsMB+p.cfg.workMB()
	return sandbox.Provider{Sandbox: p, Resources: res}, nil
}

// helpersFromEnv reads SANDBOX_WSLC_RUNSC_HELPERS: comma-separated NAME=SHA512 pairs, each a
// file in gvisor-bin beside runsc. Unset is none; a pair without a digest, an empty name or a
// name given twice is an error (Config.validate checks the characters).
func helpersFromEnv(raw string) (map[string]string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	helpers := map[string]string{}
	for _, pair := range strings.Split(raw, ",") {
		name, sum, ok := strings.Cut(strings.TrimSpace(pair), "=")
		if !ok || name == "" || sum == "" {
			return nil, fmt.Errorf("wslc: SANDBOX_WSLC_RUNSC_HELPERS entry %q is not NAME=SHA512", pair)
		}
		if _, dup := helpers[name]; dup {
			return nil, fmt.Errorf("wslc: SANDBOX_WSLC_RUNSC_HELPERS names %q twice", name)
		}
		helpers[name] = sum
	}
	return helpers, nil
}
