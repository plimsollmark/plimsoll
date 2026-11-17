package wslc

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// FromEnv builds the provider from SANDBOX_WSLC_* and the shared variables, as plimsolld
// does (cmd/plimsolld/wslc.go, whose -h text names each one).
func FromEnv(getenv func(string) string) (sandbox.Provider, error) {
	res, err := sandbox.ResourcesFromEnv(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	if res.PidsLimit > 0 {
		return sandbox.Provider{}, errors.New("wslc: SANDBOX_PIDS cannot be honored: WSLC has no per-container process limit (no --pids-limit); SANDBOX_WSLC_NPROC sets --ulimit nproc, which counts per uid across the session VM; unset SANDBOX_PIDS")
	}
	pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
	if err != nil {
		return sandbox.Provider{}, err
	}
	nproc, err := intFromEnv(getenv, "SANDBOX_WSLC_NPROC")
	if err != nil {
		return sandbox.Provider{}, err
	}
	maxSessions, err := intFromEnv(getenv, "SANDBOX_WSLC_MAX_SESSIONS")
	if err != nil {
		return sandbox.Provider{}, err
	}
	gvisor, err := sandbox.BoolFromEnv(getenv, "SANDBOX_WSLC_GVISOR")
	if err != nil {
		return sandbox.Provider{}, err
	}
	helpers, err := helpersFromEnv(getenv("SANDBOX_WSLC_RUNSC_HELPERS"))
	if err != nil {
		return sandbox.Provider{}, err
	}
	// The setting means nothing in the shared mode, so any value fails there, 0 and false
	// included: an operator who set it expected it to change something (finding wslc-32).
	// Config.validate refuses AcceptVMTier there for a caller of New.
	mode := Mode(strings.TrimSpace(getenv("SANDBOX_WSLC_MODE")))
	if mode == ModeShared && strings.TrimSpace(getenv("SANDBOX_WSLC_ACCEPT_VM_TIER")) != "" {
		return sandbox.Provider{}, errors.New("wslc: " + acceptVMTierPerRunOnly)
	}
	acceptVM, err := sandbox.BoolFromEnv(getenv, "SANDBOX_WSLC_ACCEPT_VM_TIER")
	if err != nil {
		return sandbox.Provider{}, err
	}
	p, err := New(Config{
		Mode:               mode,
		MaxSessions:        maxSessions,
		RunRoot:            getenv("SANDBOX_WSLC_RUN_ROOT"),
		Path:               getenv("SANDBOX_WSLC_PATH"),
		Image:              getenv("SANDBOX_WSLC_IMAGE"),
		RequirePinnedImage: pinned,
		MemoryMB:           res.MemoryMB,
		CPUs:               res.CPUs,
		DiskMB:             res.DiskMB,
		Nproc:              nproc,
		GVisor:             gvisor,
		RunscPath:          getenv("SANDBOX_WSLC_RUNSC_PATH"),
		RunscSHA512:        strings.TrimSpace(getenv("SANDBOX_WSLC_RUNSC_SHA512")),
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

// intFromEnv is a whole-number variable; unset is 0, the default.
func intFromEnv(getenv func(string) string, name string) (int, error) {
	raw := strings.TrimSpace(getenv(name))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("wslc: %s=%q is not a whole number", name, raw)
	}
	return n, nil
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
