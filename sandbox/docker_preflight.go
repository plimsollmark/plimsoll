package sandbox

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

func (d *DockerSandbox) preflightTime() time.Time {
	if d.preflightNow != nil {
		return d.preflightNow()
	}
	return time.Now()
}

// Preflight resolves the effective Docker context, contacts the daemon, and verifies
// a configured OCI runtime is registered there. This makes readiness and the
// reported isolation tier conservative instead of trusting only a client-side PATH
// or runtime label while the daemon is unavailable/misconfigured. This verifies
// daemon registration and executable basename; it is configuration evidence, not
// cryptographic runtime attestation.
// cachedReady reports whether a recent successful probe still vouches for the
// provider, so a caller need not run one itself.
func (d *DockerSandbox) cachedReady() bool {
	now := d.preflightTime()
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	cacheAge := now.Sub(d.lastVerified)
	return d.ready && d.daemonHost != "" && d.verifiedRuntime == d.Runtime && d.verifiedGuestUID == d.guestUID() &&
		!d.lastVerified.IsZero() && cacheAge >= 0 && cacheAge < dockerPreflightCacheTTL
}

func (d *DockerSandbox) preflightWaitBudget() time.Duration {
	if d.preflightWait > 0 {
		return d.preflightWait
	}
	return dockerPreflightWaitDefault
}

// waitForPreflight is the bounded wait a caller performs when another goroutine
// already holds the preflight lock.
//
// Failing immediately here was measured to be severe for concurrent consumers:
// with a 5 s cache TTL, every expiry turned a burst of legitimate runs into
// errors (47 of 48 graded runs lost at 24 workers, while neighbouring levels lost
// none, purely depending on where the expiry fell). Waiting is still safe for the
// reason the fail-fast existed: callers never block on the mutex, they poll, they
// honour their own context deadline, and they give up after a bound, so no
// unbounded queue can form behind one daemon probe.
//
// ready=true means the in-flight probe published a fresh ready state and NO lock
// is held. ready=false with a nil error means this caller now HOLDS the lock and
// must run the probe itself.
func (d *DockerSandbox) waitForPreflight(ctx context.Context) (ready bool, err error) {
	if d.cachedReady() {
		return true, nil
	}
	giveUp := time.NewTimer(d.preflightWaitBudget())
	defer giveUp.Stop()
	tick := time.NewTicker(dockerPreflightPoll)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-giveUp.C:
			return false, errors.New("docker preflight is already in progress")
		case <-tick.C:
			// Cache first: the holder publishes its result before releasing, so a
			// successful refresh is visible without taking the lock at all.
			if d.cachedReady() {
				return true, nil
			}
			if d.preflightMu.TryLock() {
				return false, nil
			}
		}
	}
}

// Preflight verifies the pinned daemon, the runtime and every configured image
// (preflight), and then, once a SmokeTest has proven the images, that they are still
// the ones it proved (review F1). A tag re-pointed after the smoke test fails it, so
// readiness reports the provider not ready and runs are refused until the new content
// is proven: plimsolld proves it at startup, so a restart; an embedder can call
// SmokeTest again. The failure leaves the verified runtime, and with it the tier, as
// it was.
func (d *DockerSandbox) Preflight(ctx context.Context) error {
	if err := d.preflight(ctx); err != nil {
		return err
	}
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	return d.unprovenLocked()
}

// unprovenLocked refuses, not dispatched (reason environment), an image whose verified
// content is not what the last smoke test proved; nil before any smoke test (an
// embedder that skipped it has no proof to keep). The caller holds stateMu.
func (d *DockerSandbox) unprovenLocked() error {
	if d.provenImageIDs == nil {
		return nil
	}
	for _, ref := range d.configuredImages() {
		if id, proven := d.verifiedImageIDs[ref], d.provenImageIDs[ref]; id != proven {
			return NotDispatched(RefusalEnvironment, fmt.Errorf(
				"docker image %q now names %s, not %s, the content the smoke test proved; restart (or run the smoke test again) to prove it",
				ref, shortImageID(id), shortImageID(proven)))
		}
	}
	return nil
}

func (d *DockerSandbox) preflight(ctx context.Context) (retErr error) {
	// Readiness is public and runs can also trigger lazy Preflight. A caller that
	// loses the race waits a bounded time for the in-flight probe rather than
	// failing outright; see waitForPreflight for why that is still queue-safe.
	if !d.preflightMu.TryLock() {
		ready, err := d.waitForPreflight(ctx)
		if err != nil || ready {
			return err
		}
		// waitForPreflight returned holding the lock.
	}
	defer d.preflightMu.Unlock()

	// Cache a recent successful probe so unauthenticated readiness polling cannot
	// continuously execute docker CLI calls. Keep the prior ready state live while
	// a refresh is in flight; only an actual failed refresh invalidates admission.
	now := d.preflightTime()
	d.stateMu.RLock()
	pinnedHost := d.daemonHost
	cacheAge := now.Sub(d.lastVerified)
	recentlyReady := d.ready && pinnedHost != "" && d.verifiedRuntime == d.Runtime && d.verifiedGuestUID == d.guestUID() &&
		!d.lastVerified.IsZero() && cacheAge >= 0 && cacheAge < dockerPreflightCacheTTL
	d.stateMu.RUnlock()
	if recentlyReady {
		return nil
	}
	defer func() {
		if retErr == nil {
			return
		}
		d.stateMu.Lock()
		d.ready = false
		d.runtimeVerified = false
		d.stateMu.Unlock()
	}()

	// The probe runs detached from the caller's cancellation, under its own bound: a
	// caller that gives up (an unauthenticated /readyz request that hangs up) would
	// otherwise kill the docker CLI mid-probe, and the deferred invalidation above
	// would take the verified runtime, and with it the kernel tier, away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), dockerPreflightTimeout)
	defer cancel()

	// A failed refresh makes the provider not-ready, but never changes the pinned
	// endpoint. In-flight runs have already snapshotted their endpoint/isolation and
	// remain able to tear down on the daemon where they started.
	if err := validateDockerImage(d.Image); err != nil {
		return err
	}
	if err := validateDockerImage(d.ProjectImage); err != nil {
		return err
	}
	if d.ModuleImage != "" {
		if err := validateDockerImage(d.ModuleImage); err != nil {
			return err
		}
	}
	if err := d.validateWritableBudget(); err != nil {
		return err
	}
	if err := validateGuestUID(d.guestUID()); err != nil {
		return err
	}
	// The daemon is local (refused below otherwise). Without remapping its containers'
	// uids are this host's; under userns-remap, rootless docker or a daemon in a VM
	// (Docker Desktop) they are not, and the check is harmless there.
	if err := checkGuestUIDUnused(d.guestUID()); err != nil {
		return err
	}
	if d.RequirePinnedImages {
		for _, img := range d.configuredImages() {
			if !isDigestPinned(img) {
				return fmt.Errorf("image %q is not pinned to an immutable @sha256: digest (RequirePinnedImages is on)", img)
			}
		}
	}
	// A custom seccomp profile must exist before we promise to enforce it; "default"
	// and "unconfined" are docker keywords, not files.
	if p := d.Seccomp; p != "" && p != "unconfined" && p != "default" {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("seccomp profile %q is not readable: %w", p, err)
		}
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker CLI not found on PATH: %w", err)
	}
	if pinnedHost == "" {
		// The container boundary assumes a LOCAL daemon: the broker bind-mounts a
		// Unix socket, and force-remove must target the same host. Resolve the active
		// context exactly once; later probes deliberately verify this pinned endpoint
		// instead of following mutable DOCKER_CONTEXT/config state.
		if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); dockerHostIsRemote(host) {
			return fmt.Errorf("DOCKER_HOST=%q points to a remote daemon; plimsoll requires a local daemon (unix socket) so its broker and teardown hold", host)
		}
		var err error
		pinnedHost, err = effectiveDockerHost(ctx)
		if err != nil {
			return err
		}
		if dockerHostIsRemote(pinnedHost) {
			return fmt.Errorf("effective Docker context points to remote daemon %q; plimsoll requires a local Unix socket", pinnedHost)
		}
	}
	runtimeVerified, err := verifyDockerDaemon(ctx, pinnedHost, d.Runtime)
	if err != nil {
		return err
	}
	// An image-declared VOLUME would make `docker run` silently auto-create an
	// anonymous WRITABLE host volume — bypassing --read-only and every tmpfs size
	// bound above (an unbounded host-disk write channel). Refuse such images, and
	// record the content-addressed ID each verified reference resolved to: runs
	// launch that ID, never the mutable tag, so this check cannot be bypassed by
	// re-pointing the tag after Preflight. This also requires both images to exist
	// on the pinned daemon, so readiness reflects the exact artifacts runs will
	// use rather than a lazy first pull.
	images := d.configuredImages()
	verifiedIDs := make(map[string]string, len(images))
	verifiedManifests := make(map[string]string, len(images))
	verifiedEnvs, platformEnvs := make(map[string][]string, len(images)), make(map[string][]string, len(images))
	platform := dockerSelectedPlatform(ctx, pinnedHost)
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, img := range images {
		id, env, err := verifyImageForRun(ctx, pinnedHost, img)
		if err != nil {
			return err
		}
		verifiedIDs[img], verifiedEnvs[img] = id, env
	}
	if platform != "" {
		containerdStore, err := dockerUsesContainerdStore(ctx, pinnedHost)
		if err != nil {
			return fmt.Errorf("docker image store: %w", err)
		}
		for _, img := range images {
			manifest, env, supported, err := inspectPlatformImage(ctx, pinnedHost, verifiedIDs[img], platform)
			if err != nil {
				return fmt.Errorf("selected platform of image %q: %w", img, err)
			}
			if !supported {
				// Only the classic store, identified by what docker info says rather
				// than by this failure, falls back to Docker's default selection. On
				// the containerd store the failure fails this Preflight, so a passing
				// error cannot switch software identity off until the next one.
				if containerdStore {
					return fmt.Errorf("docker could not inspect the %s manifest of image %q on the containerd image store", platform, img)
				}
				if os.Getenv("DOCKER_DEFAULT_PLATFORM") != "" {
					return fmt.Errorf("cannot verify image %q for DOCKER_DEFAULT_PLATFORM=%q", img, platform)
				}
				platform = "" // classic image store: Docker's default selection, no software identity
				break
			}
			verifiedManifests[img], platformEnvs[img] = manifest, env
		}
	}
	if platform == "" {
		clear(verifiedManifests)
	} else {
		// A run selects this platform, so it starts with that platform's config.
		maps.Copy(verifiedEnvs, platformEnvs)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.stateMu.Lock()
	d.daemonHost = pinnedHost
	d.ready = true
	d.runtimeVerified = runtimeVerified
	d.verifiedRuntime = d.Runtime
	d.verifiedGuestUID = d.guestUID()
	d.verifiedImageIDs = verifiedIDs
	d.verifiedImageEnvs = verifiedEnvs
	d.verifiedManifestIDs = verifiedManifests
	d.verifiedPlatform = platform
	d.lastVerified = d.preflightTime()
	d.stateMu.Unlock()
	return nil
}

// isDigestPinned reports whether an image reference is pinned to an immutable
// content digest (…@sha256:<hex>) rather than a mutable tag.
func isDigestPinned(image string) bool {
	const marker = "@sha256:"
	i := strings.LastIndex(image, marker)
	if i <= 0 {
		return false
	}
	digest := image[i+len(marker):]
	if len(digest) != 64 {
		return false
	}
	for _, c := range digest {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// hostPasswdPath and hostGroupPath are where checkGuestUIDUnused looks; variables so a
// test can point them at files of its own.
var hostPasswdPath, hostGroupPath = "/etc/passwd", "/etc/group"

// checkGuestUIDUnused refuses a guest uid, or its identity check's, that an account in
// this host's /etc/passwd has as its uid or primary group, or a group in its
// /etc/group has: under runc without user-namespace remapping, a process that escaped
// its container would act as that account, or with that group's access. Ids are
// compared as numbers ("061000" is 61000 to the C library). Accounts that come from a
// directory service (LDAP, SSSD) are not in those files, so this is not a proof;
// validateGuestUID refuses systemd's own such bands, and the default sits in a band no
// allocator uses (defaultGuestUID). A file that does not exist is skipped.
func checkGuestUIDUnused(uid int) error {
	for _, f := range []struct{ path, what string }{{hostPasswdPath, "account"}, {hostGroupPath, "group"}} {
		data, err := os.ReadFile(f.path)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return fmt.Errorf("reading %s to check the guest uid: %w", f.path, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			fields := strings.Split(line, ":")
			if len(fields) < 3 {
				continue
			}
			columns := []string{fields[2]} // a group's gid, an account's uid
			if f.what == "account" && len(fields) >= 4 {
				columns = append(columns, fields[3]) // and the account's primary group
			}
			for _, column := range columns {
				n, err := strconv.Atoi(strings.TrimSpace(column))
				if err != nil {
					continue
				}
				for _, id := range []int{uid, uid + 1} {
					if n == id {
						return fmt.Errorf("guest uid %d: this host's %s names the %s %q with id %d, which a process that escaped its container under runc would act as; set SANDBOX_GUEST_UID to an id no account or group uses (the identity check uses it plus one)", uid, f.path, f.what, fields[0], id)
					}
				}
			}
		}
	}
	return nil
}

// dockerHostIsRemote reports whether a DOCKER_HOST value targets a daemon off this
// host. Empty, unix://, and absolute socket paths are local; every other form is
// rejected rather than guessed to be a local daemon.
func dockerHostIsRemote(host string) bool {
	if host == "" {
		return false
	}
	return !strings.HasPrefix(host, "unix://") && !filepath.IsAbs(host)
}

// effectiveDockerHost asks the CLI to resolve DOCKER_HOST, DOCKER_CONTEXT, and the
// persisted active context using Docker's own precedence rules. Checking only an
// environment variable is insufficient: a saved SSH/TCP context can otherwise run
// hostile code on a remote daemon where local broker and teardown assumptions fail.
func effectiveDockerHost(ctx context.Context) (string, error) {
	out, err := dockerResolveOutput(ctx, "context", "inspect", "--format", `{{(index .Endpoints "docker").Host}}`)
	if err != nil {
		return "", fmt.Errorf("resolve effective Docker context: %w", err)
	}
	host := strings.TrimSpace(string(out))
	if host == "" {
		return "", errors.New("resolve effective Docker context: empty daemon endpoint")
	}
	return host, nil
}

func verifyDockerDaemon(ctx context.Context, host, runtime string) (bool, error) {
	out, err := dockerOutput(ctx, "--host", host, "info", "--format", `{{json .Runtimes}}`)
	if err != nil {
		return false, fmt.Errorf("docker daemon is not ready: %w", err)
	}
	var runtimes map[string]struct {
		Path string `json:"path"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &runtimes); err != nil {
		return false, fmt.Errorf("docker daemon returned unparseable runtime metadata: %w", err)
	}
	if runtime != "" {
		cfg, ok := runtimes[runtime]
		if !ok {
			return false, fmt.Errorf("configured OCI runtime %q is not registered with the Docker daemon", runtime)
		}
		if runtime == "runsc" && filepath.Base(cfg.Path) != "runsc" {
			return false, fmt.Errorf("OCI runtime %q is registered with path %q, not a runsc executable", runtime, cfg.Path)
		}
	}
	return runtime == "runsc", nil
}

// verifyImageForRun inspects an image on the pinned daemon and returns the
// content-addressed ID runs must launch. It rejects an image whose config
// declares VOLUMEs: for each declared volume `docker run` auto-creates an
// anonymous writable volume on the host, which is exempt from --read-only and
// has no size bound — exactly the aggregate-writable-storage hole this provider
// promises is closed. Returning the ID from the same inspect binds that check to
// the exact image content, so a tag re-pointed after Preflight cannot swap in an
// unverified config. Requires the image to be present (inspect does not pull).
func verifyImageForRun(ctx context.Context, host, image string) (string, []string, error) {
	// One whole-object inspect: a compound template like `{{.Id}} {{json
	// .Config.Volumes}}` fails on daemons that omit the empty Volumes key, and two
	// separate inspects would let the tag move between reading the ID and the
	// volume config.
	args, err := dockerArgs(host, "image", "inspect", "--format", "{{json .}}", image)
	if err != nil {
		return "", nil, err
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return "", nil, fmt.Errorf("docker image %q is not inspectable on the pinned daemon (build or pull it before serving): %w", image, err)
	}
	id, volumes, env, err := parseImageIDAndVolumes(out)
	if err != nil {
		return "", nil, fmt.Errorf("docker image %q: %w", image, err)
	}
	if len(volumes) > 0 {
		return "", nil, fmt.Errorf("docker image %q declares VOLUME %s; docker would auto-create unbounded writable host volumes for it, so this image is refused — rebuild it without VOLUME", image, strings.Join(volumes, ", "))
	}
	return id, env, nil
}

// dockerSelectedPlatform fixes the platform Docker will select at launch. A
// caller may intentionally set DOCKER_DEFAULT_PLATFORM; otherwise the daemon's
// native platform is used. The launch receives this exact value explicitly, so
// a later environment change cannot select a different manifest.
func dockerSelectedPlatform(ctx context.Context, host string) string {
	if p := os.Getenv("DOCKER_DEFAULT_PLATFORM"); p != "" {
		return p
	}
	args, err := dockerArgs(host, "version", "--format", "{{.Server.Os}}/{{.Server.Arch}}")
	if err != nil {
		return ""
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// inspectPlatformImage inspects, once, the config of the very platform a run will
// select, from an immutable outer image ID. supported is false when this Docker
// cannot answer for that platform. A VOLUME or malformed output is a hard
// Preflight failure. The manifest identity is claimed only when the descriptor's
// platform and ID agree; older stores may not expose it, and then it stays empty
// and a caller who requires it gets a pre-dispatch refusal.
func inspectPlatformImage(ctx context.Context, host, imageID, platform string) (manifest string, env []string, supported bool, err error) {
	args, err := dockerArgs(host, "image", "inspect", "--platform", platform, "--format", "{{json .}}", imageID)
	if err != nil {
		return "", nil, false, err
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		if ctx.Err() != nil {
			return "", nil, false, ctx.Err()
		}
		return "", nil, false, nil
	}
	_, volumes, env, err := parseImageIDAndVolumes(out)
	if err != nil {
		return "", nil, false, err
	}
	if len(volumes) != 0 {
		return "", nil, false, fmt.Errorf("image declares VOLUME %s; it would create an unbounded writable host volume", strings.Join(volumes, ", "))
	}
	return parseDockerSelectedManifest(out, platform), env, true, nil
}

// dockerUsesContainerdStore reports whether the daemon keeps images in the
// containerd image store, which answers image inspect for a platform. docker info
// names the snapshotter as the storage driver's driver-type; the classic store
// does not.
func dockerUsesContainerdStore(ctx context.Context, host string) (bool, error) {
	args, err := dockerArgs(host, "info", "--format", "{{json .DriverStatus}}")
	if err != nil {
		return false, err
	}
	out, err := dockerOutput(ctx, args...)
	if err != nil {
		return false, fmt.Errorf("docker info: %w", err)
	}
	return containerdStoreFromDriverStatus(out)
}

func containerdStoreFromDriverStatus(out []byte) (bool, error) {
	var status [][]string
	if err := json.Unmarshal(bytes.TrimSpace(out), &status); err != nil {
		return false, fmt.Errorf("docker info driver status: %w", err)
	}
	for _, kv := range status {
		if len(kv) == 2 && kv[0] == "driver-type" && kv[1] == "io.containerd.snapshotter.v1" {
			return true, nil
		}
	}
	return false, nil
}

// normalizePlatform writes os/arch[/variant] the way Docker's own platform
// matching compares it, modeled on containerd's platforms.Normalize, so the daemon's
// linux/arm64 and an image's linux/arm64/v8 are one platform: aarch64 is arm64,
// x86_64 is amd64 and i386 is 386, arm64's default variant v8 and amd64's v1 are
// dropped, and arm without a variant is arm/v7. It goes beyond containerd in one
// place: the arm64 spellings v8.0 and v9.0 fold to their short forms. An identity is
// written with this form, so it is the same on every host.
func normalizePlatform(p string) string {
	parts := strings.Split(strings.ToLower(p), "/")
	if len(parts) < 2 || len(parts) > 3 {
		return strings.ToLower(p)
	}
	osName, arch, variant := parts[0], parts[1], ""
	if len(parts) == 3 {
		variant = parts[2]
	}
	switch arch {
	case "aarch64", "arm64":
		arch = "arm64"
		switch variant {
		case "8", "v8", "v8.0":
			variant = ""
		case "9", "9.0", "v9.0":
			variant = "v9"
		}
	case "x86_64", "x86-64", "amd64":
		arch = "amd64"
		if variant == "v1" {
			variant = ""
		}
	case "i386":
		arch = "386"
	case "armhf":
		arch, variant = "arm", "v7"
	case "armel":
		arch, variant = "arm", "v6"
	case "arm":
		switch variant {
		case "", "7":
			variant = "v7"
		case "5", "6", "8":
			variant = "v" + variant
		}
	}
	if variant == "" {
		return osName + "/" + arch
	}
	return osName + "/" + arch + "/" + variant
}

func parseDockerSelectedManifest(out []byte, platform string) string {
	var inspected struct {
		ID         string `json:"Id"`
		OS         string `json:"Os"`
		Arch       string `json:"Architecture"`
		Variant    string `json:"Variant"`
		Descriptor struct {
			Digest    string `json:"digest"`
			MediaType string `json:"mediaType"`
		} `json:"Descriptor"`
	}
	if json.Unmarshal(bytes.TrimSpace(out), &inspected) != nil {
		return ""
	}
	actual := inspected.OS + "/" + inspected.Arch
	if inspected.Variant != "" {
		actual += "/" + inspected.Variant
	}
	manifestType := inspected.Descriptor.MediaType == "application/vnd.oci.image.manifest.v1+json" ||
		inspected.Descriptor.MediaType == "application/vnd.docker.distribution.manifest.v2+json"
	if normalizePlatform(actual) != normalizePlatform(platform) || inspected.ID != inspected.Descriptor.Digest || !manifestType ||
		!strings.HasPrefix(inspected.ID, "sha256:") || len(inspected.ID) != len("sha256:")+64 {
		return ""
	}
	if _, err := hex.DecodeString(strings.TrimPrefix(inspected.ID, "sha256:")); err != nil {
		return ""
	}
	return "oci-manifest:" + normalizePlatform(platform) + "@" + inspected.ID
}

// parseImageIDAndVolumes decodes `docker image inspect --format '{{json .}}'`
// output into the content-addressed ID, the declared volume paths (daemons omit the
// Volumes key entirely when none are declared) and the image's environment, which
// plimsoll hands to guest processes itself (guestArgv; the warning in
// docker_cli.go). Anything malformed fails closed — an image whose identity, volume
// config or environment cannot be read is not runnable evidence.
func parseImageIDAndVolumes(out []byte) (string, []string, []string, error) {
	var inspect struct {
		ID     string `json:"Id"`
		Config struct {
			Volumes map[string]json.RawMessage `json:"Volumes"`
			Env     []string                   `json:"Env"`
		} `json:"Config"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &inspect); err != nil {
		return "", nil, nil, fmt.Errorf("returned unparseable inspect output: %w", err)
	}
	if !strings.HasPrefix(inspect.ID, "sha256:") {
		return "", nil, nil, fmt.Errorf("returned no content-addressed image ID (got %q)", inspect.ID)
	}
	if err := checkEnvEntries(inspect.Config.Env); err != nil {
		return "", nil, nil, err
	}
	if err := checkLoaderEnv(inspect.Config.Env); err != nil {
		return "", nil, nil, err
	}
	paths := make([]string, 0, len(inspect.Config.Volumes))
	for p := range inspect.Config.Volumes {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	return inspect.ID, paths, slices.Clip(inspect.Config.Env), nil
}

type dockerExecutionState struct {
	host      string
	runtime   string
	isolation IsolationClass
	// imageID/projectImageID are the Preflight-verified content IDs runs launch in
	// place of the mutable Image/ProjectImage references.
	imageID         string
	projectImageID  string
	moduleImageID   string // "" when no module image is configured
	platform        string
	imageManifest   string
	projectManifest string
	moduleManifest  string
	// env is each launched image's environment, by content ID: what its guest
	// processes start with. Shared and read-only.
	env map[string][]string
}

// executionState is the verified state runs launch under (verifiedState), refused
// when an image is not the one the smoke test proved (unprovenLocked, review F1).
func (d *DockerSandbox) executionState() (dockerExecutionState, error) {
	state, err := d.verifiedState()
	if err != nil {
		return state, err
	}
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	if err := d.unprovenLocked(); err != nil {
		return dockerExecutionState{}, err
	}
	return state, nil
}

// shortImageID is an image ID cut for a message: the digest's first 12 hex digits.
func shortImageID(id string) string {
	if id == "" {
		return "nothing"
	}
	hex := strings.TrimPrefix(id, "sha256:")
	return "sha256:" + hex[:min(12, len(hex))]
}

// verifiedState is what Preflight verified: the pinned daemon, the runtime, and the
// content ID and manifest of every configured image.
func (d *DockerSandbox) verifiedState() (dockerExecutionState, error) {
	d.stateMu.RLock()
	defer d.stateMu.RUnlock()
	// A guest uid changed since Preflight was never checked against this host's
	// accounts.
	if !d.ready || d.daemonHost == "" || d.verifiedRuntime != d.Runtime || d.verifiedGuestUID != d.guestUID() {
		return dockerExecutionState{}, errors.New("docker provider is not ready for its current configuration")
	}
	imageID, projectImageID := d.verifiedImageIDs[d.Image], d.verifiedImageIDs[d.ProjectImage]
	moduleImageID := ""
	if d.ModuleImage != "" {
		moduleImageID = d.verifiedImageIDs[d.ModuleImage]
	}
	if imageID == "" || projectImageID == "" || (d.ModuleImage != "" && moduleImageID == "") {
		// The configured references changed since Preflight verified them; running
		// the new tags would launch content whose volume config was never checked.
		return dockerExecutionState{}, errors.New("docker images are not the Preflight-verified ones; re-run Preflight")
	}
	isolation := IsolationContainer
	if d.Runtime == "runsc" && d.runtimeVerified {
		isolation = IsolationKernel
	}
	return dockerExecutionState{
		host:            d.daemonHost,
		runtime:         d.verifiedRuntime,
		isolation:       isolation,
		imageID:         imageID,
		projectImageID:  projectImageID,
		moduleImageID:   moduleImageID,
		platform:        d.verifiedPlatform,
		imageManifest:   d.verifiedManifestIDs[d.Image],
		projectManifest: d.verifiedManifestIDs[d.ProjectImage],
		moduleManifest:  d.verifiedManifestIDs[d.ModuleImage],
		env: map[string][]string{
			imageID:        d.verifiedImageEnvs[d.Image],
			projectImageID: d.verifiedImageEnvs[d.ProjectImage],
			moduleImageID:  d.verifiedImageEnvs[d.ModuleImage],
		},
	}, nil
}

// guestEnv is the environment a guest process in imageID starts with: the image's
// own, then extra (the run's variables, such as a grant's socket), in a new slice.
func (s dockerExecutionState) guestEnv(imageID string, extra ...string) []string {
	return append(slices.Clone(s.env[imageID]), extra...)
}

// configuredImages lists every image reference this provider will launch, each
// once: the snippet image, the project image, and the module image when set.
// Preflight verifies and pins exactly this set.
func (d *DockerSandbox) configuredImages() []string {
	images := []string{d.Image}
	for _, img := range []string{d.ProjectImage, d.ModuleImage} {
		if img == "" || slices.Contains(images, img) {
			continue
		}
		images = append(images, img)
	}
	return images
}

// notReady marks a refusal from the provider's own checks before dispatch (an image
// reference it cannot use, a daemon or image Preflight cannot verify, an execution
// state not proven): no container was started, so it is not dispatched, reason
// environment, and placement may send the call elsewhere; reason capacity when the
// caller gave up while the checks ran. A mark it already carries stays.
func notReady(ctx context.Context, err error) error {
	if _, marked := NotDispatchedReason(err); marked {
		return err
	}
	if ctx.Err() != nil {
		return NotDispatched(RefusalCapacity, err)
	}
	return NotDispatched(RefusalEnvironment, err)
}

func (d *DockerSandbox) ensurePreflight(ctx context.Context) error {
	if err := d.Preflight(ctx); err != nil {
		return err
	}
	_, err := d.executionState()
	return err
}
