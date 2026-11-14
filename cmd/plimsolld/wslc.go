package main

import (
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/wslc"
)

// The wslc provider (WSL containers on Windows, driven through WSL interop) is built here,
// off unless SANDBOX_PROVIDER=wslc, and outside sandbox.Build, as the openshell and
// agentsandbox providers are: it needs a Windows host with wslc.exe, which no other
// provider does.
func init() {
	providers[wslc.Name] = providerDescriptor{
		build: wslc.FromEnv,
		usage: wslcUsage,
		// Every container gets --memory and --cpus, and the four tmpfs mounts are sized
		// from SANDBOX_DISK_MB; there is no process limit, so SANDBOX_PIDS is refused.
		hardenedEnvelope: []string{"SANDBOX_MEMORY_MB", "SANDBOX_CPUS", "SANDBOX_DISK_MB"},
		// Hardened mode refuses wslc in both modes. The shared mode is container tier with
		// five of the docker provider's controls absent (wslc.Absent); the per-run mode's VM
		// wall is Hyper-V's, but the same controls are absent inside it, the CLI cannot turn
		// off the session VM's GPU sharing, and its vendor disclaims WSL as a sandbox for
		// untrusted code. Whether hardened mode may ever accept the per-run mode is the
		// project owner's decision, not this file's.
		hardened: func(_ func(string) string, fail func(string, ...any), _ func(error)) {
			fail("hardened mode does not serve wslc in either mode: the shared mode is container tier, below the docker provider under runc; in the per-run mode the VM wall is Hyper-V's, but inside it there is still no read-only root, seccomp choice, no-new-privileges, process limit or user namespaces, and the session VM's GPU sharing cannot be turned off; and Microsoft states that WSL is not a security sandbox for running untrusted code")
		},
		resourceLog: func(sb sandbox.Sandbox, res sandbox.Resources) []any {
			args := []any{"max_mem_mb", res.MemoryMB, "max_cpus", res.CPUs, "max_disk_mb", res.DiskMB}
			p, ok := sb.(*wslc.Provider)
			if ok && p.Mode() == wslc.ModePerRun {
				// The tier is stated with its qualification wherever it is stated.
				args = append(args, "wslc_mode", p.Mode(), "isolation_qualification", p.Qualification(),
					"pids", "no per-container limit (--ulimit nproc counts per uid in the run's own VM)")
			} else {
				args = append(args, "wslc_mode", wslc.ModeShared, "isolation_qualification", p.Qualification(),
					"pids", "no per-container limit (--ulimit nproc counts per uid across the session VM, so the shared mode runs one run at a time)")
			}
			// Which runtime starts a run's container: runsc (gVisor) only in the per-run mode
			// with SANDBOX_WSLC_GVISOR=1, runc otherwise.
			runtime := "runc"
			if ok && p.GVisor() {
				runtime = "runsc (gVisor, systrap): proven on at each run, and a run that cannot be is refused, never started under runc"
			}
			args = append(args, "wslc_runtime", runtime, "absent_controls", strings.Join(wslcAbsentShort, ", "))
			if ok {
				if ev, ok := p.Evidence(); ok {
					args = append(args, "wsl", ev.WSLVersion, "kernel", ev.KernelRelease, "moby", ev.Moby,
						"seccomp", ev.Seccomp, "no_new_privs", ev.NoNewPrivs, "pids_max", ev.PidsMax,
						"nproc", ev.NprocLimit)
					if ev.Mode == wslc.ModePerRun {
						// Each run's VM has its own boot ID; the smoke test's two are the evidence.
						boots := make([]string, 0, len(ev.RunSessions))
						for _, rs := range ev.RunSessions {
							boots = append(boots, rs.BootID)
						}
						args = append(args, "smoke_run_boot_ids", strings.Join(boots, ","), "template_bytes", ev.TemplateBytes)
						if g := ev.GVisor; g != nil {
							// gVisor is an added wall inside each VM, proven on at each run; the
							// tier stays vm and hardened mode still refuses the provider.
							args = append(args, "gvisor_runtime", g.Runtime, "gvisor_runsc_version", g.RunscVersion,
								"gvisor_runsc_sha512", g.RunscSHA512, "gvisor_platform", g.Platform,
								"gvisor_sentry_seccomp", g.SentrySeccomp, "gvisor_run_policy", wslc.PolicyGVisor)
						}
					} else {
						// The default session depends on the caller's elevation.
						args = append(args, "session", ev.Session, "session_boot_id", ev.BootID)
					}
				}
			}
			return args
		},
	}
}

// wslcAbsentShort names wslc.Absent's controls for the startup log line.
var wslcAbsentShort = []string{"read-only root", "seccomp choice", "no-new-privileges", "process limit", "user namespaces", "log driver", "init"}

const wslcUsage = `
  SANDBOX_PROVIDER=wslc
                             WSL containers (WSLC) on Windows, driven through WSL
                             interop from a plimsolld in a WSL distribution. Needs
                             WSL 3.0.5 or later. Microsoft states that WSL is not a
                             security sandbox for running untrusted code; hardened
                             mode refuses it in both modes.
                             In both, a run's container has no read-only root, no
                             seccomp choice or no-new-privileges, no process limit
                             and no user namespaces. The smoke test refuses startup
                             unless the probe container has loopback alone, no
                             capability, the guest uid, the memory limit, a seccomp
                             filter, no GPU device, no Windows folder and no writable
                             place but its four tmpfs mounts.
                             Snippets and projects only: no grants, sessions or modules.
                             Guide: docs/wslc.md.
  SANDBOX_WSLC_MODE          per-run (default) or shared.
                             per-run, tier vm, always stated with its qualification
                             (Describe carries it as isolation_qualification, and the
                             startup log too): a Hyper-V VM per run (one WSLC session
                             per run), booted from a fresh copy of a template disk
                             plimsolld builds at startup and deleted after the run; the
                             VM wall is Hyper-V's, and the Windows components around it
                             (network relay, shares, interop) run with the user's
                             rights. Uses wslc.exe's undocumented "system session
                             enter", powershell.exe (System32) and /usr/sbin/mkfs.ext4;
                             about 0.9 GB of Windows memory per live run. Each per-run
                             plimsolld needs a run folder of its own: it ends only
                             sessions whose folder is under its run folder, and a
                             second process on the same folder refuses to start.
                             shared, chosen by setting it, tier container: every run is
                             a fresh container in the caller's default WSLC session VM
                             (one per Windows user and elevation), beside the others,
                             sharing its kernel and rootful dockerd. Weaker than docker
                             under runc. One run at a time: the process limit is counted
                             across the session VM, so a second run waits for its turn,
                             no longer than its own timeout, and is refused (not
                             dispatched, capacity) if the wait ends first.
  SANDBOX_WSLC_MAX_SESSIONS  per-run only: the most runs in VMs of their own at once
                             (default 2, at most 16); a run past it is refused, not
                             dispatched, and a run waits while an ended one's VM is
                             still being torn down
  SANDBOX_WSLC_GVISOR        per-run only, off by default: 1 makes gVisor (runsc, the
                             systrap platform) the runtime inside every run's VM, an
                             added wall inside the Hyper-V VM. The tier stays vm and
                             is stated with gVisor's position added; hardened mode
                             still refuses the provider. The template carries runsc
                             (streamed in at startup and checked by SHA-512 inside
                             the VM). WSLC rewrites the docker settings at every VM
                             boot, so each run writes them again, reloads dockerd and
                             reads the default runtime back: a run whose VM does not
                             read runsc is refused (not dispatched, environment) and
                             is never started under runc. The smoke test then proves
                             gVisor from inside (its kernel string) and from the VM's
                             side (the container's runtime, a runsc process, the
                             memory limit and the Sentry's own filter). Each result
                             carries the policy gvisor:proven. Rests on three
                             behaviors Microsoft does not document: "system session
                             enter", "system session run" as root in the VM, and
                             dockerd rereading /etc/docker/daemon.json on SIGHUP.
                             The VM has no /dev/kvm, so systrap. Refused in the shared
                             mode
  SANDBOX_WSLC_RUNSC_PATH    with SANDBOX_WSLC_GVISOR=1: the runsc binary as this
                             distribution sees it (an absolute path; nothing is
                             downloaded). Needs SANDBOX_WSLC_RUNSC_SHA512
  SANDBOX_WSLC_RUNSC_SHA512  with SANDBOX_WSLC_GVISOR=1: the binary's SHA-512, 128
                             lowercase hex digits (a path without a digest, or a digest
                             that does not match, refuses startup)
  SANDBOX_WSLC_RUNSC_HELPERS with SANDBOX_WSLC_GVISOR=1: the files runsc needs from the
                             gvisor-bin directory beside it, as NAME=SHA512 pairs
                             separated by commas (default none); each is sent and
                             checked, and the store must hold exactly this set
  SANDBOX_WSLC_RUN_ROOT      per-run only: the directory for the template and the run
                             disks, on a Windows drive as this distribution mounts it
                             (default the Windows user's %LOCALAPPDATA%\plimsoll-wslc);
                             only names plimsolld creates there are ever deleted. Every
                             run boots the template kept there, so startup refuses to
                             serve unless the root's owner and everyone who can write,
                             create or delete there (by Windows access list, inherited
                             rules included) is this Windows user, SYSTEM or
                             Administrators, or the list cannot be read. Every folder
                             above it, to the drive's own, is read too and refused when
                             anyone else could delete, rename or take it over, and so
                             are the built template's folder and disk file. The
                             template is not checked again between runs
  SANDBOX_WSLC_PATH          wslc.exe as this distribution sees it (default
                             /mnt/c/Program Files/WSL/wslc.exe)
  SANDBOX_WSLC_IMAGE         the image every run starts: plimsoll's sandbox image or
                             one built FROM it (required; with
                             SANDBOX_REQUIRE_PINNED_IMAGES=1, name@sha256:<digest>)
  SANDBOX_WSLC_NPROC         --ulimit nproc (default 256): processes of the guest uid
                             at once in the session VM (shared: one run at a time, so
                             one run's; per-run: in the run's own VM)
                             SANDBOX_MEMORY_MB, SANDBOX_CPUS and SANDBOX_DISK_MB size
                             each container; SANDBOX_PIDS fails startup
`
