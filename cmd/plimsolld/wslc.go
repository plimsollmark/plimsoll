package main

import (
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
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
		// Every container gets --memory and --cpus, and the four tmpfs mounts are sized
		// from SANDBOX_DISK_MB; there is no process limit, so SANDBOX_PIDS is refused.
		hardenedEnvelope: []settings.Size{settings.MemoryMB, settings.CPUs, settings.DiskMB},
		// Hardened mode refuses wslc in both modes, whatever tier it reports. The shared mode
		// is container tier with five of the docker provider's controls absent (wslc.Absent);
		// the per-run mode's VM wall is Hyper-V's (tier container, or vm with
		// SANDBOX_WSLC_ACCEPT_VM_TIER=1), but the same controls are absent inside it, the CLI
		// cannot turn off the session VM's GPU sharing, and its vendor disclaims WSL as a
		// sandbox for untrusted code. Whether hardened mode may ever accept the per-run mode
		// is the project owner's decision, not this file's.
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
				if ev, ok := p.Evidence(); ok {
					args = append(args, "wslc_vm_tier_accepted", ev.VMTierAccepted)
				}
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
							// gVisor is an added wall inside each VM, proven on at each run; it
							// does not change the tier, and hardened mode still refuses the provider.
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
