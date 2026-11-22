package main

import (
	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/sandbox"
	"github.com/plimsollmark/plimsoll/sandbox/openshell"
)

// The openshell provider is built here rather than in sandbox.Build: its generated
// OpenShell protocol code registers the protobuf names NVIDIA's OpenShell Go SDK also
// registers, so only this binary links it (sandbox/openshell's package comment).
func init() {
	providers[openshell.Name] = providerDescriptor{
		build: openshell.FromEnv,
		// The gateway sets the process limit for all its sandboxes, so the provider
		// refuses SANDBOX_PIDS; SANDBOX_DISK_MB sizes /tmp.
		hardenedEnvelope: []settings.Size{settings.MemoryMB, settings.CPUs, settings.DiskMB},
		pinnedImages:     true,
		// The tier is unknown until the first driver check (Provider.IsolationClass).
		tierFromChecks: func(sandbox.Sandbox) bool { return true },
	}
}
