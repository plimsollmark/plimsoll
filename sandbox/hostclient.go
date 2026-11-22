package sandbox

import (
	_ "embed"
	"slices"
)

// A granted run's Python steps get no host client of their own: the injected host.*
// client is preloaded into Node processes only (the plan's hostSDK on docker and
// openshell, NODE_OPTIONS on e2b and dockercloud). On the providers whose every project
// step is handed the broker's socket (HOST_API_SOCKET, PythonGrantProviders), a caller
// that wants Python code to call the grant's routes writes HostClientPython into the
// project at HostClientPythonPath and puts its directory on the step's import path. It
// speaks HTTP over that socket with the standard library and carries no credential:
// the broker checks every request as it checks the Node client's.
//
// Nothing in the daemon reads these: they are the one source of the module the clients
// write (the Python and TypeScript clients' copies are generated from them by
// internal/wiretables, and the MCP server reads them here).

// HostClientPython is the Python module plimsoll_host (hostclient/plimsoll_host.py).
//
//go:embed hostclient/plimsoll_host.py
var HostClientPython string

// HostClientPythonPath is where a project carries HostClientPython: under
// CellRunnerDir, which a fresh cell, a code tool's script and their runners reserve.
const HostClientPythonPath = CellRunnerDir + "/lib/plimsoll_host.py"

// HostClientPythonDir is HostClientPythonPath's directory, the one a step puts on
// Python's import path.
const HostClientPythonDir = CellRunnerDir + "/lib"

// PythonGrantProviders are the providers (by Name, as Describe states it) whose granted
// project runs hand HOST_API_SOCKET to every step, Python's included: docker puts it in
// the runner plan's env (grantGuestEnv) and openshell in the runner's own environment,
// which the runner passes to its steps. On e2b and dockercloud a granted step reaches
// the guard only through the client NODE_OPTIONS preloads into Node, so a Python step
// there has no route to the broker; agentsandbox and wslc carry no grants.
//
// A client reads it beside Describe's supports_project_grants to decide, before it
// offers a model a Python tool, whether that tool's Python can call the API. It is a
// statement of this release's providers: the protocol has no field for it, and a
// daemon of a later release whose provider gained the path is under-offered, never
// over-offered.
var PythonGrantProviders = []string{"docker", "openshell"}

// PythonCarriesGrant reports whether a granted project run on provider hands its Python
// steps the broker's socket (PythonGrantProviders).
func PythonCarriesGrant(provider string) bool { return slices.Contains(PythonGrantProviders, provider) }
