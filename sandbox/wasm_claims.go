package sandbox

import b "github.com/plimsollmark/plimsoll/internal/boundary"

// wasmClaims is the wasm provider's declaration: it has no smoke test, since its walls are
// library code built into plimsolld, the same on every host, so every claim says why no
// startup test checks it and, where one does, which of the project's own tests does.
// docs/isolation-tiers.md prints it.
var wasmClaims = b.Declare(b.Declaration{
	Provider: "wasm",
	Source:   "sandbox/wasm.go",
	Startup:  "It has no startup test: its walls are library code built into plimsolld, the same on every host, so the project's own tests prove them, and its startup check reads only its settings. Its tier is process: an escape from the engine lands inside plimsolld.",
	Entries: map[b.Claim]b.Entry{
		b.WritablePlaces:    {Not: "no filesystem is opened to the engine, so there is no place to write (`TestWasmDefaultCannotReachHostResources`, `TestWasmHasNoNetworkOrFS`)."},
		b.WritableBounds:    {Not: "there is no place to write; the engine's memory is capped instead (see `memory-limit`)."},
		b.LoopbackOnly:      {Not: "the engine has no network API at all, so there is no interface to list (`TestWasmHasNoNetworkOrFS`)."},
		b.NoEgress:          {Not: "the engine has no network API at all (`TestWasmHasNoNetworkOrFS`)."},
		b.GuestUser:         {Not: "the code runs inside plimsolld's own process, as plimsolld's user: the wall is the engine, not a user."},
		b.NoCapabilities:    {Not: "the code runs inside plimsolld's process, which holds what plimsolld holds; the engine gives the code no <dfn>*system call*</dfn> (a request a program makes to the kernel) through which to use it."},
		b.SeccompFilter:     {Not: "no filter is set: the engine gives the code no system call, only WebAssembly's system interface with no directory opened and the host functions plimsolld defines."},
		b.GuestGuard:        {Not: "not applicable: the engine starts no program, so there is nothing for the guest guard to stand in front of."},
		b.ProcessLimit:      {Not: "the code cannot start a process: the engine runs it inside plimsolld's own process."},
		b.MemoryLimit:       {Not: "wazero caps the engine's memory (`WithMemoryLimitPages`) the same way on every host (`TestWasmMemoryLimitEnforced`)."},
		b.CPULimit:          {Not: "a configured CPU limit is refused (`TestWasmRejectsUnsupportedResourceDimensions`), and the run's time limit bounds it instead."},
		b.FixedResolver:     {Not: "the code has no network, so no resolver."},
		b.ClosedEnvironment: {Not: "the engine is given no environment variables (`TestWasmDefaultCannotReachHostResources` sets a secret in plimsolld's own environment and the code cannot read it)."},
		b.ControlChannel:    {Not: "there is no runner: plimsolld calls the engine directly and reads its output."},
		b.NoHostShare:       {Not: "no directory is opened to the engine and no device exists inside it (`TestWasmDefaultCannotReachHostResources`)."},
		b.TierInside:        {Not: "the process tier promises no kernel of its own."},
		b.SetupReadBack:     {Not: "there is no service to read back: its startup check reports only whether the settings were valid, and the QuickJS build is embedded in plimsolld and checked against its SHA-256 (`TestEmbeddedQuickJSProvenance`)."},
		b.RunPath:           {Not: "the engine is built into plimsolld, the same on every host, so the project's own tests run snippets through it."},
		b.DeadlineKill:      {Not: "wazero ends the run when its deadline passes (`WithCloseOnContextDone`, `TestWasmTimeout`)."},
		b.OutputCap:         {Not: "plimsolld reads each stream through a capped buffer of its own."},
		b.GrantSocket:       {Not: "there is no socket: a grant reaches the engine through host functions plimsolld defines."},
		b.Languages:         {Not: "the engine runs JavaScript alone, and states nothing else."},
		b.Teardown:          {Not: "the engine's instance is closed when the run returns, inside plimsolld's process."},
	},
})
