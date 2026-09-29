package openshell

import "github.com/plimsollmark/plimsoll/sandbox"

// FromEnv builds the provider from the environment, as sandbox.Build builds the
// providers it knows: the gateway and its mutual TLS files from the
// SANDBOX_OPENSHELL_* variables, the pin rule from SANDBOX_REQUIRE_PINNED_IMAGES, and
// the resource envelope parsed as Build parses it. A process or disk limit is passed
// through so New refuses it. It contacts nothing; the gateway is first called by
// Preflight. plimsolld builds the provider with it, and so does any program that runs
// the provider outside the daemon.
func FromEnv(getenv func(string) string) (sandbox.Provider, error) {
	res, err := sandbox.ResourcesFromEnv(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
	if err != nil {
		return sandbox.Provider{}, err
	}
	p, err := New(Config{
		GatewayURL:         getenv("SANDBOX_OPENSHELL_GATEWAY_URL"),
		CAFile:             getenv("SANDBOX_OPENSHELL_CA_FILE"),
		CertFile:           getenv("SANDBOX_OPENSHELL_CERT_FILE"),
		KeyFile:            getenv("SANDBOX_OPENSHELL_KEY_FILE"),
		Image:              getenv("SANDBOX_OPENSHELL_IMAGE"),
		RequirePinnedImage: pinned,
		MemoryMB:           res.MemoryMB,
		CPUs:               res.CPUs,
		PidsLimit:          res.PidsLimit,
		DiskMB:             res.DiskMB,
	})
	if err != nil {
		return sandbox.Provider{}, err
	}
	return sandbox.Provider{Sandbox: p, Resources: res}, nil
}
