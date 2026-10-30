package agentsandbox

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// The service account files a pod is given, the defaults for plimsolld running in the
// cluster, which it must to reach the pods' addresses.
const (
	inClusterAPIServer = "https://kubernetes.default.svc"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
)

// FromEnv builds the provider from SANDBOX_AGENTSANDBOX_* and the shared variables, as
// plimsolld does (cmd/plimsolld/agentsandbox.go, whose -h text names each one). The API
// server, its CA and the token default to the pod's own service account. sandboxd's token
// is read from a file, never from the environment, which every child process inherits.
func FromEnv(getenv func(string) string) (sandbox.Provider, error) {
	res, err := sandbox.ResourcesFromEnv(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	if res.PidsLimit > 0 {
		return sandbox.Provider{}, errors.New("agentsandbox: SANDBOX_PIDS cannot be honored: a pod's process limit is the kubelet's podPidsLimit on each node, which the API does not show; unset it")
	}
	pinned, err := sandbox.BoolFromEnv(getenv, "SANDBOX_REQUIRE_PINNED_IMAGES")
	if err != nil {
		return sandbox.Provider{}, err
	}
	or := func(name, def string) string {
		if v := getenv(name); v != "" {
			return v
		}
		return def
	}
	tokenFile := getenv("SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE")
	if tokenFile == "" {
		return sandbox.Provider{}, errors.New("agentsandbox: SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE is required: the file holding the token sandboxd checks")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: sandboxd token: %w", err)
	}
	var missing []string
	for _, name := range []string{"SANDBOX_AGENTSANDBOX_NAMESPACE", "SANDBOX_AGENTSANDBOX_WARM_POOL", "SANDBOX_AGENTSANDBOX_RUNTIME_CLASS", "SANDBOX_AGENTSANDBOX_IMAGE"} {
		if getenv(name) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: %s required", strings.Join(missing, ", "))
	}
	handlers := splitList(getenv("SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS"))
	if err := checkRunscHandlers(handlers); err != nil {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS: %w", err)
	}
	p, err := New(Config{
		APIServer:          or("SANDBOX_AGENTSANDBOX_API_SERVER", inClusterAPIServer),
		CAFile:             or("SANDBOX_AGENTSANDBOX_CA_FILE", inClusterCAFile),
		TokenFile:          or("SANDBOX_AGENTSANDBOX_TOKEN_FILE", inClusterTokenFile),
		Namespace:          getenv("SANDBOX_AGENTSANDBOX_NAMESPACE"),
		WarmPool:           getenv("SANDBOX_AGENTSANDBOX_WARM_POOL"),
		RuntimeClass:       getenv("SANDBOX_AGENTSANDBOX_RUNTIME_CLASS"),
		RunscHandlers:      handlers,
		Image:              getenv("SANDBOX_AGENTSANDBOX_IMAGE"),
		RequirePinnedImage: pinned,
		SandboxdToken:      strings.TrimSpace(string(token)),
		MemoryMB:           res.MemoryMB,
		CPUs:               res.CPUs,
		DiskMB:             res.DiskMB,
	})
	if err != nil {
		return sandbox.Provider{}, err
	}
	return sandbox.Provider{Sandbox: p, Resources: res}, nil
}

// splitList reads a comma list: unset or blank is none, and each entry is trimmed of
// surrounding spaces. An empty entry ("a,,b", a trailing comma) is kept, for the caller
// to refuse.
func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	for i, part := range parts {
		parts[i] = strings.TrimSpace(part)
	}
	return parts
}
