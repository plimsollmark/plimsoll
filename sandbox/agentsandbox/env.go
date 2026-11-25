package agentsandbox

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/settings"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// The service account files a pod is given, the defaults for plimsolld running in the
// cluster, which it must to reach the pods' addresses.
// FromEnv builds the provider from SANDBOX_AGENTSANDBOX_* and the shared variables, as
// plimsolld does (each is a setting in internal/settings, which -h is printed from). The API
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
	pinned, err := settings.RequirePinnedImages.Get(getenv)
	if err != nil {
		return sandbox.Provider{}, err
	}
	tokenFile := settings.AgentsandboxSandboxdTokenFile.Get(getenv)
	if tokenFile == "" {
		return sandbox.Provider{}, errors.New("agentsandbox: SANDBOX_AGENTSANDBOX_SANDBOXD_TOKEN_FILE is required: the file holding the token sandboxd checks")
	}
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: sandboxd token: %w", err)
	}
	var missing []string
	for _, s := range []*settings.Text{settings.AgentsandboxNamespace, settings.AgentsandboxWarmPool, settings.AgentsandboxRuntimeClass, settings.AgentsandboxImage, settings.AgentsandboxSandboxdCAFile, settings.AgentsandboxSandboxdTrustDomain} {
		if s.Get(getenv) == "" {
			missing = append(missing, s.Name)
		}
	}
	if len(missing) > 0 {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: %s required", strings.Join(missing, ", "))
	}
	handlers := splitList(settings.AgentsandboxRunscHandlers.Get(getenv))
	if err := checkRunscHandlers(handlers); err != nil {
		return sandbox.Provider{}, fmt.Errorf("agentsandbox: SANDBOX_AGENTSANDBOX_RUNSC_HANDLERS: %w", err)
	}
	p, err := New(Config{
		APIServer:           settings.AgentsandboxAPIServer.Get(getenv), // default: the pod's own service account
		CAFile:              settings.AgentsandboxCAFile.Get(getenv),
		TokenFile:           settings.AgentsandboxTokenFile.Get(getenv),
		Namespace:           settings.AgentsandboxNamespace.Get(getenv),
		WarmPool:            settings.AgentsandboxWarmPool.Get(getenv),
		RuntimeClass:        settings.AgentsandboxRuntimeClass.Get(getenv),
		RunscHandlers:       handlers,
		Image:               settings.AgentsandboxImage.Get(getenv),
		RequirePinnedImage:  pinned,
		SandboxdToken:       strings.TrimSpace(string(token)),
		SandboxdCAFile:      settings.AgentsandboxSandboxdCAFile.Get(getenv),
		SandboxdServerName:  settings.AgentsandboxSandboxdServerName.Get(getenv),
		SandboxdTrustDomain: settings.AgentsandboxSandboxdTrustDomain.Get(getenv),
		MemoryMB:            res.MemoryMB,
		CPUs:                res.CPUs,
		DiskMB:              res.DiskMB,
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
