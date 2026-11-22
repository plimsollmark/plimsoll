package sandbox

import (
	"strings"
	"testing"
)

// The providers PythonGrantProviders names are the ones whose granted project runs hand
// every step the socket: docker (grantGuestEnv, measured by
// TestDockerGrantedPythonReachesTheBroker) and openshell (its own test). The guard
// providers, whose granted Node steps reach the broker through a preloaded client only,
// are left out, and so are the providers without grants.
func TestPythonGrantProviders(t *testing.T) {
	t.Parallel()
	if !PythonCarriesGrant((&DockerSandbox{}).Name()) {
		t.Errorf("docker is not in %v", PythonGrantProviders)
	}
	for _, name := range []string{(&E2B{}).Name(), (&DockerCloud{}).Name(), "wasm", "agentsandbox", "wslc", ""} {
		if PythonCarriesGrant(name) {
			t.Errorf("%q is in %v, but its Python steps get no route to the broker", name, PythonGrantProviders)
		}
	}
	if (&DockerSandbox{}).grantGuestEnv(&HostAPIGrant{})[0] != HostAPISocketEnv+"="+containerSocketPath {
		t.Error("docker's granted guest environment no longer starts with the socket")
	}
}

// GrantedCellProject keeps a JavaScript cell's form exactly (the provider preloads the
// host client into Node), and gives a Python cell the module and its directory on the
// runner's path; the module is the one source the clients' copies are generated from.
func TestGrantedCellProject(t *testing.T) {
	t.Parallel()
	js := CellRequest{Language: LanguageJavaScript, Code: "1"}
	f1, s1 := FreshCellProject(js)
	f2, s2 := GrantedCellProject(js)
	if s1 != s2 || len(f1) != len(f2) {
		t.Fatalf("a granted JavaScript cell differs from a fresh one: %q %q", s1, s2)
	}
	files, step := GrantedCellProject(CellRequest{Language: LanguagePython, Code: "1"})
	var module bool
	for _, f := range files {
		module = module || (f.Path == HostClientPythonPath && f.Content == HostClientPython)
	}
	if !module || !strings.Contains(step, HostClientPythonDir) || !strings.HasPrefix(step, "python3 -I ") {
		t.Fatalf("a granted Python cell: module %v, step %q", module, step)
	}
	for _, c := range HostClientPython {
		if c > 0x7e || (c < 0x20 && c != '\n') {
			t.Fatalf("plimsoll_host.py holds %q: the clients carry it as an ASCII string literal", c)
		}
	}
}
