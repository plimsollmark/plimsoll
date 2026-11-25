package agentsandbox

import (
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestSandboxdFlagsAreThePinnedSandboxds holds the read-back's list of sandboxd's flags to
// the TLS terminator's (docker/sandboxdtls/main.go, a program of its own that cannot
// import this one) and both to the commit the image builds sandboxd from
// (docker/agentsandbox.Dockerfile), so moving the pin fails here until both lists are read
// again from the new sandboxd's -h. Each flag on the list passes the read-back.
func TestSandboxdFlagsAreThePinnedSandboxds(t *testing.T) {
	root := filepath.Join("..", "..", "docker")
	dockerfile, err := os.ReadFile(filepath.Join(root, "agentsandbox.Dockerfile"))
	if err != nil {
		t.Fatal(err)
	}
	pin := regexp.MustCompile(`(?m)^ARG AGENT_SANDBOX_COMMIT=([0-9a-f]{40})$`).FindSubmatch(dockerfile)
	if pin == nil || string(pin[1]) != sandboxdFlagsCommit {
		t.Fatalf("the image builds sandboxd from %q; sandboxdFlags was read from %s: read the new sandboxd's -h, then update both lists and both commits", pin, sandboxdFlagsCommit)
	}
	front, err := os.ReadFile(filepath.Join(root, "sandboxdtls", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(front), `const sandboxdFlagsCommit = "`+sandboxdFlagsCommit+`"`) {
		t.Fatal("the TLS terminator's sandboxdFlagsCommit is not the read-back's")
	}
	body := regexp.MustCompile(`(?s)var sandboxdFlags = map\[string\]bool\{(.*?)\n\}`).FindSubmatch(front)
	if body == nil {
		t.Fatal("the TLS terminator has no sandboxdFlags map literal")
	}
	var theirs []string
	for _, m := range regexp.MustCompile(`"([a-z0-9-]+)": true`).FindAllSubmatch(body[1], -1) {
		theirs = append(theirs, string(m[1]))
	}
	slices.Sort(theirs)
	if ours := slices.Sorted(maps.Keys(sandboxdFlags)); !slices.Equal(ours, theirs) {
		t.Fatalf("the read-back's sandboxd flags %q are not the TLS terminator's %q", ours, theirs)
	}

	p := &Provider{tokenDigest: digestOf("plimsoll")}
	good := goodSpec(p.tokenDigest).Containers[0].Command[1:]
	if err := p.checkSandboxdArgs(good); err != nil {
		t.Fatalf("the good arguments refused: %v", err)
	}
	for name := range sandboxdFlags {
		switch name {
		case "auth-token-sha256", "auth-token-file", "listen-host", "grpc-port":
			continue // each has a rule of its own
		}
		for _, form := range []string{"--", "-"} {
			if err := p.checkSandboxdArgs(append(slices.Clone(good), form+name+"=x")); err != nil {
				t.Errorf("the pinned sandboxd's flag %s%s refused: %v", form, name, err)
			}
		}
	}
}
