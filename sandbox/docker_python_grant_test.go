package sandbox

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// TestDockerGrantedPythonReachesTheBroker: on docker, a granted project's Python step
// reaches the grant's API through plimsoll_host (HostClientPython), the standard library
// over HOST_API_SOCKET and nothing else, both as a plain script with the module's
// directory on its path and in GrantedCellProject's form (the cell's final expression
// printed). The broker adds the credential, refuses a route the grant does not list, and
// the run's trace holds the route template only. This is the measurement behind
// PythonGrantProviders' "docker"; openshell's is the same socket through its relay, not
// run here.
func TestDockerGrantedPythonReachesTheBroker(t *testing.T) {
	t.Parallel()
	d := testDocker()
	d.ProjectImage = "plimsoll/sandbox-python:latest"
	requireProjectImage(t, d)

	const token = "python-grant-bearer-6c1e"
	var mu sync.Mutex
	var paths, auths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		paths = append(paths, r.Method+" "+r.URL.Path)
		auths = append(auths, r.Header.Get("Authorization"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"path":"`+r.URL.Path+`","got":`+string(orJSONNull(body))+`}`)
	}))
	defer upstream.Close()
	grant := &HostAPIGrant{
		BaseURL: upstream.URL,
		Allow:   []HostRoute{{Method: "GET", Path: "/v1/lights/*"}, {Method: "POST", Path: "/v1/lights/*/on"}},
		Minter:  StaticToken(token),
	}
	script := `import sys, os
sys.path.insert(1, "` + HostClientPythonDir + `")
import plimsoll_host
print("GET", plimsoll_host.get("/v1/lights/kitchen")["path"])
print("POST", plimsoll_host.post("/v1/lights/kitchen/on", {"level": 40})["got"])
try:
    plimsoll_host.get("/v1/doors/front")
except plimsoll_host.HostAPIError as e:
    print("REFUSED", e.status)
print("TOKEN-IN-ENV", any("` + token + `" in v for v in os.environ.values()))
`
	cellFiles, cellStep := GrantedCellProject(CellRequest{Language: LanguagePython, Code: "import plimsoll_host\nplimsoll_host.get('/v1/lights/hall')['path']"})
	files := append([]File{{Path: HostClientPythonPath, Content: HostClientPython}, {Path: "main.py", Content: script}}, cellFiles...)
	res, err := d.RunProject(context.Background(), ProjectRequest{Files: dedupeFiles(files), Steps: []string{"python3 main.py", cellStep}, Grant: grant})
	if err != nil {
		t.Fatalf("RunProject: %v", err)
	}
	if res.Outcome != ProjectOutcomeCompleted || len(res.Steps) != 2 {
		t.Fatalf("outcome %v (%q), steps %+v", res.Outcome, res.Detail, res.Steps)
	}
	out := res.Steps[0].Stdout
	for _, want := range []string{"GET /v1/lights/kitchen", "POST {'level': 40}", "REFUSED 403", "TOKEN-IN-ENV False"} {
		if !strings.Contains(out, want) {
			t.Errorf("script stdout lacks %q: %q (stderr %q)", want, out, res.Steps[0].Stderr)
		}
	}
	if got := res.Steps[1].Stdout; res.Steps[1].ExitCode != 0 || strings.TrimSpace(got) != "'/v1/lights/hall'" {
		t.Errorf("granted cell: exit %d stdout %q stderr %q, want its final value '/v1/lights/hall'", res.Steps[1].ExitCode, got, res.Steps[1].Stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 3 {
		t.Errorf("upstream saw %v, want the three allowed calls only", paths)
	}
	for _, a := range auths {
		if a != "Bearer "+token {
			t.Errorf("upstream Authorization %q, want the broker's", a)
		}
	}
	js, _ := json.Marshal(res.CallTrace)
	for _, leak := range []string{"kitchen", "hall", "doors", token} {
		if strings.Contains(string(js), leak) {
			t.Errorf("the trace holds %q: %s", leak, js)
		}
	}
}

// orJSONNull is b, or the JSON null when b is empty.
func orJSONNull(b []byte) []byte {
	if len(b) == 0 {
		return []byte("null")
	}
	return b
}

// dedupeFiles keeps the first file of each path: GrantedCellProject adds the module the
// script already carries.
func dedupeFiles(files []File) []File {
	seen := map[string]bool{}
	var out []File
	for _, f := range files {
		if !seen[f.Path] {
			seen[f.Path] = true
			out = append(out, f)
		}
	}
	return out
}
