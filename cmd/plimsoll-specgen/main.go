// Command plimsoll-specgen derives a host-API grant description from an OpenAPI
// 3.x document (Sluice "spec-import"). It emits the three things an operator otherwise
// hand-writes and must keep in sync: the grant's `allow` route list, the typed JS
// `preamble` SDK, and the model-facing tool description a gateway shows the agent.
// Generating all three from the one spec lets a consumer delete the hand-maintained
// copies. When the spec designates a concrete health/readiness/capacity GET, it also
// emits the optional `health_check` backpressure probe (see docs/examples/specgen).
//
// It is offline and metadata-only: it never fetches the spec's server, embeds no
// credential, and is byte-deterministic, so it fits a build step and the outputs can
// be committed and diffed.
//
// Usage:
//
//	plimsoll-specgen [flags] [spec.json]
//	cat spec.json | plimsoll-specgen -emit description
//
// Flags:
//
//	-global  JS global the typed SDK attaches to (default "host")
//	-emit    all | allow | catalog | preamble | description | health | json (default "all", stdout)
//	-outdir  write allow.json, preamble.js, description.txt (+ health_check.txt) into this dir
//
// The `catalog` emit is the full route list for a profile's `catalog` field, which
// Prospector reads to name an ungranted batch route worth adding; `allow` is the same
// list, meant as the starting point an operator trims to the routes it actually grants.
// The `health` emit is the "GET /path" line for a profile's `health_check` backpressure
// probe, derived from an operation marked x-plimsoll-health-check or a well-known
// health/readiness/capacity endpoint name (empty, with a stderr note, if none/ambiguous).
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/specgen"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-specgen:", err)
		os.Exit(1)
	}
}

func run() error {
	global := flag.String("global", "host", "JS global the typed SDK attaches to")
	emit := flag.String("emit", "all", "all | allow | catalog | preamble | description | health | json")
	outdir := flag.String("outdir", "", "write generated profile artifacts into this dir")
	flag.Parse()

	var (
		in     io.Reader = os.Stdin
		inName           = "stdin"
	)
	if arg := flag.Arg(0); arg != "" {
		f, err := os.Open(arg)
		if err != nil {
			return fmt.Errorf("open spec: %w", err)
		}
		defer f.Close()
		in, inName = f, arg
	}
	spec, err := io.ReadAll(in)
	if err != nil {
		return fmt.Errorf("read %s: %w", inName, err)
	}

	res, err := specgen.Generate(spec, specgen.Options{Global: *global})
	if err != nil {
		return err
	}
	// Surface anything the grant model can't represent, so the omission is never silent.
	for _, s := range res.Skipped {
		fmt.Fprintf(os.Stderr, "plimsoll-specgen: skipped %s %s (%s)\n", s.Method, s.Path, s.Reason)
	}
	// Surface an unresolved health route the same way: the caller learns their spec has
	// candidates but needs to disambiguate, rather than silently getting no health_check.
	if res.HealthNote != "" {
		fmt.Fprintf(os.Stderr, "plimsoll-specgen: health_check not set: %s\n", res.HealthNote)
	}

	if *outdir != "" {
		return writeDir(*outdir, res)
	}

	switch *emit {
	case "allow", "catalog":
		// Identical rendering today: the generator's full route list is both the
		// starting point for `allow` and the complete `catalog` Prospector reads.
		return printAllowJSON(os.Stdout, res)
	case "preamble":
		fmt.Fprint(os.Stdout, res.Preamble)
	case "description":
		fmt.Fprint(os.Stdout, res.Description)
	case "health":
		// A bare line so it composes in a script; empty (with the stderr note above) when
		// the spec declares no unambiguous health route.
		if res.HealthCheck != "" {
			fmt.Fprintln(os.Stdout, res.HealthCheck)
		}
	case "json":
		return printBundleJSON(os.Stdout, res)
	case "all":
		fmt.Fprintf(os.Stdout, "=== allow (paste into the grants profile's \"allow\") ===\n")
		if err := printAllowJSON(os.Stdout, res); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "\n=== preamble (the profile's preamble / preamble_file) ===\n%s", res.Preamble)
		fmt.Fprintf(os.Stdout, "\n=== description (the model-facing tool description) ===\n%s", res.Description)
		if res.HealthCheck != "" {
			fmt.Fprintf(os.Stdout, "\n=== health_check (the profile's health_check backpressure probe) ===\n%s\n", res.HealthCheck)
		}
	default:
		return fmt.Errorf("unknown -emit %q (want all|allow|catalog|preamble|description|health|json)", *emit)
	}
	return nil
}

// printAllowJSON writes the allow list as the JSON array of "METHOD /path" strings a
// grants profile's `allow` field expects.
func printAllowJSON(w io.Writer, res *specgen.Result) error {
	b, err := json.MarshalIndent(res.AllowStrings(), "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// bundle is the -emit json shape: everything a programmatic consumer needs from one call.
type bundle struct {
	Title       string   `json:"title"`
	Version     string   `json:"version"`
	Global      string   `json:"global"`
	Allow       []string `json:"allow"`
	Preamble    string   `json:"preamble"`
	Description string   `json:"description"`
	HealthCheck string   `json:"health_check,omitempty"`
	HealthNote  string   `json:"health_note,omitempty"`
}

func printBundleJSON(w io.Writer, res *specgen.Result) error {
	b, err := json.MarshalIndent(bundle{
		Title:       res.Title,
		Version:     res.Version,
		Global:      res.Global,
		Allow:       res.AllowStrings(),
		Preamble:    res.Preamble,
		Description: res.Description,
		HealthCheck: res.HealthCheck,
		HealthNote:  res.HealthNote,
	}, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(b))
	return err
}

// writeDir is the build-step mode: emit the artifacts as separate files a consumer
// commits and wires into its grant profile and MCP tool description.
func writeDir(dir string, res *specgen.Result) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	allow, err := json.MarshalIndent(res.AllowStrings(), "", "  ")
	if err != nil {
		return err
	}
	files := map[string][]byte{
		"allow.json":      append(allow, '\n'),
		"preamble.js":     []byte(res.Preamble),
		"description.txt": []byte(res.Description),
	}
	// health_check.txt is written only when a health route was resolved, so its presence
	// is itself the signal that the spec designates one.
	if res.HealthCheck != "" {
		files["health_check.txt"] = []byte(res.HealthCheck + "\n")
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), files[name], 0o644); err != nil {
			return fmt.Errorf("write %s: %w", name, err)
		}
	}
	if res.HealthCheck == "" {
		// Outdirs are normally regenerated in place. Remove a previously generated probe
		// when the route disappears or becomes ambiguous; otherwise the stale file would
		// silently keep authority that the current spec no longer designates.
		if err := os.Remove(filepath.Join(dir, "health_check.txt")); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale health_check.txt: %w", err)
		}
	}
	fmt.Fprintf(os.Stderr, "plimsoll-specgen: wrote %s to %s\n", strings.Join(names, ", "), dir)
	return nil
}
