// Command sbom converts checked signed project-run bundles to CycloneDX 1.6 JSON,
// one BOM per run, a qualification verdict included where the platform signed one,
// and verifies the resulting mapping without creating another sandbox.
package main

import (
	"bytes"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/sandbox"
)

//go:embed page.html
var pageHTML string

//go:embed check.js
var receiptJS string

func main() {
	if err := execute(os.Args[1:], os.Stdout); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "sbom:", err)
		os.Exit(1)
	}
}

type pageRun struct {
	Title, File, Record, RequestDigest, Image, Tier, Floor, Grant, Start, End, Outcome, JSON string
	Anchor                                                                    string
	Line                                                                      uint64
	BundleURL, QualificationURL                                               string
	Files                                                                     []pageFile
	Steps                                                                     []pageStep
	Checks                                                                    []string
	Mappings                                                                  []mappingRow
	Verdict                                                                   *pageVerdict
}
type pageFile struct{ Path, Content, Hash string }
type pageStep struct {
	Command, Stdout, Stderr string
	Exit                    int32
	Duration                int64
	TimedOut                bool
}
type pageVerdict struct {
	Adapter, Scenario, Says, Verdict string
	Rules                            []pageRule
	Broken                           int
}
type pageRule struct {
	Name, Says, Detail string
	Held               bool
}
type mappingRow struct{ Field, Source string }
type pageData struct {
	Runs            []pageRun
	Verdicts        []pageRun
	Outside, Limits string
	Pages, Floor    string
	StepCount       int
	Contrast        *pageStep
	VMEgress        *pageStep
	VMUsed          bool
	RoomsUsed       string
	ReceiptScript   template.JS
	Images          []*imageBOM
	ReceiptImages   template.JS
}

// Bound uploaded BOMs and bundles before materializing their nested attachments.
// 32 MiB covers the RPC's request/result budgets plus base64 expansion in a BOM.
const inputLimit = 32 << 20

func readInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, inputLimit+1))
	if err != nil {
		return nil, err
	}
	if len(b) > inputLimit {
		return nil, fmt.Errorf("%s exceeds the 32 MiB input budget", path)
	}
	return b, nil
}

// parseLines is a comma-separated list of bundle line numbers.
func parseLines(s string) ([]int, error) {
	var out []int
	for _, part := range strings.Split(s, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 1 {
			return nil, fmt.Errorf("-qualified-runs: %q is not a line number", part)
		}
		out = append(out, n)
	}
	return out, nil
}

// referenced reads the digests a BOM states for its shared files, so a checker can tell
// whether a file beside the BOM is the one referenced; nothing here is trusted beyond
// choosing which file to read.
func referenced(raw []byte) (bundle, qualification string) {
	var doc struct {
		Metadata struct {
			Component struct {
				ExternalReferences []struct {
					Type, URL string
					Hashes    []struct{ Content string }
				} `json:"externalReferences"`
			}
		}
	}
	if json.Unmarshal(raw, &doc) != nil {
		return "", ""
	}
	for _, ref := range doc.Metadata.Component.ExternalReferences {
		if ref.Type != "attestation" || len(ref.Hashes) != 1 {
			continue
		}
		switch {
		case strings.HasSuffix(ref.URL, "bundle.jsonl"):
			bundle = ref.Hashes[0].Content
		case strings.HasSuffix(ref.URL, "qualification.jsonl"):
			qualification = ref.Hashes[0].Content
		}
	}
	return bundle, qualification
}

// sharedFor is what the checker has of a BOM's shared files: the files named
// explicitly, else a sibling bundle.jsonl or qualification.jsonl whose digest is the
// one the BOM references. A sibling with another digest is not that file and is left
// alone. No URL is fetched.
func sharedFor(raw []byte, dir, explicitBundle, explicitQualification string) (sharedFiles, error) {
	var have sharedFiles
	wantBundle, wantQualification := referenced(raw)
	read := func(explicit, name, want string) ([]byte, error) {
		if explicit != "" {
			return readInput(explicit)
		}
		b, err := readInput(filepath.Join(dir, name))
		if err != nil || digest(b) != want {
			return nil, nil
		}
		return b, nil
	}
	var err error
	if have.Bundle, err = read(explicitBundle, "bundle.jsonl", wantBundle); err != nil {
		return have, err
	}
	if have.Qualification, err = read(explicitQualification, "qualification.jsonl", wantQualification); err != nil {
		return have, err
	}
	// A sibling qualification file is only of use beside its bundle; an explicit one
	// without the bundle is the caller's mistake, which checkBOM reports.
	if have.Bundle == nil && explicitQualification == "" {
		have.Qualification = nil
	}
	return have, nil
}

func execute(args []string, out io.Writer) error {
	o := defaults()
	f := flag.NewFlagSet("sbom", flag.ContinueOnError)
	f.SetOutput(out)
	bundlePath := f.String("bundle", "../../docs/examples/sbom/bundle.jsonl", "signed single-run bundle")
	pubPath := f.String("pub", "../../docs/examples/sbom/harness.pub", "public key for generation")
	outDir := f.String("out", "../../docs/examples/sbom/", "output directory")
	checkPath := f.String("check", "", "check this BOM from its attached evidence")
	trustedPath := f.String("trusted-pub", "", "independently trusted public key, for -check")
	checkBundle := f.String("check-bundle", "", "for -check: the whole bundle the BOM references, to check the line's place in it; otherwise a sibling bundle.jsonl with the referenced digest is used when present")
	checkQualification := f.String("check-qualification", "", "for -check: the whole qualification file the BOM references, to run the checks across runs; otherwise a sibling qualification.jsonl with the referenced digest is used when present")
	outsidePath := f.String("outside", "", "optional unsigned comparison transcript; defaults to outside-plimsoll.txt beside the bundle when present")
	imagePath := f.String("image-bom", "", "optional local image SBOM; otherwise use its digest-named sibling when present")
	qualifiedBundle := f.String("qualified-bundle", "../../docs/examples/adapter/bundle.jsonl", "a bundle whose runs the platform's qualification statements speak for; empty for none")
	qualifiedPub := f.String("qualified-pub", "../../docs/examples/adapter/harness.pub", "that bundle's public key")
	qualificationPath := f.String("qualification", "../../docs/examples/adapter/qualification.jsonl", "its qualification statements, one DSSE envelope per line")
	qualifiedRuns := f.String("qualified-runs", "10,4", "the lines of that bundle to write verdict BOMs for")
	qualifiedPages := f.String("qualified-pages", "https://plimsollmark.github.io/plimsoll/examples/adapter/", "absolute base URL ending in / where that bundle and qualification file are published")
	line := f.Int("line", 0, "write only the BOM of this line of -bundle, with its checks, and no page: for a caller that converts runs as they happen; needs -out and -pages")
	f.StringVar(&o.Name, "name", o.Name, "program display name, unsigned")
	f.StringVar(&o.ImageName, "image-name", o.ImageName, "image display name, unsigned")
	f.StringVar(&o.Operator, "operator", o.Operator, "self-assessor display name, unsigned")
	f.StringVar(&o.Pages, "pages", o.Pages, "absolute base URL ending in / for references")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments")
	}
	if *checkPath != "" {
		raw, err := readInput(*checkPath)
		if err != nil {
			return err
		}
		var trusted []byte
		if *trustedPath != "" {
			trusted, err = readInput(*trustedPath)
			if err != nil {
				return err
			}
		}
		var doc struct{ Components []struct{ Version string } }
		if err := json.Unmarshal(raw, &doc); err != nil {
			return err
		}
		if len(doc.Components) != 1 {
			return fmt.Errorf("expected one image component")
		}
		image, err := readImageBOM(*imagePath, filepath.Dir(*checkPath), doc.Components[0].Version)
		if err != nil {
			return err
		}
		have, err := sharedFor(raw, filepath.Dir(*checkPath), *checkBundle, *checkQualification)
		if err != nil {
			return err
		}
		lines, err := checkBOM(raw, trusted, image, have)
		if err != nil {
			return err
		}
		for _, line := range lines {
			fmt.Fprintln(out, line)
		}
		return nil
	}
	if *trustedPath != "" || *checkBundle != "" || *checkQualification != "" {
		return fmt.Errorf("-trusted-pub, -check-bundle and -check-qualification require -check")
	}
	if *line != 0 {
		given := map[string]bool{}
		f.Visit(func(fl *flag.Flag) { given[fl.Name] = true })
		if !given["out"] || !given["pages"] {
			return fmt.Errorf("-line needs -out and -pages: the defaults are the published example's")
		}
		for _, name := range []string{"qualified-bundle", "qualified-pub", "qualification", "qualified-runs", "qualified-pages", "outside"} {
			if given[name] {
				return fmt.Errorf("-%s does not apply to -line", name)
			}
		}
	}
	if err := o.validate(); err != nil {
		return err
	}
	bundle, err := readInput(*bundlePath)
	if err != nil {
		return err
	}
	pem, err := readInput(*pubPath)
	if err != nil {
		return err
	}
	if *line != 0 {
		return writeOne(bundle, pem, *line, o, *outDir, *imagePath, filepath.Dir(*bundlePath), out)
	}
	runs, err := sources(bundle, pem, o.Pages)
	if err != nil {
		return err
	}
	if *qualifiedBundle != "" {
		qb, err := readInput(*qualifiedBundle)
		if err != nil {
			return err
		}
		qp, err := readInput(*qualifiedPub)
		if err != nil {
			return err
		}
		qs, err := readInput(*qualificationPath)
		if err != nil {
			return err
		}
		lines, err := parseLines(*qualifiedRuns)
		if err != nil {
			return err
		}
		qo := o
		qo.Pages = *qualifiedPages
		if err := qo.validate(); err != nil {
			return fmt.Errorf("-qualified-pages: %w", err)
		}
		verdicts, err := qualified(qb, qp, qs, *qualifiedPages, lines)
		if err != nil {
			return err
		}
		runs = append(runs, verdicts...)
	}
	data := pageData{Limits: limits, Pages: o.Pages, Floor: runs[0].Request.GetMinimumIsolation(), ReceiptScript: template.JS(receiptJS)}
	if data.Floor == "" {
		data.Floor = "process"
	}
	transcript := *outsidePath
	if transcript == "" {
		transcript = filepath.Join(filepath.Dir(*bundlePath), "outside-plimsoll.txt")
	}
	outside, err := readInput(transcript)
	var pairedRecord, pairedStep string
	if err == nil {
		data.Outside = string(outside)
		pairedRecord, pairedStep, err = transcriptPair(outside, runs)
		if err != nil {
			return err
		}
	} else if *outsidePath != "" || !os.IsNotExist(err) {
		return err
	}
	outputs := map[string][]byte{}
	plain := 0
	for _, s := range runs {
		ro := o
		ro.Name = s.displayName(o.Name)
		manifest, _, _ := imageDigest(s.Record)
		ro.ImageBOM, err = readImageBOM(*imagePath, filepath.Dir(*bundlePath), "sha256:"+manifest)
		if err != nil {
			return err
		}
		if ro.ImageBOM != nil {
			seen := false
			for _, image := range data.Images {
				if image.File == ro.ImageBOM.File {
					seen = true
				}
			}
			if !seen {
				data.Images = append(data.Images, ro.ImageBOM)
			}
		}
		raw, err := buildBOM(s, ro)
		if err != nil {
			return err
		}
		have := sharedFiles{Bundle: s.Shared.bundle, Qualification: s.Shared.qualification}
		checks, err := checkBOM(raw, s.PEM, ro.ImageBOM, have)
		if err != nil {
			return fmt.Errorf("generated BOM refused: %w", err)
		}
		tamper, err := tamperChecks(raw, s.PEM, ro.ImageBOM, have)
		if err != nil {
			return err
		}
		name := "run-" + s.Record.SHA256[:12] + ".cdx.json"
		if _, exists := outputs[name]; exists {
			return fmt.Errorf("duplicate run filename %s", name)
		}
		outputs[name] = raw
		p := pageRun{File: name, Anchor: "run-" + s.Record.SHA256[:12], Record: s.Record.SHA256, RequestDigest: s.Record.RequestSHA256, Image: s.Record.SoftwareIdentity, Tier: s.Record.Isolation, Floor: s.Request.GetMinimumIsolation(), Grant: s.grant(), Line: s.Line.Index, BundleURL: s.Shared.Pages + "bundle.jsonl", Start: timestamp(s.Record.Started.UnixMilli()), End: timestamp(s.Record.Ended.UnixMilli()), Outcome: outcomeText(s), JSON: string(raw), Checks: append(checks, tamper...), Mappings: mappingRows(raw)}
		if p.Image == "" {
			p.Image = s.Record.Environment
		}
		if p.Floor == "" {
			p.Floor = "process"
		}
		if s.Verdict != nil {
			v := &pageVerdict{Adapter: s.Verdict.Adapter.Path, Scenario: s.Verdict.Evidence.Scenario.Name, Says: s.Verdict.Evidence.Scenario.Says, Verdict: s.Verdict.Verdict}
			for _, oc := range s.Verdict.Rules {
				v.Rules = append(v.Rules, pageRule{Name: ruleName(oc.Rule), Says: ruleSays(oc.Rule), Held: oc.Held, Detail: oc.Detail})
				if !oc.Held {
					v.Broken++
				}
			}
			p.Verdict = v
			p.QualificationURL = s.Shared.Pages + "qualification.jsonl"
			switch {
			case v.Verdict == "pass":
				p.Title = fmt.Sprintf("An adapter that passed all %d rules", len(v.Rules))
			case v.Broken == 1:
				p.Title = "An adapter that broke one rule"
			default:
				p.Title = fmt.Sprintf("An adapter that broke %d rules", v.Broken)
			}
		} else {
			vm := s.Record.Isolation == sandbox.IsolationVM.String()
			egress := false
			for _, step := range s.Response.GetProject().GetSteps() {
				if pairedStep != "" && step.GetCommand() == pairedStep {
					egress = true
				}
			}
			switch {
			case vm && egress:
				p.Title = "The egress attempt, in a VM"
			case vm:
				p.Title = "The same request, in a VM"
			case egress:
				p.Title = "The run with an egress attempt"
			default:
				plain++
				p.Title = "The run"
				if plain > 1 {
					p.Title = fmt.Sprintf("Run %d", plain)
				}
			}
			if vm {
				data.VMUsed = true
			}
		}
		for _, file := range s.Request.GetProject().GetFiles() {
			p.Files = append(p.Files, pageFile{file.GetPath(), file.GetContent(), digest([]byte(file.GetContent()))})
		}
		for _, step := range s.Response.GetProject().GetSteps() {
			row := pageStep{step.GetCommand(), string(step.GetStdout()), string(step.GetStderr()), step.GetExitCode(), step.GetDurationMs(), step.GetTimedOut()}
			p.Steps = append(p.Steps, row)
			data.StepCount++
			if s.Record.SHA256 == pairedRecord && row.Command == pairedStep && data.Outside != "" {
				data.Contrast = &row
			}
			if pairedStep != "" && row.Command == pairedStep && s.Record.Isolation == sandbox.IsolationVM.String() {
				data.VMEgress = &row
			}
		}
		if s.Verdict != nil {
			data.Verdicts = append(data.Verdicts, p)
		}
		data.Runs = append(data.Runs, p)
	}
	if len(data.Verdicts) != 0 {
		data.Limits += verdictLimits
	}
	tiers := map[string]bool{}
	for _, s := range runs {
		tiers[s.Record.Isolation] = true
	}
	data.RoomsUsed = []string{"none was used", "one was used", "two were used", "three were used", "all four were used"}[min(len(tiers), 4)]
	imageBytes := map[string]string{}
	for _, image := range data.Images {
		imageBytes[image.File] = base64.StdEncoding.EncodeToString(image.raw)
	}
	imageJSON, err := json.Marshal(imageBytes)
	if err != nil {
		return err
	}
	data.ReceiptImages = template.JS(imageJSON)
	tmpl, err := template.New("page").Parse(pageHTML)
	if err != nil {
		return err
	}
	var page bytes.Buffer
	if err := tmpl.Execute(&page, data); err != nil {
		return err
	}
	outputs["index.html"] = page.Bytes()
	// No output is created until every source and every resulting BOM has passed.
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		return err
	}
	for _, image := range data.Images {
		path := filepath.Join(*outDir, image.File)
		existing, err := readInput(path)
		if err == nil {
			if !bytes.Equal(existing, image.raw) {
				return fmt.Errorf("refusing to overwrite image evidence %s", path)
			}
			continue
		}
		if !os.IsNotExist(err) {
			return err
		}
		if err := os.WriteFile(path, image.raw, 0644); err != nil {
			return err
		}
	}
	for _, p := range data.Runs {
		if err := os.WriteFile(filepath.Join(*outDir, p.File), outputs[p.File], 0644); err != nil {
			return err
		}
		fmt.Fprintln(out, "wrote", p.File)
	}
	if err := os.WriteFile(filepath.Join(*outDir, "index.html"), outputs["index.html"], 0644); err != nil {
		return err
	}
	fmt.Fprintf(out, "verified %d single runs (%d with a qualification verdict); wrote index.html; schema and integrity checks passed; altered evidence refused\n", len(runs), len(data.Verdicts))
	return nil
}

// writeOne writes the BOM of line n of a verified bundle and prints the checks it
// passed, the refusals of altered copies included. The other lines need not be runs it
// can map: only line n becomes a BOM. The image's own BOM is found as the full run
// finds it (explicit, or its digest-named sibling in dir). A caller that converts runs as they happen passes
// the signed file up to that run's checkpoint as the bundle, so the digest the BOM
// cites never moves when later runs are appended.
func writeOne(bundle, pem []byte, n int, o options, outDir, imagePath, dir string, out io.Writer) error {
	pub, entries, err := verifiedBundle(bundle, pem)
	if err != nil {
		return err
	}
	// verifiedBundle followed the links, so entries[i] is line i+1.
	if n < 1 || n > len(entries) || len(entries[n-1].Request) == 0 {
		return fmt.Errorf("-line %d: the bundle's line %d is not a run", n, n)
	}
	s, err := lineSource(attest.NewVerifier(pub), entries[n-1])
	if err != nil {
		return err
	}
	s.PEM = pem
	s.Shared = shared{Pages: o.Pages, BundleSHA256: digest(bundle), bundle: bundle}
	o.Name = s.displayName(o.Name)
	manifest, _, _ := imageDigest(s.Record)
	if o.ImageBOM, err = readImageBOM(imagePath, dir, "sha256:"+manifest); err != nil {
		return err
	}
	raw, err := buildBOM(s, o)
	if err != nil {
		return err
	}
	have := sharedFiles{Bundle: bundle}
	checks, err := checkBOM(raw, pem, o.ImageBOM, have)
	if err != nil {
		return fmt.Errorf("generated BOM refused: %w", err)
	}
	tamper, err := tamperChecks(raw, pem, o.ImageBOM, have)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return err
	}
	name := "run-" + s.Record.SHA256[:12] + ".cdx.json"
	if err := os.WriteFile(filepath.Join(outDir, name), raw, 0644); err != nil {
		return err
	}
	fmt.Fprintln(out, "wrote", name)
	for _, c := range append(checks, tamper...) {
		fmt.Fprintln(out, c)
	}
	return nil
}

func transcriptPair(raw []byte, runs []source) (string, string, error) {
	lines := strings.SplitN(string(raw), "\n", 3)
	if len(lines) < 3 || !strings.HasPrefix(lines[0], "# record: ") || !strings.HasPrefix(lines[1], "# step: ") {
		return "", "", fmt.Errorf("outside transcript needs # record: and # step: headers")
	}
	id, command := strings.TrimPrefix(lines[0], "# record: "), strings.TrimPrefix(lines[1], "# step: ")
	for _, s := range runs {
		if s.Record.SHA256 != id {
			continue
		}
		count := 0
		for _, step := range s.Response.GetProject().GetSteps() {
			if step.GetCommand() == command {
				count++
			}
		}
		if count != 1 {
			return "", "", fmt.Errorf("outside transcript step must match exactly one recorded command")
		}
		return id, command, nil
	}
	return "", "", fmt.Errorf("outside transcript record is not in the bundle")
}
