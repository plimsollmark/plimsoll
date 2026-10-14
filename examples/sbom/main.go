// Command sbom converts a checked signed project-run bundle to CycloneDX 1.6
// JSON and verifies the resulting mapping without creating another sandbox.
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
	"strings"
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
	Title, File, Record, Image, Tier, Start, End, Outcome, JSON string
	Anchor                                                      string
	Files                                                       []pageFile
	Steps                                                       []pageStep
	Checks                                                      []string
	Mappings                                                    []mappingRow
}
type pageFile struct{ Path, Content, Hash string }
type pageStep struct {
	Command, Stdout, Stderr string
	Exit                    int32
	Duration                int64
	TimedOut                bool
}
type mappingRow struct{ Field, Source string }
type pageData struct {
	Runs            []pageRun
	Outside, Limits string
	Pages           string
	StepCount       int
	Contrast        *pageStep
	ReceiptScript   template.JS
	ReceiptBOMs     template.JS
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

func execute(args []string, out io.Writer) error {
	o := defaults()
	f := flag.NewFlagSet("sbom", flag.ContinueOnError)
	f.SetOutput(out)
	bundlePath := f.String("bundle", "../../docs/examples/sbom/bundle.jsonl", "signed single-run bundle")
	pubPath := f.String("pub", "../../docs/examples/sbom/harness.pub", "public key for generation")
	outDir := f.String("out", "../../docs/examples/sbom/", "output directory")
	checkPath := f.String("check", "", "check this BOM from its attached evidence")
	trustedPath := f.String("trusted-pub", "", "independently trusted public key, for -check")
	outsidePath := f.String("outside", "", "optional unsigned comparison transcript; defaults to outside-plimsoll.txt beside the bundle when present")
	imagePath := f.String("image-bom", "", "optional local image SBOM; otherwise use its digest-named sibling when present")
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
		lines, err := checkBOM(raw, trusted, image)
		if err != nil {
			return err
		}
		for _, line := range lines {
			fmt.Fprintln(out, line)
		}
		return nil
	}
	if *trustedPath != "" {
		return fmt.Errorf("-trusted-pub requires -check")
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
	runs, err := sources(bundle, pem)
	if err != nil {
		return err
	}
	data := pageData{Limits: limits, Pages: o.Pages, ReceiptScript: template.JS(receiptJS)}
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
	var inline []json.RawMessage
	for i, s := range runs {
		o.ImageBOM, err = readImageBOM(*imagePath, filepath.Dir(*bundlePath), strings.Split(s.Record.SoftwareIdentity, "@")[1])
		if err != nil {
			return err
		}
		if o.ImageBOM != nil {
			seen := false
			for _, image := range data.Images {
				if image.File == o.ImageBOM.File {
					seen = true
				}
			}
			if !seen {
				data.Images = append(data.Images, o.ImageBOM)
			}
		}
		raw, err := buildBOM(s, bundle, pem, o)
		if err != nil {
			return err
		}
		checks, err := checkBOM(raw, pem, o.ImageBOM)
		if err != nil {
			return fmt.Errorf("generated BOM refused: %w", err)
		}
		tamper, err := tamperChecks(raw, pem, o.ImageBOM)
		if err != nil {
			return err
		}
		name := "run-" + s.Record.SHA256[:12] + ".cdx.json"
		if _, exists := outputs[name]; exists {
			return fmt.Errorf("duplicate run filename %s", name)
		}
		outputs[name] = raw
		inline = append(inline, raw)
		title := fmt.Sprintf("Run %d", i+1)
		if i == 0 {
			title = "The run"
		}
		p := pageRun{Title: title, Anchor: "run-" + s.Record.SHA256[:12], File: name, Record: s.Record.SHA256, Image: s.Record.SoftwareIdentity, Tier: s.Record.Isolation, Start: timestamp(s.Record.Started.UnixMilli()), End: timestamp(s.Record.Ended.UnixMilli()), Outcome: outcomeText(s), JSON: string(raw), Checks: append(checks, tamper...), Mappings: mappingRows(raw)}
		for _, file := range s.Request.GetProject().GetFiles() {
			p.Files = append(p.Files, pageFile{file.GetPath(), file.GetContent(), digest([]byte(file.GetContent()))})
		}
		for _, step := range s.Response.GetProject().GetSteps() {
			row := pageStep{step.GetCommand(), string(step.GetStdout()), string(step.GetStderr()), step.GetExitCode(), step.GetDurationMs(), step.GetTimedOut()}
			p.Steps = append(p.Steps, row)
			data.StepCount++
			if s.Record.SHA256 == pairedRecord && row.Command == pairedStep {
				p.Title = "The run with an egress attempt"
				if data.Outside != "" {
					data.Contrast = &row
				}
			}
		}
		data.Runs = append(data.Runs, p)
	}
	inlineBytes, err := json.Marshal(inline)
	if err != nil {
		return err
	}
	// json.Marshal escapes HTML-sensitive bytes, so a file's </script> stays data.
	data.ReceiptBOMs = template.JS(inlineBytes)
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
	fmt.Fprintf(out, "verified %d single runs; wrote index.html; schema and integrity checks passed; altered evidence refused\n", len(runs))
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
