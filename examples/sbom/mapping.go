package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"path"
	"reflect"
	"slices"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/plimsollmark/plimsoll/attest"
	"github.com/plimsollmark/plimsoll/examples/adapter/qualify"
	"github.com/plimsollmark/plimsoll/examples/sbom/cdxutil"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const limits = "The attached run record is signed; this BOM is unsigned. Agent authorship is supplied example context, not a record fact, and the execution layer cannot identify the model. Network isolation is provider configuration, not a separately signed runtime measurement; a granted run reaches only the routes its grant lists, and what reached the other side is not in this record. The run's times are the daemon's own unwitnessed clock. An attached key alone establishes consistency, not signer identity; use an independently trusted key. Display names and the assessor label are unsigned presentation. The attached bundle line proves itself; the whole bundle it belongs to is referenced by digest and checked when supplied. This is run evidence, not an inventory of the image's installed packages."
const verdictLimits = " A qualification verdict is the platform's own signed account of one run against a simulated vendor, re-evaluated here from its evidence; it is not an independent audit, and the vendor's ledger is trusted as the signer read it."
const reasoning = "Each claim restates the run record the daemon stated and the attest harness checked against the stored request and result and signed. The attached bundle line permits those checks to be repeated. This emitter did not observe execution. The tier is configuration and provider evidence plus startup smoke tests, never runtime attestation."
const verdictReasoning = "The verdict is recomputed from the attached statement's evidence by the same rules the platform applied; the statement's seal is checked under the attached key, its subject is this run's signed record, and the files, step, report and exit code it names are checked against the stored request and response. The ledger is the simulated vendor's account as the platform read it; trusting it is trusting the signer."

type object = map[string]any

// shared is what a BOM refers to by URL and digest rather than attaching: the bundle
// its line belongs to and, for a qualified run, the file of qualification statements.
type shared struct {
	Pages               string // base URL, ending in /, where bundle.jsonl (and qualification.jsonl) are published
	BundleSHA256        string
	QualificationSHA256 string // "" for a run no statement speaks for
	// bundle and qualification are the files themselves, when the emitter read them;
	// a checker given only the BOM has neither.
	bundle, qualification []byte
}

type source struct {
	PEM      []byte // the harness's public key, as attached
	Entry    attest.Entry
	Line     attest.Link // the line's signed place in its bundle
	Record   sandbox.RunRecord
	Request  *plimsollv1.RunRequest
	Response *plimsollv1.RunResponse
	Shared   shared
	// Statement and Verdict are the platform's qualification statement for the run,
	// verified, when there is one.
	Statement *attest.Envelope
	Verdict   *qualify.Predicate
}

func (s source) grant() string { return s.Request.GetProject().GetGrantProfile() }

// displayName is the program's unsigned display name: the judged file's name for a
// qualified run, else the one the caller gave.
func (s source) displayName(given string) string {
	if s.Verdict != nil {
		return strings.TrimSuffix(path.Base(s.Verdict.Adapter.Path), ".js")
	}
	return given
}

func verifiedBundle(bundle, pem []byte) (ed25519.PublicKey, []attest.Entry, error) {
	pub, err := attest.ParsePublicKey(pem)
	if err != nil {
		return nil, nil, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle))
	if err != nil {
		return nil, nil, err
	}
	rep, err := attest.VerifyBundle(entries, attest.NewVerifier(pub))
	if err != nil {
		return nil, nil, fmt.Errorf("bundle refused: %w", err)
	}
	if len(rep.Sessions) != 0 {
		return nil, nil, fmt.Errorf("sessions are not supported: a session is many runs of one sandbox and needs its own shape")
	}
	return pub, entries, nil
}

// sources is every single project run of a verified bundle, published at pages.
func sources(bundle, pem []byte, pages string) ([]source, error) {
	pub, entries, err := verifiedBundle(bundle, pem)
	if err != nil {
		return nil, err
	}
	v := attest.NewVerifier(pub)
	var runs []source
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue
		} // verified checkpoint, never a guessed entry kind
		s, err := lineSource(v, e)
		if err != nil {
			return nil, err
		}
		s.PEM = pem
		s.Shared = shared{Pages: pages, BundleSHA256: cdxutil.Digest(bundle), bundle: bundle}
		runs = append(runs, s)
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("bundle contains no single project runs")
	}
	return runs, nil
}

// lineSource is one bundle line as a source: its record, link and messages, checked as
// attest.VerifyEntry checks a line on its own.
func lineSource(v *attest.Verifier, e attest.Entry) (source, error) {
	r, link, err := attest.VerifyEntry(v, e)
	if err != nil {
		return source{}, err
	}
	req, resp, err := e.Messages()
	if err != nil {
		return source{}, err
	}
	if r.Session != "" {
		return source{}, fmt.Errorf("sessions are not supported: a session is many runs of one sandbox and needs its own shape")
	}
	if req.GetProject() == nil || resp.GetProject() == nil {
		return source{}, fmt.Errorf("only answered single project runs are supported")
	}
	if _, _, ok := cdxutil.ImageDigest(r); !ok {
		return source{}, fmt.Errorf("run %s states no image identity this emitter can map", r.SHA256)
	}
	return source{Entry: e, Line: link, Record: r, Request: req, Response: resp}, nil
}

// qualified is the runs of a bundle, by line number, that the platform's qualification
// statements speak for, each with its statement. Every statement is verified against the
// whole bundle first, so the checks across runs (every run has one statement, no
// credential served two runs) hold for the set the BOMs refer to.
func qualified(bundle, pem, qualification []byte, pages string, lines []int) ([]source, error) {
	runs, err := sources(bundle, pem, pages)
	if err != nil {
		return nil, err
	}
	pub, entries, err := verifiedBundle(bundle, pem)
	if err != nil {
		return nil, err
	}
	statements, err := qualify.ReadStatements(qualification)
	if err != nil {
		return nil, err
	}
	verified, err := qualify.Verify(pub, statements, entries)
	if err != nil {
		return nil, fmt.Errorf("qualification refused: %w", err)
	}
	var out []source
	for _, n := range lines {
		var s *source
		for i := range runs {
			if runs[i].Line.Index == uint64(n) {
				s = &runs[i]
			}
		}
		if s == nil {
			return nil, fmt.Errorf("line %d is not a single project run of the bundle", n)
		}
		found := false
		for i, ver := range verified {
			if ver.Predicate.Run == n {
				st := statements[i]
				pred := ver.Predicate
				s.Statement, s.Verdict = &st, &pred
				found = true
			}
		}
		if !found {
			return nil, fmt.Errorf("line %d has no qualification statement", n)
		}
		s.Shared.QualificationSHA256, s.Shared.qualification = cdxutil.Digest(qualification), qualification
		out = append(out, *s)
	}
	return out, nil
}

func programFiles(s source) ([]object, string, error) {
	var components []cdx.Component
	files := slices.Clone(s.Request.GetProject().GetFiles())
	slices.SortFunc(files, func(a, b *plimsollv1.ProjectFile) int { return strings.Compare(a.GetPath(), b.GetPath()) })
	var mapped []object
	for _, f := range files {
		h := cdxutil.Digest([]byte(f.GetContent()))
		components = append(components, cdx.Component{Type: cdx.ComponentTypeFile, Name: f.GetPath(), Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: h}}})
		mapped = append(mapped, object{"type": "file", "name": f.GetPath(), "hashes": cdxutil.Hashes(h), "properties": cdxutil.Props("bytes", strconv.Itoa(len(f.GetContent())))})
	}
	if len(mapped) == 0 {
		return nil, "", fmt.Errorf("project has no files")
	}
	d, err := fileSetDigest(components)
	return mapped, d, err
}

// ruleName is a qualification rule's name in plain words, by its ID.
func ruleName(id string) string {
	for _, r := range slices.Concat(qualify.AdapterRules, qualify.ProbeRules) {
		if r.ID == id {
			return r.Name
		}
	}
	return id
}

// ruleSays is what a qualification rule requires, in plain words, by its ID.
func ruleSays(id string) string {
	for _, r := range slices.Concat(qualify.AdapterRules, qualify.ProbeRules) {
		if r.ID == id {
			return r.Says
		}
	}
	return ""
}

// verdictPredicate is the verdict claim's text: the statement's rules and verdict, in
// words, so a reader of the BOM alone sees what was judged and how it came out.
func verdictPredicate(p qualify.Predicate) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The platform's qualification statement, bound to this run's record, judges %s (SHA-256 %s) in scenario %s (%s) by %d rules read from the vendor's ledger, the vendor's record of its robots and the harness's plan, never from the program's own account:", p.Adapter.Path, p.Adapter.SHA256, p.Evidence.Scenario.Name, p.Evidence.Scenario.Says, len(p.Rules))
	for i, o := range p.Rules {
		sep := " "
		if i > 0 {
			sep = "; "
		}
		state := "held"
		if !o.Held {
			state = "broken"
		}
		fmt.Fprintf(&b, "%s%s: %s", sep, ruleName(o.Rule), state)
		if o.Detail != "" {
			fmt.Fprintf(&b, " (%s)", o.Detail)
		}
	}
	fmt.Fprintf(&b, ". Verdict: %s.", p.Verdict)
	return b.String()
}

// verdictConformance is the verdict's conformance score and rationale: 1 when every rule
// held, 0 otherwise, named by the rules that did not.
func verdictConformance(p qualify.Predicate) (float64, string) {
	var broken []string
	for _, o := range p.Rules {
		if !o.Held {
			broken = append(broken, ruleName(o.Rule))
		}
	}
	tail := " The statement's subject is this run's signed record. Self-assessed by the platform against a simulated vendor, not an independent audit."
	if p.Verdict == "pass" && len(broken) == 0 {
		return 1, fmt.Sprintf("All %d rules held when re-evaluated from the attached statement's evidence.", len(p.Rules)) + tail
	}
	return 0, fmt.Sprintf("%d of %d rules did not hold when re-evaluated from the attached statement's evidence: %s.", len(broken), len(p.Rules), strings.Join(broken, "; ")) + tail
}

func buildBOM(s source, o options) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	if (s.Statement == nil) != (s.Verdict == nil) || (s.Verdict != nil) != (s.Shared.QualificationSHA256 != "") {
		return nil, fmt.Errorf("a qualified run needs its statement, verdict and qualification digest together")
	}
	files, fileDigest, err := programFiles(s)
	if err != nil {
		return nil, err
	}
	r := s.Record
	end, start := cdxutil.Timestamp(r.Ended.UnixMilli()), cdxutil.Timestamp(r.Started.UnixMilli())
	imageDigest, imageHow, ok := cdxutil.ImageDigest(r)
	if !ok {
		return nil, fmt.Errorf("run %s states no image identity this emitter can map", r.SHA256)
	}
	pem := s.PEM
	pub, err := attest.ParsePublicKey(pem)
	if err != nil {
		return nil, err
	}
	keyID := attest.KeyID(pub)
	envelope, err := json.Marshal(s.Entry.Envelope)
	if err != nil {
		return nil, err
	}
	line, err := json.Marshal(s.Entry)
	if err != nil {
		return nil, err
	}
	exchange, err := exchangeBytes(s)
	if err != nil {
		return nil, err
	}
	tool := object{"type": "application", "name": "plimsoll-sbom", "version": "0.2.0", "externalReferences": []object{{"type": "vcs", "url": cdxutil.Repository}}}
	programProps := cdxutil.Props("author_kind", "agent", "author_kind_basis", "supplied example context, unverified", "request_sha256", r.RequestSHA256, "result_sha256", r.ResultSHA256, "record_sha256", r.SHA256)
	if s.Request.GetTraceId() != "" {
		programProps = append(programProps, cdxutil.Props("trace_id", s.Request.GetTraceId())...)
	}
	grant := s.grant()
	grantWords := "none"
	if grant != "" {
		grantWords = grant
	}
	workflowProps := cdxutil.Props("provider", r.Provider, "isolation", r.Isolation, "minimum_isolation", s.Request.GetMinimumIsolation(), "timeout_ms", strconv.Itoa(int(s.Request.GetTimeoutMs())), "grant", grantWords, "outcome", strings.ToLower(strings.TrimPrefix(s.Response.GetProject().GetOutcome().String(), "PROJECT_OUTCOME_")))
	if r.Policy != "" {
		workflowProps = append(workflowProps, cdxutil.Props("policy", r.Policy)...)
	}
	var tasks, dependencies []object
	var kinds []string
	commands := s.Request.GetProject().GetSteps()
	steps := s.Response.GetProject().GetSteps()
	if len(steps) > len(commands) {
		return nil, fmt.Errorf("more result steps than requested commands")
	}
	for i, step := range steps {
		if step.GetCommand() != commands[i] {
			return nil, fmt.Errorf("step %d command differs from the request", i+1)
		}
		n := strconv.Itoa(i + 1)
		kind := "other"
		if !slices.Contains(kinds, kind) {
			kinds = append(kinds, kind)
		}
		tasks = append(tasks, object{"bom-ref": "step-" + n, "uid": n, "name": commands[i], "taskTypes": []string{kind}, "steps": []object{{"commands": []object{{"executed": commands[i], "properties": cdxutil.Props(
			"exit_code", strconv.Itoa(int(step.GetExitCode())), "duration_ms", strconv.FormatInt(step.GetDurationMs(), 10), "timed_out", strconv.FormatBool(step.GetTimedOut()), "stdout_truncated", strconv.FormatBool(step.GetStdoutTruncated()), "stderr_truncated", strconv.FormatBool(step.GetStderrTruncated()),
		)}}}}})
		dep := object{"ref": "step-" + n}
		if i > 0 {
			dep["dependsOn"] = []string{"step-" + strconv.Itoa(i)}
		}
		dependencies = append(dependencies, dep)
	}
	if len(kinds) == 0 {
		kinds = []string{"other"}
	}
	workflow := object{"bom-ref": "run", "uid": r.SHA256, "name": "plimsoll run", "taskTypes": kinds, "timeStart": start, "timeEnd": end,
		"inputs":          []object{{"resource": object{"ref": "program"}}},
		"outputs":         []object{{"type": "other", "resource": object{"ref": "evidence-run-record"}, "properties": cdxutil.Props("result_sha256", r.ResultSHA256)}},
		"runtimeTopology": []object{{"ref": "program", "dependsOn": []string{"image"}}}, "properties": workflowProps,
	}
	if len(tasks) != 0 {
		workflow["tasks"], workflow["taskDependencies"] = tasks, dependencies
	}
	tier := fmt.Sprintf("The daemon states provider %s and isolation tier %s, at or above requested floor %s, from %s to %s UTC; ", r.Provider, r.Isolation, s.Request.GetMinimumIsolation(), start, end)
	if grant == "" {
		tier += fmt.Sprintf("the stored request names no host-API grant and the result digest is %s. The provider's no-grant configuration supplies network isolation; this record is not a network measurement.", r.ResultSHA256)
	} else {
		tier += fmt.Sprintf("the stored request names host-API grant profile %s, the run's only route out, served by the daemon's broker, and the result digest is %s. Network beyond the grant is provider configuration; this record is not a network measurement.", grant, r.ResultSHA256)
	}
	predicates := []string{
		fmt.Sprintf("The program's %d files, file-set digest %s, are the files in the stored request whose signed digest %s covers them with the isolation floor and timeout.", len(files), fileDigest, r.RequestSHA256),
		"The daemon states that the run executed in " + fmt.Sprintf(imageHow, imageDigest, r.Environment) + ".",
		tier,
	}
	var claims, requirements, maps []object
	for i, name := range []string{"code", "image", "tier"} {
		claims = append(claims, object{"bom-ref": "claim-" + name, "target": "program", "predicate": predicates[i], "reasoning": reasoning, "evidence": []string{"evidence-run-record"}})
		titles := []string{"the code that ran is identified by digest", "the image is identified by its manifest digest", "the isolation tier the daemon states is signed"}
		requirements = append(requirements, object{"bom-ref": "req-" + name, "identifier": "R" + strconv.Itoa(i+1), "title": titles[i]})
		maps = append(maps, object{"requirement": "req-" + name, "claims": []string{"claim-" + name},
			"conformance": object{"score": 1, "rationale": "The claim matches the signed exchange under a deterministic comparison; this is self-assessed consistency, not independent runtime assurance."},
			"confidence":  object{"score": 1, "rationale": "a signature check and a digest recomputation, not a judgement or a probability that the runtime assertion is true"}})
	}
	description := "An agent-style example program run once through plimsoll; authorship is supplied context, not verified evidence."
	references := []object{{"type": "attestation", "url": s.Shared.Pages + "bundle.jsonl", "hashes": cdxutil.Hashes(s.Shared.BundleSHA256)}}
	bomProps := cdxutil.Props("bundle_sha256", s.Shared.BundleSHA256, "bundle_line", strconv.FormatUint(s.Line.Index, 10), "emitter", "examples/sbom")
	evidence := []object{{"bom-ref": "evidence-run-record", "propertyName": "plimsoll:run_record", "description": fmt.Sprintf("Public example evidence: DSSE envelope, signed body type %s, in-toto statement %s, predicate %s, key id %s. entry.json is line %d of the referenced bundle as stored: the exact binary protobuf request and response, the record's envelope and the harness's signed link placing the line. exchange.json is a plain JSON copy checked against those bytes.", attest.PayloadType, attest.StatementType, attest.PredicateType, keyID, s.Line.Index), "created": end, "author": object{"name": "plimsoll-attest key " + keyID}, "data": []object{cdxutil.Attachment("envelope.json", "application/json", envelope), cdxutil.Attachment("harness.pub", "application/x-pem-file", pem), cdxutil.Attachment("entry.json", "application/json", line), cdxutil.Attachment("exchange.json", "application/json", exchange)}}}
	annotation := limits
	if s.Verdict != nil {
		statement, err := json.Marshal(*s.Statement)
		if err != nil {
			return nil, err
		}
		score, rationale := verdictConformance(*s.Verdict)
		description = "A program an AI wrote against a simulated fleet vendor's API, run once through plimsoll under a per-run grant and judged by the platform's rules; authorship is supplied context, not verified evidence."
		references = append(references, object{"type": "attestation", "url": s.Shared.Pages + "qualification.jsonl", "hashes": cdxutil.Hashes(s.Shared.QualificationSHA256)})
		bomProps = append(bomProps, cdxutil.Props("qualification_sha256", s.Shared.QualificationSHA256)...)
		evidence = append(evidence, object{"bom-ref": "evidence-qualification", "propertyName": "plimsoll:qualification", "description": fmt.Sprintf("The platform's qualification statement for this run: DSSE envelope, signed body type %s, in-toto statement %s, predicate %s, key id %s; its subject is this run's record. The referenced qualification file holds one such statement for every run of the referenced bundle.", attest.PayloadType, attest.StatementType, qualify.PredicateType, keyID), "created": end, "author": object{"name": "plimsoll-attest key " + keyID}, "data": []object{cdxutil.Attachment("statement.json", "application/json", statement)}})
		claims = append(claims, object{"bom-ref": "claim-verdict", "target": "program", "predicate": verdictPredicate(*s.Verdict), "reasoning": verdictReasoning, "evidence": []string{"evidence-qualification", "evidence-run-record"}})
		requirements = append(requirements, object{"bom-ref": "req-verdict", "identifier": "R4", "title": "the program met the platform's rules"})
		maps = append(maps, object{"requirement": "req-verdict", "claims": []string{"claim-verdict"},
			"conformance": object{"score": score, "rationale": rationale},
			"confidence":  object{"score": 1, "rationale": "a deterministic re-evaluation of the recorded evidence and a signature check, not a judgement or a probability"}})
		annotation += verdictLimits
	}
	references = append(references, object{"type": "documentation", "url": o.Pages + "index.html"}, object{"type": "vcs", "url": cdxutil.Repository})
	doc := object{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": cdxutil.Serial(r.SHA256),
		"metadata": object{"timestamp": end, "lifecycles": []object{{"phase": "operations"}}, "tools": object{"components": []object{tool}}, "component": object{
			"type": "application", "bom-ref": "program", "name": o.Name, "version": fileDigest[:12], "hashes": cdxutil.Hashes(fileDigest), "description": description, "components": files,
			"externalReferences": references, "properties": programProps,
		}},
		"components":  []object{{"type": "container", "bom-ref": "image", "name": o.ImageName, "version": "sha256:" + imageDigest, "purl": "pkg:oci/" + o.ImageName + "@sha256:" + imageDigest, "hashes": cdxutil.Hashes(imageDigest), "properties": cdxutil.Props("environment", r.Environment, "software_identity", r.SoftwareIdentity)}},
		"formulation": []object{{"bom-ref": "formula", "workflows": []object{workflow}}},
		"declarations": object{
			"assessors": []object{{"bom-ref": "assessor", "thirdParty": false, "organization": object{"name": o.Operator}}}, "claims": claims,
			"evidence":     evidence,
			"attestations": []object{{"assessor": "assessor", "summary": "A self-assessed restatement of a signed run record with reproducible consistency checks.", "map": maps}},
			"affirmation":  object{"statement": "The attached run record was stated by plimsolld, checked and signed by plimsoll-attest, and restated here; plimsoll-attest verify and this program's -check recompute it. This affirmation and BOM are unsigned."},
		},
		"definitions": object{"standards": []object{{"bom-ref": "std-plimsoll-run-evidence", "name": "plimsoll run evidence", "version": "1", "requirements": requirements}}},
		"annotations": []object{{"bom-ref": "limits", "subjects": []string{"program"}, "annotator": object{"component": tool}, "timestamp": end, "text": annotation}},
		"properties":  bomProps,
	}
	if image := o.ImageBOM; image != nil {
		if image.Manifest != "sha256:"+imageDigest {
			return nil, fmt.Errorf("image SBOM differs from run manifest")
		}
		doc["components"].([]object)[0]["externalReferences"] = []object{
			{"type": "bom", "url": o.Pages + image.File, "hashes": cdxutil.Hashes(image.SHA256)},
			{"type": "bom", "url": image.Link},
		}
	}
	return cdxutil.EncodeBOM(doc)
}

// Use the official Go model and JSON encoder, then restore explicit false for
// self-assessment: the library's bool omitempty would otherwise omit that fact.

// sharedFiles are the files a BOM refers to by digest, when the checker has them: the
// whole bundle and, for a qualified run, the whole qualification file. Either may be nil.
type sharedFiles struct{ Bundle, Qualification []byte }

// decodeAttachments reads one evidence item's attachments by name, refusing a duplicate,
// a non-base64 encoding or a set other than want.
func decodeAttachments(e cdx.DeclarationEvidence, want []string) (map[string][]byte, error) {
	if e.Data == nil || len(*e.Data) != len(want) {
		return nil, fmt.Errorf("%s: expected attachments %s", e.BOMRef, strings.Join(want, ", "))
	}
	attached := map[string][]byte{}
	for _, d := range *e.Data {
		if d.Contents == nil || d.Contents.Attachment == nil || d.Contents.Attachment.Encoding != "base64" || !slices.Contains(want, d.Name) {
			return nil, fmt.Errorf("%s: invalid attachment %q", e.BOMRef, d.Name)
		}
		if _, exists := attached[d.Name]; exists {
			return nil, fmt.Errorf("%s: duplicate attachment %q", e.BOMRef, d.Name)
		}
		b, err := base64.StdEncoding.DecodeString(d.Contents.Attachment.Content)
		if err != nil {
			return nil, fmt.Errorf("attachment %s: %w", d.Name, err)
		}
		attached[d.Name] = b
	}
	return attached, nil
}

func checkBOM(raw, trustedPEM []byte, image *imageBOM, have sharedFiles) ([]string, error) {
	if err := cdxutil.UniqueJSON(raw); err != nil {
		return nil, err
	}
	if err := cdxutil.ValidateSchema(raw); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Components == nil || bom.Components == nil || len(*bom.Components) != 1 || bom.Declarations == nil || bom.Declarations.Evidence == nil || len(*bom.Declarations.Evidence) < 1 || len(*bom.Declarations.Evidence) > 2 || bom.Declarations.Assessors == nil || len(*bom.Declarations.Assessors) != 1 {
		return nil, fmt.Errorf("required program, image, assessor or run evidence missing")
	}
	e := (*bom.Declarations.Evidence)[0]
	if e.BOMRef != "evidence-run-record" {
		return nil, fmt.Errorf("the first evidence item is not the run record")
	}
	attached, err := decodeAttachments(e, []string{"envelope.json", "harness.pub", "entry.json", "exchange.json"})
	if err != nil {
		return nil, err
	}
	qualifiedBOM := len(*bom.Declarations.Evidence) == 2
	var statementBytes []byte
	if qualifiedBOM {
		q := (*bom.Declarations.Evidence)[1]
		if q.BOMRef != "evidence-qualification" {
			return nil, fmt.Errorf("the second evidence item is not the qualification statement")
		}
		qa, err := decodeAttachments(q, []string{"statement.json"})
		if err != nil {
			return nil, err
		}
		statementBytes = qa["statement.json"]
	}
	pub, err := attest.ParsePublicKey(attached["harness.pub"])
	if err != nil {
		return nil, err
	}
	trust := "LIMIT: attached key only; signer identity is not established."
	if len(trustedPEM) != 0 {
		trusted, err := attest.ParsePublicKey(trustedPEM)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(pub, trusted) {
			return nil, fmt.Errorf("attached key differs from independently trusted key")
		}
		trust = "PASS: attached key matches independently trusted key."
	}
	var env attest.Envelope
	if err := cdxutil.UniqueJSON(attached["envelope.json"]); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(attached["envelope.json"]))
	d.DisallowUnknownFields()
	if err := d.Decode(&env); err != nil {
		return nil, err
	}
	v := attest.NewVerifier(ed25519.PublicKey(pub))
	r, err := v.Verify(env)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	// The attached line is read as a bundle line is: exactly the harness's encoding.
	lines, err := attest.ReadBundle(bytes.NewReader(append(slices.Clone(attached["entry.json"]), '\n')))
	if err != nil || len(lines) != 1 {
		return nil, fmt.Errorf("entry.json is not one bundle line: %v", err)
	}
	selected, err := lineSource(v, lines[0])
	if err != nil {
		return nil, fmt.Errorf("entry.json: %w", err)
	}
	selected.PEM = attached["harness.pub"]
	if selected.Record.SHA256 != r.SHA256 || !reflect.DeepEqual(env, selected.Entry.Envelope) {
		return nil, fmt.Errorf("envelope differs from the attached line's")
	}
	if err := checkExchangeJSON(attached["exchange.json"], selected); err != nil {
		return nil, err
	}
	if qualifiedBOM {
		if err := cdxutil.UniqueJSON(statementBytes); err != nil {
			return nil, err
		}
		var st attest.Envelope
		sd := json.NewDecoder(bytes.NewReader(statementBytes))
		sd.DisallowUnknownFields()
		if err := sd.Decode(&st); err != nil {
			return nil, err
		}
		ver, err := qualify.VerifyOne(pub, st, selected.Entry)
		if err != nil {
			return nil, fmt.Errorf("qualification statement: %w", err)
		}
		pred := ver.Predicate
		selected.Statement, selected.Verdict = &st, &pred
	}
	program := bom.Metadata.Component
	files, err := fileSetDigest(*program.Components)
	if err != nil {
		return nil, err
	}
	if program.Hashes == nil || len(*program.Hashes) != 1 || (*program.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 || (*program.Hashes)[0].Value != files {
		return nil, fmt.Errorf("file-set digest differs from program hash")
	}
	// The references to the shared files are unsigned presentation until the files are
	// at hand; the rebuild below compares them with themselves, and the lines say so.
	pages := ""
	if program.ExternalReferences != nil {
		for _, ref := range *program.ExternalReferences {
			switch {
			case ref.Type == cdx.ERTypeDocumentation && strings.HasSuffix(ref.URL, "index.html"):
				pages = strings.TrimSuffix(ref.URL, "index.html")
			case ref.Type == cdx.ERTypeAttestation && strings.HasSuffix(ref.URL, "bundle.jsonl") && ref.Hashes != nil && len(*ref.Hashes) == 1:
				selected.Shared.Pages, selected.Shared.BundleSHA256 = strings.TrimSuffix(ref.URL, "bundle.jsonl"), (*ref.Hashes)[0].Value
			case ref.Type == cdx.ERTypeAttestation && strings.HasSuffix(ref.URL, "qualification.jsonl") && ref.Hashes != nil && len(*ref.Hashes) == 1:
				selected.Shared.QualificationSHA256 = (*ref.Hashes)[0].Value
			}
		}
	}
	if selected.Shared.BundleSHA256 == "" || qualifiedBOM != (selected.Shared.QualificationSHA256 != "") {
		return nil, fmt.Errorf("the references to the bundle and qualification file do not match the evidence attached")
	}
	bundleLine := "LIMIT: the referenced bundle was not supplied; the attached line's own seal and link were checked, the chain around it was not."
	qualificationLine := ""
	if have.Bundle != nil {
		if cdxutil.Digest(have.Bundle) != selected.Shared.BundleSHA256 {
			return nil, fmt.Errorf("the supplied bundle is not the one the BOM references")
		}
		_, entries, err := verifiedBundle(have.Bundle, attached["harness.pub"])
		if err != nil {
			return nil, err
		}
		n := selected.Line.Index
		if n < 1 || n > uint64(len(entries)) || !reflect.DeepEqual(entries[n-1], selected.Entry) {
			return nil, fmt.Errorf("the attached line is not line %d of the referenced bundle", n)
		}
		bundleLine = fmt.Sprintf("PASS: the attached line is line %d of the referenced bundle, whole to its checkpoint (%d lines).", n, len(entries))
		if qualifiedBOM {
			qualificationLine = "LIMIT: the referenced qualification file was not supplied; the attached statement was checked against its run, the checks across runs were not."
			if have.Qualification != nil {
				if cdxutil.Digest(have.Qualification) != selected.Shared.QualificationSHA256 {
					return nil, fmt.Errorf("the supplied qualification file is not the one the BOM references")
				}
				statements, err := qualify.ReadStatements(have.Qualification)
				if err != nil {
					return nil, err
				}
				if _, err := qualify.Verify(pub, statements, entries); err != nil {
					return nil, fmt.Errorf("qualification file refused: %w", err)
				}
				if !slices.ContainsFunc(statements, func(s attest.Envelope) bool { return reflect.DeepEqual(s, *selected.Statement) }) {
					return nil, fmt.Errorf("the attached statement is not in the referenced qualification file")
				}
				qualificationLine = fmt.Sprintf("PASS: the attached statement is one of the referenced qualification file's %d, every verdict rebuilt from its evidence, no credential serving two runs.", len(statements))
			}
		}
	} else if have.Qualification != nil {
		return nil, fmt.Errorf("the qualification file can be checked only with its bundle")
	}
	assessor := (*bom.Declarations.Assessors)[0]
	if assessor.Organization == nil {
		return nil, fmt.Errorf("assessor organization missing")
	}
	if (*bom.Components)[0].ExternalReferences != nil && image == nil {
		return nil, fmt.Errorf("referenced image SBOM is missing; supply the digest-named sibling file or -image-bom")
	}
	o := options{Name: program.Name, ImageName: (*bom.Components)[0].Name, Operator: assessor.Organization.Name, Pages: pages, ImageBOM: image}
	expected, err := buildBOM(selected, o)
	if err != nil {
		return nil, err
	}
	var got, want any
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(expected, &want); err != nil {
		return nil, err
	}
	if !reflect.DeepEqual(got, want) {
		return nil, fmt.Errorf("BOM differs from the verified exchange: file contents, digests, claims or another mapped field was changed")
	}
	lines2 := []string{
		"PASS: CycloneDX 1.6 schema (vendored, offline).",
		"PASS: DSSE envelope signature and run-record digest.",
		"PASS: the attached bundle line: its link's seal and place, the stored request and result against the signed digests.",
		"PASS: exchange.json equals the line's protobuf messages and reproduces their digests.",
		"PASS: file-set digest recomputed from file components and bound to the signed request.",
	}
	if qualifiedBOM {
		lines2 = append(lines2, "PASS: the qualification statement's seal, its subject (this record), its files, step, report and exit code against the line, and its verdict re-evaluated from its evidence.")
	}
	lines2 = append(lines2, "PASS: every mapped field and claim matches the verified exchange.", trust, bundleLine)
	if qualificationLine != "" {
		lines2 = append(lines2, qualificationLine)
	}
	lines2 = append(lines2, "LIMIT: names, page URL and assessor label are unsigned presentation; runtime assertions remain the daemon's statements.")
	if image != nil {
		lines2 = append(lines2, "PASS: image SBOM hash, manifest identity and BOM-Link match the local evidence file.")
	}
	return lines2, nil
}
