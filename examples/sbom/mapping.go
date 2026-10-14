package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/plimsollmark/plimsoll/attest"
	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

const repository = "https://github.com/plimsollmark/plimsoll"
const limits = "The attached run record is signed; this BOM is unsigned. Agent authorship is supplied example context, not a record fact, and the execution layer cannot identify the model. No host-API grant was requested. Network isolation is provider configuration, not a separately signed runtime measurement. The run's times are the daemon's own unwitnessed clock. An attached key alone establishes consistency, not signer identity; use an independently trusted key. Display names and the assessor label are unsigned presentation. This is run evidence, not an inventory of the image's installed packages."
const reasoning = "Each claim restates the run record the daemon stated and the attest harness checked against the stored request and result and signed. The attached bundle permits those checks to be repeated. This emitter did not observe execution. The tier is configuration and provider evidence plus startup smoke tests, never runtime attestation."

type object = map[string]any

var selectedImagePattern = regexp.MustCompile(`^oci-manifest:[a-z0-9._/-]+@sha256:[a-f0-9]{64}$`)

type source struct {
	Entry    attest.Entry
	Record   sandbox.RunRecord
	Request  *plimsollv1.RunRequest
	Response *plimsollv1.RunResponse
}

func sources(bundle, pem []byte) ([]source, error) {
	pub, err := attest.ParsePublicKey(pem)
	if err != nil {
		return nil, err
	}
	entries, err := attest.ReadBundle(bytes.NewReader(bundle))
	if err != nil {
		return nil, err
	}
	v := attest.NewVerifier(pub)
	rep, err := attest.VerifyBundle(entries, v)
	if err != nil {
		return nil, fmt.Errorf("bundle refused: %w", err)
	}
	if len(rep.Sessions) != 0 {
		return nil, fmt.Errorf("sessions are not supported: a session is many runs of one sandbox and needs its own shape")
	}
	var runs []source
	for _, e := range entries {
		if len(e.Request) == 0 {
			continue
		} // verified checkpoint, never a guessed entry kind
		r, err := v.Verify(e.Envelope)
		if err != nil {
			return nil, err
		}
		req, resp, err := e.Messages()
		if err != nil {
			return nil, err
		}
		if req.GetProject() == nil || resp.GetProject() == nil {
			return nil, fmt.Errorf("only answered single project runs are supported")
		}
		if req.GetProject().GetGrantProfile() != "" {
			return nil, fmt.Errorf("granted runs are not supported: the no-grant claims cannot describe them")
		}
		if r.Environment == "" || !selectedImagePattern.MatchString(r.SoftwareIdentity) {
			return nil, fmt.Errorf("run %s lacks an OCI selected-image identity or environment", r.SHA256)
		}
		runs = append(runs, source{e, r, req, resp})
	}
	if len(runs) == 0 {
		return nil, fmt.Errorf("bundle contains no single project runs")
	}
	return runs, nil
}

func props(pairs ...string) []object {
	p := make([]object, 0, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		p = append(p, object{"name": "plimsoll:" + pairs[i], "value": pairs[i+1]})
	}
	return p
}

func hashes(value string) []object { return []object{{"alg": "SHA-256", "content": value}} }

func attachment(name, kind string, content []byte) object {
	return object{"name": name, "contents": object{"attachment": object{
		"contentType": kind, "encoding": "base64", "content": base64.StdEncoding.EncodeToString(content),
	}}}
}

func programFiles(s source) ([]object, string, error) {
	var components []cdx.Component
	files := slices.Clone(s.Request.GetProject().GetFiles())
	slices.SortFunc(files, func(a, b *plimsollv1.ProjectFile) int { return strings.Compare(a.GetPath(), b.GetPath()) })
	var mapped []object
	for _, f := range files {
		h := digest([]byte(f.GetContent()))
		components = append(components, cdx.Component{Type: cdx.ComponentTypeFile, Name: f.GetPath(), Hashes: &[]cdx.Hash{{Algorithm: cdx.HashAlgoSHA256, Value: h}}})
		mapped = append(mapped, object{"type": "file", "name": f.GetPath(), "hashes": hashes(h), "properties": props("bytes", strconv.Itoa(len(f.GetContent())))})
	}
	if len(mapped) == 0 {
		return nil, "", fmt.Errorf("project has no files")
	}
	d, err := fileSetDigest(components)
	return mapped, d, err
}

func buildBOM(s source, bundle, pem []byte, o options) ([]byte, error) {
	if err := o.validate(); err != nil {
		return nil, err
	}
	files, fileDigest, err := programFiles(s)
	if err != nil {
		return nil, err
	}
	r := s.Record
	end, start := timestamp(r.Ended.UnixMilli()), timestamp(r.Started.UnixMilli())
	imageDigest := strings.Split(r.SoftwareIdentity, "@sha256:")[1]
	pub, err := attest.ParsePublicKey(pem)
	if err != nil {
		return nil, err
	}
	keyID := attest.KeyID(pub)
	envelope, err := json.Marshal(s.Entry.Envelope)
	if err != nil {
		return nil, err
	}
	exchange, err := exchangeBytes(s)
	if err != nil {
		return nil, err
	}
	tool := object{"type": "application", "name": "plimsoll-sbom", "version": "0.1.0", "externalReferences": []object{{"type": "vcs", "url": repository}}}
	programProps := props("author_kind", "agent", "author_kind_basis", "supplied example context, unverified", "request_sha256", r.RequestSHA256, "result_sha256", r.ResultSHA256, "record_sha256", r.SHA256)
	if s.Request.GetTraceId() != "" {
		programProps = append(programProps, props("trace_id", s.Request.GetTraceId())...)
	}
	workflowProps := props("provider", r.Provider, "isolation", r.Isolation, "minimum_isolation", s.Request.GetMinimumIsolation(), "timeout_ms", strconv.Itoa(int(s.Request.GetTimeoutMs())), "grant", "none", "outcome", strings.ToLower(strings.TrimPrefix(s.Response.GetProject().GetOutcome().String(), "PROJECT_OUTCOME_")))
	if r.Policy != "" {
		workflowProps = append(workflowProps, props("policy", r.Policy)...)
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
		tasks = append(tasks, object{"bom-ref": "step-" + n, "uid": n, "name": commands[i], "taskTypes": []string{kind}, "steps": []object{{"commands": []object{{"executed": commands[i], "properties": props(
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
		"outputs":         []object{{"type": "other", "resource": object{"ref": "evidence-run-record"}, "properties": props("result_sha256", r.ResultSHA256)}},
		"runtimeTopology": []object{{"ref": "program", "dependsOn": []string{"image"}}}, "properties": workflowProps,
	}
	if len(tasks) != 0 {
		workflow["tasks"], workflow["taskDependencies"] = tasks, dependencies
	}
	predicates := []string{
		fmt.Sprintf("The program's %d files, file-set digest %s, are the files in the stored request whose signed digest %s covers them with the isolation floor and timeout.", len(files), fileDigest, r.RequestSHA256),
		fmt.Sprintf("The daemon states that the run executed in the image whose OCI manifest digest is sha256:%s (environment %s), verified before launch.", imageDigest, r.Environment),
		fmt.Sprintf("The daemon states provider %s and isolation tier %s, at or above requested floor %s, from %s to %s UTC; the stored request names no host-API grant and the result digest is %s. The provider's no-grant configuration supplies network isolation; this record is not a network measurement.", r.Provider, r.Isolation, s.Request.GetMinimumIsolation(), start, end, r.ResultSHA256),
	}
	var claims, requirements, maps []object
	for i, name := range []string{"code", "image", "tier"} {
		claims = append(claims, object{"bom-ref": "claim-" + name, "target": "program", "predicate": predicates[i], "reasoning": reasoning, "evidence": []string{"evidence-run-record"}})
		titles := []string{"the code that ran is identified by digest", "the image is identified by its OCI manifest digest", "the isolation tier the daemon states is signed"}
		requirements = append(requirements, object{"bom-ref": "req-" + name, "identifier": "R" + strconv.Itoa(i+1), "title": titles[i]})
		maps = append(maps, object{"requirement": "req-" + name, "claims": []string{"claim-" + name},
			"conformance": object{"score": 1, "rationale": "The claim matches the signed exchange under a deterministic comparison; this is self-assessed consistency, not independent runtime assurance."},
			"confidence":  object{"score": 1, "rationale": "a signature check and a digest recomputation, not a judgement or a probability that the runtime assertion is true"}})
	}
	doc := object{"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1, "serialNumber": serial(r.SHA256),
		"metadata": object{"timestamp": end, "lifecycles": []object{{"phase": "operations"}}, "tools": object{"components": []object{tool}}, "component": object{
			"type": "application", "bom-ref": "program", "name": o.Name, "version": fileDigest[:12], "hashes": hashes(fileDigest), "description": "An agent-style example program run once through plimsoll; authorship is supplied context, not verified evidence.", "components": files,
			"externalReferences": []object{{"type": "attestation", "url": o.Pages + "bundle.jsonl", "hashes": hashes(digest(bundle))}, {"type": "documentation", "url": o.Pages + "index.html"}, {"type": "vcs", "url": repository}}, "properties": programProps,
		}},
		"components":  []object{{"type": "container", "bom-ref": "image", "name": o.ImageName, "version": "sha256:" + imageDigest, "purl": "pkg:oci/" + o.ImageName + "@sha256:" + imageDigest, "hashes": hashes(imageDigest), "properties": props("environment", r.Environment, "software_identity", r.SoftwareIdentity)}},
		"formulation": []object{{"bom-ref": "formula", "workflows": []object{workflow}}},
		"declarations": object{
			"assessors": []object{{"bom-ref": "assessor", "thirdParty": false, "organization": object{"name": o.Operator}}}, "claims": claims,
			"evidence":     []object{{"bom-ref": "evidence-run-record", "propertyName": "plimsoll:run_record", "description": fmt.Sprintf("Public example evidence: DSSE envelope, signed body type %s, in-toto statement %s, predicate %s, key id %s. The bundle includes the exact binary protobuf request and response and signed checkpoint links. exchange.json is a plain JSON copy checked against those bytes.", attest.PayloadType, attest.StatementType, attest.PredicateType, keyID), "created": end, "author": object{"name": "plimsoll-attest key " + keyID}, "data": []object{attachment("envelope.json", "application/json", envelope), attachment("harness.pub", "application/x-pem-file", pem), attachment("bundle.jsonl", "application/x-ndjson", bundle), attachment("exchange.json", "application/json", exchange)}}},
			"attestations": []object{{"assessor": "assessor", "summary": "A self-assessed restatement of a signed run record with reproducible consistency checks.", "map": maps}},
			"affirmation":  object{"statement": "The attached run record was stated by plimsolld, checked and signed by plimsoll-attest, and restated here; plimsoll-attest verify and this program's -check recompute it. This affirmation and BOM are unsigned."},
		},
		"definitions": object{"standards": []object{{"bom-ref": "std-plimsoll-run-evidence", "name": "plimsoll run evidence", "version": "1", "requirements": requirements}}},
		"annotations": []object{{"bom-ref": "limits", "subjects": []string{"program"}, "annotator": object{"component": tool}, "timestamp": end, "text": limits}},
		"properties":  props("bundle_sha256", digest(bundle), "emitter", "examples/sbom"),
	}
	if image := o.ImageBOM; image != nil {
		if image.Manifest != "sha256:"+imageDigest {
			return nil, fmt.Errorf("image SBOM differs from run manifest")
		}
		doc["components"].([]object)[0]["externalReferences"] = []object{
			{"type": "bom", "url": o.Pages + image.File, "hashes": hashes(image.SHA256)},
			{"type": "bom", "url": image.Link},
		}
	}
	return encodeBOM(doc)
}

// Use the official Go model and JSON encoder, then restore explicit false for
// self-assessment: the library's bool omitempty would otherwise omit that fact.
func encodeBOM(doc object) ([]byte, error) {
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := cdx.NewBOMEncoder(&b, cdx.BOMFileFormatJSON).SetPretty(true).Encode(&bom); err != nil {
		return nil, err
	}
	var encoded object
	if err := json.Unmarshal(b.Bytes(), &encoded); err != nil {
		return nil, err
	}
	encoded["declarations"].(map[string]any)["assessors"].([]any)[0].(map[string]any)["thirdParty"] = false
	b.Reset()
	encoder := json.NewEncoder(&b)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(encoded); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func checkBOM(raw, trustedPEM []byte, image *imageBOM) ([]string, error) {
	if err := uniqueJSON(raw); err != nil {
		return nil, err
	}
	if err := validateSchema(raw); err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(raw), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, err
	}
	if bom.Metadata == nil || bom.Metadata.Component == nil || bom.Metadata.Component.Components == nil || bom.Components == nil || len(*bom.Components) != 1 || bom.Declarations == nil || bom.Declarations.Evidence == nil || len(*bom.Declarations.Evidence) != 1 || bom.Declarations.Assessors == nil || len(*bom.Declarations.Assessors) != 1 {
		return nil, fmt.Errorf("required program, image, assessor or run evidence missing")
	}
	e := (*bom.Declarations.Evidence)[0]
	if e.BOMRef != "evidence-run-record" || e.Data == nil || len(*e.Data) != 4 {
		return nil, fmt.Errorf("expected envelope, public key, bundle and exchange attachments")
	}
	attached := map[string][]byte{}
	for _, d := range *e.Data {
		if d.Contents == nil || d.Contents.Attachment == nil || d.Contents.Attachment.Encoding != "base64" {
			return nil, fmt.Errorf("invalid attachment %q", d.Name)
		}
		if _, exists := attached[d.Name]; exists {
			return nil, fmt.Errorf("duplicate attachment %q", d.Name)
		}
		b, err := base64.StdEncoding.DecodeString(d.Contents.Attachment.Content)
		if err != nil {
			return nil, fmt.Errorf("attachment %s: %w", d.Name, err)
		}
		attached[d.Name] = b
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
	if err := uniqueJSON(attached["envelope.json"]); err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(attached["envelope.json"]))
	d.DisallowUnknownFields()
	if err := d.Decode(&env); err != nil {
		return nil, err
	}
	r, err := attest.NewVerifier(ed25519.PublicKey(pub)).Verify(env)
	if err != nil {
		return nil, fmt.Errorf("envelope: %w", err)
	}
	runs, err := sources(attached["bundle.jsonl"], attached["harness.pub"])
	if err != nil {
		return nil, err
	}
	var selected *source
	for i := range runs {
		if runs[i].Record.SHA256 == r.SHA256 {
			selected = &runs[i]
			break
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("envelope record is not in attached bundle")
	}
	if !reflect.DeepEqual(env, selected.Entry.Envelope) {
		return nil, fmt.Errorf("envelope differs from bundle")
	}
	if err := checkExchangeJSON(attached["exchange.json"], *selected); err != nil {
		return nil, err
	}
	program := bom.Metadata.Component
	files, err := fileSetDigest(*program.Components)
	if err != nil {
		return nil, err
	}
	if program.Hashes == nil || len(*program.Hashes) != 1 || (*program.Hashes)[0].Algorithm != cdx.HashAlgoSHA256 || (*program.Hashes)[0].Value != files {
		return nil, fmt.Errorf("file-set digest differs from program hash")
	}
	pages := ""
	if program.ExternalReferences != nil {
		for _, ref := range *program.ExternalReferences {
			if ref.Type == cdx.ERTypeDocumentation && strings.HasSuffix(ref.URL, "index.html") {
				pages = strings.TrimSuffix(ref.URL, "index.html")
			}
		}
	}
	assessor := (*bom.Declarations.Assessors)[0]
	if assessor.Organization == nil {
		return nil, fmt.Errorf("assessor organization missing")
	}
	if (*bom.Components)[0].ExternalReferences != nil && image == nil {
		return nil, fmt.Errorf("referenced image SBOM is missing; supply the digest-named sibling file or -image-bom")
	}
	o := options{Name: program.Name, ImageName: (*bom.Components)[0].Name, Operator: assessor.Organization.Name, Pages: pages, ImageBOM: image}
	expected, err := buildBOM(*selected, attached["bundle.jsonl"], attached["harness.pub"], o)
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
	lines := []string{
		"PASS: CycloneDX 1.6 schema (vendored, offline).",
		"PASS: DSSE envelope signature and run-record digest.",
		"PASS: bundle signatures, checkpoint links, stored request and result digests.",
		"PASS: exchange.json equals the bundle's protobuf messages and reproduces their digests.",
		"PASS: file-set digest recomputed from file components and bound to the signed request.",
		"PASS: every mapped field and claim matches the verified exchange.",
		trust,
		"LIMIT: names, page URL and assessor label are unsigned presentation; runtime assertions remain the daemon's statements.",
	}
	if image != nil {
		lines = append(lines, "PASS: image SBOM hash, manifest identity and BOM-Link match the local evidence file.")
	}
	return lines, nil
}
