package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

func outcomeText(s source) string {
	return strings.ToLower(strings.TrimPrefix(s.Response.GetProject().GetOutcome().String(), "PROJECT_OUTCOME_"))
}

// Exercise independent altered copies. Never write or alter the source evidence.
func tamperChecks(raw, pem []byte, image *imageBOM) ([]string, error) {
	var lines []string
	for _, kind := range []string{"envelope", "file hash", "claim digest"} {
		var doc object
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, err
		}
		switch kind {
		case "envelope":
			e := doc["declarations"].(map[string]any)["evidence"].([]any)[0].(map[string]any)
			a := e["data"].([]any)[0].(map[string]any)["contents"].(map[string]any)["attachment"].(map[string]any)
			content, err := base64.StdEncoding.DecodeString(a["content"].(string))
			if err != nil {
				return nil, err
			}
			var env object
			if err := json.Unmarshal(content, &env); err != nil {
				return nil, err
			}
			payload, err := base64.StdEncoding.DecodeString(env["payload"].(string))
			if err != nil {
				return nil, err
			}
			// Preserve JSON syntax and change exactly one byte inside the signed body.
			payload, _, err = changeSubjectByte(payload)
			if err != nil {
				return nil, err
			}
			env["payload"] = base64.StdEncoding.EncodeToString(payload)
			content, err = json.Marshal(env)
			if err != nil {
				return nil, err
			}
			a["content"] = base64.StdEncoding.EncodeToString(content)
		case "file hash":
			f := doc["metadata"].(map[string]any)["component"].(map[string]any)["components"].([]any)[0].(map[string]any)
			h := f["hashes"].([]any)[0].(map[string]any)
			h["content"] = changeHex(h["content"].(string))
		case "claim digest":
			c := doc["declarations"].(map[string]any)["claims"].([]any)[0].(map[string]any)
			p := c["predicate"].(string)
			prefix := "file-set digest "
			at := strings.Index(p, prefix) + len(prefix)
			c["predicate"] = p[:at] + changeHex(p[at:at+64]) + p[at+64:]
		}
		changed, err := json.Marshal(doc)
		if err != nil {
			return nil, err
		}
		_, err = checkBOM(changed, pem, image)
		if err == nil {
			return nil, fmt.Errorf("altered %s was accepted", kind)
		}
		lines = append(lines, "PASS: altered "+kind+" refused: "+err.Error())
	}
	return lines, nil
}

func changeHex(s string) string {
	if s[0] == '0' {
		return "1" + s[1:]
	}
	return "0" + s[1:]
}

// Every emitted leaf gets a source label. Property values name their actual
// source, while fixed identifiers, vocabulary and text are mapping constants.
func mappingRows(raw []byte) []mappingRow {
	var doc any
	_ = json.Unmarshal(raw, &doc)
	var rows []mappingRow
	var walk func(any, string)
	walk = func(v any, path string) {
		switch value := v.(type) {
		case map[string]any:
			keys := make([]string, 0, len(value))
			for k := range value {
				keys = append(keys, k)
			}
			slices.Sort(keys)
			for _, k := range keys {
				p := k
				if path != "" {
					p = path + "." + k
				}
				if k == "value" && value["name"] != nil {
					rows = append(rows, mappingRow{p, propertySource(fmt.Sprint(value["name"]))})
					continue
				}
				walk(value[k], p)
			}
		case []any:
			for i, item := range value {
				walk(item, fmt.Sprintf("%s[%d]", path, i))
			}
		default:
			rows = append(rows, mappingRow{path, fieldSource(path)})
		}
	}
	walk(doc, "")
	return rows
}

func propertySource(name string) string {
	key := strings.TrimPrefix(name, "plimsoll:")
	switch key {
	case "bytes":
		return "Byte length of request.project.files[].content."
	case "request_sha256", "result_sha256", "record_sha256", "provider", "isolation", "environment", "software_identity", "policy":
		return "Signed record: " + key + "."
	case "minimum_isolation", "timeout_ms", "trace_id":
		return "Stored request: " + key + "; the bundle link signs the exact stored bytes."
	case "grant":
		return "Stored request.project.grant_profile is empty; granted runs are refused."
	case "outcome":
		return "Stored response.project.outcome."
	case "exit_code", "duration_ms", "timed_out", "stdout_truncated", "stderr_truncated":
		return "Stored response.project.steps[]." + key + "; the bundle link signs the stored bytes."
	case "bundle_sha256":
		return "SHA-256 of the original complete bundle file bytes."
	case "author_kind", "author_kind_basis":
		return "Unsigned supplied example context; the run record does not establish authorship."
	default:
		return "Emitter mapping constant."
	}
}

func fieldSource(p string) string {
	switch {
	case p == "serialNumber":
		return "First 16 bytes of SHA-256(plimsoll-sbom-serial + newline + record digest), UUID version/variant bits set."
	case p == "metadata.timestamp" || strings.HasSuffix(p, ".timeEnd") || strings.HasSuffix(p, ".created") || strings.HasSuffix(p, ".timestamp"):
		return "Signed record.ended_unix_ms, formatted in UTC with milliseconds."
	case strings.HasSuffix(p, ".timeStart"):
		return "Signed record.started_unix_ms, formatted in UTC with milliseconds."
	case p == "metadata.component.name":
		return "Unsigned -name display label."
	case p == "components[0].name":
		return "Unsigned -image-name display label."
	case strings.HasPrefix(p, "declarations.assessors") && strings.HasSuffix(p, ".name"):
		return "Unsigned -operator self-assessor label."
	case strings.HasPrefix(p, "metadata.component.components") && strings.HasSuffix(p, ".name"):
		return "Stored request.project.files[].path, sorted by path."
	case strings.HasPrefix(p, "metadata.component.components") && strings.HasSuffix(p, ".content"):
		return "SHA-256 of stored request.project.files[].content bytes."
	case p == "metadata.component.version":
		return "First 12 hex characters of the file-set digest."
	case p == "metadata.component.hashes[0].content":
		return "File-set digest recomputed from the stored request's file paths and contents."
	case strings.HasPrefix(p, "components[0].externalReferences[0]") && strings.HasSuffix(p, ".content"):
		return "SHA-256 of the pinned local image SBOM's original file bytes."
	case p == "components[0].externalReferences[0].url":
		return "Unsigned -pages base URL plus the manifest-derived image SBOM filename."
	case p == "components[0].externalReferences[1].url":
		return "BOM-Link from the image SBOM's serialNumber UUID, version and root component bom-ref."
	case strings.HasPrefix(p, "components[0]") && (strings.HasSuffix(p, ".content") || strings.HasSuffix(p, ".version") || strings.HasSuffix(p, ".purl")):
		return "Selected OCI manifest digest from signed record.software_identity; purl also uses the unsigned display name."
	case strings.HasPrefix(p, "metadata.component.externalReferences") && strings.HasSuffix(p, ".url"):
		return "Unsigned -pages base URL for evidence/documentation, or fixed repository URL."
	case strings.HasPrefix(p, "metadata.component.externalReferences") && strings.HasSuffix(p, ".content"):
		return "SHA-256 of the complete original bundle file bytes."
	case strings.HasPrefix(p, "formulation") && strings.HasSuffix(p, ".uid"):
		return "Signed record.record_sha256 for the workflow; one-based result-step index for a task."
	case strings.HasPrefix(p, "formulation") && (strings.HasSuffix(p, ".executed") || (strings.Contains(p, ".tasks[") && strings.HasSuffix(p, ".name"))):
		return "Stored request.project.steps[] equals stored response.project.steps[].command."
	case strings.Contains(p, ".taskTypes["):
		return "Constant other: no task type was declared; the command supplies the name."
	case strings.HasPrefix(p, "declarations.claims") && strings.HasSuffix(p, ".predicate"):
		return "Verified signed record and its stored request; code claim also uses the file-set digest."
	case strings.HasPrefix(p, "declarations.evidence") && strings.HasSuffix(p, ".attachment.content"):
		return "Base64 of the selected DSSE envelope, public PEM key, complete bundle or checked JSON exchange copy (attachment name identifies which)."
	case strings.HasPrefix(p, "declarations.evidence") && (strings.HasSuffix(p, ".description") || strings.HasSuffix(p, ".author.name")):
		return "Fixed envelope/statement/predicate type names plus key id = SHA-256 of the public key bytes."
	default:
		return "Emitter mapping constant: CycloneDX vocabulary, reference, requirement, check rationale or limitation text."
	}
}
