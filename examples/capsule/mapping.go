package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	emit "github.com/action-state-group/capsule-emit-go"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// verdict is one plimsoll outcome in the capsule vocabulary: why the run ended
// (verdict_class), what is known about its effect (effect.status), and whether
// the capsule commits a reason. setup_failed and protocol_error share a class
// and a status, and a dispatched effect carries no response digest, so without
// the reason nothing in the capsule would tell them apart.
type verdict struct {
	class  emit.VerdictClass
	status emit.EffectStatus
	reason bool
}

// verdicts is the whole mapping, as data. Every run plimsoll answered was
// dispatched, so no row derives effect_mode not_applicable: blocked and denied
// belong to refusals, and a refusal carries no run record today.
//
// A completed run is confirmed whatever its exit code. The daemon observed the
// result and the response digest binds it, exit code included; the capsule
// status "failed" would derive dispatched_unconfirmed, which understates what a
// gate that ran the code saw.
var verdicts = map[plimsollv1.ProjectOutcome]verdict{
	plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED:      {emit.VerdictExecuted, emit.EffectConfirmed, false},
	plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT:      {emit.VerdictTimeout, emit.EffectDispatched, true},
	plimsollv1.ProjectOutcome_PROJECT_OUTCOME_SETUP_FAILED:   {emit.VerdictErrored, emit.EffectDispatched, true},
	plimsollv1.ProjectOutcome_PROJECT_OUTCOME_PROTOCOL_ERROR: {emit.VerdictErrored, emit.EffectDispatched, true},
}

// outcome reads one outcome from any payload kind. A snippet has no outcome
// field: it timed out or it completed, and its exit code is part of its result.
func outcome(resp *plimsollv1.RunResponse) (plimsollv1.ProjectOutcome, error) {
	switch r := resp.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		if r.Javascript.GetTimedOut() {
			return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT, nil
		}
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, nil
	case *plimsollv1.RunResponse_Project:
		return r.Project.GetOutcome(), nil
	case *plimsollv1.RunResponse_Module:
		return r.Module.GetOutcome(), nil
	}
	return 0, fmt.Errorf("response carries no result")
}

// source names what one import read, so every capsule it makes can say where
// it came from and when.
type source struct {
	operator   string
	developer  string
	batch      string // the bundle's own digest
	importedAt time.Time
}

// recordRefType is the source_ref type for a plimsoll run record. It is not in
// the capsule registry; the spec reads an unregistered type as informational.
const recordRefType = "plimsoll-run-record"

// effectType is the effect type for a sandboxed code run. Also unregistered: the
// seeded types are write_order, send_payment and inference_completion.
const effectType = "code_execution"

// capsuleInput states one verified run record as a capsule. rec must be the
// record plimsoll's verifier accepted for req and resp; parent is the previous
// call's capsule ID, or "" for a single run or a session's first call.
func capsuleInput(rec sandbox.RunRecord, req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse, parent string, src source) (emit.Input, error) {
	// An import cannot precede what it imports, and one stamped at the same instant
	// is the shape the spec's verifier refuses as laundering an import into a
	// contemporaneous record.
	if !src.importedAt.After(rec.Ended) {
		return emit.Input{}, fmt.Errorf("import time %s does not follow the record's time %s", wireTime(src.importedAt), wireTime(rec.Ended))
	}
	o, err := outcome(resp)
	if err != nil {
		return emit.Input{}, err
	}
	v, ok := verdicts[o]
	if !ok {
		return emit.Input{}, fmt.Errorf("outcome %v has no capsule verdict", o)
	}
	reqDigest, err := jsonDigest(req)
	if err != nil {
		return emit.Input{}, fmt.Errorf("request digest: %w", err)
	}
	effect := &emit.Effect{
		Type:                 effectType,
		Status:               v.status,
		IrreversibilityClass: emit.IrreversibilityTwoWay,
		EffectAttestation:    emit.AttestationGateExecuted,
		RequestDigest:        reqDigest,
	}
	// confirmed requires a digest of the response actually observed; dispatched
	// forbids one.
	if v.status == emit.EffectConfirmed {
		if effect.ResponseDigest, err = jsonDigest(resp); err != nil {
			return emit.Input{}, fmt.Errorf("response digest: %w", err)
		}
	}
	in := emit.Input{
		ActionID:   "plimsoll-run:" + rec.SHA256,
		ActionType: emit.ActionTypeDecide,
		Operator:   src.operator,
		Developer:  src.developer,
		Timestamp:  rec.Ended,
		Domain:     emit.DomainAction,
		Provenance: emit.ProvenanceCollector,
		Disposition: &emit.Disposition{
			Decision:     emit.DecisionAccept,
			Approver:     emit.ApproverPolicy,
			VerdictClass: v.class,
		},
		Effect:  effect,
		Compute: &emit.ComputeAttestation{Runtime: runtime(rec)},
		ProvenanceMode: &emit.ProvenanceMode{
			Mode:             emit.ProvenanceModeBackfilled,
			SourceRef:        &emit.Reference{Type: recordRefType, DigestAlg: "SHA-256", Digest: rec.SHA256},
			SourceAssertedAt: wireTime(rec.Ended),
			ImportBatch:      src.batch,
			ImportedAt:       wireTime(src.importedAt),
			TimeRung:         emit.TimeRungSelfAttested,
		},
	}
	if v.reason {
		// The spec's reason object: machine-readable members only, never the
		// outcome's human detail, so two producers stating the same outcome
		// commit the same digest.
		if in.Disposition.ReasonDigest, err = emit.DigestJSON(map[string]any{"plimsoll_outcome": outcomeWord(o)}); err != nil {
			return emit.Input{}, fmt.Errorf("reason digest: %w", err)
		}
	}
	if parent != "" {
		in.Chain = &emit.Chain{ParentCapsuleID: parent, Relation: chainFollows}
	}
	return in, nil
}

// wireTime writes a time the way the emitter writes a capsule's own timestamp
// (whole seconds carry no fraction, anything else six digits), so the capsule's
// time fields agree in form as well as in instant.
func wireTime(t time.Time) string {
	u := t.UTC().Truncate(time.Microsecond)
	if u.Nanosecond() == 0 {
		return u.Format(time.RFC3339)
	}
	return u.Format("2006-01-02T15:04:05.000000Z")
}

// runtime is the record's evidence about what ran the code, in one line.
func runtime(rec sandbox.RunRecord) string {
	parts := []string{"plimsoll", "provider=" + rec.Provider, "isolation=" + rec.Isolation}
	for _, f := range []struct{ k, v string }{
		{"environment", rec.Environment}, {"software", rec.SoftwareIdentity}, {"policy", rec.Policy},
	} {
		if f.v != "" {
			parts = append(parts, f.k+"="+f.v)
		}
	}
	return strings.Join(parts, " ")
}

// jsonDigest is the capsule's JSON digest of a protobuf message: its protobuf
// JSON mapping, canonicalized by the emitter. Bytes fields are base64 in that
// mapping. A double that is NaN becomes the string "NaN", so two NaNs with
// different payloads share a digest here; plimsoll's own record digest does not
// have that loss (see README).
func jsonDigest(m proto.Message) (string, error) {
	b, err := protojson.Marshal(m)
	if err != nil {
		return "", err
	}
	// UseNumber keeps each number's text, so no value passes through a float64.
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return "", err
	}
	return emit.DigestJSON(v)
}

// chainFollows is draft -05's default relation for an ordinary sequential record:
// ordering only, no claim about the parent. capsule-emit-go v0.2.0 has no named
// constant for it, though its registry data lists it.
const chainFollows emit.ChainRelation = "follows"
