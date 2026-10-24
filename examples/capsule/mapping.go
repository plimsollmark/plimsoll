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
// the capsule commits a reason. setup_failed, runner_failed and protocol_error
// share a class and a status, and a dispatched effect carries no response digest, so without
// the reason nothing in the capsule would tell them apart.
type verdict struct {
	class  emit.VerdictClass
	status emit.EffectStatus
	reason bool
}

// verdicts is the mapping of an answered call, as data. Every run plimsoll
// answered was dispatched, so no row derives effect_mode not_applicable: blocked
// and denied belong to refusals, and a refusal carries no run record today.
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
	plimsollv1.ProjectOutcome_PROJECT_OUTCOME_RUNNER_FAILED:  {emit.VerdictErrored, emit.EffectDispatched, true},
}

// unanswered is the verdict of a session call that may have run but got no
// answer (a record with no result and an error code): the daemon dispatched it and reports no result,
// which is the capsule's errored class (ran and threw, state unknown) with a
// dispatched effect. The reason object carries the error's status code.
var unanswered = verdict{emit.VerdictErrored, emit.EffectDispatched, true}

// outcome reads one outcome from a snippet, a cell or a project run. A snippet
// and a cell have no outcome field: each timed out or completed, and its exit
// code is part of its result. A module run is refused: its request (end_time,
// step) and its outputs are doubles, and draft -05 forbids JSON floating-point
// values in digest-bearing material (Section 2). The emitter refuses most of
// them, but it reads a double written as an integer as an integer and digests
// -0 as 0 (RFC 8785, Appendix B), so a capsule could still be made for some
// module runs, against the rule and without binding the sign of a zero output.
func outcome(resp *plimsollv1.RunResponse) (plimsollv1.ProjectOutcome, error) {
	switch r := resp.GetResult().(type) {
	case *plimsollv1.RunResponse_Javascript:
		if r.Javascript.GetTimedOut() {
			return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT, nil
		}
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, nil
	case *plimsollv1.RunResponse_Cell:
		if r.Cell.GetTimedOut() {
			return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_TIMED_OUT, nil
		}
		return plimsollv1.ProjectOutcome_PROJECT_OUTCOME_COMPLETED, nil
	case *plimsollv1.RunResponse_Project:
		return r.Project.GetOutcome(), nil
	case *plimsollv1.RunResponse_Module:
		return 0, fmt.Errorf("a module run cannot be stated under draft -05: its request and result carry floating-point values, which the spec forbids in digest-bearing material")
	}
	return 0, fmt.Errorf("response carries no result")
}

// grantProfile is the host-API grant a request names, or "" for an isolated run.
// A cell carries no grant.
func grantProfile(req *plimsollv1.RunRequest) string {
	if p := req.GetJavascript().GetGrantProfile(); p != "" {
		return p
	}
	return req.GetProject().GetGrantProfile()
}

// source names what one import read, so every capsule it makes can say where
// it came from and when.
type source struct {
	operator   string
	developer  string
	batch      string // the bundle's own digest
	importedAt time.Time
	published  bool // the published bundle, whose story the page tells
}

// recordRefType is the source_ref type for a plimsoll run record. It is not in
// the capsule registry; the spec reads an unregistered type as informational.
const recordRefType = "plimsoll-run-record"

// effectType is the effect type for a sandboxed code run. Also unregistered: the
// seeded types are write_order, send_payment and inference_completion.
const effectType = "code_execution"

// capsuleInput states one verified run record as a capsule. rec must be the
// record plimsoll's verifier accepted for req and resp; for an unanswered call
// (rec.Unanswered set) there is no response and resp is nil. parent is the
// previous call's capsule ID, or "" for a single run or a session's first call.
func capsuleInput(rec sandbox.RunRecord, req *plimsollv1.RunRequest, resp *plimsollv1.RunResponse, parent string, src source) (emit.Input, error) {
	// An import cannot precede what it imports, and one stamped at the same instant
	// is the shape the spec's verifier refuses as laundering an import into a
	// contemporaneous record.
	if !src.importedAt.After(rec.Ended) {
		return emit.Input{}, fmt.Errorf("import time %s does not follow the record's time %s", wireTime(src.importedAt), wireTime(rec.Ended))
	}
	// A granted call's code can reach a host API with PUT, POST or DELETE, and the
	// response carries no call trace (it stays in the daemon), so nothing here can
	// tell what the call did outside the sandbox. The irreversibility class is an
	// ordered enumeration with no "unknown" value, so a granted call is refused
	// rather than given a class by guesswork.
	if p := grantProfile(req); p != "" {
		return emit.Input{}, fmt.Errorf("a call granted %q cannot be stated: its code could reach a host API with PUT, POST or DELETE, and the response carries no call trace, so its irreversibility class is unknown", p)
	}
	v := unanswered
	reason := map[string]any{"plimsoll_unanswered": rec.Unanswered}
	if rec.Unanswered == "" {
		o, err := outcome(resp)
		if err != nil {
			return emit.Input{}, err
		}
		var ok bool
		if v, ok = verdicts[o]; !ok {
			return emit.Input{}, fmt.Errorf("outcome %v has no capsule verdict", o)
		}
		reason = map[string]any{"plimsoll_outcome": outcomeWord(o)}
	} else if resp != nil {
		return emit.Input{}, fmt.Errorf("an unanswered call has no response to state")
	}
	reqDigest, err := jsonDigest(req)
	if err != nil {
		return emit.Input{}, fmt.Errorf("request digest: %w", err)
	}
	effect := &emit.Effect{
		Type:   effectType,
		Status: v.status,
		// Every call stated here ran with no grant (refused above), so whatever it
		// did stayed inside the sandbox, where the next call can overwrite it: the
		// lowest of the draft's four classes.
		IrreversibilityClass: emit.IrreversibilityTwoWay,
		// This program read a signed record afterwards and observed nothing itself.
		// The record is the daemon's statement, checked against the bytes by the
		// harness, which is the draft's "the executing runtime asserted completion;
		// the capsule records that claim, not an observation". Whether a collector
		// restating a gate's signed record may carry gate_executed instead is Q1 to
		// the draft's author, unanswered; the lower grade is what this program can
		// vouch for, and the draft reads an unrecognized grade as no stronger.
		EffectAttestation: emit.AttestationRuntimeClaimed,
		RequestDigest:     reqDigest,
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
		if in.Disposition.ReasonDigest, err = emit.DigestJSON(reason); err != nil {
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
// mapping, and 64-bit integers decimal strings. No double reaches it: only a
// module run carries one, and outcome refuses a module run before this is called.
// The mapping is the one the protobuf library produces for the schema this
// program was compiled with (a field that schema does not know is dropped), so
// these digests are reproducible with this program and its schema, not from a
// specification; plimsoll's own record digests are the specified ones.
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
