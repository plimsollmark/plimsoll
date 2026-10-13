package record

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"math"
	"os"
	"slices"
	"strconv"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// floatVector is one entry of testdata/float-bits.json, written by
// testdata/float_bits.py from docs/run-records.md alone.
type floatVector struct {
	ID            string `json:"id"`
	Domain        string `json:"domain"`
	MustFail      bool   `json:"must_fail"`
	FailureReason string `json:"failure_reason"`
	PreImageHex   string `json:"pre_image_bytes_hex"`
	Digest        string `json:"digest"`
	Input         struct {
		Kind          string `json:"kind"`
		Outcome       int32  `json:"outcome"`
		OutcomeDetail string `json:"outcome_detail"`
		Width         int32  `json:"width"`
		StdoutHex     string `json:"stdout_hex"`
		StderrHex     string `json:"stderr_hex"`
		Runs          []struct {
			Status         int32    `json:"status"`
			OutputsBitsHex []string `json:"outputs_bits_hex"`
		} `json:"runs"`
	} `json:"input"`
}

// response builds the module result a vector describes, each output from its bit
// pattern, so a NaN keeps its payload.
func (v floatVector) response(t *testing.T) *plimsollv1.RunResponse {
	t.Helper()
	in := v.Input
	if in.Kind != "module" {
		t.Fatalf("%s: kind %q, want module", v.ID, in.Kind)
	}
	stdout, err1 := hex.DecodeString(in.StdoutHex)
	stderr, err2 := hex.DecodeString(in.StderrHex)
	if err1 != nil || err2 != nil {
		t.Fatalf("%s: output hex: %v %v", v.ID, err1, err2)
	}
	m := &plimsollv1.ModuleResult{
		Outcome:       plimsollv1.ProjectOutcome(in.Outcome),
		OutcomeDetail: in.OutcomeDetail,
		Width:         in.Width,
		Stdout:        stdout,
		Stderr:        stderr,
	}
	for _, r := range in.Runs {
		row := &plimsollv1.ModuleRowResult{Status: r.Status}
		for _, h := range r.OutputsBitsHex {
			b, err := strconv.ParseUint(h, 16, 64)
			if err != nil || len(h) != 16 {
				t.Fatalf("%s: output bits %q: %v", v.ID, h, err)
			}
			row.Outputs = append(row.Outputs, math.Float64frombits(b))
		}
		m.Runs = append(m.Runs, row)
	}
	return &plimsollv1.RunResponse{Result: &plimsollv1.RunResponse_Module{Module: m}}
}

func TestFloatBitVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/float-bits.json")
	if err != nil {
		t.Fatal(err)
	}
	var file struct {
		Vectors []floatVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatal(err)
	}
	var pass, fail int
	for _, v := range file.Vectors {
		if v.Domain != resultDomain {
			t.Errorf("%s: domain %q, want %q", v.ID, v.Domain, resultDomain)
		}
		pre, err := hex.DecodeString(v.PreImageHex)
		if err != nil {
			t.Fatalf("%s: pre-image hex: %v", v.ID, err)
		}
		if sum := sha256.Sum256(pre); hex.EncodeToString(sum[:]) != v.Digest {
			t.Errorf("%s: the pre-image does not hash to the vector's digest", v.ID)
		}
		got := ResultDigest(v.response(t))
		switch {
		case v.MustFail && v.FailureReason == "":
			t.Errorf("%s: a MUST-FAIL vector names no failure reason", v.ID)
		case v.MustFail && got == v.Digest:
			t.Errorf("%s: the Go implementation reproduced a computation it must not (%s)", v.ID, v.FailureReason)
		case !v.MustFail && got != v.Digest:
			t.Errorf("%s: digest %s, the vector says %s", v.ID, got, v.Digest)
		}
		if v.MustFail {
			fail++
		} else {
			pass++
		}
	}
	if pass == 0 || fail == 0 {
		t.Fatalf("%d positive and %d MUST-FAIL vectors: both directions are required", pass, fail)
	}
}

// A domain string names one encoding for good (docs/run-records.md), and nothing in a
// result says which result domain hashed it. So a payload kind added to RunResponse
// must come with a new result domain and a new record version, not join this one.
func TestResultDomainCoversItsKinds(t *testing.T) {
	if resultDomain != "plimsoll.run-result.v1" {
		t.Fatalf("the result domain is now %s: list the kinds it covers in this test", resultDomain)
	}
	fields := (&plimsollv1.RunResponse{}).ProtoReflect().Descriptor().Oneofs().ByName("result").Fields()
	var kinds []string
	for i := range fields.Len() {
		kinds = append(kinds, string(fields.Get(i).Name()))
	}
	if want := []string{"javascript", "project", "module", "cell"}; !slices.Equal(kinds, want) {
		t.Errorf("RunResponse carries result kinds %v; %s covers exactly %v, so a new kind needs a new result domain and record version", kinds, resultDomain, want)
	}
}
