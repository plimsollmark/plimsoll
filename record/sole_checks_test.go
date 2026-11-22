package record

import (
	"errors"
	"strings"
	"testing"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// A request whose software rule no daemon accepts (exact with two identities, a repeated
// identity) has no record that checks, though the record's rule ID and selected software
// agree with the rule as written. This is the one test of check's rule.Validate
// (hunt-quality-29): without it, the record of a request no daemon would run passes.
func TestARequestWithAnInvalidSoftwareRuleHasNoRecord(t *testing.T) {
	a := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("a", 64)
	b := "oci-manifest:linux/amd64@sha256:" + strings.Repeat("b", 64)
	for name, rule := range map[string]*plimsollv1.SoftwareRule{
		"exact with two identities": {Mode: "exact", Identities: []string{a, b}},
		"a repeated identity":       {Mode: "approved", Identities: []string{a, a}},
	} {
		req := &plimsollv1.RunRequest{Protocol: protocol.Number, SoftwareRule: rule,
			Payload: &plimsollv1.RunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{Code: "1"}}}
		resp := &plimsollv1.RunResponse{Sandbox: "docker", Isolation: "kernel", Environment: "docker-image:sha256:outer", SoftwareIdentity: a,
			Result: &plimsollv1.RunResponse_Javascript{Javascript: &plimsollv1.JavaScriptResult{}}}
		ruleID := sandbox.SoftwareRule{Mode: sandbox.SoftwareMode(rule.GetMode()), Identities: rule.GetIdentities()}.ID()
		resp.Record = Stamp(sandbox.RunRecord{RequestSHA256: RunRequestDigest(req), SoftwareRuleID: ruleID}, resp)
		if _, err := Check(req, resp); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "invalid software rule") {
			t.Errorf("%s: Check: %v, want ErrMismatch for an invalid software rule", name, err)
		}
		if _, err := CheckExchange(req, resp); !errors.Is(err, ErrMismatch) || !strings.Contains(err.Error(), "invalid software rule") {
			t.Errorf("%s: CheckExchange: %v, want ErrMismatch for an invalid software rule", name, err)
		}
	}
}
