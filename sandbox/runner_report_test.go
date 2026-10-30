package sandbox

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"reflect"
	"testing"

	"github.com/plimsollmark/plimsoll/sandbox/internal/runnerwire"
)

// reportOwns is every ProjectResult field the runner's report states. Every other field
// is the provider's, and RunnerReport must hand it back as the provider gave it.
var reportOwns = map[string]bool{"Steps": true, "Artifacts": true, "ArtifactsTruncated": true, "Outcome": true, "Detail": true}

// TestRunnerReportKeepsTheProvidersOwnFields: the report fills in what it states and
// nothing else. Before RunnerReport took the provider's result, it returned a fresh one,
// and two providers returned it as it was: the signed record of every completed project
// run on agentsandbox and on openshell named no image (found 2026-10-29). Every field is
// set by reflection, so a field added to ProjectResult later is covered without a change
// here, and a field of a kind this test cannot fill fails it.
func TestRunnerReportKeepsTheProvidersOwnFields(t *testing.T) {
	var base ProjectResult
	v := reflect.ValueOf(&base).Elem()
	for i := 0; i < v.NumField(); i++ {
		f, name := v.Field(i), v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.String:
			f.SetString("provider-" + name)
		case reflect.Int, reflect.Int64:
			f.SetInt(int64(i + 1))
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Pointer:
			f.Set(reflect.New(f.Type().Elem()))
		case reflect.Slice:
			f.Set(reflect.MakeSlice(f.Type(), 1, 1))
		default:
			t.Fatalf("ProjectResult.%s is a %s, which this test does not fill: extend it", name, f.Kind())
		}
	}
	key := make([]byte, runnerwire.KeySize)
	body := `{"steps":[{"command":"node main.js","stdoutBase64":"aGk=","stderrBase64":"","stdoutTruncated":false,"stderrTruncated":false,"exitCode":0,"timedOut":false,"durationMs":5}],"artifacts":[{"path":"out.txt","content":"QUFB"}],"artifactsTruncated":false,"error":"","stepsBegan":false}`
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(body))
	stdout := fmt.Sprintf("\n%s %d %s\n%s", runnerwire.Marker, len(body), hex.EncodeToString(mac.Sum(nil)), body)

	for _, c := range []struct {
		name, stdout string
		reported     bool
	}{
		{"an authenticated report", stdout, true},
		{"no report at all", "the runner wrote nothing", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			res, reported := RunnerReport(base, c.stdout, key)
			if reported != c.reported {
				t.Fatalf("reported %v, want %v", reported, c.reported)
			}
			got := reflect.ValueOf(res)
			for i := 0; i < v.NumField(); i++ {
				name := v.Type().Field(i).Name
				if !reportOwns[name] && !reflect.DeepEqual(got.Field(i).Interface(), v.Field(i).Interface()) {
					t.Errorf("ProjectResult.%s = %v, want the provider's %v", name, got.Field(i).Interface(), v.Field(i).Interface())
				}
			}
			if !c.reported {
				return
			}
			if res.Outcome != ProjectOutcomeCompleted || res.Detail != "" || res.ArtifactsTruncated ||
				len(res.Steps) != 1 || res.Steps[0].Stdout != "hi" || len(res.Artifacts) != 1 || string(res.Artifacts[0].Content) != "AAA" {
				t.Fatalf("the report's own fields: outcome %s, detail %q, truncated %v, steps %+v, artifacts %+v",
					res.Outcome, res.Detail, res.ArtifactsTruncated, res.Steps, res.Artifacts)
			}
		})
	}
}
