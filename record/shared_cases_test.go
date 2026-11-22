package record_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/internal/clientcases"
	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// sharedVectors is the part of record/testdata/golden.json and each published file this
// runner reads: every input with what the file states of it.
type sharedVectors struct {
	Requests []struct {
		Name, Kind, SHA256 string
		Request            json.RawMessage
	} `json:"requests"`
	Results []struct {
		Name, SHA256 string
		Response     json.RawMessage
	} `json:"results"`
	Records []struct {
		Name, SHA256 string
		Record       json.RawMessage
	} `json:"records"`
	SessionFingerprints []struct {
		Name, SessionID, SHA256 string
	} `json:"sessionFingerprints"`
	Refused []struct {
		Name, SHA256, Why string
		Record            json.RawMessage
	} `json:"refused"`
	Malformed []struct {
		Name, Why string
		Record    json.RawMessage
	} `json:"malformed"`
	Qualifications []struct {
		Name, Text string
		Valid      bool
	} `json:"qualifications"`
	Meets []struct {
		Tier, Floor string
		Meets       bool
	} `json:"meets"`
}

// TestSharedCases is the Go client's runner for the shared cases on the record package's
// paths (internal/clientcases): every digest vector of golden.json and the published
// files, the records every reader must refuse or read, the qualification and tier rows,
// and the record cases of internal/clientcases/testdata/records.json on the stored and
// session-unanswered paths. Each verdict is asserted here and judged at the end against
// what the files state, so a case this runner skips fails as surely as a wrong one.
func TestSharedCases(t *testing.T) {
	var vs []clientcases.Verdict
	say := func(id, path string, says any) { vs = append(vs, clientcases.Say(id, path, says)) }

	read := func(rel string) sharedVectors {
		b, err := os.ReadFile(filepath.Join("..", rel))
		if err != nil {
			t.Fatal(err)
		}
		var v sharedVectors
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		return v
	}
	decode := func(raw json.RawMessage) (*plimsollv1.RunRecord, error) {
		m := &plimsollv1.RunRecord{}
		return m, protojson.Unmarshal(raw, m)
	}
	vectors := func(prefix string, v sharedVectors) {
		for _, r := range v.Requests {
			var got string
			switch r.Kind {
			case "run":
				m := &plimsollv1.RunRequest{}
				if err := protojson.Unmarshal(r.Request, m); err != nil {
					t.Fatalf("%s%s: %v", prefix, r.Name, err)
				}
				got = record.RunRequestDigest(m)
			case "session":
				m := &plimsollv1.SessionRunRequest{}
				if err := protojson.Unmarshal(r.Request, m); err != nil {
					t.Fatalf("%s%s: %v", prefix, r.Name, err)
				}
				got = record.SessionRunRequestDigest(m)
			default:
				t.Fatalf("%s%s: unknown kind %q", prefix, r.Name, r.Kind)
			}
			say(prefix+"requests/"+r.Name, clientcases.PathDigest, got)
		}
		for _, r := range v.Results {
			m := &plimsollv1.RunResponse{}
			if err := protojson.Unmarshal(r.Response, m); err != nil {
				t.Fatalf("%s%s: %v", prefix, r.Name, err)
			}
			say(prefix+"results/"+r.Name, clientcases.PathDigest, record.ResultDigest(m))
		}
		for _, r := range v.Records {
			m, err := decode(r.Record)
			if err != nil {
				t.Fatalf("%s%s: %v", prefix, r.Name, err)
			}
			rec := record.FromWire(m)
			say(prefix+"records/"+r.Name, clientcases.PathDigest, record.Digest(rec))
			rec.SHA256 = r.SHA256
			say(prefix+"records/"+r.Name+"/check", clientcases.PathStored, clientcases.SaysOf(record.CheckStored(rec)))
		}
		for _, f := range v.SessionFingerprints {
			say(prefix+"sessionFingerprints/"+f.Name, clientcases.PathDigest, record.SessionFingerprint(f.SessionID))
		}
	}

	g := read("record/testdata/golden.json")
	vectors("golden/", g)
	for _, r := range g.Refused {
		m, err := decode(r.Record)
		if err != nil {
			t.Fatalf("%s: %v", r.Name, err)
		}
		rec := record.FromWire(m)
		rec.SHA256 = r.SHA256
		say("golden/refused/"+r.Name, clientcases.PathStored, clientcases.SaysOf(record.CheckStored(rec)))
	}
	for _, r := range g.Malformed {
		got := "accept"
		if _, err := decode(r.Record); err != nil {
			got = "may_have_run/malformed"
		}
		say("golden/malformed/"+r.Name, clientcases.PathDecode, got)
	}
	for _, q := range g.Qualifications {
		say("golden/qualifications/"+q.Name, clientcases.PathQualification, map[bool]string{true: "valid", false: "invalid"}[record.ValidQualification(q.Text)])
	}
	for _, m := range g.Meets {
		meets := sandbox.ParseIsolationClass(m.Tier).Meets(sandbox.ParseIsolationClass(m.Floor))
		say(clientcases.MeetsID(m.Tier, m.Floor), clientcases.PathMeets, map[bool]string{true: "meets", false: "below"}[meets])
	}
	published, err := filepath.Glob("testdata/published/*-golden.json")
	if err != nil || len(published) == 0 {
		t.Fatalf("no published vectors: %v", err)
	}
	for _, f := range published {
		vectors(clientcases.PublishedPrefix(filepath.Base(f)), read("record/"+f))
	}

	for _, c := range readRecordCases(t) {
		m, err := decode(c.Input.Record)
		if err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		req := &plimsollv1.SessionRunRequest{}
		if err := protojson.Unmarshal(c.Input.Request, req); err != nil {
			t.Fatalf("%s: %v", c.ID, err)
		}
		// The digests the case states were computed by the independent implementation;
		// this one must agree, or the case tests something other than it says.
		if got := record.SessionRunRequestDigest(req); got != c.Input.RequestSHA256 {
			t.Fatalf("%s: the request digests to %s here, the case states %s", c.ID, got, c.Input.RequestSHA256)
		}
		if got := record.Digest(record.FromWire(m)); got != m.GetRecordSha256() {
			t.Fatalf("%s: the record digests to %s here, the case states %s", c.ID, got, m.GetRecordSha256())
		}
		for _, p := range c.Paths {
			switch p {
			case clientcases.PathStored:
				say(c.ID, p, clientcases.SaysOf(record.CheckStored(record.FromWire(m))))
			case clientcases.PathSessionUnanswered:
				_, err := record.CheckUnanswered(req, m, c.Input.Chain.Session, c.Input.Chain.Calls, c.Input.Chain.Last)
				say(c.ID, p, clientcases.SaysOf(err))
			}
		}
	}

	a, err := clientcases.Load("..")
	if err != nil {
		t.Fatal(err)
	}
	clientcases.Judge(t, a, "go", vs, "record/shared_cases_test.go")
}

// recordCase is a case of internal/clientcases/testdata/records.json, as a runner reads it.
type recordCase struct {
	ID    string   `json:"id"`
	Paths []string `json:"paths"`
	Input struct {
		Request       json.RawMessage `json:"request"`
		RequestSHA256 string          `json:"requestSha256"`
		Record        json.RawMessage `json:"record"`
		Chain         struct {
			Session string `json:"session"`
			Calls   uint64 `json:"calls,string"`
			Last    string `json:"last"`
		} `json:"chain"`
	} `json:"input"`
}

func readRecordCases(t *testing.T) []recordCase {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", clientcases.RecordsFile))
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Cases []recordCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	if len(f.Cases) == 0 {
		t.Fatal("no record cases")
	}
	return f.Cases
}
