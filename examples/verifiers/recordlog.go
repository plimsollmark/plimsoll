package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/plimsollmark/plimsoll/record"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// logEntry is one line of the record log plimsoll_client.verifiers_runtime writes: a
// session's open, one call's checked record, or the session's close.
type logEntry struct {
	Kind             string     `json:"kind"`
	Op               string     `json:"op"`
	Record           *logRecord `json:"record"`
	Session          string     `json:"session"`
	Calls            *int       `json:"calls"`
	LastRecordSHA256 string     `json:"last_record_sha256"`
	End              string     `json:"end"`
	Error            string     `json:"error"`
	Isolation        string     `json:"isolation"`
	Provider         string     `json:"provider"`
	Runtime          string     `json:"runtime"`
	TimeUnixMs       int64      `json:"time_unix_ms"`
}

// logRecord is a run record in the field names the Python client writes, which are the
// wire message's.
type logRecord struct {
	Version          int    `json:"version"`
	RequestSHA256    string `json:"request_sha256"`
	ResultSHA256     string `json:"result_sha256"`
	Provider         string `json:"provider"`
	Isolation        string `json:"isolation"`
	Environment      string `json:"environment"`
	SoftwareIdentity string `json:"software_identity"`
	SoftwareRuleID   string `json:"software_rule_id"`
	Policy           string `json:"policy"`
	StartedUnixMs    int64  `json:"started_unix_ms"`
	EndedUnixMs      int64  `json:"ended_unix_ms"`
	Session          string `json:"session"`
	Sequence         uint64 `json:"sequence"`
	PreviousSHA256   string `json:"previous_sha256"`
	Unanswered       string `json:"unanswered"`
	Instance         string `json:"instance"`
	SHA256           string `json:"sha256"`
}

func (r logRecord) runRecord() sandbox.RunRecord {
	return sandbox.RunRecord{
		Version: r.Version, RequestSHA256: r.RequestSHA256, ResultSHA256: r.ResultSHA256,
		Provider: r.Provider, Isolation: r.Isolation, Environment: r.Environment,
		SoftwareIdentity: r.SoftwareIdentity, SoftwareRuleID: r.SoftwareRuleID, Policy: r.Policy,
		Started: time.UnixMilli(r.StartedUnixMs).UTC(), Ended: time.UnixMilli(r.EndedUnixMs).UTC(),
		Session: r.Session, Sequence: r.Sequence, PreviousSHA256: r.PreviousSHA256,
		Unanswered: r.Unanswered, Instance: r.Instance, SHA256: r.SHA256,
	}
}

// logCheck is what a record log shows when it rechecks: the same counts the Python
// client's check_record_log returns, so the two checkers can be compared field by field.
type logCheck struct {
	Sessions   int            `json:"sessions"`
	Records    int            `json:"records"`
	Closed     int            `json:"closed"`
	Tiers      map[string]int `json:"tiers"`
	Incomplete []string       `json:"incomplete"`
}

// chainCall is one record of a log as the page draws it.
type chainCall struct {
	Session  string `json:"session"` // the session fingerprint, as the record names it
	Sequence uint64 `json:"sequence"`
	Op       string `json:"op"`
	Tier     string `json:"tier"`
	SHA256   string `json:"sha256"`
	Started  int64  `json:"started_unix_ms"`
	Millis   int64  `json:"millis"`
}

// checkRecordLog rechecks a record log with nothing but the file and this repository's
// Go record package, independently of the Python client that wrote it: every record's
// own digest recomputed (record.CheckStored), every session's chain unbroken (calls 1, 2,
// 3, each naming the one before), each close's call count and last record equal to the
// chain's, every tier at or above floor. A session with no successful close is listed as
// incomplete, not refused, as the Python checker does. It returns the counts and every
// record in log order.
func checkRecordLog(raw []byte, floor string) (logCheck, []chainCall, error) {
	min := sandbox.ParseIsolationClass(floor)
	if floor != "" && min == sandbox.IsolationUnknown {
		return logCheck{}, nil, fmt.Errorf("floor %q is not a tier", floor)
	}
	chains := map[string][]logRecord{}
	var order []string
	closed := map[string]bool{}
	closeErr := map[string]string{}
	check := logCheck{Tiers: map[string]int{}, Incomplete: []string{}}
	var calls []chainCall
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		dec := json.NewDecoder(bytes.NewReader(line))
		dec.DisallowUnknownFields()
		var e logEntry
		if err := dec.Decode(&e); err != nil {
			return logCheck{}, nil, fmt.Errorf("line %d: %w", n, err)
		}
		switch e.Kind {
		case "open":
			if _, ok := chains[e.Session]; !ok {
				chains[e.Session] = nil
				order = append(order, e.Session)
			}
		case "record":
			if e.Record == nil {
				return logCheck{}, nil, fmt.Errorf("line %d: a record line without a record", n)
			}
			r := *e.Record
			if err := record.CheckStored(r.runRecord()); err != nil {
				return logCheck{}, nil, fmt.Errorf("line %d: %w", n, err)
			}
			chain, seen := chains[r.Session]
			if !seen {
				order = append(order, r.Session)
			}
			previous := ""
			if len(chain) > 0 {
				previous = chain[len(chain)-1].SHA256
			}
			if r.Sequence != uint64(len(chain)+1) || r.PreviousSHA256 != previous {
				return logCheck{}, nil, fmt.Errorf("line %d: session %.12s call %d does not follow the log's call %d", n, r.Session, r.Sequence, len(chain))
			}
			if floor != "" && !sandbox.ParseIsolationClass(r.Isolation).Meets(min) {
				return logCheck{}, nil, fmt.Errorf("line %d: tier %q is below %s", n, r.Isolation, floor)
			}
			chains[r.Session] = append(chain, r)
			check.Tiers[r.Isolation]++
			calls = append(calls, chainCall{Session: r.Session, Sequence: r.Sequence, Op: e.Op, Tier: r.Isolation,
				SHA256: r.SHA256, Started: r.StartedUnixMs, Millis: r.EndedUnixMs - r.StartedUnixMs})
		case "close":
			if e.Calls == nil {
				closeErr[e.Session] = e.Error
				if closeErr[e.Session] == "" {
					closeErr[e.Session] = "the close failed"
				}
				continue
			}
			chain := chains[e.Session]
			last := ""
			if len(chain) > 0 {
				last = chain[len(chain)-1].SHA256
			}
			if *e.Calls != len(chain) || e.LastRecordSHA256 != last {
				return logCheck{}, nil, fmt.Errorf("line %d: the daemon closed session %.12s after %d calls, the log holds %d", n, e.Session, *e.Calls, len(chain))
			}
			check.Closed++
			closed[e.Session] = true
		default:
			return logCheck{}, nil, fmt.Errorf("line %d: unknown kind %q", n, e.Kind)
		}
	}
	if err := sc.Err(); err != nil {
		return logCheck{}, nil, err
	}
	for _, s := range order {
		check.Records += len(chains[s])
		if !closed[s] {
			reason := closeErr[s]
			if reason == "" {
				reason = "no close in the log"
			}
			check.Incomplete = append(check.Incomplete, fmt.Sprintf("%.12s: %s", s, reason))
		}
	}
	check.Sessions = len(order)
	sort.Strings(check.Incomplete)
	return check, calls, nil
}

// checkRecordFile is checkRecordLog over a file.
func checkRecordFile(path, floor string) (logCheck, []chainCall, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return logCheck{}, nil, err
	}
	c, calls, err := checkRecordLog(raw, floor)
	if err != nil {
		return logCheck{}, nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, calls, nil
}
