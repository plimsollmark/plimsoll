package fleetsim

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

type vendor struct {
	t   *testing.T
	s   *Server
	url string
	tok string
}

func newVendor(t *testing.T, scenario string) *vendor {
	t.Helper()
	s := New(Static("secret-token"))
	s.Reset(scenario)
	srv := httptest.NewServer(s)
	t.Cleanup(srv.Close)
	return &vendor{t: t, s: s, url: srv.URL, tok: "secret-token"}
}

// call sends one request and returns the status and decoded body; status 0 means no
// answer arrived.
func (v *vendor) call(method, path string, body any) (int, map[string]any) {
	v.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, v.url+path, rd)
	req.Header.Set("Authorization", "Bearer "+v.tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (v *vendor) create(robot string, x, y float64, cmd string) (int, map[string]any) {
	body := map[string]any{"target": map[string]float64{"x": x, "y": y}}
	if cmd != "" {
		body["command_id"] = cmd
	}
	return v.call("POST", "/robots/"+robot+"/missions", body)
}

func (v *vendor) status(id string) string {
	_, m := v.call("GET", "/missions/"+id, nil)
	s, _ := m["status"].(string)
	return s
}

func (v *vendor) order(id string) Order {
	for _, o := range v.s.Ledger() {
		if o.ID == id {
			return o
		}
	}
	v.t.Fatalf("no order %s on the ledger", id)
	return Order{}
}

func (v *vendor) noIllegal() {
	v.t.Helper()
	if n := v.s.Illegal(); n != 0 {
		v.t.Fatalf("%d illegal transitions", n)
	}
}

// The review's reproduction: a cancelled queued order must never start when the order
// ahead of it finishes.
func TestCancelledQueuedOrderNeverRuns(t *testing.T) {
	v := newVendor(t, ScenarioNominal)
	v.create("r2", 10, 4, "")
	if code, m := v.create("r2", 20, 4, ""); code != http.StatusCreated || m["status"] != "queued" {
		t.Fatalf("second order: %d %v", code, m)
	}
	if _, m := v.call("POST", "/missions/m2/cancel", nil); m["status"] != "cancelled" {
		t.Fatalf("cancel: %v", m)
	}
	for range 10 {
		v.status("m1")
	}
	if v.status("m1") != "done" {
		t.Fatal("m1 did not finish")
	}
	for range 5 {
		if s := v.status("m2"); s != "cancelled" {
			t.Fatalf("cancelled m2 became %s", s)
		}
	}
	if h := v.order("m2").History; !slices.Equal(h, []string{"queued", "cancelled"}) {
		t.Fatalf("m2 history %v", h)
	}
	if v.order("m2").Steps != 0 {
		t.Fatal("the robot moved under a cancelled order")
	}
	v.noIllegal()
}

func TestCancelRunningStopsAndStartsTheNext(t *testing.T) {
	v := newVendor(t, ScenarioNominal)
	v.create("r1", 5, 0, "")
	v.create("r1", 5, 3, "")
	v.status("m1")
	v.call("POST", "/missions/m1/cancel", nil)
	m1 := v.order("m1")
	if m1.Status != "cancelled" || m1.StoppedAt == nil || m1.StoppedAt.X != 1 {
		t.Fatalf("m1 = %+v", m1)
	}
	if v.status("m2") != "running" {
		t.Fatal("the next queued order did not start")
	}
	// Cancelling a finished order changes nothing.
	for range 10 {
		v.status("m2")
	}
	v.call("POST", "/missions/m2/cancel", nil)
	if o := v.order("m2"); o.Status != "done" || *o.StoppedAt != (Pose{5, 3}) {
		t.Fatalf("m2 = %+v", o)
	}
	v.noIllegal()
}

func TestCommandIDNamesOneOrder(t *testing.T) {
	v := newVendor(t, ScenarioNominal)
	code, first := v.create("r1", 3, 0, "cmd-000001")
	if code != http.StatusCreated {
		t.Fatalf("create: %d", code)
	}
	for range 5 {
		v.status("m1")
	}
	// Repeated after the order finished: the same order, still one on the ledger.
	code, again := v.create("r1", 3, 0, "cmd-000001")
	if code != http.StatusOK || again["mission_id"] != first["mission_id"] || again["status"] != "done" {
		t.Fatalf("repeat: %d %v", code, again)
	}
	if code, _ := v.create("r1", 4, 0, "cmd-000001"); code != http.StatusConflict {
		t.Fatalf("another target under the same command_id: %d", code)
	}
	if code, _ := v.create("r2", 3, 0, "cmd-000001"); code != http.StatusConflict {
		t.Fatalf("another robot under the same command_id: %d", code)
	}
	if code, _ := v.create("r1", 3, 0, "bad id"); code != http.StatusBadRequest {
		t.Fatalf("malformed command_id: %d", code)
	}
	if n := v.s.Orders()["r1"]; n != 1 {
		t.Fatalf("r1 has %d orders", n)
	}
	if o := v.order("m1"); o.CommandID != "cmd-000001" {
		t.Fatalf("ledger lost the command_id: %+v", o)
	}
}

func TestFaultFailsTheOrderAndTheQueue(t *testing.T) {
	v := newVendor(t, ScenarioFault)
	v.create("r2", 10, 4, "")
	v.create("r2", 10, 8, "")
	for range FaultAtStep {
		v.status("m1")
	}
	if a, b := v.order("m1"), v.order("m2"); a.Status != "failed" || b.Status != "failed" || b.Steps != 0 {
		t.Fatalf("m1 %+v, m2 %+v", a, b)
	}
	if code, _ := v.create("r2", 1, 1, ""); code != http.StatusConflict {
		t.Fatalf("a faulted robot took an order: %d", code)
	}
	v.noIllegal()
}

func TestLostAndDroppedAnswersStillPlaceTheOrder(t *testing.T) {
	v := newVendor(t, ScenarioLostAck)
	if code, _ := v.create("r2", 10, 4, "cmd-lost-01"); code != http.StatusServiceUnavailable {
		t.Fatalf("lost answer: %d", code)
	}
	if code, m := v.create("r2", 10, 4, "cmd-lost-01"); code != http.StatusOK || m["mission_id"] != "m1" {
		t.Fatalf("repeat after a lost answer: %d %v", code, m)
	}
	v = newVendor(t, ScenarioDropped)
	if code, _ := v.create("r2", 10, 4, "cmd-drop-01"); code != 0 {
		t.Fatalf("dropped connection answered %d", code)
	}
	if o := v.order("m1"); o.Status != "running" || o.CommandID != "cmd-drop-01" {
		t.Fatalf("dropped: %+v", o)
	}
	if code, _ := v.create("r1", 3, 0, ""); code != http.StatusCreated {
		t.Fatalf("the drop is one order only: %d", code)
	}
}

func TestOverloadRefusesTheNextRequests(t *testing.T) {
	v := newVendor(t, ScenarioOverload)
	v.create("r1", 3, 0, "")
	for range DegradedRequests {
		if code, _ := v.call("GET", "/health", nil); code != http.StatusServiceUnavailable {
			t.Fatalf("degraded vendor answered %d", code)
		}
	}
	if code, _ := v.call("GET", "/health", nil); code != http.StatusOK || v.s.Refused() != DegradedRequests {
		t.Fatalf("recovered: %d, refused %d", code, v.s.Refused())
	}
}

func jwt(secret string, claims map[string]any) string {
	enc := base64.RawURLEncoding
	h, _ := json.Marshal(map[string]string{"alg": "HS256", "typ": "JWT"})
	c, _ := json.Marshal(claims)
	s := enc.EncodeToString(h) + "." + enc.EncodeToString(c)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(s))
	return s + "." + enc.EncodeToString(mac.Sum(nil))
}

func TestHS256(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	auth := HS256([]byte("k"), "fleet-vendor")
	good := map[string]any{"sub": "caller", "aud": "fleet-vendor", "jti": "j1", "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Unix() + 95}
	c, err := auth.Check("Bearer "+jwt("k", good), now)
	if err != nil || c != (Credential{ID: "j1", Subject: "caller", LifetimeSeconds: 95}) {
		t.Fatalf("valid token: %+v %v", c, err)
	}
	with := func(k string, val any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		m[k] = val
		return m
	}
	none := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + strings.Split(jwt("k", good), ".")[1] + "."
	for label, header := range map[string]string{
		"wrong key":      "Bearer " + jwt("other", good),
		"wrong audience": "Bearer " + jwt("k", with("aud", "someone-else")),
		"expired":        "Bearer " + jwt("k", with("exp", now.Unix())),
		"not yet valid":  "Bearer " + jwt("k", with("nbf", now.Unix()+60)),
		"no jti":         "Bearer " + jwt("k", with("jti", "")),
		"alg none":       "Bearer " + none,
		"not a jwt":      "Bearer abc",
		"no bearer":      jwt("k", good),
	} {
		if _, err := auth.Check(header, now); err == nil {
			t.Errorf("%s: accepted", label)
		}
	}
}

func TestCredentialsAreRecordedOncePerID(t *testing.T) {
	s := New(Static("t0ken"))
	srv := httptest.NewServer(s)
	defer srv.Close()
	for range 3 {
		req, _ := http.NewRequest("GET", srv.URL+"/health", nil)
		req.Header.Set("Authorization", "Bearer t0ken")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if c := s.Credentials(); len(c) != 1 || c[0].ID != "static" {
		t.Fatalf("credentials %+v", c)
	}
	s.Reset(ScenarioNominal)
	if len(s.Credentials()) != 0 {
		t.Fatal("Reset kept the credentials")
	}
}

// The event log agrees with the ledger: where a robot's last event left it is where its
// order stopped, the fault included (it faults on the read, before moving).
func TestEventsAgreeWithTheLedger(t *testing.T) {
	v := newVendor(t, ScenarioFault)
	v.create("r2", 10, 4, "cmd-fault-01")
	for range 3 {
		v.status("m1")
	}
	o := v.order("m1")
	if o.Status != "failed" || *o.StoppedAt != (Pose{10, 1}) {
		t.Fatalf("m1 = %+v", o)
	}
	events, lost := v.s.Events()
	var kinds []string
	var last *Pose
	for _, e := range events {
		kinds = append(kinds, e.Kind)
		if e.Robot == "r2" && e.Pose != nil {
			last = e.Pose
		}
	}
	if want := []string{"order", "start", "move", "fault"}; !slices.Equal(kinds, want) || lost != 0 {
		t.Fatalf("events %v (lost %d), want %v", kinds, lost, want)
	}
	if *last != *o.StoppedAt {
		t.Fatalf("the events leave r2 at %v, the ledger at %v", *last, *o.StoppedAt)
	}
	if r := v.s.Robots(); r[1].ID != "r2" || r[1].Status != "fault" || r[1].Pose != (Pose{10, 1}) {
		t.Fatalf("robots %+v", r)
	}
}

func TestServerErrorAfterAccepting(t *testing.T) {
	v := newVendor(t, ScenarioServerError)
	if code, _ := v.create("r2", 10, 4, "cmd-500-0001"); code != http.StatusInternalServerError {
		t.Fatalf("answer %d, want 500", code)
	}
	if o := v.order("m1"); o.Status != "running" {
		t.Fatalf("the order was not placed: %+v", o)
	}
	if code, m := v.create("r2", 10, 4, "cmd-500-0001"); code != http.StatusOK || m["mission_id"] != "m1" {
		t.Fatalf("repeat: %d %v", code, m)
	}
}

// In the refused scenario r3 is in fault from the start: the vendor lists it so,
// answers an order for it with 409 and places none, and logs both.
func TestRefusedScenarioRefusesTheFaultedRobot(t *testing.T) {
	v := newVendor(t, ScenarioRefused)
	if code, _ := v.create("r3", 0, 15, "run01-c3"); code != http.StatusConflict {
		t.Fatalf("an order for the robot in fault answered %d, want 409", code)
	}
	if code, _ := v.create("r1", 3, 0, "run01-c1"); code != http.StatusCreated {
		t.Fatalf("an order for an idle robot answered %d", code)
	}
	if n := len(v.s.Ledger()); n != 1 {
		t.Fatalf("the ledger holds %d orders, want 1 (r3's refused)", n)
	}
	for _, r := range v.s.Robots() {
		if want := map[string]string{"r1": "moving", "r2": "idle", "r3": "fault"}[r.ID]; r.Status != want {
			t.Errorf("%s is %s, want %s", r.ID, r.Status, want)
		}
	}
	events, _ := v.s.Events()
	if len(events) == 0 || events[0].Kind != "out_of_service" || events[0].Robot != "r3" || !slices.ContainsFunc(events, func(e Event) bool { return e.Kind == "rejected" && e.Robot == "r3" }) {
		t.Errorf("events %+v: want out_of_service for r3 first and a rejected order", events)
	}
}

// The vendor counts every status read of a mission, a refused one included, and forgets
// them at a reset: the count the read budget is held to.
func TestStatusReadsAreCountedPerMission(t *testing.T) {
	v := newVendor(t, ScenarioOverload)
	_, m := v.create("r1", 3, 0, "")
	id, _ := m["mission_id"].(string)
	for range DegradedRequests + 2 {
		v.call("GET", "/missions/"+id, nil)
	}
	v.call("GET", "/robots", nil)
	if got := v.s.Reads(); got[id] != DegradedRequests+2 || len(got) != 1 {
		t.Fatalf("reads %v, want %d of %s", got, DegradedRequests+2, id)
	}
	v.s.Reset(ScenarioNominal)
	if got := v.s.Reads(); len(got) != 0 {
		t.Errorf("a reset kept the reads: %v", got)
	}
}

// In the silent scenario r2's first order is accepted, started and answered 504, and then
// nothing about r2 is answered or done: a repeat, a new order, a read of r2, a read or a
// cancel of its order. The fleet list, health and the other robots are answered, the reads
// of r2's order are still counted, and the order keeps running on the list's ticks alone.
func TestSilentScenarioAnswersNothingAboutTheRobot(t *testing.T) {
	v := newVendor(t, ScenarioSilent)
	if code, _ := v.create("r2", 10, 4, "run01-c2"); code != http.StatusGatewayTimeout {
		t.Fatalf("the first order answered %d, want 504", code)
	}
	if o := v.order("m1"); o.Status != "running" || o.CommandID != "run01-c2" {
		t.Fatalf("the order was not placed and started: %+v", o)
	}
	for _, c := range []struct{ method, path string }{
		{"GET", "/robots/r2"}, {"GET", "/missions/m1"}, {"POST", "/missions/m1/cancel"},
	} {
		if code, _ := v.call(c.method, c.path, nil); code != http.StatusGatewayTimeout {
			t.Errorf("%s %s answered %d, want 504", c.method, c.path, code)
		}
	}
	if code, _ := v.create("r2", 10, 4, "run01-c2"); code != http.StatusGatewayTimeout {
		t.Errorf("a repeat answered %d, want 504", code)
	}
	if code, _ := v.create("r2", 10, 4, "run01-c2-again"); code != http.StatusGatewayTimeout {
		t.Errorf("a new order for r2 answered %d, want 504", code)
	}
	if n := len(v.s.Ledger()); n != 1 {
		t.Fatalf("the ledger holds %d orders, want 1: nothing after the first is done", n)
	}
	if o := v.order("m1"); o.Status != "running" || o.Steps != 0 {
		t.Fatalf("an unanswered read or cancel changed the order: %+v", o)
	}
	if code, _ := v.call("GET", "/health", nil); code != http.StatusOK {
		t.Errorf("health answered %d", code)
	}
	if code, _ := v.create("r1", 3, 0, "run01-c1"); code != http.StatusCreated {
		t.Errorf("an order for r1 answered %d", code)
	}
	if code, m := v.call("GET", "/robots", nil); code != http.StatusOK || len(m["robots"].([]any)) != 3 {
		t.Fatalf("the fleet list answered %d: %v", code, m)
	}
	if o := v.order("m1"); o.Steps != 1 {
		t.Errorf("the fleet list should tick r2's order once; steps %d", o.Steps)
	}
	if got := v.s.Reads()["m1"]; got != 1 {
		t.Errorf("reads of m1 %d, want 1: an unanswered read is a read", got)
	}
	if got := v.s.Unanswered(); got != 5 {
		t.Errorf("unanswered %d, want 5", got)
	}
	events, _ := v.s.Events()
	var silenced, unanswered int
	for _, e := range events {
		switch e.Kind {
		case "silenced":
			silenced++
		case "unanswered":
			unanswered++
		}
	}
	if silenced != 1 || unanswered != 5 {
		t.Errorf("events: %d silenced and %d unanswered, want 1 and 5", silenced, unanswered)
	}
}

// The vendor counts the answers that told the caller an order had ended: a read or a cancel
// of a terminal order, never one of a running order, and never in the silent scenario's 504s.
func TestToldCountsOnlyAnswersShowingTheEnd(t *testing.T) {
	v := newVendor(t, ScenarioNominal)
	v.create("r1", 3, 0, "cmd-told-0001") // three steps from (0, 0)
	for range 3 {
		v.call("GET", "/missions/m1", nil)
	}
	if got := v.s.Told()["m1"]; got != 1 {
		t.Fatalf("told %d after the read that ended it, want 1", got)
	}
	v.call("POST", "/missions/m1/cancel", nil)
	if got := v.s.Told()["m1"]; got != 2 {
		t.Fatalf("told %d after a cancel of the ended order, want 2", got)
	}
	v.create("r2", 10, 4, "cmd-told-0002")
	v.call("GET", "/missions/m2", nil)
	if got := v.s.Told()["m2"]; got != 0 {
		t.Fatalf("told %d about a running order, want 0", got)
	}
	// A repeated create answers with the order's status: an ended order's repeat tells too.
	if code, m := v.create("r1", 3, 0, "cmd-told-0001"); code != http.StatusOK || m["status"] != "done" {
		t.Fatalf("repeat: %d %v", code, m)
	}
	if got := v.s.Told()["m1"]; got != 3 {
		t.Fatalf("told %d after a repeat of the ended order, want 3", got)
	}
}
