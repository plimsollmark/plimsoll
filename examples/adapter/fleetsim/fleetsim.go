// Package fleetsim is the simulated robot-fleet vendor API the adapter example runs
// against. It is deterministic on purpose: a mission moves its robot one unit toward
// the target on every read of that robot's or mission's state, so a scenario's call
// pattern decides its trajectory, and two runs with the same adapter make the same
// requests. The server keeps counts by route template, never by path, so the page can
// put "what the API saw" beside what the broker's trace says the sandbox sent.
//
// It also keeps the vendor's ledger: every order it accepted, with the command ID the
// caller gave it (if any), the robot, the target, every state the order entered and
// where its robot stood when it ended. The ledger is what a platform qualifies an
// adapter against: it is the vendor's account, read on the host after the run, and the
// adapter under test cannot write to it.
//
// An order's states are queued, running, done, failed and cancelled; the last three are
// terminal, and no transition leaves them. A robot runs one order at a time and queues
// the rest. Cancelling a running order stops the robot where it is and starts its next
// queued order; a cancelled queued order never runs. A robot that faults fails its
// running order and every order queued behind it.
//
// A create may carry a command_id, the caller's name for the order. A create repeated
// with a command_id the vendor already accepted is answered with that original order
// instead of a new one (409 when the robot or target differ), so a caller that never
// learned whether its create went through can send it again safely.
//
// Scenarios are set by the host between runs, never by the sandbox; Scenarios lists
// them as data.
//
// In the silent scenario the vendor's gateway stops answering about one robot after its
// first order: every later request about that robot is answered 504 and does nothing.
// A 504 and not a closed connection, because an HTTP client may replay an idempotent
// request once when a reused connection closes before answering (Go's does), and a
// replayed read would reach the vendor twice and corrupt the read count it keeps.
//
// Two catalog-only operations exist so a grant that omits them can be shown refusing
// them: DELETE /robots/{id} and POST /robots/{id}/firmware. The server counts any
// request that reaches them separately; in a correct run that count stays zero.
package fleetsim

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// Version names this simulator's behaviour. A qualification statement carries it, so a
// verdict says which vendor it was made against.
const Version = "fleetsim/3"

// Scenario names the host may set.
const (
	ScenarioNominal  = "nominal"
	ScenarioFault    = "fault"
	ScenarioOverload = "overload"
	ScenarioLostAck  = "lost_ack"
	ScenarioDropped  = "dropped"
	// ScenarioServerError is the lost answer with a 500 in place of the 503.
	ScenarioServerError = "server_error"
	// ScenarioRefused has r3 in fault before the run starts: the vendor refuses every
	// order for it, so an adapter's refused path runs.
	ScenarioRefused = "refused"
	// ScenarioSilent has r2's first order accepted and started, and then nothing about
	// r2 answered, so the order's outcome stays unknown to the adapter to the end.
	ScenarioSilent = "silent"
)

// DegradedRequests is how many requests the overload scenario refuses with 503 after
// the first order is accepted. Four, so that the broker's one-second breaker opens,
// sheds, probes the health route (which is also refused while degraded) and reopens
// at least once before the vendor recovers.
const DegradedRequests = 4

// FaultAtStep is the mission step at which robot r2 faults in the fault scenario.
const FaultAtStep = 2

// Scenario is what the vendor does in one run, as data.
type Scenario struct {
	Name string `json:"name"`
	// Says is the scenario in plain words.
	Says string `json:"says"`
	// FaultRobot faults FaultAtStep steps into its running order.
	FaultRobot  string `json:"fault_robot,omitempty"`
	FaultAtStep int    `json:"fault_at_step,omitempty"`
	// Degraded is how many requests are answered 503 once the first order is accepted.
	Degraded int `json:"degraded,omitempty"`
	// LoseAnswer is the robot whose first order is accepted and answered with an error,
	// LoseStatus (503 when zero).
	LoseAnswer string `json:"lose_answer,omitempty"`
	LoseStatus int    `json:"lose_status,omitempty"`
	// DropAnswer is the robot whose first order is accepted and never answered: the
	// vendor closes the connection.
	DropAnswer string `json:"drop_answer,omitempty"`
	// OutOfService is the robot in fault when the run starts; the vendor answers every
	// order for it with 409 and places none.
	OutOfService string `json:"out_of_service,omitempty"`
	// Silent is the robot whose first order is accepted, started and answered 504, after
	// which the vendor's gateway answers 504 to every request about it (an order for it,
	// a read of it, a read or cancel of any of its orders) and does nothing. The fleet
	// list is still answered.
	Silent string `json:"silent,omitempty"`
}

// Scenarios are the scenarios this simulator runs, by name.
var Scenarios = map[string]Scenario{
	ScenarioNominal: {Name: ScenarioNominal, Says: "three idle robots; every order can complete"},
	ScenarioFault: {Name: ScenarioFault, Says: fmt.Sprintf("robot r2 faults %d steps into its order", FaultAtStep),
		FaultRobot: "r2", FaultAtStep: FaultAtStep},
	ScenarioOverload: {Name: ScenarioOverload, Says: fmt.Sprintf("the next %d requests after the first order answer 503, health probes included", DegradedRequests),
		Degraded: DegradedRequests},
	ScenarioLostAck: {Name: ScenarioLostAck, Says: "r2's first order is accepted and started, but its answer is a 503",
		LoseAnswer: "r2"},
	ScenarioDropped: {Name: ScenarioDropped, Says: "r2's first order is accepted and started, then the connection closes with no answer",
		DropAnswer: "r2"},
	ScenarioServerError: {Name: ScenarioServerError, Says: "r2's first order is accepted and started, but its answer is a 500",
		LoseAnswer: "r2", LoseStatus: 500},
	ScenarioRefused: {Name: ScenarioRefused, Says: "r3 is in fault before the run starts, and the vendor refuses every order for it with a 409",
		OutOfService: "r3"},
	ScenarioSilent: {Name: ScenarioSilent, Says: "r2's first order is accepted and started, then the vendor's gateway answers 504 to every request about r2 and does nothing; the fleet list is still answered",
		Silent: "r2"},
}

// ScenarioOrder is the order the example and its test run the scenarios in.
var ScenarioOrder = []string{ScenarioNominal, ScenarioFault, ScenarioOverload, ScenarioLostAck, ScenarioDropped, ScenarioServerError, ScenarioRefused, ScenarioSilent}

// StartPoses is where each robot stands after Reset; the page's floor replay draws
// the same fleet.
var StartPoses = map[string]Pose{"r1": {0, 0}, "r2": {10, 0}, "r3": {0, 10}}

// Pose is a position on the floor.
type Pose struct {
	X float64 `json:"x"`
	Y float64 `json:"y"`
}

// Order is one entry of the vendor's ledger.
type Order struct {
	ID        string `json:"id"`
	Robot     string `json:"robot"`
	CommandID string `json:"command_id,omitempty"`
	Target    Pose   `json:"target"`
	Status    string `json:"status"`
	// History is every state the order entered, in order, starting with queued.
	History []string `json:"history"`
	// Steps is how many units its robot moved under this order.
	Steps int `json:"steps"`
	// StoppedAt is where its robot stood when the order ended; nil while it is live.
	StoppedAt *Pose `json:"stopped_at,omitempty"`
}

// Event is one thing the vendor did, in the order it did it: what the page's floor
// replays, so the drawing shows the run rather than a sketch of it. Kinds: order (an
// order accepted, queued until its start), repeat (a create
// repeating an accepted command ID, answered with its order), conflict, answer_lost
// (an order accepted and answered with the error in Status), dropped (an order accepted
// and the connection closed), degraded, refused (a request the degraded vendor answered
// 503), recovered, start (a queued order starts), move, fault, failed (a queued order
// failed by a fault), done, cancelled.
type Event struct {
	Kind    string `json:"kind"`
	Robot   string `json:"robot,omitempty"`
	Mission string `json:"mission,omitempty"`
	Command string `json:"command,omitempty"`
	Pose    *Pose  `json:"pose,omitempty"`
	Status  string `json:"status,omitempty"`
}

// MaxEvents bounds a run's event log; past it the log keeps counting in Dropped.
const MaxEvents = 4000

// RobotState is a robot as the vendor holds it.
type RobotState struct {
	ID      string `json:"id"`
	Status  string `json:"status"`
	Battery int    `json:"battery"`
	Pose    Pose   `json:"pose"`
}

// Credential is one credential the vendor accepted, by its ID: a JWT's jti, or
// "static" for the one shared bearer.
type Credential struct {
	ID string `json:"id"`
	// Subject is the JWT's sub, the principal it was minted for.
	Subject string `json:"subject,omitempty"`
	// LifetimeSeconds is exp minus iat: how long the credential lives.
	LifetimeSeconds int64 `json:"lifetime_seconds,omitempty"`
}

// Auth checks a request's Authorization header and names the credential it carries.
type Auth interface {
	Check(header string, now time.Time) (Credential, error)
}

// Static accepts one shared bearer token.
func Static(token string) Auth { return staticAuth(token) }

type staticAuth string

func (a staticAuth) Check(header string, _ time.Time) (Credential, error) {
	if !hmac.Equal([]byte(header), []byte("Bearer "+string(a))) {
		return Credential{}, errors.New("unknown bearer")
	}
	return Credential{ID: "static"}, nil
}

// HS256 accepts a JWT signed with secret (HS256) whose aud is audience, inside its
// nbf to exp window and carrying a sub and a jti: what plimsoll's jwt minter issues,
// one per run.
func HS256(secret []byte, audience string) Auth {
	return hs256{secret: append([]byte(nil), secret...), audience: audience}
}

type hs256 struct {
	secret   []byte
	audience string
}

func (a hs256) Check(header string, now time.Time) (Credential, error) {
	tok, ok := strings.CutPrefix(header, "Bearer ")
	if !ok {
		return Credential{}, errors.New("no bearer")
	}
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		return Credential{}, errors.New("not a JWT")
	}
	enc := base64.RawURLEncoding
	var head struct {
		Alg string `json:"alg"`
	}
	hb, err := enc.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &head) != nil || head.Alg != "HS256" {
		return Credential{}, errors.New("not an HS256 JWT")
	}
	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return Credential{}, errors.New("bad signature encoding")
	}
	mac := hmac.New(sha256.New, a.secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return Credential{}, errors.New("bad signature")
	}
	var c struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Jti string `json:"jti"`
		Iat int64  `json:"iat"`
		Nbf int64  `json:"nbf"`
		Exp int64  `json:"exp"`
	}
	cb, err := enc.DecodeString(parts[1])
	if err != nil || json.Unmarshal(cb, &c) != nil {
		return Credential{}, errors.New("bad claims")
	}
	switch {
	case c.Aud != a.audience:
		return Credential{}, errors.New("wrong audience")
	case c.Sub == "" || c.Jti == "":
		return Credential{}, errors.New("no sub or jti")
	case now.Unix() >= c.Exp:
		return Credential{}, errors.New("expired")
	case now.Unix()+2 < c.Nbf: // two seconds of clock skew
		return Credential{}, errors.New("not yet valid")
	}
	return Credential{ID: c.Jti, Subject: c.Sub, LifetimeSeconds: c.Exp - c.Iat}, nil
}

type robot struct {
	ID      string `json:"id"`
	Status  string `json:"status"` // idle | moving | fault
	Battery int    `json:"battery"`
	Pose    Pose   `json:"pose"`
	Mission string `json:"mission,omitempty"`
	queued  []string
}

type mission struct {
	ID        string  `json:"id"`
	Robot     string  `json:"robot"`
	CommandID string  `json:"command_id,omitempty"`
	Status    string  `json:"status"` // queued | running | done | failed | cancelled
	Target    Pose    `json:"target"`
	Progress  float64 `json:"progress"`
	Error     string  `json:"error,omitempty"`
	start     Pose
	steps     int
	history   []string
	stoppedAt *Pose
}

// legal is every transition an order may make; terminal states have none.
var legal = map[string][]string{
	"queued":  {"running", "failed", "cancelled"},
	"running": {"done", "failed", "cancelled"},
}

var commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// Server is the vendor. It serves HTTP and is safe for concurrent use.
type Server struct {
	mu           sync.Mutex
	auth         Auth
	now          func() time.Time
	scenario     Scenario
	robots       map[string]*robot
	order        []string
	missions     map[string]*mission
	nextMission  int
	commands     map[string]string // command_id -> mission ID
	degradedLeft int
	counts       map[string]int // "METHOD /route/template" -> requests served (any status)
	reads        map[string]int // mission ID -> status reads that reached the vendor (any status)
	told         map[string]int // mission ID -> answers that told the caller the order had ended
	refused      int            // 503s answered in the overload scenario
	reached      map[string]int // catalog-only routes that received a request
	unauthorized int
	orders       map[string]int // orders accepted per robot
	answerFaults map[string]bool
	silenced     bool // the silent scenario's robot has had its first order
	unanswered   int  // requests the silent scenario answered 504
	illegal      int
	credentials  []Credential
	events       []Event
	eventsLost   int
}

// New returns a vendor that checks every request with auth, in the nominal scenario.
func New(auth Auth) *Server {
	s := &Server{auth: auth, now: time.Now}
	s.Reset(ScenarioNominal)
	return s
}

// Reset puts the fleet back to its starting state under the named scenario. Counts,
// the ledger and the credentials seen are reset too, so each run's stand alone. It
// panics on a scenario Scenarios does not list.
func (s *Server) Reset(name string) {
	sc, ok := Scenarios[name]
	if !ok {
		panic("fleetsim: unknown scenario " + name)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scenario = sc
	s.robots = map[string]*robot{
		"r1": {ID: "r1", Status: "idle", Battery: 96, Pose: StartPoses["r1"]},
		"r2": {ID: "r2", Status: "idle", Battery: 71, Pose: StartPoses["r2"]},
		"r3": {ID: "r3", Status: "idle", Battery: 58, Pose: StartPoses["r3"]},
	}
	s.order = []string{"r1", "r2", "r3"}
	s.missions = map[string]*mission{}
	s.nextMission = 0
	s.commands = map[string]string{}
	s.degradedLeft = 0
	s.counts = map[string]int{}
	s.reads = map[string]int{}
	s.told = map[string]int{}
	s.refused = 0
	s.reached = map[string]int{}
	s.unauthorized = 0
	s.orders = map[string]int{}
	s.answerFaults = map[string]bool{}
	s.silenced = false
	s.unanswered = 0
	s.illegal = 0
	s.credentials = nil
	s.events = nil
	s.eventsLost = 0
	if rb := s.robots[sc.OutOfService]; rb != nil {
		rb.Status = "fault"
		s.events = append(s.events, Event{Kind: "out_of_service", Robot: rb.ID, Pose: posePtr(rb.Pose)})
	}
}

func (s *Server) event(e Event) {
	if len(s.events) >= MaxEvents {
		s.eventsLost++
		return
	}
	s.events = append(s.events, e)
}

func posePtr(p Pose) *Pose { return &p }

// Events is what the vendor did since Reset, in order, and how many events the log
// had no room for.
func (s *Server) Events() ([]Event, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.events), s.eventsLost
}

// Robots is every robot as the vendor holds it now, in the fleet's order.
func (s *Server) Robots() []RobotState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]RobotState, 0, len(s.order))
	for _, id := range s.order {
		rb := s.robots[id]
		out = append(out, RobotState{ID: rb.ID, Status: rb.Status, Battery: rb.Battery, Pose: rb.Pose})
	}
	return out
}

// Scenario is the scenario the vendor is in.
func (s *Server) Scenario() Scenario {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.scenario
}

// Ledger is every order the vendor accepted since Reset, in the order it accepted
// them, whether or not the answer reached the caller.
func (s *Server) Ledger() []Order {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Order, 0, len(s.missions))
	for i := 1; i <= s.nextMission; i++ {
		m := s.missions[fmt.Sprintf("m%d", i)]
		o := Order{ID: m.ID, Robot: m.Robot, CommandID: m.CommandID, Target: m.Target, Status: m.Status,
			History: slices.Clone(m.history), Steps: m.steps}
		if m.stoppedAt != nil {
			p := *m.stoppedAt
			o.StoppedAt = &p
		}
		out = append(out, o)
	}
	return out
}

// Reads is how many status reads of each mission reached the vendor, refused ones
// included: the vendor's own count, which an adapter cannot write. A read the broker
// shed never reached it, so this is the least the adapter made.
func (s *Server) Reads() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.reads))
	for k, v := range s.reads {
		out[k] = v
	}
	return out
}

// Told is, per mission, how many answers the vendor sent (a status read, a cancel, or a repeated
// create, each of which carries the order's status) that showed the order in a terminal state:
// whether the caller was ever told it had ended. A final state reached later, after the caller
// stopped asking, is not in it. It counts answers the vendor wrote, not answers the broker
// delivered: one lost on the way would still count, which the verdict's wording allows for.
func (s *Server) Told() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.told))
	for k, v := range s.told {
		out[k] = v
	}
	return out
}

// Orders counts the ledger's orders per robot.
func (s *Server) Orders() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.orders))
	for k, v := range s.orders {
		out[k] = v
	}
	return out
}

// Credentials are the distinct credentials the vendor accepted since Reset, in the
// order it first saw them.
func (s *Server) Credentials() []Credential {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.credentials)
}

// Illegal counts transitions the vendor was asked to make and refused because the
// order's state does not allow them. The simulator never asks for one, so a nonzero
// count is a bug in it.
func (s *Server) Illegal() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.illegal
}

// Counts returns requests served per route template, sorted for display.
func (s *Server) Counts() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counts))
	for k, v := range s.counts {
		out[k] = v
	}
	return out
}

// Refused is how many requests the overload scenario answered with 503.
func (s *Server) Refused() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.refused
}

// Reached returns the catalog-only routes that received a request, with counts. A
// correct grant keeps this empty.
func (s *Server) Reached() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.reached))
	for k, v := range s.reached {
		out[k] = v
	}
	return out
}

// Unanswered is how many requests the silent scenario answered 504.
func (s *Server) Unanswered() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unanswered
}

// Unauthorized is how many requests arrived without a credential auth accepts.
func (s *Server) Unauthorized() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.unauthorized
}

// SortedCounts renders Counts as "METHOD /template: n" lines in route order.
func SortedCounts(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, fmt.Sprintf("%s: %d", k, m[k]))
	}
	return out
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cred, err := s.auth.Check(r.Header.Get("Authorization"), s.now())
	if err != nil {
		s.unauthorized++
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if !slices.ContainsFunc(s.credentials, func(c Credential) bool { return c.ID == cred.ID }) {
		s.credentials = append(s.credentials, cred)
	}
	segs := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	template, handler := s.route(r.Method, segs)
	if handler == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such route"})
		return
	}
	s.counts[template]++
	if template == "GET /missions/*" {
		s.reads[segs[1]]++ // a read the degraded or silent vendor refuses is a read too
	}
	if s.silenced && s.about(template, segs) == s.scenario.Silent {
		s.unanswered++
		s.event(Event{Kind: "unanswered", Robot: s.scenario.Silent, Status: template})
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "gateway timeout: the fleet service did not answer"})
		return
	}
	if s.degradedLeft > 0 {
		s.degradedLeft--
		s.refused++
		s.event(Event{Kind: "refused"})
		if s.degradedLeft == 0 {
			s.event(Event{Kind: "recovered"})
		}
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "degraded: scheduler backlog"})
		return
	}
	handler(w, r, segs)
}

// about is the robot a request concerns: the robot its path names, or the robot of the
// order its path names; "" for the fleet list, health, an order the vendor does not hold,
// and the catalog-only routes, which must reach their handler to be counted.
func (s *Server) about(template string, segs []string) string {
	switch template {
	case "GET /robots/*", "POST /robots/*/missions":
		return segs[1]
	case "GET /missions/*", "POST /missions/*/cancel":
		if m := s.missions[segs[1]]; m != nil {
			return m.Robot
		}
	}
	return ""
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, segs []string)

// route maps a request to its template and handler. Templates use the same "*" a
// grant's allow list uses, so the counts read beside the broker's trace.
func (s *Server) route(method string, segs []string) (string, handlerFunc) {
	switch {
	case method == "GET" && len(segs) == 1 && segs[0] == "health":
		return "GET /health", s.health
	case method == "GET" && len(segs) == 1 && segs[0] == "robots":
		return "GET /robots", s.listRobots
	case method == "GET" && len(segs) == 2 && segs[0] == "robots":
		return "GET /robots/*", s.getRobot
	case method == "DELETE" && len(segs) == 2 && segs[0] == "robots":
		return "DELETE /robots/*", s.catalogOnly("DELETE /robots/*")
	case method == "POST" && len(segs) == 3 && segs[0] == "robots" && segs[2] == "missions":
		return "POST /robots/*/missions", s.createMission
	case method == "POST" && len(segs) == 3 && segs[0] == "robots" && segs[2] == "firmware":
		return "POST /robots/*/firmware", s.catalogOnly("POST /robots/*/firmware")
	case method == "GET" && len(segs) == 2 && segs[0] == "missions":
		return "GET /missions/*", s.getMission
	case method == "POST" && len(segs) == 3 && segs[0] == "missions" && segs[2] == "cancel":
		return "POST /missions/*/cancel", s.cancelMission
	}
	return "", nil
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request, _ []string) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "robots": len(s.robots)})
}

func (s *Server) listRobots(w http.ResponseWriter, _ *http.Request, _ []string) {
	out := make([]*robot, 0, len(s.order))
	for _, id := range s.order {
		s.tick(s.robots[id])
		out = append(out, s.robots[id])
	}
	writeJSON(w, http.StatusOK, map[string]any{"robots": out})
}

func (s *Server) getRobot(w http.ResponseWriter, _ *http.Request, segs []string) {
	rb, ok := s.robots[segs[1]]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such robot"})
		return
	}
	s.tick(rb)
	writeJSON(w, http.StatusOK, rb)
}

func (s *Server) createMission(w http.ResponseWriter, r *http.Request, segs []string) {
	rb, ok := s.robots[segs[1]]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such robot"})
		return
	}
	var body struct {
		Target    *Pose  `json:"target"`
		CommandID string `json:"command_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Target == nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be {\"target\":{\"x\":..,\"y\":..},\"command_id\":..}"})
		return
	}
	if body.CommandID != "" {
		if !commandIDPattern.MatchString(body.CommandID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command_id must be 8 to 64 letters, digits, - or _"})
			return
		}
		if id, seen := s.commands[body.CommandID]; seen {
			m := s.missions[id]
			if m.Robot != rb.ID || m.Target != *body.Target {
				s.event(Event{Kind: "conflict", Robot: rb.ID, Command: body.CommandID})
				writeJSON(w, http.StatusConflict, map[string]string{"error": "command_id already names an order for another robot or target"})
				return
			}
			// The same command again: the original order, not a new one. Its answer carries the
			// order's status, so an ended order's repeat tells the caller it ended.
			s.event(Event{Kind: "repeat", Robot: m.Robot, Mission: m.ID, Command: m.CommandID})
			s.tell(m)
			writeJSON(w, http.StatusOK, map[string]any{"mission_id": m.ID, "robot": m.Robot, "status": m.Status, "command_id": m.CommandID, "repeated": true})
			return
		}
	}
	if rb.Status == "fault" {
		s.event(Event{Kind: "rejected", Robot: rb.ID, Command: body.CommandID})
		writeJSON(w, http.StatusConflict, map[string]string{"error": "robot is in fault"})
		return
	}
	s.nextMission++
	s.orders[rb.ID]++
	m := &mission{ID: fmt.Sprintf("m%d", s.nextMission), Robot: rb.ID, CommandID: body.CommandID, Status: "queued", Target: *body.Target, history: []string{"queued"}}
	s.missions[m.ID] = m
	if body.CommandID != "" {
		s.commands[body.CommandID] = m.ID
	}
	rb.queued = append(rb.queued, m.ID)
	s.event(Event{Kind: "order", Robot: rb.ID, Mission: m.ID, Command: m.CommandID})
	if rb.Mission == "" {
		s.startNext(rb)
	}
	if s.scenario.Degraded > 0 && s.nextMission == 1 {
		s.degradedLeft = s.scenario.Degraded
		s.event(Event{Kind: "degraded", Status: fmt.Sprint(s.scenario.Degraded)})
	}
	if rb.ID == s.scenario.LoseAnswer && !s.answerFaults["lose"] {
		// The order is in, the robot is moving, and the answer is an error.
		s.answerFaults["lose"] = true
		status := s.scenario.LoseStatus
		if status == 0 {
			status = http.StatusServiceUnavailable
			w.Header().Set("Retry-After", "1")
		}
		s.event(Event{Kind: "answer_lost", Robot: rb.ID, Mission: m.ID, Status: fmt.Sprint(status)})
		writeJSON(w, status, map[string]string{"error": "acknowledgement lost"})
		return
	}
	if rb.ID == s.scenario.Silent && !s.silenced {
		// The order is in, the robot is moving, and from here on nothing about it answers.
		s.silenced = true
		s.event(Event{Kind: "silenced", Robot: rb.ID, Mission: m.ID})
		writeJSON(w, http.StatusGatewayTimeout, map[string]string{"error": "gateway timeout: the fleet service did not answer"})
		return
	}
	if rb.ID == s.scenario.DropAnswer && !s.answerFaults["drop"] {
		// The order is in, the robot is moving, and no answer comes at all.
		s.answerFaults["drop"] = true
		s.event(Event{Kind: "dropped", Robot: rb.ID, Mission: m.ID})
		if hj, ok := w.(http.Hijacker); ok {
			if conn, _, err := hj.Hijack(); err == nil {
				_ = conn.Close()
				return
			}
		}
		panic(http.ErrAbortHandler) // closes the connection where hijacking is not offered
	}
	writeJSON(w, http.StatusCreated, map[string]any{"mission_id": m.ID, "robot": rb.ID, "status": m.Status, "command_id": m.CommandID})
}

func (s *Server) getMission(w http.ResponseWriter, _ *http.Request, segs []string) {
	m, ok := s.missions[segs[1]]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such mission"})
		return
	}
	s.tick(s.robots[m.Robot])
	s.tell(m)
	writeJSON(w, http.StatusOK, m)
}

// tell notes an answer about m that shows it ended.
func (s *Server) tell(m *mission) {
	if m.Status == "done" || m.Status == "failed" || m.Status == "cancelled" {
		s.told[m.ID]++
	}
}

func (s *Server) cancelMission(w http.ResponseWriter, _ *http.Request, segs []string) {
	m, ok := s.missions[segs[1]]
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such mission"})
		return
	}
	rb := s.robots[m.Robot]
	switch m.Status {
	case "running":
		s.end(m, "cancelled", "", rb.Pose)
		s.event(Event{Kind: "cancelled", Robot: rb.ID, Mission: m.ID, Pose: posePtr(rb.Pose)})
		rb.Status, rb.Mission = "idle", ""
		s.startNext(rb)
	case "queued":
		s.end(m, "cancelled", "", rb.Pose)
		s.event(Event{Kind: "cancelled", Robot: rb.ID, Mission: m.ID})
		rb.queued = slices.DeleteFunc(rb.queued, func(id string) bool { return id == m.ID })
	}
	// A terminal order is answered as it is: cancelling it changes nothing.
	s.tell(m)
	writeJSON(w, http.StatusOK, m)
}

func (s *Server) catalogOnly(template string) handlerFunc {
	return func(w http.ResponseWriter, _ *http.Request, _ []string) {
		s.reached[template]++
		writeJSON(w, http.StatusOK, map[string]string{"warning": "this operation is in the vendor's catalog and should never have been reachable"})
	}
}

// transition moves m to state to if the transition is legal, and counts it otherwise.
func (s *Server) transition(m *mission, to string) bool {
	if !slices.Contains(legal[m.Status], to) {
		s.illegal++
		return false
	}
	m.Status = to
	m.history = append(m.history, to)
	return true
}

// end moves m to a terminal state, noting where its robot stood.
func (s *Server) end(m *mission, to, why string, at Pose) {
	if s.transition(m, to) {
		m.Error = why
		m.stoppedAt = &at
	}
}

// startNext starts rb's first queued order still queued, from where rb stands.
func (s *Server) startNext(rb *robot) {
	for len(rb.queued) > 0 {
		m := s.missions[rb.queued[0]]
		rb.queued = rb.queued[1:]
		if m.Status != "queued" {
			continue
		}
		if s.transition(m, "running") {
			m.start = rb.Pose
			rb.Status, rb.Mission = "moving", m.ID
			s.event(Event{Kind: "start", Robot: rb.ID, Mission: m.ID})
			return
		}
	}
}

// tick advances a moving robot one unit toward its target, or faults it where the
// scenario says.
func (s *Server) tick(rb *robot) {
	if rb.Mission == "" {
		return
	}
	m := s.missions[rb.Mission]
	if m == nil || m.Status != "running" {
		return
	}
	m.steps++
	if rb.ID == s.scenario.FaultRobot && m.steps == s.scenario.FaultAtStep {
		rb.Status, rb.Mission = "fault", ""
		s.end(m, "failed", "obstacle detected; motors stopped", rb.Pose)
		s.event(Event{Kind: "fault", Robot: rb.ID, Mission: m.ID, Pose: posePtr(rb.Pose)})
		for _, id := range rb.queued {
			if q := s.missions[id]; q.Status == "queued" {
				s.end(q, "failed", "robot is in fault", rb.Pose)
				s.event(Event{Kind: "failed", Robot: rb.ID, Mission: q.ID})
			}
		}
		rb.queued = nil
		return
	}
	dx, dy := m.Target.X-rb.Pose.X, m.Target.Y-rb.Pose.Y
	dist := math.Hypot(dx, dy)
	total := math.Hypot(m.Target.X-m.start.X, m.Target.Y-m.start.Y)
	if dist <= 1+1e-9 {
		rb.Pose = m.Target
		rb.Status, rb.Mission = "idle", ""
		m.Progress = 1
		s.end(m, "done", "", rb.Pose)
		s.event(Event{Kind: "done", Robot: rb.ID, Mission: m.ID, Pose: posePtr(rb.Pose)})
		s.startNext(rb)
		return
	}
	rb.Pose.X += dx / dist
	rb.Pose.Y += dy / dist
	s.event(Event{Kind: "move", Robot: rb.ID, Mission: m.ID, Pose: posePtr(rb.Pose)})
	if total > 0 {
		m.Progress = math.Round((1-math.Hypot(m.Target.X-rb.Pose.X, m.Target.Y-rb.Pose.Y)/total)*1000) / 1000
	}
	if rb.Battery > 1 {
		rb.Battery--
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
