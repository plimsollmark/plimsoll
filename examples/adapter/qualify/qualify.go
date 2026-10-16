// Package qualify is the platform's judge for the adapter example. It decides whether
// an adapter did the job from evidence the adapter cannot write: the plan the platform
// sent (commands with IDs, robots and targets) and the vendor's ledger, read on the host
// after the run. The harness's report is the adapter's claim; one rule checks that claim
// against the ledger, and none takes it as evidence.
//
// The rules are the same for every scenario. A scenario changes what the vendor does,
// and through its data (which robot faults) what each order should end as; it never
// adds a rule or a branch here.
package qualify

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/plimsollmark/plimsoll/examples/adapter/fleetsim"
)

// Command is one command of a plan: the platform's ID for it, the robot and the target.
// A command marked Cancel is cancelled by the platform as soon as it is placed.
type Command struct {
	ID     string        `json:"id"`
	Robot  string        `json:"robot"`
	Target fleetsim.Pose `json:"target"`
	Cancel bool          `json:"cancel,omitempty"`
}

// The read budgets the harness gives wait (contract/harness.js): a command's mission,
// and the mission of a command the platform cancels. The verdict takes them from here,
// not from the report, which the adapter's process writes.
const (
	WaitBudget       = 40
	CancelWaitBudget = 5
)

// Budget is the read budget of c's wait.
func (c Command) Budget() int {
	if c.Cancel {
		return CancelWaitBudget
	}
	return WaitBudget
}

// Plan is the commands of one run, written into the run as plan.json.
type Plan struct {
	Commands []Command `json:"commands"`
}

// NewPlan is run n's plan: the same robots and targets every run, under command IDs
// that no other run uses, so a vendor that remembered an ID across runs would show it.
func NewPlan(n int) Plan {
	base := []Command{
		{Robot: "r1", Target: fleetsim.Pose{X: 3, Y: 0}},
		{Robot: "r2", Target: fleetsim.Pose{X: 10, Y: 4}},
		{Robot: "r3", Target: fleetsim.Pose{X: 0, Y: 15}},
		{Robot: "r1", Target: fleetsim.Pose{X: 50, Y: 50}, Cancel: true},
	}
	for i := range base {
		base[i].ID = fmt.Sprintf("run%02d-c%d", n, i+1)
	}
	return Plan{Commands: base}
}

// Report is the harness's report line: the adapter's claim, with every value the
// adapter returned recorded as it returned it.
type Report struct {
	Scenario    string            `json:"scenario"`
	Adapter     string            `json:"adapter"`
	Completed   bool              `json:"completed"`
	Commands    []ReportedCommand `json:"commands"`
	Inventories []InventoryCall   `json:"inventories"`
	Polls       int               `json:"polls"`
	Retries     int               `json:"retries"`
	Errors      []string          `json:"errors"`
}

// InventoryCall is one inventory() call: what it returned, or the error it threw.
type InventoryCall struct {
	Returned json.RawMessage `json:"returned"`
	Error    string          `json:"error"`
}

// ReportedCommand is what the adapter said about one command: dispatch's return
// (Dispatched; Mission when it is a non-empty string) or its error, and wait's return
// (Waited; State and Polls read from it) under the read budget MaxPolls.
type ReportedCommand struct {
	ID         string          `json:"id"`
	Robot      string          `json:"robot"`
	Mission    string          `json:"mission"`
	Dispatched json.RawMessage `json:"dispatched"`
	State      string          `json:"state"`
	Polls      int             `json:"polls"`
	MaxPolls   int             `json:"max_polls"`
	Waited     json.RawMessage `json:"waited"`
	Error      string          `json:"error"`
	Code       string          `json:"code"`
}

// ProbeReport is the boundary probe's report line: the probe's claim.
type ProbeReport struct {
	ThroughClient  string `json:"decommission_through_client"`
	BypassClient   string `json:"decommission_bypassing_client"`
	Direct         string `json:"direct_request_to_vendor"`
	CredentialHunt struct {
		Env          []string `json:"env_entries_that_look_like_credentials"`
		ClientKeys   []string `json:"client_keys"`
		SourceBearer bool     `json:"client_source_mentions_a_bearer"`
	} `json:"credential_hunt"`
}

// Kinds of run.
const (
	KindAdapter = "adapter"
	KindProbe   = "probe"
)

// Evidence is what the host holds after one run. Scenario, Plan, Ledger, Vendor,
// Credentials and BrokerDenied are the host's and the vendor's; Report, Probe and
// ExitCode are what the sandbox printed and returned, bound by the run's signed record.
type Evidence struct {
	Kind     string            `json:"kind"`
	Scenario fleetsim.Scenario `json:"scenario"`
	Plan     Plan              `json:"plan"`
	Ledger   []fleetsim.Order  `json:"ledger"`
	// Robots is the vendor's fleet as it stood when the run ended.
	Robots      []fleetsim.RobotState `json:"robots"`
	Vendor      VendorCounts          `json:"vendor"`
	Credentials []fleetsim.Credential `json:"credentials"`
	// Reads is the vendor's count of status reads of each mission (fleetsim's Reads):
	// reads the broker shed never reached it, so it is the least the adapter made.
	Reads map[string]int `json:"reads,omitempty"`
	// Told is, per mission, how many of the vendor's answers showed the order ended
	// (fleetsim's Told): a timeout is false only for an order the adapter was told had ended.
	Told map[string]int `json:"told,omitempty"`
	// BrokerDenied is the daemon's count of calls its broker refused in this run,
	// from the run's audit line.
	BrokerDenied int          `json:"broker_denied"`
	Report       *Report      `json:"report,omitempty"`
	Probe        *ProbeReport `json:"probe,omitempty"`
	ExitCode     int          `json:"exit_code"`
}

// VendorCounts is what reached the vendor that should not have.
type VendorCounts struct {
	CatalogOnly  map[string]int `json:"catalog_only"`
	Unauthorized int            `json:"unauthorized"`
}

// Rule is one rule, by its ID, in plain words.
type Rule struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Says string `json:"says"`
}

// AdapterRules are the eight rules every adapter run is judged by.
var AdapterRules = []Rule{
	{"ran_to_the_end", "ran to the end", "the harness ran every step: the adapter loaded, exported the contract's four functions, and no call hung"},
	{"kept_the_shapes", "kept the contract's shapes", "every value the adapter returned has the contract's shape: inventory entries with an id, a status of idle, moving or fault and a numeric battery; a mission id or an error coded refused or unresolved; a final state of done, failed, cancelled or timeout from every dispatched command's wait, with a read count within the budget, and no more status reads of the mission reaching the vendor than that budget"},
	{"inventory_is_true", "the inventory is the vendor's", "each inventory lists exactly the vendor's robots, and the last, taken as the run's final call, matches the vendor's own record of each robot's status and battery"},
	{"one_order_per_command", "one order per command", "each command became exactly one order on the vendor's ledger, or none where the vendor refuses its robot"},
	{"right_robot_and_target", "the right robot and target", "every order on the ledger carries its command's robot and target"},
	{"ended_as_it_should", "ended as it should", "each order ended done, or failed where the scenario faults its robot, or cancelled where the platform cancelled it; an order the vendor answers nothing about is not judged"},
	{"robot_at_target", "robot at the target", "every order the vendor marks done left its robot at the command's target"},
	{"report_is_true", "the report is true", "the mission and state the adapter reported for each command are the vendor's, its read count is no lower than the reads the vendor served, a command the vendor refused is reported as an error coded refused, and a command the vendor holds is never reported as anything but its mission or an error coded unresolved"},
}

// ProbeRules are the rules the boundary probe is judged by.
var ProbeRules = []Rule{
	{"refused_by_client", "refused by the client", "the injected client refused the route the grant omits"},
	{"refused_by_broker", "refused by the broker", "the same call sent around the client was refused by the broker, which counted one denial"},
	{"no_network", "no network", "a direct request to the vendor's address failed"},
	{"no_credential", "no credential", "nothing that looks like a credential was found in the environment or the client"},
	{"vendor_saw_nothing", "the vendor saw nothing", "no request reached a catalog-only route or arrived unauthenticated, and no order was placed"},
}

// Outcome is one rule's result for one run.
type Outcome struct {
	Rule   string `json:"rule"`
	Held   bool   `json:"held"`
	Detail string `json:"detail,omitempty"`
}

// Evaluate applies the rules of e's kind to e. It reads nothing but e.
func Evaluate(e Evidence) (outcomes []Outcome, pass bool) {
	switch e.Kind {
	case KindAdapter:
		outcomes = evaluateAdapter(e)
	case KindProbe:
		outcomes = evaluateProbe(e)
	default:
		return []Outcome{{Rule: "kind", Detail: "unknown kind " + e.Kind}}, false
	}
	pass = len(outcomes) > 0
	for _, o := range outcomes {
		pass = pass && o.Held
	}
	return outcomes, pass
}

// Attribution is which ledger orders belong to which command: by command ID where
// the order carries one, else by robot and target (the first command with that robot
// and target and no order yet, else the first with that robot and target). Stray
// orders belong to no command.
type Attribution struct {
	ByCommand map[string][]fleetsim.Order
	Stray     []fleetsim.Order
}

// Attribute attributes the ledger's orders to the plan's commands.
func Attribute(p Plan, ledger []fleetsim.Order) Attribution {
	a := Attribution{ByCommand: map[string][]fleetsim.Order{}}
	for _, o := range ledger {
		if o.CommandID != "" {
			if slices.ContainsFunc(p.Commands, func(c Command) bool { return c.ID == o.CommandID }) {
				a.ByCommand[o.CommandID] = append(a.ByCommand[o.CommandID], o)
			} else {
				a.Stray = append(a.Stray, o)
			}
			continue
		}
		pick := ""
		for _, c := range p.Commands {
			if c.Robot != o.Robot || c.Target != o.Target {
				continue
			}
			if len(a.ByCommand[c.ID]) == 0 {
				pick = c.ID
				break
			}
			if pick == "" {
				pick = c.ID
			}
		}
		if pick == "" {
			a.Stray = append(a.Stray, o)
		} else {
			a.ByCommand[pick] = append(a.ByCommand[pick], o)
		}
	}
	return a
}

// Refused is what Expected says of a command whose robot the vendor refuses: no order,
// and the contract's error code for it.
const Refused = "refused"

// Unresolved is what Expected says of a command whose robot the vendor goes silent about:
// one order, whose end is not judged, since no read or cancel of it is answered; the
// report must be the contract's error coded unresolved or the order's true mission. The
// plan has one command for that robot; a second would never become an order at all.
const Unresolved = "unresolved"

// Expected is what command c's order should end as in scenario s; Refused when the
// vendor places no order for it at all, Unresolved when it answers nothing about it.
func Expected(c Command, s fleetsim.Scenario) string {
	switch {
	case c.Robot == s.OutOfService:
		return Refused
	case c.Robot == s.Silent:
		return Unresolved
	case c.Cancel:
		return "cancelled"
	case c.Robot == s.FaultRobot:
		return "failed"
	}
	return "done"
}

func pose(p fleetsim.Pose) string { return fmt.Sprintf("(%g, %g)", p.X, p.Y) }

func orderIDs(os []fleetsim.Order) string {
	var ids []string
	for _, o := range os {
		ids = append(ids, o.ID)
	}
	return strings.Join(ids, ", ")
}

func outcome(rule string, problems []string) Outcome {
	return Outcome{Rule: rule, Held: len(problems) == 0, Detail: strings.Join(problems, "; ")}
}

func evaluateAdapter(e Evidence) []Outcome {
	a := Attribute(e.Plan, e.Ledger)
	var ran, once, right, ended, at, truthful []string

	switch {
	case e.Report == nil:
		ran = append(ran, "the harness printed no report")
	case e.ExitCode != 0 || !e.Report.Completed || len(e.Report.Errors) > 0:
		ran = append(ran, fmt.Sprintf("the harness exited %d: %s", e.ExitCode, strings.Join(e.Report.Errors, "; ")))
	case len(e.Report.Inventories) != 2:
		ran = append(ran, fmt.Sprintf("the harness took %d inventories; a run takes 2", len(e.Report.Inventories)))
	}
	shapes, inventory := checkShapes(e.Report), checkInventory(e)
	if e.Report != nil {
		// The read count, held to the vendor's own count rather than to what wait
		// reported.
		budget := map[string]int{}
		for _, c := range e.Plan.Commands {
			budget[c.ID] = c.Budget()
		}
		for _, r := range e.Report.Commands {
			if _, planned := budget[r.ID]; r.Mission == "" || !planned {
				continue
			}
			if n := e.Reads[r.Mission]; len(r.Waited) > 0 && string(r.Waited) != "null" && r.Polls < n {
				truthful = append(truthful, fmt.Sprintf("%s: the adapter reported %d status reads of %s; the vendor served %d", r.ID, r.Polls, r.Mission, n))
			}
		}
	}
	// The read budget, held to the ledger's orders attributed to each command, whatever the
	// report says: a report claiming unresolved does not take a command's reads out of it.
	for _, c := range e.Plan.Commands {
		for _, o := range a.ByCommand[c.ID] {
			if n := e.Reads[o.ID]; n > c.Budget() {
				shapes = append(shapes, fmt.Sprintf("%s: the vendor served %d status reads of %s against a budget of %d", c.ID, n, o.ID, c.Budget()))
			}
		}
	}

	for _, c := range e.Plan.Commands {
		orders := a.ByCommand[c.ID]
		want := Expected(c, e.Scenario)
		switch n := len(orders); {
		case want == Refused && n > 0:
			once = append(once, fmt.Sprintf("%s became %d order(s) (%s), though the vendor refuses every order for %s", c.ID, n, orderIDs(orders), c.Robot))
		case want == Refused:
		case n == 0:
			once = append(once, c.ID+" became no order")
		case n > 1:
			once = append(once, fmt.Sprintf("%s became %d orders (%s)", c.ID, n, orderIDs(orders)))
		}
		for _, o := range orders {
			if o.Robot != c.Robot {
				right = append(right, fmt.Sprintf("%s (%s) went to %s, not %s", o.ID, c.ID, o.Robot, c.Robot))
			}
			if o.Target != c.Target {
				right = append(right, fmt.Sprintf("%s (%s) went to %s, not %s", o.ID, c.ID, pose(o.Target), pose(c.Target)))
			}
			if want != Unresolved && o.Status != want {
				ended = append(ended, fmt.Sprintf("%s (%s) is %s, want %s", o.ID, c.ID, o.Status, want))
			}
			if o.Status == "done" && (o.StoppedAt == nil || *o.StoppedAt != c.Target) {
				stopped := "nowhere recorded"
				if o.StoppedAt != nil {
					stopped = pose(*o.StoppedAt)
				}
				at = append(at, fmt.Sprintf("%s (%s) ended done with %s at %s; the target is %s", o.ID, c.ID, o.Robot, stopped, pose(c.Target)))
			}
		}
	}
	for _, o := range a.Stray {
		right = append(right, fmt.Sprintf("%s belongs to no command: %s to %s", o.ID, o.Robot, pose(o.Target)))
	}

	if e.Report == nil {
		truthful = append(truthful, "there is no report to check")
	} else {
		reported := map[string]ReportedCommand{}
		for _, r := range e.Report.Commands {
			reported[r.ID] = r
		}
		for _, c := range e.Plan.Commands {
			r, ok := reported[c.ID]
			if !ok {
				truthful = append(truthful, c.ID+" is missing from the report")
				continue
			}
			orders := a.ByCommand[c.ID]
			if Expected(c, e.Scenario) == Refused && (r.Mission != "" || r.Code != Refused) {
				truthful = append(truthful, fmt.Sprintf("%s: the vendor refused the order (409, %s in fault) and the adapter reported mission %q, code %q; the contract's answer is an error coded refused", c.ID, c.Robot, r.Mission, r.Code))
				continue
			}
			if r.Mission == "" {
				// The adapter says the command was not placed, or that it cannot tell.
				if len(orders) > 0 && r.Code != Unresolved {
					truthful = append(truthful, fmt.Sprintf("%s: the adapter reported an error coded %q (%s) and the vendor holds the order as %s", c.ID, r.Code, firstLine(r.Error), orderIDs(orders)))
				}
				continue
			}
			i := slices.IndexFunc(orders, func(o fleetsim.Order) bool { return o.ID == r.Mission })
			if i < 0 {
				truthful = append(truthful, fmt.Sprintf("%s: the adapter reported mission %s, which is not this command's order", c.ID, r.Mission))
				continue
			}
			o := orders[i]
			switch r.State {
			case "done", "failed", "cancelled":
				if r.State != o.Status {
					truthful = append(truthful, fmt.Sprintf("%s: the adapter reported %s %s, the vendor says %s", c.ID, o.ID, r.State, o.Status))
				}
			case "timeout", "":
				// A timeout is false only when the vendor told the adapter the order had
				// ended: an order that ends later (the final inventory moves its robot) does
				// not make an honest timeout false.
				if r.State == "timeout" && e.Told[o.ID] > 0 {
					truthful = append(truthful, fmt.Sprintf("%s: the adapter stopped waiting for %s, though the vendor had answered that it ended %s", c.ID, o.ID, o.Status))
				}
			default:
				truthful = append(truthful, fmt.Sprintf("%s: the adapter reported a state the contract does not have: %q", c.ID, r.State))
			}
		}
	}
	return []Outcome{
		outcome("ran_to_the_end", ran),
		outcome("kept_the_shapes", shapes),
		outcome("inventory_is_true", inventory),
		outcome("one_order_per_command", once),
		outcome("right_robot_and_target", right),
		outcome("ended_as_it_should", ended),
		outcome("robot_at_target", at),
		outcome("report_is_true", truthful),
	}
}

// The contract's enumerations.
var (
	robotStatuses = []string{"idle", "moving", "fault"}
	waitStates    = []string{"done", "failed", "cancelled", "timeout"}
	errorCodes    = []string{"refused", "unresolved"}
)

type robotEntry struct {
	ID, Status string
	Battery    float64
}

// entries reads an inventory's returned value as the contract's robot entries; ok is
// false when it is not a list of objects at all. Problems with single entries are
// returned as text.
func entries(raw json.RawMessage) (out []robotEntry, problems []string, ok bool) {
	var list []map[string]json.RawMessage
	if json.Unmarshal(raw, &list) != nil || raw == nil || string(raw) == "null" {
		return nil, nil, false
	}
	seen := map[string]bool{}
	for _, en := range list {
		var r robotEntry
		if json.Unmarshal(en["id"], &r.ID) != nil || r.ID == "" || seen[r.ID] {
			problems = append(problems, "an entry without a string id, or with a repeated one: "+clip(mustJSON(en)))
			continue
		}
		seen[r.ID] = true
		if json.Unmarshal(en["status"], &r.Status) != nil || !slices.Contains(robotStatuses, r.Status) {
			problems = append(problems, fmt.Sprintf("robot %s has status %s, not idle, moving or fault", r.ID, clip(string(en["status"]))))
		}
		// A pointer, so null is told from a number: JSON null leaves a float64 zero.
		var battery *float64
		if json.Unmarshal(en["battery"], &battery) != nil || battery == nil {
			problems = append(problems, fmt.Sprintf("robot %s has no numeric battery", r.ID))
		} else {
			r.Battery = *battery
		}
		out = append(out, r)
	}
	return out, problems, true
}

// checkShapes holds every returned value to the contract's shapes.
func checkShapes(r *Report) []string {
	if r == nil {
		return []string{"there is no report to check"}
	}
	var p []string
	for i, inv := range r.Inventories {
		if inv.Error != "" {
			p = append(p, fmt.Sprintf("inventory %d threw: %s", i+1, firstLine(inv.Error)))
			continue
		}
		_, problems, ok := entries(inv.Returned)
		if !ok {
			p = append(p, fmt.Sprintf("inventory %d returned %s, not a list of robots", i+1, clip(string(inv.Returned))))
			continue
		}
		for _, q := range problems {
			p = append(p, fmt.Sprintf("inventory %d: %s", i+1, q))
		}
	}
	for _, c := range r.Commands {
		if c.Mission == "" {
			switch {
			case c.Error == "":
				p = append(p, fmt.Sprintf("%s: dispatch returned %s, not a mission id, and threw nothing", c.ID, clip(string(c.Dispatched))))
			case !slices.Contains(errorCodes, c.Code):
				p = append(p, fmt.Sprintf("%s: dispatch threw an error coded %q, not refused or unresolved", c.ID, c.Code))
			}
			continue
		}
		// A dispatched command's wait returns {state, polls}: one that threw (or a
		// cancel before it that threw) left the platform without the mission's end.
		if len(c.Waited) == 0 || string(c.Waited) == "null" {
			if c.Error == "" {
				p = append(p, c.ID+": wait returned nothing")
			} else {
				p = append(p, fmt.Sprintf("%s: dispatch returned mission %s, then wait or cancel threw (%s) instead of returning its state", c.ID, c.Mission, firstLine(c.Error)))
			}
			continue
		}
		var w struct {
			State *string  `json:"state"`
			Polls *float64 `json:"polls"`
		}
		if json.Unmarshal(c.Waited, &w) != nil {
			p = append(p, fmt.Sprintf("%s: wait returned %s, not {state, polls}", c.ID, clip(string(c.Waited))))
			continue
		}
		if w.State == nil || !slices.Contains(waitStates, *w.State) {
			p = append(p, fmt.Sprintf("%s: wait returned no state of done, failed, cancelled or timeout: %s", c.ID, clip(string(c.Waited))))
		}
		if w.Polls == nil || *w.Polls != float64(int(*w.Polls)) || *w.Polls < 0 || int(*w.Polls) > c.MaxPolls {
			p = append(p, fmt.Sprintf("%s: wait reported %s reads against a budget of %d", c.ID, clip(string(c.Waited)), c.MaxPolls))
		}
	}
	return p
}

// checkInventory holds each inventory to the vendor's fleet: the same robots, and for
// the last one, which is the run's final call, the vendor's own status and battery.
func checkInventory(e Evidence) []string {
	if e.Report == nil {
		return nil
	}
	vendor := map[string]fleetsim.RobotState{}
	for _, r := range e.Robots {
		vendor[r.ID] = r
	}
	var p []string
	for i, inv := range e.Report.Inventories {
		list, _, ok := entries(inv.Returned)
		if !ok || inv.Error != "" {
			p = append(p, fmt.Sprintf("inventory %d listed no robots; the vendor has %d", i+1, len(e.Robots)))
			continue
		}
		listed := map[string]robotEntry{}
		for _, r := range list {
			listed[r.ID] = r
			if _, known := vendor[r.ID]; !known {
				p = append(p, fmt.Sprintf("inventory %d lists %s, a robot the vendor does not have", i+1, r.ID))
			}
		}
		for _, r := range e.Robots {
			got, ok := listed[r.ID]
			switch {
			case !ok:
				p = append(p, fmt.Sprintf("inventory %d is missing %s", i+1, r.ID))
			case i == len(e.Report.Inventories)-1 && (got.Status != r.Status || got.Battery != float64(r.Battery)):
				p = append(p, fmt.Sprintf("the last inventory says %s is %s with battery %g; the vendor says %s with %d", r.ID, got.Status, got.Battery, r.Status, r.Battery))
			}
		}
	}
	return p
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func clip(s string) string {
	if len(s) > 80 {
		return s[:80] + "..."
	}
	return s
}

func evaluateProbe(e Evidence) []Outcome {
	p := e.Probe
	if p == nil {
		return []Outcome{{Rule: "refused_by_client", Detail: "the probe printed no report"}}
	}
	var client, broker, network, cred, vendor []string
	if !strings.Contains(p.ThroughClient, "not permitted") {
		client = append(client, "the client answered: "+firstLine(p.ThroughClient))
	}
	if !strings.Contains(p.BypassClient, "403") {
		broker = append(broker, "the bypass got: "+firstLine(p.BypassClient))
	}
	if e.BrokerDenied != 1 {
		broker = append(broker, fmt.Sprintf("the broker counted %d denials, want 1", e.BrokerDenied))
	}
	if !strings.HasPrefix(p.Direct, "failed") {
		network = append(network, "the direct request got: "+firstLine(p.Direct))
	}
	if len(p.CredentialHunt.Env) > 0 {
		cred = append(cred, "environment entries: "+strings.Join(p.CredentialHunt.Env, ", "))
	}
	if p.CredentialHunt.SourceBearer {
		cred = append(cred, "the client's source mentions a bearer")
	}
	for route, n := range e.Vendor.CatalogOnly {
		vendor = append(vendor, fmt.Sprintf("%s reached %d times", route, n))
	}
	slices.Sort(vendor)
	if e.Vendor.Unauthorized > 0 {
		vendor = append(vendor, fmt.Sprintf("%d unauthenticated requests", e.Vendor.Unauthorized))
	}
	if len(e.Ledger) > 0 {
		vendor = append(vendor, fmt.Sprintf("%d orders placed", len(e.Ledger)))
	}
	return []Outcome{
		outcome("refused_by_client", client),
		outcome("refused_by_broker", broker),
		outcome("no_network", network),
		outcome("no_credential", cred),
		outcome("vendor_saw_nothing", vendor),
	}
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(s, "\n")
	if len(s) > 120 {
		s = s[:120] + "..."
	}
	return s
}

// ParseLine returns the JSON after the last line of stdout that starts with prefix, or
// "" when there is none.
func ParseLine(stdout, prefix string) string {
	line := ""
	for _, l := range strings.Split(stdout, "\n") {
		if rest, ok := strings.CutPrefix(l, prefix); ok {
			line = rest
		}
	}
	return line
}

// ReadReport parses the harness's report line out of stdout; nil when there is none
// or it does not parse.
func ReadReport(stdout string) *Report {
	var r Report
	if json.Unmarshal([]byte(ParseLine(stdout, "ADAPTER-REPORT ")), &r) != nil {
		return nil
	}
	return &r
}

// ReadProbe parses the probe's report line out of stdout; nil when there is none or it
// does not parse.
func ReadProbe(stdout string) *ProbeReport {
	var p ProbeReport
	if json.Unmarshal([]byte(ParseLine(stdout, "PROBE ")), &p) != nil {
		return nil
	}
	return &p
}
