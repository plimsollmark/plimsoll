package clientsuite

import (
	"net"
	"net/url"
	"slices"
	"strings"
	"testing"
)

// Every daemon has a name, at least one variable and a line saying what it tests, and no
// two daemons set the same variable or share a name.
func TestTheTableNamesEachDaemonOnce(t *testing.T) {
	names, vars := map[string]bool{}, map[string]bool{}
	for _, d := range Daemons {
		if d.Name == "" || len(d.Vars) == 0 || strings.TrimSpace(d.Tests) == "" || d.serve == nil {
			t.Errorf("%+v: a daemon needs a name, its variables, what it tests and a server", d)
		}
		if names[d.Name] {
			t.Errorf("two daemons are named %s", d.Name)
		}
		names[d.Name] = true
		for _, v := range d.Vars {
			if vars[v] || !strings.HasPrefix(v, "PLIMSOLL_") {
				t.Errorf("%s: %s is set twice or is not a PLIMSOLL_ variable", d.Name, v)
			}
			vars[v] = true
		}
		if !strings.HasSuffix(d.Vars[0], "_URL") {
			t.Errorf("%s: its first variable, %s, is not its URL", d.Name, d.Vars[0])
		}
	}
}

// Env serves every daemon: each URL variable names a listening address.
func TestEnvServesEveryDaemon(t *testing.T) {
	env := Env(t)
	want := 0
	for _, d := range Daemons {
		want += len(d.Vars)
	}
	if len(env) != want {
		t.Fatalf("Env set %d variables, the table names %d", len(env), want)
	}
	for _, kv := range env {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasSuffix(name, "_URL") {
			continue
		}
		u, err := url.Parse(value)
		if err != nil || u.Host == "" {
			t.Fatalf("%s=%q is not a URL", name, value)
		}
		conn, err := net.Dial("tcp", u.Host)
		if err != nil {
			t.Fatalf("%s: nothing listens at %s: %v", name, u.Host, err)
		}
		_ = conn.Close()
	}
}

// The declined rule: a variable read and declined, neither read nor declined, declined
// with no reason, or declined though no daemon sets it is each a problem; a suite that
// reads one and declines the other with a reason has none.
func TestDeclinedProblems(t *testing.T) {
	table := []Daemon{{Name: "a", Vars: []string{"PLIMSOLL_A_URL"}, Tests: "a"}, {Name: "b", Vars: []string{"PLIMSOLL_B_URL", "PLIMSOLL_B_KEY"}, Tests: "b"}}
	const reads = `url = os.environ["PLIMSOLL_A_URL"]; other = "PLIMSOLL_B_URL"`
	if got := declinedProblems(table, map[string]string{"PLIMSOLL_B_KEY": "this suite sends no key"}, reads); len(got) != 0 {
		t.Fatalf("a suite that reads two and declines one with a reason: %v", got)
	}
	for name, c := range map[string]struct {
		declined map[string]string
		text     string
		want     string
	}{
		"neither read nor declined":      {map[string]string{}, reads, "neither reads PLIMSOLL_B_KEY"},
		"declined and read":              {map[string]string{"PLIMSOLL_B_KEY": "x", "PLIMSOLL_A_URL": "x"}, reads, "PLIMSOLL_A_URL (the a daemon) is declined"},
		"declined with no reason":        {map[string]string{"PLIMSOLL_B_KEY": " "}, reads, "declined without a reason"},
		"declined but no daemon sets it": {map[string]string{"PLIMSOLL_B_KEY": "x", "PLIMSOLL_GONE_URL": "x"}, reads, "names PLIMSOLL_GONE_URL"},
		"a longer name is not a read":    {map[string]string{"PLIMSOLL_B_KEY": "x"}, `"PLIMSOLL_A_URL_OLD" "PLIMSOLL_B_URL"`, "neither reads PLIMSOLL_A_URL"},
	} {
		got := declinedProblems(table, c.declined, c.text)
		if !slices.ContainsFunc(got, func(p string) bool { return strings.Contains(p, c.want) }) {
			t.Errorf("%s: %v, want a problem containing %q", name, got, c.want)
		}
	}
}
