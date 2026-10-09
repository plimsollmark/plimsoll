package sandbox

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// A session's credential reaches a grant only while one is lent, and nothing once
// unregistered.
func TestGuardRegistrySessionSlot(t *testing.T) {
	var g guardRegistry
	token, slot, unregister, err := g.register()
	if err != nil {
		t.Fatal(err)
	}
	if g.lookup(token) != nil {
		t.Fatal("an empty slot reaches a grant")
	}
	core, err := brokerSessionForGrant(context.Background(), &HostAPIGrant{BaseURL: "https://api.example.com", Minter: StaticToken("t")}, time.Minute, nil)
	if err != nil {
		t.Fatal(err)
	}
	release := slot.lend(core)
	if g.lookup(token) != core {
		t.Fatal("a lent grant is not reached")
	}
	release()
	release()
	if g.lookup(token) != nil {
		t.Fatal("a released grant is still reached")
	}
	slot.lend(core)
	unregister()
	unregister()
	if g.lookup(token) != nil {
		t.Fatal("an unregistered credential still reaches a grant")
	}
}

// The open check takes exactly the guard's host and header rule, and nothing near it.
func TestE2BCheckOpenGuardRule(t *testing.T) {
	cfg := &e2bGuardConfig{Endpoint: &guardEndpoint{Host: "guard.example.test"}, Token: "crg_1"}
	record := func(network map[string]any) e2bRecord {
		network["denyOut"] = []string{"0.0.0.0/0"}
		network["allowPublicTraffic"] = false
		raw, _ := json.Marshal(map[string]any{"state": "running", "metadata": map[string]string{"lease": "l"}, "network": network})
		var r e2bRecord
		if err := json.Unmarshal(raw, &r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	rule := func(headers map[string]string) []any {
		return []any{map[string]any{"transform": map[string]any{"headers": headers}}}
	}
	vm := e2bVM{lease: "l"}
	good := record(map[string]any{"allowOut": []string{"guard.example.test"},
		"rules": map[string]any{"guard.example.test": rule(map[string]string{EgressGuardHeader: "crg_1"})}})
	if err := good.checkOpen(vm, nil, cfg); err != nil {
		t.Fatalf("the guard's own rule: %v", err)
	}
	if err := good.checkOpen(vm, nil, nil); err == nil {
		t.Fatal("a session without a guard took a sandbox with the guard's rule")
	}
	for name, network := range map[string]map[string]any{
		"no rule": {"allowOut": []string{"guard.example.test"}},
		"another host too": {"allowOut": []string{"guard.example.test", "example.com"},
			"rules": map[string]any{"guard.example.test": rule(map[string]string{EgressGuardHeader: "crg_1"})}},
		"another credential": {"allowOut": []string{"guard.example.test"},
			"rules": map[string]any{"guard.example.test": rule(map[string]string{EgressGuardHeader: "crg_2"})}},
		"another header too": {"allowOut": []string{"guard.example.test"},
			"rules": map[string]any{"guard.example.test": rule(map[string]string{EgressGuardHeader: "crg_1", "X-Other": "1"})}},
	} {
		if err := record(network).checkOpen(vm, nil, cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// An empty egress list or rule set reads as an absent one, and a rule's credential is
// scrubbed from the difference shown.
func TestE2BRecordDiffers(t *testing.T) {
	open := e2bRecord{State: "running", Network: &e2bNetwork{DenyOut: []string{"0.0.0.0/0"}}}
	after := e2bRecord{State: "running", Network: &e2bNetwork{DenyOut: []string{"0.0.0.0/0"}, AllowOut: []string{}, Rules: map[string]json.RawMessage{}}}
	if d := after.differs(open); d != "" {
		t.Fatalf("an emptied rule set differs: %s", d)
	}
	ruled := e2bRecord{State: "running", Network: &e2bNetwork{DenyOut: []string{"0.0.0.0/0"},
		Rules: map[string]json.RawMessage{"guard.example.test": json.RawMessage(`[{"transform":{"headers":{"X-Plimsoll-Guard":"crg_0123456789abcdef0123"}}}]`)}}}
	d := ruled.differs(open)
	if d == "" || strings.Contains(d, "crg_0123456789abcdef") {
		t.Fatalf("a rule left on: %q", d)
	}
}

func TestValidateE2BSessionGrants(t *testing.T) {
	for _, v := range []string{"", "session", "call"} {
		if err := validateE2BSessionGrants(v, "https://guard.example.test"); err != nil {
			t.Errorf("%q: %v", v, err)
		}
	}
	if validateE2BSessionGrants("Session", "https://guard.example.test") == nil {
		t.Error("an unknown value was accepted")
	}
	if validateE2BSessionGrants("call", "") == nil {
		t.Error("session grants without a guard URL were accepted")
	}
}
