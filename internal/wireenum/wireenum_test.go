package wireenum

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
)

// Every value the protocol defines, but unspecified, is in the table exactly once, and
// each round-trips: a value added to sandbox.proto fails here until the table names it.
func TestEveryProtocolValueRoundTrips(t *testing.T) {
	check := func(d protoreflect.EnumDescriptor, roundTrip func(n protoreflect.EnumNumber) (protoreflect.EnumNumber, bool)) {
		vs := d.Values()
		for i := range vs.Len() {
			n := vs.Get(i).Number()
			if n == 0 {
				continue
			}
			back, named := roundTrip(n)
			if !named || back != n {
				t.Errorf("%s: %s is not in the table, or does not come back as itself", d.FullName(), vs.Get(i).Name())
			}
		}
	}
	check(plimsollv1.ProjectOutcome(0).Descriptor(), func(n protoreflect.EnumNumber) (protoreflect.EnumNumber, bool) {
		w := plimsollv1.ProjectOutcome(n)
		return protoreflect.EnumNumber(OutcomeToWire(OutcomeFromWire(w))), OutcomeFromWire(w) != 0
	})
	check(plimsollv1.SessionEnd(0).Descriptor(), func(n protoreflect.EnumNumber) (protoreflect.EnumNumber, bool) {
		w := plimsollv1.SessionEnd(n)
		s := SessionEndFromWire(w)
		return protoreflect.EnumNumber(SessionEndToWire(s)), SessionEndToWire(s) != 0
	})
	check(plimsollv1.NotDispatchedReason(0).Descriptor(), func(n protoreflect.EnumNumber) (protoreflect.EnumNumber, bool) {
		w := plimsollv1.NotDispatchedReason(n)
		return protoreflect.EnumNumber(RefusalToWire(RefusalFromWire(w))), RefusalToWire(RefusalFromWire(w)) != 0
	})
	check(plimsollv1.CapacityLimit(0).Descriptor(), func(n protoreflect.EnumNumber) (protoreflect.EnumNumber, bool) {
		w := plimsollv1.CapacityLimit(n)
		return protoreflect.EnumNumber(CapacityLimitToWire(CapacityLimitFromWire(w))), CapacityLimitToWire(CapacityLimitFromWire(w)) != 0
	})
	// Each limit's short name is the protocol's, as the Python and TypeScript clients
	// name it (internal/wiretables), so the three clients say the same word.
	for _, e := range capacityLimits {
		if want := strings.ToLower(strings.TrimPrefix(e.w.String(), "CAPACITY_LIMIT_")); e.s.String() != want {
			t.Errorf("capacity limit %s is named %q in package sandbox, the protocol's name is %q", e.w, e.s, want)
		}
	}
	// No sandbox value appears twice, which would make the reverse direction ambiguous.
	seen := map[any]bool{}
	for _, e := range capacityLimits {
		if seen[e.s] {
			t.Errorf("capacity limit %v twice", e.s)
		}
		seen[e.s] = true
	}
	for _, e := range outcomes {
		if seen[e.s] {
			t.Errorf("outcome %v twice", e.s)
		}
		seen[e.s] = true
	}
	for _, e := range sessionEnds {
		if seen[e.s] {
			t.Errorf("session end %v twice", e.s)
		}
		seen[e.s] = true
	}
	for _, e := range refusals {
		if seen[e.s] {
			t.Errorf("refusal %v twice", e.s)
		}
		seen[e.s] = true
	}
}
