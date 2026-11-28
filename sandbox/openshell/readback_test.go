package openshell

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/datamodelv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
)

// goodReadBack is a session sandbox's record and effective configuration as a v0.1.10
// gateway returns them when nothing differs from what p sent.
func goodReadBack(p *Provider) (*openshellv1.Sandbox, map[string]string, *sandboxv1.GetSandboxConfigResponse) {
	labels := map[string]string{instanceLabel: p.instance, runLabel: "1", sessionLabel: "1"}
	sb := &openshellv1.Sandbox{
		Metadata: &datamodelv1.ObjectMeta{Id: "id-1", Name: "plp-readback", Labels: labels},
		Spec: &openshellv1.SandboxSpec{
			Template: &openshellv1.SandboxTemplate{Image: p.cfg.Image, Resources: proto.Clone(p.resources).(*structpb.Struct)},
			Policy:   proto.Clone(p.policy).(*sandboxv1.SandboxPolicy),
			Command:  sessionCommand,
		},
		Status: &openshellv1.SandboxStatus{Phase: openshellv1.SandboxPhase_SANDBOX_PHASE_READY},
	}
	cfg := &sandboxv1.GetSandboxConfigResponse{
		Policy:                      proto.Clone(p.policy).(*sandboxv1.SandboxPolicy),
		Version:                     1,
		PolicyHash:                  p.policyHash,
		PolicySource:                sandboxv1.PolicySource_POLICY_SOURCE_SANDBOX,
		ConfigurationAdmitted:       true,
		PolicyValidationFailureMode: "fail_closed",
		Settings:                    map[string]*sandboxv1.EffectiveSetting{agentProposalsSetting: {}},
	}
	return sb, labels, cfg
}

// readBackOf runs the read-back the root's message goes through: verifySandbox for the
// sandbox record, checkConfig for the effective configuration.
func readBackOf(p *Provider, labels map[string]string, m proto.Message) error {
	switch m := m.(type) {
	case *openshellv1.Sandbox:
		return p.verifySandbox(m, labels, sessionCommand, nil)
	case *sandboxv1.GetSandboxConfigResponse:
		return p.checkConfig(m, func() (string, error) { return "v0.1.10", nil })
	}
	panic("no read-back for " + string(m.ProtoReflect().Descriptor().FullName()))
}

// changeField gives the field at path (from the root message m) a value it does not
// have: a new element or entry for a list or map, the opposite presence for a message
// (a Struct gets an entry), and for a scalar another value (an enum its last defined
// value other than the current one).
func changeField(m protoreflect.Message, path []protoreflect.FieldDescriptor) {
	for _, fd := range path[:len(path)-1] {
		m = m.Mutable(fd).Message()
	}
	fd := path[len(path)-1]
	switch {
	case fd.IsList():
		l := m.Mutable(fd).List()
		if fd.Message() != nil {
			l.Append(l.NewElement())
		} else {
			l.Append(otherScalar(fd, protoreflect.Value{}))
		}
	case fd.IsMap():
		mp := m.Mutable(fd).Map()
		key := protoreflect.ValueOfString("plimsoll-readback-test").MapKey()
		if fd.MapValue().Message() != nil {
			mp.Set(key, mp.NewValue())
		} else {
			mp.Set(key, otherScalar(fd.MapValue(), protoreflect.Value{}))
		}
	case fd.Message() != nil:
		switch {
		case m.Has(fd):
			m.Clear(fd)
		case fd.Message().FullName() == "google.protobuf.Struct":
			s, _ := structpb.NewStruct(map[string]any{"plimsoll-readback-test": 1})
			m.Set(fd, protoreflect.ValueOfMessage(s.ProtoReflect()))
		default:
			m.Mutable(fd)
		}
	default:
		m.Set(fd, otherScalar(fd, m.Get(fd)))
	}
}

func otherScalar(fd protoreflect.FieldDescriptor, cur protoreflect.Value) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(!cur.Bool())
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(cur.String() + "-changed")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(append(cur.Bytes(), 1))
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		for i := values.Len() - 1; i >= 0; i-- {
			if n := values.Get(i).Number(); n != cur.Enum() {
				return protoreflect.ValueOfEnum(n)
			}
		}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(cur.Int()) + 1)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(cur.Int() + 1)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(cur.Uint()) + 1)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(cur.Uint() + 1)
	}
	panic("no other value for " + string(fd.FullName()))
}

// TestEveryReadBackFieldIsDecided walks every field the vendored API defines under the
// messages the read-back reads and fails on one with no row in readBackFields, so a
// re-vendoring that adds a field fails until someone decides it. For each compared,
// refused or ignored field it then changes that one field of a read-back that passes and
// checks the row: compared and refused refuse the run, ignored passes it.
func TestEveryReadBackFieldIsDecided(t *testing.T) {
	t.Parallel()
	_, p := newFake(t)
	sb, labels, cfg := goodReadBack(p)
	for _, m := range []proto.Message{sb, cfg} {
		if err := readBackOf(p, labels, m); err != nil {
			t.Fatalf("the unchanged %s is refused: %v", m.ProtoReflect().Descriptor().FullName(), err)
		}
	}
	seen := map[protoreflect.FullName]bool{}
	var walk func(root proto.Message, md protoreflect.MessageDescriptor, path []protoreflect.FieldDescriptor)
	walk = func(root proto.Message, md protoreflect.MessageDescriptor, path []protoreflect.FieldDescriptor) {
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			seen[fd.FullName()] = true
			row, ok := readBackFields[fd.FullName()]
			if !ok {
				t.Errorf("%s (field %d) has no row in readBackFields: decide whether the read-back compares it, refuses it when set, or ignores it, and why", fd.FullName(), fd.Number())
				continue
			}
			here := append(append([]protoreflect.FieldDescriptor(nil), path...), fd)
			switch row.rule {
			case readWalked:
				if fd.Message() == nil || fd.IsList() || fd.IsMap() {
					t.Errorf("%s is walked but is not a single message", fd.FullName())
					continue
				}
				walk(root, fd.Message(), here)
				continue
			case readChecked:
				if row.why == "" {
					t.Errorf("%s is checked in part with no reason", fd.FullName())
				}
				continue
			case readCompared, readRefused, readIgnored:
				if row.why == "" {
					t.Errorf("%s has no reason", fd.FullName())
				}
			default:
				t.Errorf("%s has no rule", fd.FullName())
				continue
			}
			changed := proto.Clone(root)
			changeField(changed.ProtoReflect(), here)
			err := readBackOf(p, labels, changed)
			switch {
			case row.rule == readIgnored && err != nil:
				t.Errorf("%s is ignored, but a changed value is refused: %v", fd.FullName(), err)
			case row.rule != readIgnored && err == nil:
				t.Errorf("%s is %s, but a changed value passes the read-back", fd.FullName(), map[readBackRule]string{readCompared: "compared", readRefused: "refused when set"}[row.rule])
			}
		}
	}
	for _, root := range []proto.Message{sb, cfg} {
		walk(root, root.ProtoReflect().Descriptor(), nil)
	}
	for name := range readBackFields {
		if !seen[name] {
			t.Errorf("readBackFields has a row for %s, which the vendored API does not define under the read-back's messages", name)
		}
	}
	if len(readBackRoots) != 2 || readBackRoots[0] != sb.ProtoReflect().Descriptor() || readBackRoots[1] != cfg.ProtoReflect().Descriptor() {
		t.Errorf("readBackRoots names other messages than this test walks")
	}
}

// TestPolicyValidationFailureMode: only fail_closed, or no value (which the v0.1.10
// supervisor reads as fail_closed), passes. Under retain_last_valid a supervisor that
// rejects a policy generation keeps the one before it, so the policy read back would not
// be the one enforced.
func TestPolicyValidationFailureMode(t *testing.T) {
	t.Parallel()
	_, p := newFake(t)
	for mode, ok := range map[string]bool{"fail_closed": true, "": true, "retain_last_valid": false, "FAIL_CLOSED": false, "keep_old": false} {
		_, _, cfg := goodReadBack(p)
		cfg.PolicyValidationFailureMode = mode
		err := readBackOf(p, nil, cfg)
		if ok && err != nil {
			t.Errorf("mode %q is refused: %v", mode, err)
		}
		if !ok && (err == nil || !strings.Contains(err.Error(), "policy_validation_failure_mode")) {
			t.Errorf("mode %q: got %v, want a refusal naming policy_validation_failure_mode", mode, err)
		}
	}
}
