package record

import (
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// unsigned names every request and response field that deliberately moves no digest,
// with the reason. Every other field, at any depth, must move one: the request digest
// for a request, and for a response the record's own digest, which covers the result
// digest and the evidence Stamp copies from the envelope. A field added to the protocol
// therefore fails TestEveryFieldMovesADigest until the encoder covers it or it is
// listed here, so nothing that changes what runs can be left out of a signed record by
// forgetting to add it to the encoder.
var unsigned = map[protoreflect.FullName]string{
	"plimsoll.v1.RunRequest.trace_id":          "the caller's correlation key: it changes nothing that runs",
	"plimsoll.v1.SessionRunRequest.trace_id":   "the caller's correlation key: it changes nothing that runs",
	"plimsoll.v1.SessionRunRequest.session_id": "a capability: the record carries the session's fingerprint instead",
	"plimsoll.v1.RunResponse.duration_ms":      "differs on every run, so no replay could reproduce it",
	"plimsoll.v1.StepResult.duration_ms":       "differs on every run, so no replay could reproduce it",
	"plimsoll.v1.RunResponse.record":           "the record itself",
	"plimsoll.v1.JavaScriptResult.advice":      "analysis of the run, not its output (docs/efficiency-advisor.md)",
	"plimsoll.v1.ProjectResult.advice":         "analysis of the run, not its output (docs/efficiency-advisor.md)",
}

type digested struct {
	msg    proto.Message
	digest func(proto.Message) string
}

func digestedMessages() []digested {
	return []digested{
		{&plimsollv1.RunRequest{}, func(m proto.Message) string { return RunRequestDigest(m.(*plimsollv1.RunRequest)) }},
		{&plimsollv1.SessionRunRequest{}, func(m proto.Message) string {
			return SessionRunRequestDigest(m.(*plimsollv1.SessionRunRequest))
		}},
		{&plimsollv1.RunResponse{}, func(m proto.Message) string {
			return Stamp(goldenRecord(), m.(*plimsollv1.RunResponse)).GetRecordSha256()
		}},
	}
}

func TestEveryFieldMovesADigest(t *testing.T) {
	seen := map[protoreflect.FullName]bool{}
	for _, d := range digestedMessages() {
		md := d.msg.ProtoReflect().Descriptor()
		for _, path := range fieldPaths(md, nil, seen) {
			base := d.msg.ProtoReflect().New()
			fill(base, path)
			for _, change := range []string{"value", "count"} {
				changed := proto.Clone(base.Interface()).ProtoReflect()
				if !mutate(changed, path, change) {
					continue
				}
				if d.digest(base.Interface()) == d.digest(changed.Interface()) {
					t.Errorf("%s: changing its %s moves no digest. Cover it in record.go, or list it in unsigned with the reason",
						pathName(path), change)
				}
			}
		}
	}
	for name := range unsigned {
		if !seen[name] {
			t.Errorf("unsigned lists %s, which no digested message has: delete the entry", name)
		}
	}
}

// Every field of the wire record survives FromWire and ToWire, so a field added to
// RunRecord in sandbox.proto cannot be dropped between the wire and the digest.
func TestEveryWireRecordFieldRoundTrips(t *testing.T) {
	m := &plimsollv1.RunRecord{}
	fill(m.ProtoReflect(), nil)
	if back := ToWire(FromWire(m)); !proto.Equal(back, m) {
		t.Errorf("FromWire then ToWire changed the record:\n got %v\nwant %v", back, m)
	}
	// The times are whole milliseconds on the wire and in the struct alike.
	if got := FromWire(m).Started; !got.Equal(time.UnixMilli(m.GetStartedUnixMs())) {
		t.Errorf("started reads %v", got)
	}
	_ = sandbox.RunRecord{}
}

// fieldPaths lists the path to every field under md that the test changes: each
// scalar, enum and repeated field, and each field of a nested message, depth first.
// A field in unsigned is marked seen and not descended into.
func fieldPaths(md protoreflect.MessageDescriptor, prefix []protoreflect.FieldDescriptor, seen map[protoreflect.FullName]bool) [][]protoreflect.FieldDescriptor {
	if len(prefix) > 8 {
		panic("record: message nesting deeper than 8 at " + pathName(prefix))
	}
	var out [][]protoreflect.FieldDescriptor
	fields := md.Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		path := append(slices.Clone(prefix), fd)
		if _, skip := unsigned[fd.FullName()]; skip {
			seen[fd.FullName()] = true
			continue
		}
		if fd.Kind() == protoreflect.MessageKind && !fd.IsMap() {
			if fd.IsList() {
				out = append(out, path)
			}
			out = append(out, fieldPaths(fd.Message(), path, seen)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// fill sets every field of m to a value other than its default: two elements in a
// list, every field of a nested message. In each oneof it sets the member path names,
// and the first member where path names none.
func fill(m protoreflect.Message, path []protoreflect.FieldDescriptor) {
	fields := m.Descriptor().Fields()
	for i := range fields.Len() {
		fd := fields.Get(i)
		if o := fd.ContainingOneof(); o != nil && !o.IsSynthetic() && fd != chosen(o, path) {
			continue
		}
		rest := path
		if len(path) > 0 && path[0] == fd {
			rest = path[1:]
		} else {
			rest = nil
		}
		switch {
		case fd.IsMap():
			panic("record: a map field needs a case in fill: " + string(fd.FullName()))
		case fd.IsList():
			list := m.Mutable(fd).List()
			for range 2 {
				list.Append(element(list, fd, rest))
			}
		case fd.Kind() == protoreflect.MessageKind:
			fill(m.Mutable(fd).Message(), rest)
		default:
			m.Set(fd, scalar(fd))
		}
	}
}

func chosen(o protoreflect.OneofDescriptor, path []protoreflect.FieldDescriptor) protoreflect.FieldDescriptor {
	for _, fd := range path {
		if fd.ContainingOneof() == o {
			return fd
		}
	}
	return o.Fields().Get(0)
}

func element(list protoreflect.List, fd protoreflect.FieldDescriptor, rest []protoreflect.FieldDescriptor) protoreflect.Value {
	if fd.Kind() == protoreflect.MessageKind {
		v := list.NewElement()
		fill(v.Message(), rest)
		return v
	}
	return scalar(fd)
}

func scalar(fd protoreflect.FieldDescriptor) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString("v-" + string(fd.Name()))
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes([]byte("v-" + string(fd.Name())))
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(true)
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(7)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(7)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(7)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(7)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(0.5)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(0.5)
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		return protoreflect.ValueOfEnum(values.Get(min(1, values.Len()-1)).Number())
	}
	panic("record: no value for " + fd.Kind().String())
}

// changed is a scalar that differs from scalar(fd).
func changed(fd protoreflect.FieldDescriptor, v protoreflect.Value) protoreflect.Value {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(v.String() + "x")
	case protoreflect.BytesKind:
		return protoreflect.ValueOfBytes(append(slices.Clone(v.Bytes()), 'x'))
	case protoreflect.BoolKind:
		return protoreflect.ValueOfBool(!v.Bool())
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return protoreflect.ValueOfInt32(int32(v.Int()) + 1)
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return protoreflect.ValueOfInt64(v.Int() + 1)
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return protoreflect.ValueOfUint32(uint32(v.Uint()) + 1)
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return protoreflect.ValueOfUint64(v.Uint() + 1)
	case protoreflect.FloatKind:
		return protoreflect.ValueOfFloat32(float32(v.Float()) + 0.25)
	case protoreflect.DoubleKind:
		return protoreflect.ValueOfFloat64(v.Float() + 0.25)
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		for i := range values.Len() {
			if n := values.Get(i).Number(); n != v.Enum() {
				return protoreflect.ValueOfEnum(n)
			}
		}
	}
	panic("record: cannot change " + string(fd.FullName()))
}

// mutate changes the field at the end of path in m: its value ("value"; in a list,
// the first element's), or a list's length ("count", one element more). It reports
// false when the change does not apply to the field.
func mutate(m protoreflect.Message, path []protoreflect.FieldDescriptor, change string) bool {
	for _, fd := range path[:len(path)-1] {
		if fd.IsList() {
			m = m.Mutable(fd).List().Get(0).Message()
		} else {
			m = m.Mutable(fd).Message()
		}
	}
	fd := path[len(path)-1]
	switch {
	case change == "count" && fd.IsList():
		list := m.Mutable(fd).List()
		list.Append(element(list, fd, nil))
		return true
	case change == "value" && fd.IsList() && fd.Kind() != protoreflect.MessageKind:
		list := m.Mutable(fd).List()
		list.Set(0, changed(fd, list.Get(0)))
		return true
	case change == "value" && !fd.IsList() && fd.Kind() != protoreflect.MessageKind:
		m.Set(fd, changed(fd, m.Get(fd)))
		return true
	}
	return false
}

func pathName(path []protoreflect.FieldDescriptor) string {
	parts := make([]string, len(path))
	for i, fd := range path {
		parts[i] = string(fd.Name())
	}
	if len(path) == 0 {
		return ""
	}
	return string(path[0].ContainingMessage().Name()) + "." + strings.Join(parts, ".")
}
