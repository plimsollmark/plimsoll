package record

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// UnmarshalJSON reads m from its proto3 JSON form as protojson.Unmarshal does, and also
// refuses an integer written in a string that is not a whole decimal: protojson reads such
// a string from its leading digits, so "5 6", "5," and "5" with a zero byte after it each
// read as 5 (measured on google.golang.org/protobuf v1.36), where the Python and
// TypeScript clients refuse them. Every client must refuse such a value or read the same
// one (the shared malformed records of testdata/golden.json), so here an integer field's
// string must be an optional minus and decimal digits with no leading zero, the form every
// client writes.
func UnmarshalJSON(b []byte, m proto.Message) error {
	if err := protojson.Unmarshal(b, m); err != nil {
		return err
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return err
	}
	return checkIntegerStrings(m.ProtoReflect().Descriptor(), v, "")
}

var wholeDecimal = regexp.MustCompile(`^-?(?:0|[1-9][0-9]*)$`)

// checkIntegerStrings walks v, the JSON form of a message md describes, and refuses an
// integer field written as a string that is not a whole decimal. Well-known types keep
// their own JSON forms and are not walked.
func checkIntegerStrings(md protoreflect.MessageDescriptor, v any, at string) error {
	obj, ok := v.(map[string]any)
	if !ok || md.FullName().Parent() == "google.protobuf" {
		return nil
	}
	fields := md.Fields()
	for k, fv := range obj {
		fd := fields.ByJSONName(k)
		if fd == nil {
			fd = fields.ByTextName(k)
		}
		if fd == nil {
			continue // protojson has refused an unknown name already
		}
		path := at + "." + k
		switch {
		case fd.IsMap():
			entries, _ := fv.(map[string]any)
			for key, ev := range entries {
				if isInteger(fd.MapKey().Kind()) && !wholeDecimal.MatchString(key) {
					return fmt.Errorf("record: %s: the key %q is not a whole decimal", path, key)
				}
				if err := checkValue(fd.MapValue(), ev, path+"."+key); err != nil {
					return err
				}
			}
		case fd.IsList():
			items, _ := fv.([]any)
			for i, item := range items {
				if err := checkValue(fd, item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
					return err
				}
			}
		default:
			if err := checkValue(fd, fv, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkValue(fd protoreflect.FieldDescriptor, v any, path string) error {
	switch {
	case fd.Kind() == protoreflect.MessageKind || fd.Kind() == protoreflect.GroupKind:
		return checkIntegerStrings(fd.Message(), v, path)
	case isInteger(fd.Kind()):
		if s, ok := v.(string); ok && !wholeDecimal.MatchString(s) {
			return fmt.Errorf("record: %s: the integer %q is not a whole decimal", path, s)
		}
	}
	return nil
}

func isInteger(k protoreflect.Kind) bool {
	switch k {
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind,
		protoreflect.Uint32Kind, protoreflect.Fixed32Kind,
		protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind,
		protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return true
	}
	return false
}
