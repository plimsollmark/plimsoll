package sandbox

import (
	"reflect"
	"testing"
)

// TestHostAPIGrantCloneSharesNothing: a clone shares no map, slice or pointer with its
// original, at any depth. Every exported field is filled and then changed by reflection,
// so a field added to HostAPIGrant later is covered without a change here; the hand
// written check this replaces had missed SetHeaders (release review,
// 2026-10-29).
func TestHostAPIGrantCloneSharesNothing(t *testing.T) {
	var fill func(v reflect.Value)
	fill = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			v.SetString("x")
		case reflect.Int, reflect.Int32, reflect.Int64:
			v.SetInt(7)
		case reflect.Bool:
			v.SetBool(true)
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					fill(v.Field(i))
				}
			}
		case reflect.Slice:
			s := reflect.MakeSlice(v.Type(), 1, 1)
			fill(s.Index(0))
			v.Set(s)
		case reflect.Map:
			m := reflect.MakeMap(v.Type())
			k, e := reflect.New(v.Type().Key()).Elem(), reflect.New(v.Type().Elem()).Elem()
			fill(k)
			fill(e)
			m.SetMapIndex(k, e)
			v.Set(m)
		case reflect.Pointer:
			p := reflect.New(v.Type().Elem())
			fill(p.Elem())
			v.Set(p)
		}
	}
	var change func(v reflect.Value)
	change = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			v.SetString(v.String() + "-changed")
		case reflect.Int, reflect.Int32, reflect.Int64:
			v.SetInt(v.Int() + 1)
		case reflect.Bool:
			v.SetBool(!v.Bool())
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if v.Field(i).CanSet() {
					change(v.Field(i))
				}
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				change(v.Index(i)) // in place: a shared backing array shows in the original
			}
		case reflect.Map:
			for _, k := range v.MapKeys() {
				e := reflect.New(v.Type().Elem()).Elem()
				e.Set(v.MapIndex(k)) // a slice value keeps its backing array
				change(e)
				v.SetMapIndex(k, e)
			}
		case reflect.Pointer:
			if !v.IsNil() {
				change(v.Elem())
			}
		}
	}
	var g, want HostAPIGrant
	fill(reflect.ValueOf(&g).Elem())
	fill(reflect.ValueOf(&want).Elem())
	c := g.Clone()
	if !reflect.DeepEqual(*c, g) {
		t.Fatalf("the clone differs from its original before any change:\n%+v\n%+v", *c, g)
	}
	change(reflect.ValueOf(c).Elem())
	gv, wv := reflect.ValueOf(g), reflect.ValueOf(want)
	for i := 0; i < gv.NumField(); i++ {
		if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
			t.Errorf("HostAPIGrant.%s changed with its clone: Clone shares it", gv.Type().Field(i).Name)
		}
	}
}
