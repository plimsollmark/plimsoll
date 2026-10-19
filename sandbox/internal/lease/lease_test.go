package lease

import "testing"

func TestSetTracksUntilUntracked(t *testing.T) {
	var s Set
	if s.Tracked("a") || s.Len() != 0 {
		t.Fatal("a zero Set tracks something")
	}
	s.Track("a")
	s.Track("b")
	s.Track("a")
	if !s.Tracked("a") || !s.Tracked("b") || s.Len() != 2 {
		t.Fatalf("after tracking a, b, a: len %d", s.Len())
	}
	keys := s.Keys()
	if len(keys) != 2 || keys[0] != "a" || keys[1] != "b" {
		t.Fatalf("keys: %v", keys)
	}
	keys[0] = "changed"
	if !s.Tracked("a") || s.Tracked("changed") {
		t.Fatal("a key snapshot changed the set")
	}
	s.Untrack("a")
	s.Untrack("never")
	if s.Tracked("a") || !s.Tracked("b") || s.Len() != 1 {
		t.Fatalf("after untracking a: len %d", s.Len())
	}
}
