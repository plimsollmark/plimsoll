package providerkit

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestCaptureKeepsAnExactPrefixAndReportsTheCutOutOfBand(t *testing.T) {
	for _, tc := range []struct {
		limit     int
		writes    []string
		want      string
		truncated bool
	}{
		{5, []string{"abc", "de"}, "abcde", false},
		{5, []string{"abc", "de", "f"}, "abcde", true},
		{4, []string{"abcdef"}, "abcd", true},
		{4, []string{"abcd"}, "abcd", false},
		{4, []string{"", "", ""}, "", false},
		{0, []string{""}, "", false},
		{0, []string{"a"}, "", true},
		{-1, []string{"a"}, "", true},
		{8, []string{"0123456789"}, "01234567", true},
	} {
		c := Capture{Limit: tc.limit}
		for _, w := range tc.writes {
			if n, err := c.Write([]byte(w)); n != len(w) || err != nil {
				t.Fatalf("Write(%q) = %d, %v: a capture always takes the whole write, so a pipe never blocks", w, n, err)
			}
		}
		if c.String() != tc.want || string(c.Bytes()) != tc.want || c.Truncated() != tc.truncated {
			t.Errorf("limit %d, writes %q: kept %q, truncated %v; want %q, %v", tc.limit, tc.writes, c.String(), c.Truncated(), tc.want, tc.truncated)
		}
		if strings.Contains(c.String(), "truncated") {
			t.Errorf("an in-band truncation marker reached the output: %q", c.String())
		}
	}
}

func TestClampTimeout(t *testing.T) {
	const def, max = 10 * time.Second, time.Minute
	for req, want := range map[time.Duration]time.Duration{
		-time.Second: def, 0: def, 1: 1, time.Second: time.Second, max - 1: max - 1, max: max, max + 1: max, 1000 * time.Hour: max,
	} {
		if got := ClampTimeout(req, def, max); got != want {
			t.Errorf("ClampTimeout(%v, %v, %v) = %v, want %v", req, def, max, got, want)
		}
	}
	if got := ClampTimeout(0, 2*time.Minute, max); got != max {
		t.Errorf("a default past the ceiling is cut to it: got %v", got)
	}
}

func TestRandHex(t *testing.T) {
	seen := map[string]bool{}
	for _, n := range []int{1, 6, 8, 12, 16, 32} {
		s := RandHex(n)
		if b, err := hex.DecodeString(s); err != nil || len(b) != n || strings.ToLower(s) != s {
			t.Fatalf("RandHex(%d) = %q, want %d bytes in lower-case hex", n, s, n)
		}
		if seen[s] {
			t.Fatalf("RandHex(%d) repeated %q", n, s)
		}
		seen[s] = true
	}
}
