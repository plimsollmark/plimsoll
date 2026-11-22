package receipt

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/plimsollmark/plimsoll/attest/tsa"
)

// MaxBytes's comment states what a receipt of eight endorsements at the largest
// time-stamp response holds: envelope files of 32,000 bytes each fit, and of 33,000 do
// not. This fails when MaxBytes, maxRoles or tsa.MaxResponse changes enough to make the
// comment false (hunt-quality-27).
func TestMaxBytesHoldsEightFullEndorsements(t *testing.T) {
	size := func(envelope int) int {
		r := Receipt{Version: 1}
		for i := range maxRoles {
			r.Endorsements = append(r.Endorsements, Endorsement{
				Role: fmt.Sprintf("role-%d", i+1), Envelope: make([]byte, envelope), Timestamp: make([]byte, tsa.MaxResponse),
			})
		}
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	}
	if maxRoles != 8 {
		t.Fatalf("maxRoles is %d; MaxBytes's comment states 8", maxRoles)
	}
	if n := size(32000); n > MaxBytes {
		t.Errorf("eight endorsements with 32,000-byte envelopes are %d bytes, past MaxBytes %d", n, MaxBytes)
	}
	if n := size(33000); n <= MaxBytes {
		t.Errorf("eight endorsements with 33,000-byte envelopes are %d bytes, within MaxBytes %d: the comment understates the room", n, MaxBytes)
	}
}
