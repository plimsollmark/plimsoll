package egress

import (
	"slices"
	"testing"
)

func TestOnlyUnansweredOrLocallyRefusedAttemptsAreClosed(t *testing.T) {
	for outcome, closed := range map[string]bool{
		"timeout": true, "UND_ERR_CONNECT_TIMEOUT": true, "EHOSTUNREACH": true, "ENETUNREACH": true,
		"ENETDOWN": true, "EADDRNOTAVAIL": true, "EACCES": true, "EPERM": true, "ENOTFOUND": true, "EAI_AGAIN": true,
		// Answers from outside the sandbox.
		"open": false, "ECONNREFUSED": false, "ECONNRESET": false, "UNABLE_TO_VERIFY_LEAF_SIGNATURE": false,
		"ERR_TLS_CERT_ALTNAME_INVALID": false, "SELF_SIGNED_CERT_IN_CHAIN": false, "something new": false, "": false,
	} {
		if Closed(outcome) != closed {
			t.Errorf("%q: closed %v, want %v", outcome, !closed, closed)
		}
	}
	got := Left(map[string]string{"tcp 1.1.1.1:443": "timeout", "tcp [2606:4700:4700::1111]:443": "ECONNREFUSED", "https://example.com": "UNABLE_TO_VERIFY_LEAF_SIGNATURE"})
	want := []string{"https://example.com UNABLE_TO_VERIFY_LEAF_SIGNATURE", "tcp [2606:4700:4700::1111]:443 ECONNREFUSED"}
	if !slices.Equal(got, want) {
		t.Fatalf("Left = %v, want %v", got, want)
	}
}
