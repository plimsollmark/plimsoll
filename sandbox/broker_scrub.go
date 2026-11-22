package sandbox

import (
	"bytes"
	"encoding/base64"
	"sort"
)

// An allowed route can answer with the credential the broker attached: an endpoint
// that echoes request headers does. The broker therefore looks for every exact copy of
// what it sent in an answer before the guest reads it, in a buffered answer and in a
// streamed one, and an answer that holds one never reaches the guest: the broker
// withholds it and ends the run's grant (brokerSession.credentialMatched). Exact means
// byte for byte: the credential itself and, for basic authentication, the base64 value
// of the header. A copy the API re-encoded, escaped, split or cut short is not
// recognized, so a route that echoes its request is still not one to grant; this is the
// second line, not the first.
//
// A match is an event, never an edit in place (finding hunt-security-32): replacing each
// copy with a mark and sending the rest told code that can have a route reflect strings
// which of them equals the credential.

// minScrubbedCredential is the shortest credential that is looked for. Below it a
// placeholder credential (a development "dev" or "x") would match ordinary words in
// every answer and end the grant, and a string that short is no secret. It is not a
// rule about which credentials are safe to use: a credential used with a grant must be
// random (docs/capability-grants.md), and none of length or form is refused here.
const minScrubbedCredential = 8

// scrubHold is how much of a stream's unfinished last word may wait for the next piece.
// It is a constant so that what is held never depends on the credential: see
// streamScrubber.
const scrubHold = 1024

// credentialCopies lists the byte strings applyCredential puts on the wire for token
// under grant's placement, longest first, leaving out any shorter than
// minScrubbedCredential. Nil means there is nothing to look for.
func credentialCopies(grant *HostAPIGrant, token string) [][]byte {
	if token == "" {
		return nil
	}
	forms := []string{token}
	if grant.CredentialPlacement.Kind == CredentialBasic {
		forms = append(forms, base64.StdEncoding.EncodeToString([]byte(grant.CredentialPlacement.Username+":"+token)))
	}
	var copies [][]byte
	for _, f := range forms {
		if len(f) >= minScrubbedCredential {
			copies = append(copies, []byte(f))
		}
	}
	sort.SliceStable(copies, func(i, j int) bool { return len(copies[i]) > len(copies[j]) })
	return copies
}

// copyStartsBefore reports whether a copy starts in data before limit (it may run past
// limit).
func copyStartsBefore(data []byte, copies [][]byte, limit int) bool {
	for _, c := range copies {
		if j := bytes.Index(data, c); j >= 0 && j < limit {
			return true
		}
	}
	return false
}

// holdsCopy reports whether data holds a whole copy. With nothing to look for, it never
// does.
func holdsCopy(data []byte, copies [][]byte) bool {
	return copyStartsBefore(data, copies, len(data))
}

// credentialByte reports whether c can be part of a copy: newBrokerSession accepts a
// credential only of bytes 0x21 to 0x7e, and base64 stays inside that range. A copy
// therefore never crosses a space, a line end or a byte outside ASCII.
func credentialByte(c byte) bool { return c >= 0x21 && c <= 0x7e }

// streamScrubber looks for copies in an answer that arrives in pieces, where a copy can
// be split across two of them. Once it has found one (hit), the stream is cut and nothing
// more of it is sent: not the piece that held the copy, not what was waiting.
//
// What it holds back between pieces must not depend on the credential. Holding "the
// end of this piece, because it matches the start of the credential" would let guest
// code that can shape an answer learn the credential a byte at a time, by watching
// which endings are delayed. So the rule reads the data alone: the unfinished last word
// of a piece (its trailing run of credentialByte bytes, at most hold of them) waits for
// the next piece, and everything before it is scanned and sent. A copy cannot start
// before that run and reach past the piece, because the byte before the run cannot be
// part of one. A server-sent event ends with a blank line, so a piece that ends on an
// event boundary holds nothing back, and a reader of events cannot use an unfinished
// line anyway.
type streamScrubber struct {
	copies [][]byte
	hold   int
	carry  []byte
	hit    bool
}

// newStreamScrubber returns nil when there is nothing to look for: the stream then
// passes through untouched.
func newStreamScrubber(copies [][]byte) *streamScrubber {
	if len(copies) == 0 {
		return nil
	}
	hold := scrubHold
	if longest := len(copies[0]) - 1; longest > hold {
		hold = longest // a credential longer than the constant: its length shows, the copy does not
	}
	return &streamScrubber{copies: copies, hold: hold}
}

// next takes one piece and returns what may go to the guest now: nil once a copy has
// been found, in this piece or before. The result is a new slice; piece is not kept.
func (s *streamScrubber) next(piece []byte) []byte {
	if s.hit {
		return nil
	}
	data := make([]byte, 0, len(s.carry)+len(piece))
	data = append(append(data, s.carry...), piece...)
	run := 0
	for run < s.hold && run < len(data) && credentialByte(data[len(data)-1-run]) {
		run++
	}
	if copyStartsBefore(data, s.copies, len(data)-run) {
		s.hit, s.carry = true, nil
		return nil
	}
	s.carry = append(s.carry[:0], data[len(data)-run:]...)
	return data[:len(data)-run]
}

// end returns what was held, scanned, when the upstream itself ended the stream: nil
// when it held a copy (hit is then set). A stream the broker cuts (the byte cap, the
// idle limit, the deadline, a guest that stopped reading) calls drop instead: the cut
// can fall inside a copy, and sending the part before it would hand over the credential
// less its last bytes.
func (s *streamScrubber) end() []byte {
	out := s.carry
	s.carry = nil
	if s.hit || holdsCopy(out, s.copies) {
		s.hit = true
		return nil
	}
	return out
}

// drop discards what was held.
func (s *streamScrubber) drop() { s.carry = nil }
