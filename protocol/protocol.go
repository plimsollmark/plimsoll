// Package protocol holds the one number the wire protocol is versioned by.
//
// Protobuf drops fields a receiver does not know, so a daemon that predates a
// security-relevant request field (an isolation floor, a limit, a capability
// restriction) would execute a request without it. A client therefore states the
// protocol it speaks on every Run request and a daemon serves exactly one number:
// a request that omits it is refused as invalid and a request on any other number
// is refused as unimplemented, both before the payload is read. Describe reports
// the daemon's number so a caller can compare before relying on it.
//
// Bump Number when a request field is added whose omission would change what a
// daemon may execute, or when clients start requiring something of the daemon's
// answers: an older daemon then refuses the request before it runs anything, instead
// of running it and giving an answer the client must reject. An informational field
// does not bump it. 3: clients accept only an answer that carries their request's
// Plimsoll-Request-Id back (internal/rpc.BindAnswers).
package protocol

import "fmt"

// Number is the protocol number this module speaks: the daemon in cmd/plimsolld
// serves exactly it and the client in package client stamps it on every request.
const Number uint32 = 3

// Mismatch is the text a daemon puts on its refusal of a request that states
// another number. A client recognises the refusal by its NotDispatched detail
// (reason protocol), never by this text.
func Mismatch(served, requested uint32) string {
	return fmt.Sprintf("%s%d and the request states %d; nothing ran", mismatchPrefix, served, requested)
}

const mismatchPrefix = "this daemon serves protocol "

// RequestIDHeader carries a client's ID for one HTTP request, 32 lowercase hex digits
// from a cryptographic random source, which the daemon copies onto the answer. What an
// answer says about a call holds only for the request it answers, so a client refuses
// an answer that does not carry its ID back.
const RequestIDHeader = "Plimsoll-Request-Id"

// NotDispatchedHeader marks an answer the daemon wrote before any procedure's handler
// was reached, so nothing can have run; its value is a refusal reason's name
// (sandbox.Refusal's String). A NotDispatched detail in the body takes precedence.
const NotDispatchedHeader = "Plimsoll-Not-Dispatched"
