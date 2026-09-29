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
// daemon may execute. An informational field does not bump it.
package protocol

import "fmt"

// Number is the protocol number this module speaks: the daemon in cmd/plimsolld
// serves exactly it and the client in package client stamps it on every request.
const Number uint32 = 1

// Mismatch is the text a daemon puts on its refusal of a request that states
// another number. A client recognises the refusal by its NotDispatched detail
// (reason protocol), never by this text.
func Mismatch(served, requested uint32) string {
	return fmt.Sprintf("%s%d and the request states %d; nothing ran", mismatchPrefix, served, requested)
}

const mismatchPrefix = "this daemon serves protocol "
