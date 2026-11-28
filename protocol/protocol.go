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
// Plimsoll-Request-Id back (internal/rpc.BindAnswers). 4: clients accept only record
// version 4, which names the sandbox instance that ran the call. 5: a Run cell may ask
// for a waiting pool member (RunRequest.prefer_warm) and an open for one
// (OpenSessionRequest.warm_only); a daemon that predated them would ignore either and
// make a sandbox, billed by the second on e2b and dockercloud, so it refuses them
// instead, before reading the request. 6: clients accept only record version 5, which
// states the sentence the provider requires beside its tier
// (RunResponse.isolation_qualification), whether a waiting pool sandbox ran the call and
// the daemon's version; an older daemon would run the code (billed by the second on e2b
// and dockercloud) and give an answer the client must then reject, so it refuses the
// request instead, before anything runs. Also 6, in the same release: every session run
// and close carries a positive ownership generation, so an older worker cannot execute or
// close after another worker attached; a daemon that predated it would ignore the field
// and run a stale worker's call. 7: clients refuse a record whose provider name is not
// UTF-8 or holds a control or bidirectional format character (record.ValidText, the rule
// the tier and the qualification were already held to), since a reader is shown the name
// beside the tier; an older client accepted such a record, so a daemon of this number
// refuses it before anything runs, and an older daemon refuses this client the same way.
// 8: every session call states the head it expects (SessionRunRequest.head, the
// generation, the count of calls and the last record digest, in place of the generation
// alone), and the daemon runs it only on that head; a daemon that predated it would
// ignore the head and run a call made from stale state, which this one refuses. In the
// same number, OpenSessionRequest.keep_no_answer asks the daemon to keep no answer, which
// an older daemon would ignore. 9: clients accept only record version 6, whose results
// are hashed under plimsoll.run-result.v2, and requests of this number are hashed under
// plimsoll.run-request.v3; both domains add the files kind, one operation on a session's
// files (SessionRunRequest.files). An older daemon would drop that payload; a client of
// this number refuses an older daemon's record version, and the daemon of either number
// refuses the other's requests, before anything runs.
package protocol

import "fmt"

// Number is the protocol number this module speaks: the daemon in cmd/plimsolld
// serves exactly it and the client in package client stamps it on every request.
const Number uint32 = 9

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

// The texts of a session's two ownership refusals, both FailedPrecondition and marked not
// dispatched: StaleOwnerText (reason permission) on a run, close or attach that carries
// a generation older than the session's, because another worker attached; and
// CheckpointMismatchText (reason request) on an attach whose checkpoint is not the
// session's head, because a call ran after the checkpoint was saved, and on a call whose
// head carries the current generation but is not the session's head. Each is a constant,
// so no refusal text states a number of the session's: a stale worker learns that it is
// stale, never what the current owner holds. A call's head mismatch, which only the
// current owner can get, carries the daemon's head as a SessionHeadMismatch detail. The clients tell a mismatch from any other
// refusal by code, reason and this text; internal/wiretables writes both into the Python
// and TypeScript clients.
const (
	StaleOwnerText         = "session ownership generation is stale"
	CheckpointMismatchText = "session checkpoint does not match"
)

// TraceIDPattern is the whole grammar of a request's correlation id (trace_id): 1 to 64
// characters of [A-Za-z0-9._:-]. The daemon drops an id outside it whole (internal/rpc),
// so the clients and the MCP server refuse one before sending; internal/wiretables
// writes it into the Python and TypeScript clients.
const TraceIDPattern = `^[A-Za-z0-9._:-]{1,64}$`
