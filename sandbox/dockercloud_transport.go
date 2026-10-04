package sandbox

import (
	"context"
	"errors"
	"time"
)

// dcTransport is the wire half of the Docker Cloud provider: the calls a run makes,
// named by what the provider needs rather than by any one API. Docker serves the
// same sandboxes through two APIs, the pre-launch Connect contract this provider was
// first written against (dcConnect, dockercloud_connect.go) and the REST API it has
// documented since its launch on 2026-09-24. Each is one implementation of this
// interface, and a provider uses one for its whole life: there is no fallback from one
// to the other.
//
// Everything else lives in DockerCloud and is the same whichever API carries it: the
// lease tracking, the charge for a create whose outcome is unknown, the checks of what
// a new sandbox reports, the deny-all read-back, the exec wrapper and its bounds, the
// guard, artifacts and orphan reaping.
type dcTransport interface {
	// createSandbox sends one create and waits until the sandbox runs. A failure is a
	// *dcCreateError saying how far the create got, which decides how the run is
	// charged if the sandbox cannot be found to delete.
	createSandbox(ctx context.Context, spec dcCreateSpec) (dcReported, error)
	// deleteSandbox deletes one sandbox, by ID once known, else by name, and waits for
	// the deletion. existed is false when nothing was there to delete.
	deleteSandbox(ctx context.Context, vm dcVM, requestID string) (existed bool, err error)
	// listSandboxes reads one page of the account's sandboxes; next is empty on the
	// last page.
	listSandboxes(ctx context.Context, pageToken string) (page []dcListed, next string, err error)
	// checkCapabilities asks the service whether it serves this token what a run
	// needs, as far as the API can say.
	checkCapabilities(ctx context.Context) error
	// effectivePolicy reads back the network policy in force on one sandbox.
	effectivePolicy(ctx context.Context, vm dcVM) (dcPolicy, error)
	// exec runs cmd on the sandbox endpoint. flooded reports that the response body
	// exceeded limit; the body is then discarded unread.
	exec(ctx context.Context, vm dcVM, cmd []string, cwd string, limit int64) (out dcExecResponse, flooded bool, err error)
	// upload writes files, each at its absolute path.
	upload(ctx context.Context, vm dcVM, files []File) error
	// download reads the given absolute paths; a path the service reports missing is
	// left out. truncated reports that the artifact budget stopped it.
	download(ctx context.Context, vm dcVM, paths []string) (arts []Artifact, truncated bool, err error)
}

// dcCreateSpec is one sandbox to create, in the provider's terms.
type dcCreateSpec struct {
	// name is ours, chosen before the request is sent: the lease key and, while the
	// service has not answered, the only handle on the sandbox.
	name     string
	image    string
	startCmd []string
	// ttl is the sandbox's own lifetime: the service deletes it when ttl runs out, the
	// backstop if every delete fails.
	ttl       time.Duration
	cpus      uint32
	memoryMiB int
}

// dcCreateStage is how far a failed create got.
type dcCreateStage int

const (
	// dcCreateSend: the create request itself failed. Its error decides the outcome:
	// never sent (nothing exists), refused (nothing was made), or unknown.
	dcCreateSend dcCreateStage = iota
	// dcCreateWait: the service accepted the create, and it was still under way when
	// the run stopped waiting. The sandbox can appear after a delete finds nothing.
	dcCreateWait
	// dcCreateDone: the create finished but failed, or the sandbox it made could not
	// be read. Whatever exists is there now, so a delete settles it.
	dcCreateDone
)

// dcCreateError is a failed createSandbox, with how far it got.
type dcCreateError struct {
	stage dcCreateStage
	// id is the sandbox's ID when the service named it before the failure, so the
	// cleanup deletes by ID rather than by name.
	id  string
	err error
}

func (e *dcCreateError) Error() string { return e.err.Error() }
func (e *dcCreateError) Unwrap() error { return e.err }

// dcCreateOutcome reads a failed create: unsent means nothing can exist, unknown
// means the sandbox may appear after the run has given up on it. An error that does
// not say how far the create got is read as unknown, the outcome that charges the run.
func dcCreateOutcome(err error) (unsent, unknown bool) {
	var ce *dcCreateError
	if !errors.As(err, &ce) {
		return false, true
	}
	switch ce.stage {
	case dcCreateSend:
		unsent = dcUnsent(ce.err)
		return unsent, !unsent && !dcRefused(ce.err)
	case dcCreateWait:
		return false, true
	}
	return false, false
}

// dcReported is what a transport read about a sandbox, in its own API's shape.
type dcReported interface {
	view() dcSandboxView
}

// dcSandboxView is a sandbox in the provider's terms. A field the API did not report
// is empty or nil.
type dcSandboxView struct {
	id   string
	name string
	// endpoint is where exec and file calls go.
	endpoint string
	// endpointRefused says why the API reports an endpoint this provider must not
	// use; nil when it may.
	endpointRefused error
	cpus            *protoUint
	memoryMiB       *protoUint
	// reportsBootedDigest says the API reports which manifest a sandbox booted
	// (Connect); imageDigest is that digest, empty when this sandbox reported none.
	reportsBootedDigest bool
	imageDigest         string
	// recordedImage is the image reference the service recorded for the sandbox, from
	// an API that reports no booted digest (REST): what was asked for, not evidence of
	// what booted.
	recordedImage string
}

// dcListed is one sandbox of a listing page.
type dcListed struct {
	name      string
	id        string
	createdAt time.Time
}

// dcPolicy is the network policy in force on a sandbox.
type dcPolicy struct {
	// mode is the API's own word for it, kept for error messages.
	mode    string
	denyAll bool
	// allow lists the networks allowed despite deny-all.
	allow []string
}

// dcExecResponse is one finished exec: its exit status and whole output streams.
type dcExecResponse struct {
	ExitCode int32  `json:"exitCode"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}

// errArtifactBudget stops a download once the artifact budget is spent.
var errArtifactBudget = errors.New("artifact budget exhausted")
