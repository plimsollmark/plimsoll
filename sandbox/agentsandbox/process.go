package agentsandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/plimsollmark/plimsoll/gen/go/agentsandbox/processv1"
	"github.com/plimsollmark/plimsoll/gen/go/agentsandbox/processv1/processv1connect"
	"github.com/plimsollmark/plimsoll/sandbox/internal/providerkit"
)

const (
	// maxMessageBytes bounds one gRPC message read from sandboxd; it streams output in
	// chunks of its stream-chunk-size (32 KiB by default), so this only stops a
	// pathological message from being buffered whole.
	maxMessageBytes = 4 << 20
	// stdinFrame is the size of each WriteStdin call: a plan of many megabytes goes in
	// frames well inside sandboxd's 4 MiB default message limit.
	stdinFrame = 256 << 10
	// postExitGrace is how long the stream is read after the exit event for output that
	// arrives after it, which the protocol does not rule out.
	postExitGrace = time.Second
)

// h2cClient speaks HTTP/2 without TLS, with prior knowledge, which is what sandboxd's
// gRPC server accepts. sandboxd serves no TLS: its protection is the network policy that
// admits only plimsoll's source to its port, and the token it checks.
func h2cClient() *http.Client {
	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	return &http.Client{
		Transport:     &http.Transport{Protocols: protocols, Proxy: nil, DialContext: (&net.Dialer{Timeout: 10 * time.Second}).DialContext},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// process returns a ProcessService client for sandboxd at ip, every request carrying the
// token.
func (p *Provider) process(ip string) processv1connect.ProcessServiceClient {
	if p.dialProcess != nil {
		return p.dialProcess(ip)
	}
	base := "http://" + net.JoinHostPort(ip, strconv.Itoa(p.cfg.sandboxdPort()))
	return processv1connect.NewProcessServiceClient(p.h2c, base, connect.WithGRPC(),
		connect.WithReadMaxBytes(maxMessageBytes), connect.WithInterceptors(bearer(p.cfg.SandboxdToken)))
}

// bearer adds the token to every request, unary and streaming.
type bearer string

func (b bearer) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		req.Header().Set("Authorization", "Bearer "+string(b))
		return next(ctx, req)
	}
}

func (b bearer) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return func(ctx context.Context, spec connect.Spec) connect.StreamingClientConn {
		conn := next(ctx, spec)
		conn.RequestHeader().Set("Authorization", "Bearer "+string(b))
		return conn
	}
}

func (bearer) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return next
}

type execOutput struct {
	stdout, stderr                   []byte
	stdoutTruncated, stderrTruncated bool
	exitCode                         int
	exited                           bool
}

// exec runs argv in the pod through sandboxd's streamed Start, with stdin written in
// frames after the process has started, then closed. Each output stream keeps its first
// stdoutCap or stderrCap bytes and flags any it drops; the rest is read and discarded so
// the exit status still arrives. sandboxd itself bounds neither time nor output
// (agent-sandbox issue 1918, unary Execute buffers everything), which is why only the
// streamed call is used.
//
// ctx's end cancels the stream, which makes sandboxd kill the command's whole process
// tree (its killProcessGroupOnContextDone, v1.0.7); the claim's delete after the run ends
// anything that escaped with setsid. The exit status is authoritative: a command that
// exits without reading its stdin makes the writes fail while its exit still arrives.
//
// The calls carry no deadline of their own. Connect would send ctx's as Grpc-Timeout, and
// sandboxd's grpc-go server would then cancel the stream on its own clock: live under
// gVisor, a hung snippet's stream was once cancelled by the server a moment before this
// process's deadline, so the run read as a broken stream instead of a timeout. Only ctx's
// end, seen here, ends the calls early.
func (p *Provider) exec(ctx context.Context, ip string, argv []string, stdin []byte, stdoutCap, stderrCap int) (execOutput, error) {
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	defer cancel()
	defer context.AfterFunc(ctx, cancel)()
	c := p.process(ip)
	cwd := workDir
	stream, err := c.Start(streamCtx, connect.NewRequest(&processv1.StartRequest{Config: &processv1.ProcessConfig{Command: argv, Cwd: &cwd}}))
	if err != nil {
		return execOutput{}, fmt.Errorf("sandboxd start: %w", err)
	}
	defer stream.Close()

	stdout, stderr := providerkit.Capture{Limit: stdoutCap}, providerkit.Capture{Limit: stderrCap}
	var out execOutput
	var recvErr error
	sent := make(chan error, 1)
	started := false
	for !out.exited {
		if !stream.Receive() {
			recvErr = stream.Err()
			break
		}
		switch ev := stream.Msg().GetEvent().(type) {
		case *processv1.StartResponse_Init:
			if started {
				recvErr = errors.New("sandboxd sent a second init event")
				break
			}
			started = true
			pid := ev.Init.GetProcessId()
			go func() { sent <- p.writeStdin(streamCtx, c, pid, stdin) }()
		case *processv1.StartResponse_Stdout:
			stdout.Write(ev.Stdout)
		case *processv1.StartResponse_Stderr:
			stderr.Write(ev.Stderr)
		case *processv1.StartResponse_Exit:
			out.exitCode, out.exited = int(ev.Exit.GetExitCode()), true
		}
		if recvErr != nil {
			break
		}
	}
	// cut: the stream after the exit event ended otherwise than by its own end (the grace
	// cancelling it, a broken connection), so output the process wrote may be missing;
	// both streams are then reported cut, never whole (review,
	// 2026-10-23).
	cut := false
	if out.exited {
		grace := time.AfterFunc(postExitGrace, cancel)
		for stream.Receive() {
			switch ev := stream.Msg().GetEvent().(type) {
			case *processv1.StartResponse_Stdout:
				stdout.Write(ev.Stdout)
			case *processv1.StartResponse_Stderr:
				stderr.Write(ev.Stderr)
			}
		}
		grace.Stop()
		cut = stream.Err() != nil
	}
	cancel()
	var sendErr error
	if started {
		sendErr = <-sent
	}
	out.stdout, out.stdoutTruncated = stdout.Buf, stdout.Dropped || cut
	out.stderr, out.stderrTruncated = stderr.Buf, stderr.Dropped || cut
	switch {
	case out.exited:
		return out, nil
	case recvErr != nil && !errors.Is(recvErr, io.EOF):
		return out, fmt.Errorf("sandboxd stream: %w", recvErr)
	case sendErr != nil:
		return out, fmt.Errorf("sandboxd stream ended without an exit status: %w", sendErr)
	default:
		return out, errors.New("sandboxd stream ended without an exit status")
	}
}

// writeStdin writes stdin to the process in frames, then end of input.
func (p *Provider) writeStdin(ctx context.Context, c processv1connect.ProcessServiceClient, pid int32, stdin []byte) error {
	for off := 0; off < len(stdin); off += stdinFrame {
		chunk := stdin[off:min(off+stdinFrame, len(stdin))]
		if _, err := c.WriteStdin(ctx, connect.NewRequest(&processv1.WriteStdinRequest{ProcessId: pid,
			Payload: &processv1.WriteStdinRequest_Input{Input: chunk}})); err != nil {
			return err
		}
	}
	_, err := c.WriteStdin(ctx, connect.NewRequest(&processv1.WriteStdinRequest{ProcessId: pid,
		Payload: &processv1.WriteStdinRequest_Eof{Eof: &emptypb.Empty{}}}))
	return err
}
