package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---- guest execution ----

type dcExecOutput struct {
	stdout          string
	stderr          string
	stdoutTruncated bool
	stderrTruncated bool
	exitCode        int
	timedOut        bool
}

// execGuarded runs argv under dcExecWrapper with an in-guest time limit derived
// from the remaining run budget.
//
// A step is reported as timed out when the in-guest `timeout` killed it: exit 137
// (or 124) AND the call took at least the in-guest limit. The elapsed-time half
// cannot be forged by guest code (it would have to actually run that long), so a
// user program that merely exits 137 is not misread as a timeout.
func (d *DockerCloud) execGuarded(ctx context.Context, vm dcVM, argv []string, cwd string) (dcExecOutput, error) {
	limit := remainingBudget(ctx, clampRunTimeout(0, d.DefaultTimeout, d.MaxTimeout)) - dcGuestMargin
	secs := int(limit / time.Second)
	if secs < 1 {
		secs = 1
	}
	return d.execLimited(ctx, vm, argv, cwd, secs)
}

// execLimited is execGuarded with an explicit in-guest limit in whole seconds.
func (d *DockerCloud) execLimited(ctx context.Context, vm dcVM, argv []string, cwd string, secs int) (dcExecOutput, error) {
	max := d.maxOutput()
	cmd := append([]string{"sh", "-c", dcExecWrapper, "plimsoll-exec", strconv.Itoa(secs), strconv.Itoa(max + 1)}, argv...)
	start := time.Now()
	raw, flooded, err := d.exec(ctx, vm, cmd, cwd, dcExecResponseLimit(max+1))
	elapsed := time.Since(start)
	if err != nil {
		return dcExecOutput{}, err
	}
	if flooded {
		// The response outgrew what the in-guest caps allow, which only guest code
		// working around them can cause: a failed user run, never infrastructure.
		return dcExecOutput{stdoutTruncated: true, stderrTruncated: true, exitCode: exitOutputFlooded}, nil
	}
	out := dcExecOutput{exitCode: int(raw.ExitCode)}
	out.stdout, out.stdoutTruncated = capStream(raw.Stdout, max)
	out.stderr, out.stderrTruncated = capStream(raw.Stderr, max)
	if (out.exitCode == 137 || out.exitCode == 124) && elapsed >= time.Duration(secs)*time.Second {
		out.timedOut, out.exitCode = true, 124
	}
	return out, nil
}

func capStream(b []byte, max int) (string, bool) {
	if len(b) > max {
		return string(b[:max]), true
	}
	return string(b), false
}

// dcExecResponseLimit is the largest Exec response the wrapper's caps allow: both
// streams base64-encoded in JSON, plus room for the envelope.
func dcExecResponseLimit(perStream int) int64 {
	return 2*int64(base64.StdEncoding.EncodedLen(perStream)) + 64<<10
}

type dcExecResponse struct {
	ExitCode int32  `json:"exitCode"`
	Stdout   []byte `json:"stdout"`
	Stderr   []byte `json:"stderr"`
}

// exec calls ProcessService.Exec on the sandbox endpoint. flooded reports that the
// response body exceeded limit; the body is then discarded unread.
func (d *DockerCloud) exec(ctx context.Context, vm dcVM, cmd []string, cwd string, limit int64) (dcExecResponse, bool, error) {
	in := map[string]any{"cmd": cmd}
	if cwd != "" {
		in["workingDir"] = cwd
	}
	body, _ := json.Marshal(in)
	status, raw, over, err := d.post(ctx, vm.endpoint+dcProcExec, "application/json", body, limit)
	if err != nil {
		return dcExecResponse{}, false, err
	}
	if status != http.StatusOK {
		return dcExecResponse{}, false, dcErrorFrom(dcProcExec, status, raw)
	}
	if over {
		return dcExecResponse{}, true, nil
	}
	var out dcExecResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return dcExecResponse{}, false, fmt.Errorf("dockercloud exec: unparseable response: %w", err)
	}
	return out, false, nil
}

// mkdirs creates the project directories with one `mkdir -p` in the guest.
// Assumption (live probe): FileService.Upload does not create parent directories,
// so they are created explicitly rather than relied on.
func (d *DockerCloud) mkdirs(ctx context.Context, vm dcVM, dirs map[string]struct{}) error {
	list := make([]string, 0, len(dirs))
	for dir := range dirs {
		list = append(list, dir)
	}
	sort.Strings(list)
	out, flooded, err := d.exec(ctx, vm, append([]string{"mkdir", "-p", "--"}, list...), "", dcExecResponseLimit(4<<10))
	if err != nil {
		return err
	}
	if flooded || out.ExitCode != 0 {
		return fmt.Errorf("mkdir exited %d: %s", out.ExitCode, strings.TrimSpace(string(out.Stderr)))
	}
	return nil
}

// ---- file transfer (Connect client and server streams) ----

// upload writes files with one FileService.Upload client stream: per file a header
// frame, then its bytes in data frames.
// Assumption (live probe): a file is complete when the next header or the end of
// the stream arrives, and an empty file is a header with no data frame.
func (d *DockerCloud) upload(ctx context.Context, vm dcVM, files []File) error {
	if len(files) == 0 {
		return nil
	}
	var body bytes.Buffer
	for _, f := range files {
		frame, _ := json.Marshal(map[string]any{"header": map[string]any{"path": f.Path, "mode": 0o644}})
		body.Write(connectEnvelope(frame))
		content := []byte(f.Content)
		for off := 0; off < len(content); off += dcUploadChunk {
			end := min(off+dcUploadChunk, len(content))
			frame, _ := json.Marshal(map[string]any{"data": content[off:end]})
			body.Write(connectEnvelope(frame))
		}
	}
	resp, err := d.stream(ctx, vm.endpoint+dcProcUpload, body.Bytes())
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	var written uint32
	var got bool
	err = readConnectFrames(resp.Body, dcProcUpload, 1<<20, 1<<20, func(msg []byte) error {
		var out struct {
			FilesWritten uint32 `json:"filesWritten"`
		}
		if err := json.Unmarshal(msg, &out); err != nil {
			return fmt.Errorf("dockercloud upload: unparseable response: %w", err)
		}
		written, got = out.FilesWritten, true
		return nil
	})
	if err != nil {
		return err
	}
	if !got || int(written) != len(files) {
		return fmt.Errorf("dockercloud upload: server reported %d of %d files written", written, len(files))
	}
	return nil
}

// errArtifactBudget stops a download once the artifact budget is spent.
var errArtifactBudget = errors.New("artifact budget exhausted")

// download reads the given absolute paths with one FileService.Download server
// stream. A path the server answers with a per-file error is treated as absent.
// Assumption (live probe): a missing file produces a per-file error frame rather
// than failing the stream, and header paths echo the requested paths.
func (d *DockerCloud) download(ctx context.Context, vm dcVM, paths []string) ([]Artifact, bool, error) {
	req, _ := json.Marshal(map[string]any{"paths": paths})
	resp, err := d.stream(ctx, vm.endpoint+dcProcDownload, connectEnvelope(req))
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	requested := make(map[string]bool, len(paths))
	for _, p := range paths {
		requested[p] = true
	}
	var (
		arts    []Artifact
		current *Artifact
		total   int64
	)
	finish := func() {
		if current != nil {
			arts = append(arts, *current)
			current = nil
		}
	}
	// The transport budget is the decoded artifact budget in base64 plus room for
	// headers and per-file errors; the decoded budget below is what normally stops it.
	transport := int64(base64.StdEncoding.EncodedLen(maxArtifactBytesTotal)) + 2<<20
	err = readConnectFrames(resp.Body, dcProcDownload, 16<<20, transport, func(msg []byte) error {
		var frame struct {
			Header *struct {
				Path string `json:"path"`
			} `json:"header"`
			Data  []byte          `json:"data"`
			Error json.RawMessage `json:"error"`
		}
		if err := json.Unmarshal(msg, &frame); err != nil {
			return fmt.Errorf("dockercloud download: unparseable frame: %w", err)
		}
		switch {
		case frame.Header != nil:
			finish()
			if !requested[frame.Header.Path] {
				return fmt.Errorf("dockercloud download: server sent unrequested path %q", frame.Header.Path)
			}
			current = &Artifact{Path: frame.Header.Path}
		case frame.Error != nil:
			finish() // a per-file error: that path is absent
		case frame.Data != nil:
			if current == nil {
				return errors.New("dockercloud download: data frame before any header")
			}
			if total+int64(len(frame.Data)) > maxArtifactBytesTotal {
				current = nil // this artifact does not fit; drop it whole
				return errArtifactBudget
			}
			total += int64(len(frame.Data))
			current.Content = append(current.Content, frame.Data...)
		}
		return nil
	})
	if errors.Is(err, errArtifactBudget) {
		return arts, true, nil
	}
	if err != nil {
		return nil, false, err
	}
	finish()
	return arts, false, nil
}

// readConnectFrames decodes a Connect streaming response. Every frame is bounded
// (maxFrame) and so is the stream (maxTotal). The end-of-stream frame is required:
// a body that ends without one was cut, and its content cannot be trusted as whole.
func readConnectFrames(r io.Reader, procedure string, maxFrame uint32, maxTotal int64, fn func(msg []byte) error) error {
	header := make([]byte, 5)
	var total int64
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if err == io.EOF {
				return fmt.Errorf("dockercloud %s: stream ended without an end-of-stream frame", procedure)
			}
			return err
		}
		flags := header[0]
		length := binary.BigEndian.Uint32(header[1:5])
		if length > maxFrame {
			return fmt.Errorf("dockercloud %s: stream frame of %d bytes exceeds %d", procedure, length, maxFrame)
		}
		total += int64(length)
		if total > maxTotal {
			return fmt.Errorf("dockercloud %s: stream exceeds %d bytes", procedure, maxTotal)
		}
		if flags&0x01 != 0 {
			return fmt.Errorf("dockercloud %s: compressed stream frame, which was not negotiated", procedure)
		}
		msg := make([]byte, length)
		if _, err := io.ReadFull(r, msg); err != nil {
			return err
		}
		if flags&0x02 != 0 {
			var end struct {
				Error *struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if len(msg) > 0 {
				if err := json.Unmarshal(msg, &end); err != nil {
					return fmt.Errorf("dockercloud %s: unparseable end-of-stream frame: %w", procedure, err)
				}
			}
			if end.Error != nil {
				return &dcRPCError{Procedure: procedure, HTTPStatus: http.StatusOK, Code: end.Error.Code, Message: end.Error.Message}
			}
			return nil
		}
		if err := fn(msg); err != nil {
			return err
		}
	}
}
