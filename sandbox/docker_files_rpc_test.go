package sandbox_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1/plimsollv1connect"
	"github.com/plimsollmark/plimsoll/internal/rpc"
	"github.com/plimsollmark/plimsoll/protocol"
	"github.com/plimsollmark/plimsoll/record"
)

// TestDockerSessionFileCallsInTheChain is a session's file calls end to end on docker: the
// daemon's RPC handler over the docker provider, driven over HTTP. Describe and the open say
// the sessions take file calls; a write, a read of a name that is not UTF-8 and a snippet that
// reads the file are one chain, each record recomputed from the request sent and the answer
// received.
func TestDockerSessionFileCallsInTheChain(t *testing.T) {
	t.Parallel()
	d := sessionDocker(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	if err := d.SmokeTest(ctx); err != nil {
		t.Fatalf("SmokeTest: %v", err)
	}
	svc := rpc.NewSandboxService(d)
	svc.Logger = slog.New(slog.DiscardHandler)
	svc.Sessions = rpc.SessionConfig{MaxSessions: 2, Lifetime: 5 * time.Minute, IdleTimeout: time.Minute, DiskBytes: 64 << 20}
	mux := http.NewServeMux()
	path, h := rpc.NewHandler(svc, connect.WithInterceptors(rpc.AuthInterceptor(nil)))
	mux.Handle(path, h)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	c := plimsollv1connect.NewSandboxServiceClient(srv.Client(), srv.URL)

	desc, err := c.Describe(ctx, connect.NewRequest(&plimsollv1.DescribeRequest{}))
	if err != nil {
		t.Fatal(err)
	}
	both := []plimsollv1.FilesScope{plimsollv1.FilesScope_FILES_SCOPE_WORK, plimsollv1.FilesScope_FILES_SCOPE_SANDBOX}
	if !slices.Equal(desc.Msg.GetSessionEnvironment().GetFileScopes(), both) || len(desc.Msg.GetProjectEnvironment().GetFileScopes()) != 0 ||
		len(desc.Msg.GetJavascriptEnvironment().GetFileScopes()) != 0 {
		t.Fatalf("Describe states the file scopes %v on the session's environment, %v on the project's, %v on the snippet's; want both on the session's alone",
			desc.Msg.GetSessionEnvironment().GetFileScopes(), desc.Msg.GetProjectEnvironment().GetFileScopes(), desc.Msg.GetJavascriptEnvironment().GetFileScopes())
	}
	o, err := c.OpenSession(ctx, connect.NewRequest(&plimsollv1.OpenSessionRequest{Protocol: protocol.Number}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = c.CloseSession(context.Background(), connect.NewRequest(&plimsollv1.CloseSessionRequest{Protocol: protocol.Number,
			SessionId: o.Msg.GetSessionId(), Generation: o.Msg.GetGeneration()}))
	})
	if !slices.Equal(o.Msg.GetFileScopes(), both) || o.Msg.GetWorkDir() != "/work" {
		t.Fatalf("the open states the file scopes %v, work_dir %q", o.Msg.GetFileScopes(), o.Msg.GetWorkDir())
	}
	name := []byte("out/r\xffsult\n.txt")
	work := plimsollv1.FilesScope_FILES_SCOPE_WORK
	var calls uint64
	var last string
	call := func(req *plimsollv1.SessionRunRequest) *plimsollv1.RunResponse {
		t.Helper()
		req.Protocol, req.SessionId = protocol.Number, o.Msg.GetSessionId()
		req.Head = &plimsollv1.SessionCheckpoint{Generation: o.Msg.GetGeneration(), Calls: calls, LastRecordSha256: last}
		resp, err := c.SessionRun(ctx, connect.NewRequest(req))
		if err != nil {
			t.Fatalf("call %d: %v", calls+1, err)
		}
		if _, err := record.CheckSessionCall(req, resp.Msg.GetRun(), o.Msg.GetSession(), calls, last); err != nil {
			t.Fatalf("call %d's record: %v", calls+1, err)
		}
		calls, last = calls+1, resp.Msg.GetRun().GetRecord().GetRecordSha256()
		return resp.Msg.GetRun()
	}
	w := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Files{Files: &plimsollv1.FilesRun{Scope: work,
		Op: &plimsollv1.FilesRun_Write{Write: &plimsollv1.FilesWrite{Path: name, Content: []byte("42\n"),
			Mode: plimsollv1.FilesWriteMode_FILES_WRITE_MODE_CREATE_ONLY, MakeParents: true}}}}})
	if w.GetFiles().GetWrite().GetWritten() != 3 || w.GetIsolation() == "" {
		t.Fatalf("write: %v", w)
	}
	r := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Files{Files: &plimsollv1.FilesRun{Scope: work,
		Op: &plimsollv1.FilesRun_Read{Read: &plimsollv1.FilesRead{Path: name, MaxBytes: 64}}}}})
	if string(r.GetFiles().GetRead().GetContent()) != "42\n" {
		t.Fatalf("read: %v", r.GetFiles())
	}
	l := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Files{Files: &plimsollv1.FilesRun{Scope: work,
		Op: &plimsollv1.FilesRun_List{List: &plimsollv1.FilesList{Path: []byte("out"), BudgetBytes: 8192}}}}})
	if es := l.GetFiles().GetList().GetEntries(); len(es) != 1 || string(es[0].GetPath()) != string(name[len("out/"):]) {
		t.Fatalf("list: %v", l.GetFiles())
	}
	// The error shapes the helper answers, each checked by the record's rule (docs/run-records.md,
	// "A file call's answer"): an answered error carries no answer, and a read_many item holds
	// its bytes or its error, never a size beside the error.
	miss := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Files{Files: &plimsollv1.FilesRun{Scope: work,
		Op: &plimsollv1.FilesRun_Read{Read: &plimsollv1.FilesRead{Path: []byte("absent"), MaxBytes: 64}}}}})
	if f := miss.GetFiles(); f.GetError() != plimsollv1.FilesError_FILES_ERROR_NOT_FOUND || f.GetErrno() != "ENOENT" || f.GetAnswer() != nil {
		t.Fatalf("a read of a missing name: %v", f)
	}
	many := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Files{Files: &plimsollv1.FilesRun{Scope: work,
		Op: &plimsollv1.FilesRun_ReadMany{ReadMany: &plimsollv1.FilesReadMany{Paths: [][]byte{name, []byte("out"), []byte("absent")},
			MaxBytesEach: 64, BudgetBytes: 8192}}}}})
	if its := many.GetFiles().GetReadMany().GetItems(); len(its) != 3 || string(its[0].GetContent()) != "42\n" ||
		its[1].GetError() != plimsollv1.FilesError_FILES_ERROR_IS_DIR || its[2].GetError() != plimsollv1.FilesError_FILES_ERROR_NOT_FOUND {
		t.Fatalf("read_many: %v", many.GetFiles())
	}
	js := call(&plimsollv1.SessionRunRequest{Payload: &plimsollv1.SessionRunRequest_Javascript{Javascript: &plimsollv1.JavaScriptRun{
		Code: `const fs = require("fs"); const n = fs.readdirSync("out", { encoding: "buffer" })[0];
process.stdout.write(fs.readFileSync(Buffer.concat([Buffer.from("out/"), n])))`}}})
	if string(js.GetJavascript().GetStdout()) != "42\n" {
		t.Fatalf("a snippet read %q", js.GetJavascript().GetStdout())
	}
}
