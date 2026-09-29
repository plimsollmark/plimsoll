package openshell

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/openshellv1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

// withDiskCap turns the provider's disk cap on at mb MiB, as New does for
// Config.DiskMB, on a gateway that allows driver configs.
func withDiskCap(t *testing.T, f *fakeGateway, p *Provider, mb int) {
	t.Helper()
	f.allowDriverConfig = true
	p.cfg.DiskMB = mb
	var err error
	if p.runDisk, err = tmpDriverConfig(int64(mb) << 20); err != nil {
		t.Fatal(err)
	}
}

// createdDriverConfigs is the driver config of every sandbox the fake was asked to create.
func createdDriverConfigs(f *fakeGateway) []*structpb.Struct {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []*structpb.Struct
	for _, b := range f.boxes {
		out = append(out, b.sb.GetSpec().GetTemplate().GetDriverConfig())
	}
	return out
}

func wantTmpfs(t *testing.T, got *structpb.Struct, size int64) {
	t.Helper()
	want, _ := structpb.NewStruct(map[string]any{"docker": map[string]any{"mounts": []any{
		map[string]any{"type": "tmpfs", "target": "/tmp", "size_bytes": float64(size), "options": []any{"noexec"}},
	}}})
	if !proto.Equal(got, want) {
		t.Fatalf("driver config %v, want %v", got.AsMap(), want.AsMap())
	}
}

func TestDiskCapMountsASizedTmpForEachRun(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	withDiskCap(t, f, p, 64)
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	got := createdDriverConfigs(f)
	if len(got) != 1 {
		t.Fatalf("%d sandboxes created", len(got))
	}
	wantTmpfs(t, got[0], 64<<20)
}

func TestNoDiskCapSendsNoDriverConfig(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	// A gateway may answer an absent driver config with an empty one: the same thing.
	f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Spec.Template.DriverConfig = &structpb.Struct{} }
	if _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatal(err)
	}
	for _, dc := range createdDriverConfigs(f) {
		if dc != nil {
			t.Fatalf("a driver config was sent with the disk cap off: %v", dc.AsMap())
		}
	}
}

// A gateway without allow_driver_config refuses the create; the error names the
// gateway setting and the plimsoll setting that asked for it, and startup fails.
func TestDiskCapNeedsAllowDriverConfig(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	withDiskCap(t, f, p, 64)
	f.allowDriverConfig = false
	for name, call := range map[string]func() error{
		"run":   func() error { _, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); return err },
		"smoke": func() error { return p.SmokeTest(context.Background()) },
	} {
		err := call()
		if err == nil || !strings.Contains(err.Error(), "allow_driver_config = true") || !strings.Contains(err.Error(), "SANDBOX_DISK_MB") {
			t.Errorf("%s: %v, want a refusal naming allow_driver_config and SANDBOX_DISK_MB", name, err)
		}
	}
	if n := f.called("ExecSandboxInteractive"); n != 0 {
		t.Fatalf("%d execs ran", n)
	}
}

func TestDiskCapReadBackRefusesAnotherSize(t *testing.T) {
	f, p := newFake(t)
	f.run = echoScript
	withDiskCap(t, f, p, 64)
	f.mutateSpec = func(sb *openshellv1.Sandbox) {
		sb.Spec.Template.DriverConfig, _ = tmpDriverConfig(1 << 40)
	}
	_, err := p.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if err == nil || !strings.Contains(err.Error(), "driver config read back") {
		t.Fatalf("err = %v, want a driver config read-back refusal", err)
	}
	if n := f.called("ExecSandboxInteractive"); n != 0 {
		t.Fatalf("%d execs ran on a sandbox with the wrong /tmp", n)
	}
}

// A session's sandbox never gets the sized /tmp, even with the cap on: docker discards a
// tmpfs when its container stops, and suspending a session stops it (measured on
// v0.1.2: the file was gone after a suspend). Its read-back refuses a driver config
// that appears later.
func TestSessionGetsNoDiskCap(t *testing.T) {
	f, p := newFake(t)
	sc := &sessionScript{}
	f.run = sc.run
	withDiskCap(t, f, p, 64)
	s, err := p.OpenSession(context.Background(), sandbox.SessionOptions{Lifetime: time.Minute, DiskBytes: 32 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close(context.Background()) }()
	got := createdDriverConfigs(f)
	if len(got) != 1 || got[0] != nil {
		t.Fatalf("session sandbox driver configs %v, want one sandbox with none", got)
	}
	if _, err := s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"}); err != nil {
		t.Fatalf("a call: %v", err)
	}
	f.mutateSpec = func(sb *openshellv1.Sandbox) { sb.Spec.Template.DriverConfig, _ = tmpDriverConfig(64 << 20) }
	_, err = s.RunJavaScript(context.Background(), sandbox.Request{Code: "1"})
	if sandbox.SessionEndReason(err) != sandbox.SessionSandboxChanged {
		t.Fatalf("a call after a driver config appeared: %v", err)
	}
}

func TestCheckTmpMount(t *testing.T) {
	good := "tmpfs /tmp tmpfs rw,nosuid,nodev,noexec,relatime,size=65536k 0 0" // measured on v0.1.2, 2026-09-29
	if err := checkTmpMount(good, 64); err != nil {
		t.Fatalf("measured mount refused: %v", err)
	}
	if err := checkTmpMount("overlay / overlay rw 0 0", 0); err != nil {
		t.Fatalf("cap off: %v", err)
	}
	for line, want := range map[string]string{
		"":                                             "not a tmpfs",
		"overlay /tmp overlay rw 0 0":                  "not a tmpfs",
		strings.Replace(good, ",noexec", "", 1):        "noexec",
		strings.Replace(good, ",nosuid", "", 1):        "nosuid",
		strings.Replace(good, ",nodev", "", 1):         "nodev",
		strings.Replace(good, "65536k", "1048576k", 1): "size=65536k",
	} {
		if err := checkTmpMount(line, 64); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want an error mentioning %q", line, err, want)
		}
	}
}
