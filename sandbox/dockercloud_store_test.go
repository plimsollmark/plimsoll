package sandbox

import (
	"context"
	"strings"
	"testing"
)

// A store image boots by its ID: the create names it in "image" and carries neither a
// start command nor a size, which the service refuses beside an image ID (2026-10-05),
// while the lifetime, delete-on-timeout, no auto-resume and the platform stay.
func TestDockerCloudStoreImageBootsByID(t *testing.T) {
	t.Parallel()
	f := newDCFake(t)
	f.reportedCPUs, f.reportedMemMiB = 1, 2048 // the image's own size, Micro (2026-10-05)
	f.exec = func([]string) (int, string, string) { return 0, "ok\n", "" }
	d := f.provider()
	d.Image, d.StoreImage = "", "tmpl_001abc@sha256:"+strings.Repeat("a", 64)
	if err := d.validateConfig(); err != nil {
		t.Fatalf("validateConfig: %v", err)
	}
	res, err := d.RunJavaScript(context.Background(), Request{Code: `console.log("ok")`})
	if err != nil || res.ExitCode != 0 {
		t.Fatalf("RunJavaScript = %+v, %v", res, err)
	}
	create := f.creates[0]
	if create["image"] != "tmpl_001abc" {
		t.Fatalf("create image = %v, want the store image's ID", create["image"])
	}
	if _, ok := create["resources"]; ok {
		t.Fatalf("create carries resources beside a store image: %v", create["resources"])
	}
	cloud := create["cloud"].(map[string]any)
	for _, k := range []string{"imageRef", "startCmd"} {
		if _, ok := cloud[k]; ok {
			t.Fatalf("cloud options carry %s beside a store image: %v", k, cloud)
		}
	}
	if cloud["onTimeout"] != "ON_TIMEOUT_DELETE" || cloud["autoResume"] != false || cloud["timeout"] == nil || cloud["platform"] == nil {
		t.Fatalf("cloud options = %v, want the lifetime, delete on timeout, no auto-resume and the platform", cloud)
	}
	if got := f.deletedRefs(); len(got) != 1 {
		t.Fatalf("deletes = %v", got)
	}
}

// The digest is the evidence: a sandbox that booted any other digest runs nothing.
func TestDockerCloudStoreImageRefusesAnotherBootedDigest(t *testing.T) {
	t.Parallel()
	f := newDCFake(t)
	f.reportedCPUs, f.reportedMemMiB = 1, 2048
	f.exec = func([]string) (int, string, string) {
		t.Error("guest code ran on a sandbox that booted another image")
		return 0, "", ""
	}
	d := f.provider()
	d.Image, d.StoreImage = "", "tmpl_001abc@sha256:"+strings.Repeat("b", 64) // the fake boots a...a
	_, err := d.RunJavaScript(context.Background(), Request{Code: `1`})
	if err == nil || !strings.Contains(err.Error(), "booted image digest") {
		t.Fatalf("err = %v, want the booted digest refused", err)
	}
	if got := f.deletedRefs(); len(got) != 1 {
		t.Fatalf("deletes = %v, want the refused sandbox deleted", got)
	}
}

// The size is the image's, so the envelope is a cap: an image made Small (2 CPUs) runs
// nothing under the Micro default.
func TestDockerCloudStoreImageLargerThanTheEnvelopeIsRefused(t *testing.T) {
	t.Parallel()
	f := newDCFake(t)
	f.reportedCPUs, f.reportedMemMiB = 2, 4096
	f.exec = func([]string) (int, string, string) {
		t.Error("guest code ran on a sandbox larger than the envelope")
		return 0, "", ""
	}
	d := f.provider()
	d.Image, d.StoreImage = "", "tmpl_001abc@sha256:"+strings.Repeat("a", 64)
	if _, err := d.RunJavaScript(context.Background(), Request{Code: `1`}); err == nil || !strings.Contains(err.Error(), "exceeds CPU cap") {
		t.Fatalf("err = %v, want the size refused", err)
	}
}

func TestDockerCloudStoreImageConfig(t *testing.T) {
	t.Parallel()
	f := newDCFake(t)
	digest := "@sha256:" + strings.Repeat("a", 64)
	for _, c := range []struct {
		image, store, api, want string
	}{
		{store: "tmpl_001abc" + digest},
		{store: "tmpl_001abc" + strings.ToUpper(digest[8:]) + "x", want: "want <image id>@sha256"},
		{store: "tmpl_001abc", want: "want <image id>@sha256"},
		{store: "@sha256:" + strings.Repeat("a", 64), want: "want <image id>@sha256"},
		{store: "a@b" + digest, want: "want <image id>@sha256"},
		{store: "tmpl/../x" + digest, want: "letters, digits"},
		{store: strings.Repeat("t", 129) + digest, want: "longer than 128"},
		{image: "registry.example/x" + digest, store: "tmpl_001abc" + digest, want: "both set"},
		{want: "nor SANDBOX_DOCKERCLOUD_STORE_IMAGE"},
		{store: "tmpl_001abc" + digest, api: dcAPIREST, want: "needs SANDBOX_DOCKERCLOUD_API=connect"},
	} {
		d := f.provider()
		d.Image, d.StoreImage, d.API = c.image, c.store, c.api
		if c.api == dcAPIREST {
			d.APIURL = ""
		}
		err := d.validateConfig()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("image %q store %q api %q: err = %v, want %q", c.image, c.store, c.api, err, c.want)
		}
	}
}
