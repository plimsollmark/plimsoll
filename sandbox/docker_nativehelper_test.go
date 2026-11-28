package sandbox

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox/internal/nativehelper"
)

// TestDockerSmokeRefusesAnImageWithoutTheRunner: SmokeTest refuses a project image whose
// project runner (the native helper at nativehelper.InContainer) is missing, is other bytes,
// is writable by others, is readable by the guest or is not root's, naming the image, what is wrong and what to do;
// plimsolld then serves nothing (EnsureReady). An image built before the helper replaced the
// Node runner is the first case.
func TestDockerSmokeRefusesAnImageWithoutTheRunner(t *testing.T) {
	t.Parallel()
	base := testDocker()
	requireSnippetImage(t, base)
	if dockerNativeHelperFile != "" {
		t.Skip("PLIMSOLL_TEST_NATIVE_HELPER_FILE mounts a file over the image's runner in every container, so no image's own file is checked")
	}
	h := nativehelper.InContainer
	for _, c := range []struct {
		name, tag, run, want string
	}{
		{"missing", throwawayTag("no-helper"), "rm " + h, "there is no file at " + h + " (ENOENT)"},
		{"other bytes", throwawayTag("wrong-helper"), "cp /bin/busybox " + h + " && chmod 0711 " + h, "has sha256 "},
		{"writable by others", throwawayTag("open-helper"), "chmod 0777 " + h, "with mode 0777; it must be root's and writable by no one else"},
		{"readable by the guest", throwawayTag("read-helper"), "chmod 0755 " + h, "has mode 0755; it must be readable by root alone and runnable by every user (0711)"},
		{"not root's", throwawayTag("owned-helper"), "chown node " + h, "it must be root's"},
		// Another build of the helper, installed as plimsoll installs it: the build pinned
		// 1b403142 (file contract 5, the same size as this one, from git history), and this build
		// with one byte of its identity changed (the same size, another identity line).
		{"the earlier build 1b403142", "earlier", "", "has sha256 " + earlierHelperSHA256},
		{"another build of the same size", "same-size", "", "has sha256 "},
	} {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			var tag string
			switch c.tag {
			case "earlier", "same-size":
				content := SameSizeOtherHelperBuild(t)
				if c.tag == "earlier" {
					b, ok := EarlierHelperBuild(t)
					if !ok {
						return // the same-size case holds the refusal where the history is not here
					}
					content = b
				}
				tag = ImageWithFile(t, base.ProjectImage, content, "RUN cp /plimsoll-test-file "+h+" && rm /plimsoll-test-file && chmod 0711 "+h+"\nUSER node\n")
			default:
				tag = c.tag
				build := exec.Command("docker", "build", "-q", "-t", c.tag, "-")
				build.Stdin = strings.NewReader("FROM " + base.ProjectImage + "\nUSER root\nRUN " + c.run + "\nUSER node\n")
				if out, err := build.CombinedOutput(); err != nil {
					infraSkip(t, "cannot build throwaway image: %v: %s", err, out)
				}
				t.Cleanup(func() { _ = exec.Command("docker", "rmi", "-f", c.tag).Run() })
			}
			c.tag = tag
			d := testDocker()
			d.ProjectImage = c.tag
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()
			err := d.SmokeTest(ctx)
			if err == nil {
				t.Fatal("SmokeTest passed an image whose project runner is not the native helper this plimsolld carries")
			}
			t.Logf("SmokeTest refused: %v", err)
			for _, want := range []string{`project runner check failed for image "` + c.tag + `"`, c.want, "make docker-images"} {
				if !strings.Contains(err.Error(), want) {
					t.Fatalf("SmokeTest: %v\nwant it to say %q", err, want)
				}
			}
		})
	}
}
