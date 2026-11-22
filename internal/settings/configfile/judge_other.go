//go:build !unix

package configfile

import "os"

// judge cannot read an owner or Unix mode bits on this system, so it says so: a caller
// that refuses a finding (hardened mode) refuses here rather than trusting a file it
// could not judge.
func judge(path string, _ os.FileInfo) []string {
	return []string{path + ": file owners and modes are not checked on this operating system"}
}
