package wslc

import "testing"

// An image that sets a variable the C library or dynamic loader reads at startup is refused,
// by the one list the docker provider uses too (sessionkit.LoaderStartupVariable); this
// package's own copy of that list is gone, and with it the chance of the two differing.
func TestCheckImageEnvRefusesLoaderVariables(t *testing.T) {
	for _, bad := range []string{"LD_PRELOAD=/x.so", "LD_LIBRARY_PATH=/opt/lib", "LD_AUDIT=/x.so", "GLIBC_TUNABLES=glibc.malloc.check=3", "LOCPATH=/work/l", "NLSPATH=/work/%N", "GCONV_PATH=/work/g", "NOEQUALS", "=x"} {
		if err := checkImageEnv([]string{"PATH=/usr/bin", bad}); err == nil {
			t.Errorf("%s was accepted", bad)
		}
	}
	if err := checkImageEnv([]string{"PATH=/usr/bin", "LD=ld.lld", "LDFLAGS=-L/opt/lib", "NODE_OPTIONS=--require /work/x.js", "LANG=C.UTF-8"}); err != nil {
		t.Errorf("refused: %v", err)
	}
}
