package guestguard

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// goSyscallTable reads the SYS_ constants of one zsysnum file: name (lower case, without
// SYS_) to number.
func goSyscallTable(t *testing.T, path string) map[string]uint32 {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	out := map[string]uint32{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if !strings.HasPrefix(n.Name, "SYS_") || i >= len(vs.Values) {
					continue
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.INT {
					continue
				}
				v, err := strconv.ParseUint(lit.Value, 0, 32)
				if err != nil {
					t.Fatalf("%s: %s = %s: %v", path, n.Name, lit.Value, err)
				}
				out[strings.ToLower(strings.TrimPrefix(n.Name, "SYS_"))] = uint32(v)
			}
		}
	}
	return out
}

func goOutput(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("go", args...).Output()
	if err != nil {
		t.Fatalf("go %s: %v", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(out))
}

// TestCeilingCoversGoSyscallTables is the tripwire of finding guest-guard-7: the filter
// answers Function not implemented to every request above the table's ceiling, so a kernel
// request nobody reviewed stays shut, and this notices when one appears. It reads the
// request numbers Go knows on both machines, from golang.org/x/sys/unix (in the module graph
// already, bumped with the toolchain) and from the standard library's syscall package, and
// fails when one is above the ceiling, naming it and what to review. It also holds every
// table row's numbers to those tables where they name the request.
func TestCeilingCoversGoSyscallTables(t *testing.T) {
	tb := mustLoad(t)
	xsys := goOutput(t, "list", "-m", "-f", "{{.Dir}} {{.Version}}", "golang.org/x/sys")
	dir, version, _ := strings.Cut(xsys, " ")
	goroot := goOutput(t, "env", "GOROOT")
	// The standard library's table stopped growing years ago: it is read for the ceiling and
	// the numbers it has, and the requests it lacks are not worth a line each.
	sources := []struct {
		what, path, arch string
		current          bool
	}{
		{"golang.org/x/sys@" + version, filepath.Join(dir, "unix", "zsysnum_linux_amd64.go"), "x86_64", true},
		{"golang.org/x/sys@" + version, filepath.Join(dir, "unix", "zsysnum_linux_arm64.go"), "aarch64", true},
		{"the standard library's syscall", filepath.Join(goroot, "src", "syscall", "zsysnum_linux_amd64.go"), "x86_64", false},
		{"the standard library's syscall", filepath.Join(goroot, "src", "syscall", "zsysnum_linux_arm64.go"), "aarch64", false},
	}
	for _, s := range sources {
		nums := goSyscallTable(t, s.path)
		// A table that reads as nearly empty means this reader broke, not that Go knows nothing.
		if len(nums) < 250 {
			t.Fatalf("%s: only %d SYS_ constants read from %s", s.what, len(nums), s.path)
		}
		highest, highestName := uint32(0), ""
		for name, n := range nums {
			if n > highest {
				highest, highestName = n, name
			}
			if n > tb.Ceiling {
				t.Errorf("%s knows %s = %d on %s, above the guest guard's ceiling %d, so the guard answers it Function not implemented. "+
					"Review it in the kernel's table: if it makes or enters a namespace, mounts or unmounts, changes the root, or writes another process's memory or requests, "+
					"add a row to sandbox/internal/guestguard/refused.json; then raise the ceiling to the highest number reviewed and run go run ./sandbox/internal/guestguard/gen",
					s.what, name, n, s.arch, tb.Ceiling)
			}
		}
		t.Logf("%s on %s: %d requests, the highest %s = %d; the ceiling is %d", s.what, s.arch, len(nums), highestName, highest, tb.Ceiling)
		for _, r := range tb.Requests {
			var a Arch
			for _, x := range tb.Arches {
				if x.Name == s.arch {
					a = x
				}
			}
			n, ok := nums[r.Name]
			if !ok {
				if !s.current {
					continue
				}
				t.Logf("%s does not name %s on %s (newer than it); the table's %d rests on the kernel's table alone", s.what, r.Name, s.arch, r.Number(a))
				continue
			}
			if n != r.Number(a) {
				t.Errorf("%s says %s is %d on %s; refused.json says %d", s.what, r.Name, n, s.arch, r.Number(a))
			}
		}
	}
}
