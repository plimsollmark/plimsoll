package wslc

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"
)

// The per-run mode keeps its disks on a Windows drive, because a WSLC session's storage
// must be a Windows path: the template at <root>/plimsoll-template/storage.vhdx and one
// directory per run named like its session. plimsolld reaches the directory both ways:
// as a Windows path (C:/..., forward slashes, which Windows' path functions accept
// and wslc.exe normalizes with std::filesystem::absolute) when it hands it to wslc.exe
// or powershell.exe, and through the distribution's drive mount (/mnt/c/...) when
// it writes the template or deletes a run's directory. A Windows path is accepted only in
// a strict form: a drive letter, then directories of letters, digits and . _ - only, none
// of them . or .. (validWinPath), so it passes safeArg, cannot change meaning in a
// PowerShell string either, and names the same directory both ways: Windows resolves a ..
// against the drive and path.Join against the mount, which differ once a .. climbs past it.
var winPathRE = regexp.MustCompile(`^[A-Za-z]:(/[A-Za-z0-9._-]+)+$`)

// errPathForm explains a refused Windows path.
const errPathForm = "a drive letter then directories of letters, digits and . _ - only (no space, no . or .. directory)"

// validWinPath reports whether win is in the strict form.
func validWinPath(win string) bool {
	if !winPathRE.MatchString(win) {
		return false
	}
	for _, seg := range strings.Split(win[3:], "/") {
		if seg == "." || seg == ".." {
			return false
		}
	}
	return true
}

// driveMounts maps each Windows drive letter (upper case) to where this distribution
// mounts it, read from a mountinfo table: a 9p mount with the drvfs share of a drive's
// root (`aname=drvfs;path=C:\` in its options), as WSL's automount makes.
func driveMounts(mountinfo string) map[string]string {
	drives := map[string]string{}
	for _, line := range strings.Split(mountinfo, "\n") {
		pre, post, ok := strings.Cut(line, " - ")
		f, g := strings.Fields(pre), strings.Fields(post)
		if !ok || len(f) < 5 || len(g) < 3 || g[0] != "9p" {
			continue
		}
		opts := strings.FieldsFunc(g[2], func(r rune) bool { return r == ',' || r == ';' })
		var drvfs bool
		var drive string
		for _, o := range opts {
			switch {
			case o == "aname=drvfs":
				drvfs = true
			case len(o) == 8 && strings.HasPrefix(o, "path=") && o[6] == ':' && o[7] == '\\':
				drive = strings.ToUpper(o[5:6])
			}
		}
		mp := unescapeMount(f[4])
		if drvfs && drive != "" && drive[0] >= 'A' && drive[0] <= 'Z' && strings.HasPrefix(mp, "/") {
			drives[drive] = mp
		}
	}
	return drives
}

// unescapeMount undoes mountinfo's octal escapes (\040 for a space).
func unescapeMount(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) && isOctal(s[i+1]) && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }

// toLinux is a Windows path (in the strict form) as this distribution mounts it.
func toLinux(drives map[string]string, win string) (string, error) {
	if !validWinPath(win) {
		return "", fmt.Errorf("wslc: the Windows path %q is not %s", win, errPathForm)
	}
	mp, ok := drives[strings.ToUpper(win[:1])]
	if !ok {
		return "", fmt.Errorf("wslc: drive %s: is not mounted in this distribution (no drvfs mount of it in /proc/self/mountinfo)", win[:1])
	}
	return path.Join(mp, win[3:]), nil
}

// toWindows is a path under a drive mount as Windows names it, in the strict form.
func toWindows(drives map[string]string, linux string) (string, error) {
	clean := path.Clean(linux)
	letters := make([]string, 0, len(drives))
	for l := range drives {
		letters = append(letters, l)
	}
	sort.Strings(letters)
	for _, l := range letters {
		mp := drives[l]
		if rel, ok := strings.CutPrefix(clean, mp+"/"); ok && rel != "" {
			win := l + ":/" + rel
			if !validWinPath(win) {
				return "", fmt.Errorf("wslc: %s is %s on Windows, which is not %s", linux, win, errPathForm)
			}
			return win, nil
		}
	}
	return "", fmt.Errorf("wslc: %s is not under a Windows drive this distribution mounts (drvfs)", linux)
}

// DefaultPowerShell is Windows PowerShell as this distribution sees it on a machine whose
// Windows is on C:.
const DefaultPowerShell = "/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe"

// psQuote is s as a PowerShell single-quoted string. Every path given to it already
// passed validWinPath, which admits no quote; this is the second wall.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

// powershell runs a script built by this package from fixed text and checked paths, never
// from anything a caller sent, through -EncodedCommand (base64 of its UTF-16 text), which
// passes safeArg. It returns stdout, and on failure PowerShell's own error text, bounded.
func (p *Provider) powershell(ctx context.Context, script string) (string, error) {
	full := "$ProgressPreference='SilentlyContinue'; $ErrorActionPreference='Stop'; " + script
	u := utf16.Encode([]rune(full))
	raw := make([]byte, 2*len(u))
	for i, c := range u {
		raw[2*i], raw[2*i+1] = byte(c), byte(c>>8)
	}
	cmd := hostCommand(ctx, p.cfg.PowerShell, "-NoProfile", "-NonInteractive", "-EncodedCommand", base64.StdEncoding.EncodeToString(raw))
	// A Windows working directory, so PowerShell does not start in the distribution's own
	// network path.
	if mp, ok := p.drives["C"]; ok {
		cmd.Dir = mp
	}
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = outputCap, errorCap
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("powershell.exe: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	if stdout.Truncated() {
		return "", errors.New("powershell.exe answered more than the output cap")
	}
	return stdout.String(), nil
}

// localAppData is the Windows user's local application data folder, in the strict form.
func (p *Provider) localAppData(ctx context.Context) (string, error) {
	out, err := p.powershell(ctx, "[Environment]::GetFolderPath('LocalApplicationData')")
	if err != nil {
		return "", err
	}
	win := strings.ReplaceAll(strings.TrimSpace(out), `\`, "/")
	if !validWinPath(win) {
		return "", fmt.Errorf("wslc: the Windows user's local application data folder %q is not %s; set SANDBOX_WSLC_RUN_ROOT to a directory under a drive mount whose Windows path is", strings.TrimSpace(out), errPathForm)
	}
	return win, nil
}

// readMountinfo is this process's mount table.
func readMountinfo() (string, error) {
	b, err := os.ReadFile("/proc/self/mountinfo")
	return string(b), err
}
