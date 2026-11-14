package wslc

import (
	"strings"
	"testing"
)

// The drive mounts are read from mountinfo lines of the shape WSL's automount makes (two
// read from a WSL 3.0.5 distribution on 2026-11-11), and paths map both ways in the strict
// form only.
func TestDriveMountsAndPaths(t *testing.T) {
	mi := strings.Join([]string{
		`82 85 0:36 / /usr/lib/wsl/drivers ro,nosuid,nodev,noatime - 9p drivers ro,aname=drivers;fmask=222;dmask=222,cache=0x5`,
		`135 85 0:70 / /mnt/c rw,noatime - 9p C:\134 rw,aname=drvfs;path=C:\;uid=1000;gid=1000;symlinkroot=/mnt/,cache=0x5,access=client,msize=65536,trans=fd,rfd=6,wfd=6`,
		`136 85 0:71 / /mnt/d rw,noatime - 9p D:\134 rw,aname=drvfs;path=D:\;uid=1000;gid=1000`,
		`137 85 0:72 / /mnt/share rw,noatime - 9p x rw,aname=drvfs;path=C:\Users;uid=1000`,
		`138 85 0:73 / /mnt/my\040disk rw,noatime - 9p E:\134 rw,aname=drvfs;path=E:\;uid=1000`,
	}, "\n")
	drives := driveMounts(mi)
	if len(drives) != 3 || drives["C"] != "/mnt/c" || drives["D"] != "/mnt/d" || drives["E"] != "/mnt/my disk" {
		t.Fatalf("drives: %v", drives)
	}
	got, err := toLinux(drives, "C:/Profiles/someuser/AppData/Local/plimsoll-wslc")
	if err != nil || got != "/mnt/c/Profiles/someuser/AppData/Local/plimsoll-wslc" {
		t.Fatalf("toLinux: %q %v", got, err)
	}
	win, err := toWindows(drives, "/mnt/d/plimsoll/runs")
	if err != nil || win != "D:/plimsoll/runs" {
		t.Fatalf("toWindows: %q %v", win, err)
	}
	for _, bad := range []string{`C:\Users\x`, "C:/Users/John Smith", "C:/x'y", "C:/", "Z:/x", "C:/x/../y" + "\x00", "C:/é",
		// A . or .. directory: path.Join would resolve C:/../../etc to /etc, outside the
		// drive mount, where Windows stays on C:.
		"C:/x/../y", "C:/../../etc", "C:/.", "C:/Users/./x", "C:/x/.."} {
		if _, err := toLinux(drives, bad); err == nil {
			t.Errorf("toLinux accepted %q", bad)
		}
	}
	for _, ok := range []string{"C:/a.b/..c/c..", "C:/.x/x."} {
		if _, err := toLinux(drives, ok); err != nil {
			t.Errorf("toLinux refused %q, whose directories only contain dots: %v", ok, err)
		}
	}
	for _, bad := range []string{"/home/someuser", "/mnt/c", "/mnt/c/a b"} {
		if _, err := toWindows(drives, bad); err == nil {
			t.Errorf("toWindows accepted %q", bad)
		}
	}
}

func TestPSQuote(t *testing.T) {
	if got := psQuote("C:/a'b"); got != "'C:/a''b'" {
		t.Fatal(got)
	}
}
