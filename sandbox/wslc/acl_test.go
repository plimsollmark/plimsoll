package wslc

import (
	"context"
	"strings"
	"testing"
)

// smokeWithACL is the per-run smoke test's fake and error on a fake whose run root has this
// access list answer.
func smokeWithACL(t *testing.T, mut func(*fakeSetup)) (*fake, error) {
	t.Helper()
	s := goodSetup(t)
	mut(&s)
	f := newFake(t, s)
	p := f.provider(perRun)
	return f, p.SmokeTest(context.Background())
}

// The smoke test reads the run root's access list and refuses one that
// another principal can write. Each case is a list the fake answers; every one that
// names a writer must name it in the error.
func TestPerRunSmokeTestChecksTheRunRootAccessList(t *testing.T) {
	user, sys, admins := fakeUserSID, "S-1-5-18", "S-1-5-32-544"
	cases := []struct {
		name    string
		acl     string
		wantErr string // "" passes
	}{
		{"owner only", ownerOnlyACL, ""},
		{"users may read and execute", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry(sys, "Allow", fullControl, false),
			aclEntry(admins, "Allow", fullControl, false), aclEntry("S-1-5-32-545", "Allow", readExecute, false)), ""},
		{"a deny rule for Everyone grants nothing", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false),
			aclEntry("S-1-1-0", "Deny", fullControl, false)), ""},
		{"Users may modify", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry("S-1-5-32-545", "Allow", modifyRight, false)), "S-1-5-32-545"},
		{"Everyone may modify", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry("S-1-1-0", "Allow", modifyRight, false)), "S-1-1-0"},
		{"Authenticated Users may modify", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry("S-1-5-11", "Allow", modifyRight, false)), "S-1-5-11"},
		{"another account may write data", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false),
			aclEntry("S-1-5-21-1111111111-2222222222-3333333333-1002", "Allow", 0x2, false)), "S-1-5-21-1111111111-2222222222-3333333333-1002"},
		{"another account may only delete", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false),
			aclEntry("S-1-5-21-1111111111-2222222222-3333333333-1002", "Allow", 0x10000, false)), "S-1-5-21-1111111111-2222222222-3333333333-1002"},
		{"another account may change permissions", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false),
			aclEntry("S-1-5-21-1111111111-2222222222-3333333333-1002", "Allow", 0x40000, false)), "S-1-5-21-1111111111-2222222222-3333333333-1002"},
		{"an unmapped generic write", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry("S-1-1-0", "Allow", 0x40000000, false)), "S-1-1-0"},
		{"an unmapped generic all", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, false), aclEntry("S-1-1-0", "Allow", 0x10000000, false)), "S-1-1-0"},
		{"an inherited entry counts", aclAnswerOf(user, aclEntry(user, "Allow", fullControl, true), aclEntry("S-1-5-11", "Allow", modifyRight, true)), "inherited"},
		{"another owner", aclAnswerOf("S-1-5-21-1111111111-2222222222-3333333333-1002", aclEntry(user, "Allow", fullControl, false)), "is owned by"},
		{"an unreadable answer", "not json", "unreadable"},
		{"no answer", "", "unreadable"},
		{"no entries (a missing list gives everyone access)", aclAnswerOf(user), "no entries"},
		{"a rule that is not a SID", aclAnswerOf(user, aclEntry("BUILTIN\\Users", "Allow", modifyRight, false)), "not a SID"},
		{"an unknown rule type", aclAnswerOf(user, aclEntry(user, "Audit", fullControl, false)), "type"},
		{"no current user", `{"user":"","owner":"S-1-5-18","entries":[]}`, "no readable current user"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := smokeWithACL(t, func(s *fakeSetup) { s.ACL = c.acl })
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("an acceptable access list was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("access list %s was accepted", c.acl)
			}
			if !strings.Contains(err.Error(), c.wantErr) {
				t.Fatalf("the error does not name %q: %v", c.wantErr, err)
			}
			// Nothing was built on the untrusted root.
			if len(f.enters()) != 0 {
				t.Fatalf("a session started on an untrusted run root: %d enters", len(f.enters()))
			}
		})
	}
}

// A script that fails (access denied, no Get-Acl) is a refusal, not a pass.
func TestPerRunSmokeTestRefusesWhenTheAccessListCannotBeRead(t *testing.T) {
	_, err := smokeWithACL(t, func(s *fakeSetup) { s.ACLFails = true })
	if err == nil || !strings.Contains(err.Error(), "access list") {
		t.Fatalf("a failed read of the access list was not refused: %v", err)
	}
}

// The script asks for SIDs and numeric rights (nothing localized), about the run root's
// Windows path, through the one powershell helper.
func TestRunRootAccessListScriptIsStructured(t *testing.T) {
	f, _ := smokeWithACL(t, func(*fakeSetup) {})
	var script string
	for _, c := range f.calls() {
		if script == "" && strings.Contains(c.Script, "Get-Acl -LiteralPath") { // the first is the root's
			script = c.Script
		}
	}
	if script == "" {
		t.Fatal("the smoke test never read the run root's access list")
	}
	for _, want := range []string{"'C:/Users/fake/AppData/Local/plimsoll-wslc'", "SecurityIdentifier", "[int64]$_.FileSystemRights", "ConvertTo-Json"} {
		if !strings.Contains(script, want) {
			t.Errorf("the script lacks %q: %s", want, script)
		}
	}
	if strings.Contains(script, "AccessToString") || strings.Contains(script, "icacls") {
		t.Errorf("the script reads localized text: %s", script)
	}
}

// The folders above the run root, up to the drive's own, are read too. A
// principal that can delete, rename or take over one of them can put another folder where
// the root was, and the root's own list never shows it. Creating a new entry beside the
// existing ones (what a drive's root gives every signed-in user) replaces nothing.
func TestPerRunSmokeTestChecksTheFoldersAboveTheRunRoot(t *testing.T) {
	user, other := fakeUserSID, "S-1-5-21-1111111111-2222222222-3333333333-1002"
	own := aclEntry(user, "Allow", fullControl, false)
	const servicing = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	cases := []struct {
		name    string
		path    string
		acl     string
		wantErr string // "" passes
	}{
		{"a drive root as Windows makes it: the servicing account owns it, signed-in users may create a folder, and modify what they create", "C:/",
			aclAnswerOf(servicing, aclEntry("S-1-5-18", "Allow", fullControl, false), aclEntry("S-1-5-32-544", "Allow", fullControl, false),
				aclEntry("S-1-5-32-545", "Allow", readExecute, false), aclEntry("S-1-5-11", "Allow", 0x4, false), aclChildrenOnly("S-1-5-11", modifyRight)), ""},
		{"Users may read the profiles folder", "C:/Users", aclAnswerOf("S-1-5-18", aclEntry("S-1-5-18", "Allow", fullControl, false),
			aclEntry("S-1-5-32-545", "Allow", readExecute, false), aclEntry("S-1-1-0", "Allow", readExecute, false)), ""},
		{"Users may modify a folder above", "C:/Users/fake/AppData", aclAnswerOf(user, own, aclEntry("S-1-5-32-545", "Allow", modifyRight, false)), "S-1-5-32-545"},
		{"another account may delete what is in a folder above", "C:/Users/fake", aclAnswerOf(user, own, aclEntry(other, "Allow", 0x40, false)), other},
		{"another account may delete the folder right above", "C:/Users/fake/AppData/Local", aclAnswerOf(user, own, aclEntry(other, "Allow", 0x10000, false)), other},
		{"another account may change a folder's permissions", "C:/Users", aclAnswerOf(user, own, aclEntry(other, "Allow", 0x40000, false)), other},
		{"another account may take a folder's ownership", "C:/Users", aclAnswerOf(user, own, aclEntry(other, "Allow", 0x80000, false)), other},
		{"an inherited rule on a folder above counts", "C:/Users/fake", aclAnswerOf(user, own, aclEntry("S-1-5-11", "Allow", modifyRight, true)), "inherited"},
		{"another account owns a folder above", "C:/Users/fake", aclAnswerOf(other, own), "is owned by"},
		{"the drive's own folder lets everyone delete what is in it", "C:/", aclAnswerOf(servicing, own, aclEntry("S-1-1-0", "Allow", 0x40, false)), "S-1-1-0"},
		{"a folder above with no entries", "C:/Users", aclAnswerOf(user), "no entries"},
		{"a folder above that cannot be read", "C:/Users", "not json", "unreadable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := smokeWithACL(t, func(s *fakeSetup) { s.ACLs = map[string]string{c.path: c.acl} })
			if c.wantErr == "" {
				if err != nil {
					t.Fatalf("an acceptable folder above the run root was refused: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("%s with access list %s was accepted", c.path, c.acl)
			}
			if !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), "a folder above the run root "+c.path) {
				t.Fatalf("the error does not name %q and the folder %s: %v", c.wantErr, c.path, err)
			}
			if len(f.enters()) != 0 {
				t.Fatalf("a session started under an untrusted folder: %d enters", len(f.enters()))
			}
		})
	}
}

// The servicing account is accepted above the run root only: it does not own a user's run
// root or template.
func TestServicingAccountIsNotTrustedOnTheRunRootItself(t *testing.T) {
	const servicing = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	_, err := smokeWithACL(t, func(s *fakeSetup) {
		s.ACL = aclAnswerOf(servicing, aclEntry(fakeUserSID, "Allow", fullControl, false))
		s.ACLs = map[string]string{"C:/": ownerOnlyACL, "C:/Users": ownerOnlyACL, "C:/Users/fake": ownerOnlyACL,
			"C:/Users/fake/AppData": ownerOnlyACL, "C:/Users/fake/AppData/Local": ownerOnlyACL}
	})
	if err == nil || !strings.Contains(err.Error(), "is owned by") {
		t.Fatalf("a run root owned by the servicing account: %v", err)
	}
}

// Once the template is built, its folder and its disk file are read: a
// write right set directly on either is in neither the root's list nor a folder's above.
func TestPerRunSmokeTestChecksTheBuiltTemplate(t *testing.T) {
	other := "S-1-5-21-1111111111-2222222222-3333333333-1002"
	own := aclEntry(fakeUserSID, "Allow", fullControl, true)
	const dir = "C:/Users/fake/AppData/Local/plimsoll-wslc/plimsoll-template"
	for _, c := range []struct{ name, path, acl, wantErr string }{
		{"another account may write the template's disk file", dir + "/storage.vhdx", aclAnswerOf(fakeUserSID, own, aclEntry(other, "Allow", 0x2, false)), other},
		{"another account may delete the template's disk file", dir + "/storage.vhdx", aclAnswerOf(fakeUserSID, own, aclEntry(other, "Allow", 0x10000, false)), other},
		{"another account owns the template's disk file", dir + "/storage.vhdx", aclAnswerOf(other, own), "is owned by"},
		{"Users may modify the template's folder", dir, aclAnswerOf(fakeUserSID, own, aclEntry("S-1-5-32-545", "Allow", modifyRight, false)), "S-1-5-32-545"},
		{"the template's disk file cannot be read", dir + "/storage.vhdx", "", "unreadable"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, err := smokeWithACL(t, func(s *fakeSetup) { s.ACLs = map[string]string{c.path: c.acl} })
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), "the template "+c.path) {
				t.Fatalf("want a refusal naming %q and %s: %v", c.wantErr, c.path, err)
			}
			// The template was built (one session), and no run's session followed it.
			if n := len(f.enters()); n != 1 {
				t.Fatalf("%d sessions entered, want only the template's", n)
			}
		})
	}
}

// Every list is asked for by its own path: the root, each folder above it to the drive,
// then the template's folder and disk file.
func TestAccessListsAreReadForEveryFolderAboveAndTheTemplate(t *testing.T) {
	f, err := smokeWithACL(t, func(*fakeSetup) {})
	if err != nil {
		t.Fatal(err)
	}
	var asked []string
	for _, c := range f.calls() {
		if i := strings.Index(c.Script, "Get-Acl -LiteralPath '"); i >= 0 {
			rest := c.Script[i+len("Get-Acl -LiteralPath '"):]
			asked = append(asked, rest[:strings.Index(rest, "'")])
		}
	}
	root := "C:/Users/fake/AppData/Local/plimsoll-wslc"
	want := []string{root, "C:/Users/fake/AppData/Local", "C:/Users/fake/AppData", "C:/Users/fake", "C:/Users", "C:/",
		root + "/plimsoll-template", root + "/plimsoll-template/storage.vhdx"}
	if strings.Join(asked, "\n") != strings.Join(want, "\n") {
		t.Fatalf("access lists read:\n%s\nwant:\n%s", strings.Join(asked, "\n"), strings.Join(want, "\n"))
	}
}

func TestFoldersAbove(t *testing.T) {
	for in, want := range map[string]string{
		"C:/a/b/c": "C:/a/b C:/a C:/",
		"D:/runs":  "D:/",
	} {
		if got := strings.Join(foldersAbove(in), " "); got != want {
			t.Errorf("foldersAbove(%q) = %q, want %q", in, got, want)
		}
	}
}
