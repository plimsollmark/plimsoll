package wslc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// The run root is trusted: every per-run run boots a copy of the template
// kept there, and nothing checks the template between runs, so a principal that can write,
// create or delete in the root decides what runs boot. The smoke test therefore reads the
// root's access list through the host command path (powershell.exe, a fixed script around
// one checked path) and refuses to serve unless only the current Windows user, SYSTEM and
// the Administrators group can write there. The answer is read as SIDs and numeric rights
// (never a localized account name or the text of an access rule), and anything unreadable
// is a refusal. The same reading is made of every folder above the root up to the drive
// (a principal that can delete, rename or take over one of them can put another folder
// where the root was), and, once the template is built, of the template's folder and its
// disk file (a write right set directly on either never shows in the root's own list).

// Well-known SIDs that may write in the run root, besides the current user's.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	// sidTrustedInstaller is the Windows servicing account, which owns a drive's root and
	// the system's own folders. It is accepted on the folders above the run root only.
	sidTrustedInstaller = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
)

// Windows FileSystemRights bits that let a principal change what is in a directory or who
// controls it: create files, create directories, write extended attributes, delete
// children, write attributes, delete, change permissions, take ownership, and the generic
// all and write rights (which an access rule may carry unmapped).
const (
	rightCreateFiles   = 0x2
	rightCreateDirs    = 0x4
	rightWriteEA       = 0x10
	rightDeleteChild   = 0x40
	rightWriteAttrs    = 0x100
	rightDelete        = 0x10000
	rightChangePerms   = 0x40000
	rightTakeOwnership = 0x80000
	rightGenericAll    = 0x10000000
	rightGenericWrite  = 0x40000000
	// rightsThatReplace are the rights on a folder above the run root that let a principal
	// put something else where the path to the root leads: delete or rename what is in the
	// folder, delete or rename the folder itself, or take control of its access list.
	// Creating a new entry beside the existing ones (what a drive's root commonly gives
	// every signed-in user) replaces nothing and is not among them.
	rightsThatReplace     = rightDeleteChild | rightDelete | rightChangePerms | rightTakeOwnership | rightGenericAll
	rightsThatChangeStuff = rightCreateFiles | rightCreateDirs | rightWriteEA | rightDeleteChild | rightWriteAttrs |
		rightDelete | rightChangePerms | rightTakeOwnership | rightGenericAll | rightGenericWrite
)

var sidRE = regexp.MustCompile(`^S-1-[0-9]+(-[0-9]+)+$`)

// aclScript prints the access list of the directory or file at winPath (a checked Windows path) as
// one line of JSON: the current user's SID, the owner's SID, and each access rule's SID,
// type (Allow or Deny), numeric rights, whether it is inherited and whether it applies to
// children only. Rules come from the effective list, inherited ones included.
func aclScript(winPath string) string {
	return "$sid = [Security.Principal.SecurityIdentifier]; " +
		"$a = Get-Acl -LiteralPath " + psQuote(winPath) + "; " +
		"$e = @($a.GetAccessRules($true, $true, $sid) | ForEach-Object { [ordered]@{ sid = $_.IdentityReference.Value; " +
		"type = [string]$_.AccessControlType; rights = [int64]$_.FileSystemRights; inherited = [bool]$_.IsInherited; " +
		"inheritOnly = (([int]$_.PropagationFlags -band 2) -ne 0) } }); " +
		"ConvertTo-Json -Compress -Depth 4 -InputObject ([ordered]@{ user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value; " +
		"owner = $a.GetOwner($sid).Value; entries = $e })"
}

// aclAnswer is aclScript's output.
type aclAnswer struct {
	User    string `json:"user"`
	Owner   string `json:"owner"`
	Entries []struct {
		SID         string `json:"sid"`
		Type        string `json:"type"`
		Rights      int64  `json:"rights"`
		Inherited   bool   `json:"inherited"`
		InheritOnly bool   `json:"inheritOnly"`
	} `json:"entries"`
}

// aclRule is what one access list is held to.
type aclRule struct {
	// what names the thing in an error: "the run root", "a folder above the run root".
	what string
	// rights are the bits no principal outside the trusted set may hold.
	rights uint32
	// selfOnly ignores rules that apply to children only: they give nothing on the folder
	// itself, and each child's own list is read where it matters.
	selfOnly bool
	// servicing also accepts the Windows servicing account (folders above the run root).
	servicing bool
	// why says what an outside writer could do, and the remedy.
	why string
}

var (
	ruleRoot = aclRule{what: "the run root", rights: rightsThatChangeStuff,
		why: "the run root is writable by another principal, so a template there could be replaced between runs; set SANDBOX_WSLC_RUN_ROOT to a directory only this user can write, or remove the access"}
	ruleAbove = aclRule{what: "a folder above the run root", rights: rightsThatReplace, selfOnly: true, servicing: true,
		why: "a folder above the run root lets another principal delete, rename or take it over, so the run root and the template in it could be replaced between runs; set SANDBOX_WSLC_RUN_ROOT under folders only this user controls, or remove the access"}
	ruleTemplate = aclRule{what: "the template", rights: rightsThatChangeStuff,
		why: "the template every run boots a copy of is writable by another principal; remove the access"}
)

// checkRootACL reads the run root's access list and refuses unless the owner and every
// principal an Allow rule gives a writing right to is the current user, SYSTEM or the
// Administrators group. A Deny rule grants nothing and is ignored. An empty list is
// refused too: a missing (null) DACL gives everyone full access and reads as no rules.
// Then every folder above the root, up to the drive's own, is read the same way and held
// to ruleAbove.
func (p *Provider) checkRootACL(ctx context.Context, winPath string) error {
	if err := p.checkACL(ctx, ruleRoot, winPath); err != nil {
		return err
	}
	for _, above := range foldersAbove(winPath) {
		if err := p.checkACL(ctx, ruleAbove, above); err != nil {
			return err
		}
	}
	return nil
}

// checkTemplateACL reads the built template's folder and its disk file and holds each to
// the run root's own rule: a right set directly on either is not in the root's list.
func (p *Provider) checkTemplateACL(ctx context.Context, rootWin string) error {
	dir := rootWin + "/" + templateDirName
	for _, win := range []string{dir, dir + "/" + storageFile} {
		if err := p.checkACL(ctx, ruleTemplate, win); err != nil {
			return err
		}
	}
	return nil
}

// foldersAbove lists the folders above winPath (a checked Windows path), nearest first,
// ending with the drive's own ("C:/").
func foldersAbove(winPath string) []string {
	var out []string
	for {
		i := strings.LastIndex(winPath, "/")
		if i < 0 {
			return out
		}
		if i == 2 { // "C:/name": what is above is the drive itself
			return append(out, winPath[:3])
		}
		winPath = winPath[:i]
		out = append(out, winPath)
	}
}

// checkACL reads one access list and holds it to rule.
func (p *Provider) checkACL(ctx context.Context, rule aclRule, winPath string) error {
	out, err := p.powershell(ctx, aclScript(winPath))
	if err != nil {
		return fmt.Errorf("reading the access list of %s %s: %w", rule.what, winPath, err)
	}
	return checkACLAnswer(rule, winPath, out)
}

// checkACLAnswer judges aclScript's output; it is separate so a test can feed it.
func checkACLAnswer(rule aclRule, winPath, out string) error {
	what := rule.what + " " + winPath
	var ans aclAnswer
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &ans); err != nil {
		return fmt.Errorf("the access list of %s is unreadable (%v): refusing to trust it", what, err)
	}
	if !sidRE.MatchString(ans.User) || !sidRE.MatchString(ans.Owner) {
		return fmt.Errorf("the access list of %s names no readable current user or owner (user %q, owner %q): refusing to trust it", what, ans.User, ans.Owner)
	}
	if len(ans.Entries) == 0 {
		return fmt.Errorf("the access list of %s has no entries (a missing list gives everyone access): refusing to trust it", what)
	}
	trusted := func(sid string) bool {
		return sid == ans.User || sid == sidSystem || sid == sidAdministrators || (rule.servicing && sid == sidTrustedInstaller)
	}
	const who = "the current Windows user, SYSTEM or Administrators"
	var errs []error
	if !trusted(ans.Owner) {
		errs = append(errs, fmt.Errorf("%s is owned by %s, not %s", what, ans.Owner, who))
	}
	for _, e := range ans.Entries {
		switch e.Type {
		case "Deny":
			continue
		case "Allow":
		default:
			return fmt.Errorf("the access list of %s has a rule of type %q for %s: refusing to trust it", what, e.Type, e.SID)
		}
		if !sidRE.MatchString(e.SID) {
			return fmt.Errorf("the access list of %s has a rule for %q, which is not a SID: refusing to trust it", what, e.SID)
		}
		if uint32(e.Rights)&rule.rights == 0 || trusted(e.SID) || (rule.selfOnly && e.InheritOnly) {
			continue
		}
		how := "set on it"
		switch {
		case e.Inherited:
			how = "inherited"
		case e.InheritOnly:
			how = "set on it for its children"
		}
		errs = append(errs, fmt.Errorf("%s holds rights 0x%x on %s (%s) that only %s may hold", e.SID, uint32(e.Rights), what, how, who))
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s: %w", rule.why, errors.Join(errs...))
	}
	return nil
}
