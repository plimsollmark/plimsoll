package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
)

// The docker provider applies one of two seccomp profiles to a run (docs/seccomp.md),
// configured through two settings: Seccomp (SANDBOX_DOCKER_SECCOMP) is the profile every
// run gets, and SeccompSDK (SANDBOX_DOCKER_SECCOMP_SDK) the one a run gets instead when
// its grant asks for the local address a standard client library reaches the broker
// through (HostAPIGrant.WantsLoopback: the profile set sdk_env). That address needs IPv4
// TCP sockets, which the audited default denies; the variant allows exactly those and a
// short list of socket options, and is derived from the default at Preflight
// (SeccompSDKDerived, deriveSDKSeccomp) or supplied as a file. Selection is per dispatch,
// from the grant, and never changes the provider's settings; an operator's own profile
// is never replaced or widened: a run that asks for the address when no variant is
// configured beside a profile is refused before dispatch (seccompFor).
//
// Preflight pins both profiles: it reads each file, digests it, and writes a copy named
// by its digest into plimsoll's private directory; runs apply the copy, so the bytes
// docker reads are the bytes whose digest the run's record names, whatever happens to
// the operator's file afterwards (dockerSeccomp.pin).

// dockerSeccomp is what Preflight verified about the profiles: for each, the path
// docker applies (a pinned copy, docker's "unconfined" keyword, or "" for docker's
// built-in profile) and its identity as a run's record and Describe state it.
type dockerSeccomp struct {
	defaultPath string
	defaultID   string
	sdkPath     string // "" when no variant is configured
	sdkID       string
}

// SeccompSDKDerived is the SeccompSDK setting that asks for the variant to be derived from
// the configured default profile at Preflight (deriveSDKSeccomp), so the two can never
// drift apart and no second file is shipped; a path names an operator's own variant.
const SeccompSDKDerived = "derived"

// Policy identities. A profile file is named by the digest of its bytes; docker's
// built-in profile and "unconfined" have no bytes of plimsoll's to digest and are named
// as such; under runsc no host profile is applied, and the record says so rather than
// naming a profile that was not in force.
const (
	seccompPolicyDockerDefault = "seccomp:docker-default"
	seccompPolicyUnconfined    = "seccomp:unconfined"
	seccompPolicySkippedRunsc  = "seccomp:skipped:runsc"
	seccompPolicyDigestPrefix  = "seccomp:sha256:"
)

// seccompProfileWord reports whether a Seccomp setting is one of docker's keywords
// rather than a file: "" and "default" (docker's built-in profile) or "unconfined".
func seccompProfileWord(setting string) bool {
	return setting == "" || setting == "default" || setting == "unconfined"
}

// verifySeccomp checks the two settings against each other and pins each profile file
// into dir. The variant is a profile beside a profile: with docker's built-in profile
// or unconfined as the default there is nothing for it to stand beside (both already
// allow IPv4 sockets), so naming one is a configuration error rather than a silent
// no-op; and the variant must itself be a file, since the point of it is a profile
// tighter than docker's.
func verifySeccomp(defaultSetting, sdkSetting, dir string) (dockerSeccomp, error) {
	var s dockerSeccomp
	switch {
	case defaultSetting == "" || defaultSetting == "default":
		s.defaultPath, s.defaultID = "", seccompPolicyDockerDefault
	case defaultSetting == "unconfined":
		s.defaultPath, s.defaultID = "unconfined", seccompPolicyUnconfined
	default:
		path, id, err := pinSeccompProfile(defaultSetting, dir)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("seccomp profile %q: %w", defaultSetting, err)
		}
		s.defaultPath, s.defaultID = path, id
	}
	switch {
	case sdkSetting == "":
	case seccompProfileWord(defaultSetting):
		return dockerSeccomp{}, fmt.Errorf("SANDBOX_DOCKER_SECCOMP_SDK is set but SANDBOX_DOCKER_SECCOMP is %q: the sdk_env variant is a profile beside a profile file; docker's built-in profile and unconfined already allow the sockets it adds", defaultSetting)
	case seccompProfileWord(sdkSetting):
		return dockerSeccomp{}, fmt.Errorf("SANDBOX_DOCKER_SECCOMP_SDK must be %q or name a profile file, not %q", SeccompSDKDerived, sdkSetting)
	case sdkSetting == SeccompSDKDerived:
		raw, err := os.ReadFile(defaultSetting)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("seccomp profile %q: %w", defaultSetting, err)
		}
		derived, err := deriveSDKSeccomp(raw)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("SANDBOX_DOCKER_SECCOMP_SDK=%s: %w", SeccompSDKDerived, err)
		}
		path, id, err := pinSeccompBytes(derived, dir)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("sdk_env seccomp profile: %w", err)
		}
		s.sdkPath, s.sdkID = path, id
	default:
		// The bytes checked are the bytes pinned, so the file cannot change between the two.
		raw, err := os.ReadFile(sdkSetting)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("sdk_env seccomp profile %q: %w", sdkSetting, err)
		}
		if err := checkSDKSeccompShape(raw); err != nil {
			return dockerSeccomp{}, fmt.Errorf("sdk_env seccomp profile %q: %w; set SANDBOX_DOCKER_SECCOMP_SDK=%s to derive one from the default instead", sdkSetting, err, SeccompSDKDerived)
		}
		path, id, err := pinSeccompBytes(raw, dir)
		if err != nil {
			return dockerSeccomp{}, fmt.Errorf("sdk_env seccomp profile %q: %w", sdkSetting, err)
		}
		s.sdkPath, s.sdkID = path, id
	}
	return s, nil
}

// checkSDKSeccompShape refuses an operator's own sdk_env variant that does not keep the
// derived variant's floor: deny by default, a syscalls list, socket allowed only with its
// address family compared, and socketcall (the 32-bit multiplexer, whose arguments a
// filter cannot read) not allowed at all. Without it a wide file, docker's own default
// saved to disk for example, would silently become the profile of every run whose grant
// sets sdk_env (release review, 2026-10-29). What a variant allows beyond that is the
// operator's choice, and its digest is in every record.
func checkSDKSeccompShape(raw []byte) error {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return fmt.Errorf("not valid JSON: %w", err)
	}
	if doc["defaultAction"] != "SCMP_ACT_ERRNO" {
		return errors.New("not deny-by-default (defaultAction SCMP_ACT_ERRNO)")
	}
	rules, ok := doc["syscalls"].([]any)
	if !ok {
		return errors.New("no syscalls list")
	}
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			return errors.New("a syscalls entry is not an object")
		}
		names, err := seccompRuleNames(rule)
		if err != nil {
			return err
		}
		if !seccompActionAllows(rule["action"]) {
			continue
		}
		if slices.Contains(names, "socketcall") {
			return errors.New("it allows socketcall, through which socket's address family cannot be filtered")
		}
		if slices.Contains(names, "socket") && !seccompComparesFamily(rule["args"]) {
			return errors.New("it allows socket without comparing the address family")
		}
	}
	return nil
}

// seccompActionAllows reports whether a rule's action lets the call proceed: anything but
// an error return, a trap or a kill.
func seccompActionAllows(action any) bool {
	switch action {
	case "SCMP_ACT_ERRNO", "SCMP_ACT_TRAP", "SCMP_ACT_KILL", "SCMP_ACT_KILL_THREAD", "SCMP_ACT_KILL_PROCESS":
		return false
	}
	return true
}

// seccompComparesFamily reports whether a rule's args hold an SCMP_CMP_EQ on argument 0,
// the address family: a rule that lists more arguments is still bound to one family.
func seccompComparesFamily(v any) bool {
	args, _ := v.([]any)
	for _, a := range args {
		arg, _ := a.(map[string]any)
		index, _ := arg["index"].(float64)
		if arg["op"] == "SCMP_CMP_EQ" && index == 0 {
			if _, ok := arg["value"].(float64); ok {
				return true
			}
		}
	}
	return false
}

// The rules deriveSDKSeccomp adds to the default for a run with sdk_env: IPv4 stream
// sockets with protocol 0 or TCP (the type masked so only SOCK_NONBLOCK and SOCK_CLOEXEC
// may join SOCK_STREAM), and the socket options the forwarder and the client transports
// set, by level and name. docs/seccomp.md says what each is for and what stays denied.
const (
	seccompAFUnix, seccompAFInet       = 1, 2
	seccompSockStream                  = 1
	seccompSockTypeMask                = 0xfff7f7ff // everything but SOCK_NONBLOCK (0o4000) and SOCK_CLOEXEC (0o2000000)
	seccompIPProtoTCP                  = 6
	seccompSolSocket                   = 1
	seccompSoReuseAddr, seccompSoType  = 2, 3
	seccompSoError, seccompSoKeepAlive = 4, 9
	seccompTCPNoDelay                  = 1
	seccompTCPKeepIdle                 = 4
	seccompTCPKeepIntvl                = 5
	seccompTCPKeepCnt                  = 6
)

type seccompSockopt struct{ level, option uint64 }

var (
	seccompSDKSetsockopt = []seccompSockopt{
		{seccompSolSocket, seccompSoReuseAddr}, {seccompSolSocket, seccompSoKeepAlive},
		{seccompIPProtoTCP, seccompTCPNoDelay}, {seccompIPProtoTCP, seccompTCPKeepIdle}, {seccompIPProtoTCP, seccompTCPKeepIntvl}, {seccompIPProtoTCP, seccompTCPKeepCnt},
	}
	seccompSDKGetsockopt = []seccompSockopt{{seccompSolSocket, seccompSoType}, {seccompSolSocket, seccompSoError}}
)

// deriveSDKSeccomp makes the sdk_env variant from the bytes of a default profile of the
// shipped profile's shape: a deny-by-default allowlist with one allow rule for socket and
// socketpair filtered to AF_UNIX, and setsockopt and getsockopt in an unfiltered allow
// list. It keeps every other rule as it is, replaces the socket rule with the AF_UNIX rule
// plus two AF_INET TCP rules, takes setsockopt and getsockopt out of the unfiltered list
// (allow rules combine as a union), and adds one filtered rule per allowed option. A
// default of another shape is refused: the operator then supplies the variant as a file.
// The output is deterministic for a given input, so its digest names it.
func deriveSDKSeccomp(raw []byte) ([]byte, error) {
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("the default profile is not valid JSON: %w", err)
	}
	if doc["defaultAction"] != "SCMP_ACT_ERRNO" {
		return nil, errors.New("the default profile is not deny-by-default (defaultAction SCMP_ACT_ERRNO), so no variant is derived from it")
	}
	rules, ok := doc["syscalls"].([]any)
	if !ok {
		return nil, errors.New("the default profile has no syscalls list")
	}
	eq := func(index int, value uint64) map[string]any {
		return map[string]any{"index": index, "value": value, "op": "SCMP_CMP_EQ"}
	}
	sockRule := func(names []string, comment string, args ...map[string]any) map[string]any {
		return map[string]any{"//": comment, "names": names, "action": "SCMP_ACT_ALLOW", "args": args}
	}
	var out []any
	sawSocket, sawSetsockopt, sawGetsockopt := false, false, false
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			return nil, errors.New("a syscalls entry is not an object")
		}
		names, err := seccompRuleNames(rule)
		if err != nil {
			return nil, err
		}
		if rule["action"] == "SCMP_ACT_ALLOW" && slices.Equal(names, []string{"socket", "socketpair"}) && seccompIsUnixOnly(rule["args"]) {
			sawSocket = true
			out = append(out,
				sockRule([]string{"socket", "socketpair"}, "AF_UNIX (1) for the host-API broker's socket and libuv's socketpairs, as in the default.", eq(0, seccompAFUnix)),
				sockRule([]string{"socket"}, "AF_INET (2) stream sockets, protocol 0: the type is masked so only SOCK_NONBLOCK and SOCK_CLOEXEC may join SOCK_STREAM; UDP, raw, SCTP (132) and MPTCP (262) fail the type or protocol check.",
					eq(0, seccompAFInet), map[string]any{"index": 1, "value": uint64(seccompSockTypeMask), "valueTwo": uint64(seccompSockStream), "op": "SCMP_CMP_MASKED_EQ"}, eq(2, 0)),
				sockRule([]string{"socket"}, "AF_INET (2) stream sockets, IPPROTO_TCP (6).",
					eq(0, seccompAFInet), map[string]any{"index": 1, "value": uint64(seccompSockTypeMask), "valueTwo": uint64(seccompSockStream), "op": "SCMP_CMP_MASKED_EQ"}, eq(2, seccompIPProtoTCP)),
			)
			continue
		}
		if rule["action"] == "SCMP_ACT_ALLOW" && rule["args"] == nil && (slices.Contains(names, "setsockopt") || slices.Contains(names, "getsockopt")) {
			kept := make([]any, 0, len(names))
			for _, n := range names {
				switch n {
				case "setsockopt":
					sawSetsockopt = true
				case "getsockopt":
					sawGetsockopt = true
				default:
					kept = append(kept, n)
				}
			}
			if len(kept) == 0 {
				continue
			}
			copied := make(map[string]any, len(rule))
			for k, v := range rule {
				copied[k] = v
			}
			delete(copied, "name")
			copied["names"] = kept
			rule = copied
		}
		out = append(out, rule)
	}
	if !sawSocket || !sawSetsockopt || !sawGetsockopt {
		return nil, errors.New("the default profile does not have the shipped profile's shape (an AF_UNIX-only socket and socketpair rule, and setsockopt and getsockopt in an unfiltered allow list), so no variant is derived from it; name the variant as a file instead")
	}
	for _, o := range seccompSDKSetsockopt {
		out = append(out, sockRule([]string{"setsockopt"}, "setsockopt allowed for one option the forwarder or a client transport sets (docs/seccomp.md).", eq(1, o.level), eq(2, o.option)))
	}
	for _, o := range seccompSDKGetsockopt {
		out = append(out, sockRule([]string{"getsockopt"}, "getsockopt allowed for one option libuv reads (docs/seccomp.md).", eq(1, o.level), eq(2, o.option)))
	}
	doc["syscalls"] = out
	doc["//sdk_env"] = "Derived by plimsolld from the default profile for runs whose grant sets sdk_env: IPv4 TCP sockets and a short list of socket options added, the unrestricted setsockopt and getsockopt allows removed, everything else as in the default. docs/seccomp.md."
	return json.MarshalIndent(doc, "", "  ")
}

// seccompRuleNames reads the system calls a rule names. Docker still reads the older
// singular "name" as a list of one, and refuses a rule that sets both (moby/profiles,
// seccomp/seccomp_linux.go), so a reader of "names" alone would pass a rule written the
// older way: {"name":"socket","action":"SCMP_ACT_ALLOW"} allows socket for every family
// (release review, 2026-10-29).
func seccompRuleNames(rule map[string]any) ([]string, error) {
	listed, _ := rule["names"].([]any)
	v, ok := rule["name"]
	if !ok {
		return seccompNames(rule["names"]), nil
	}
	name, isString := v.(string)
	switch {
	case !isString:
		return nil, errors.New("a syscalls entry's name is not a string")
	case name == "":
		return seccompNames(rule["names"]), nil
	case len(listed) != 0:
		return nil, fmt.Errorf("a syscalls entry sets both name %q and names, which docker refuses", name)
	}
	return []string{name}, nil
}

// seccompNames reads a rule's names list.
func seccompNames(v any) []string {
	items, _ := v.([]any)
	names := make([]string, 0, len(items))
	for _, it := range items {
		if s, ok := it.(string); ok {
			names = append(names, s)
		}
	}
	return names
}

// seccompIsUnixOnly reports whether a rule's args are exactly one SCMP_CMP_EQ on
// argument 0 with value AF_UNIX.
func seccompIsUnixOnly(v any) bool {
	args, _ := v.([]any)
	if len(args) != 1 {
		return false
	}
	a, _ := args[0].(map[string]any)
	index, _ := a["index"].(float64)
	value, _ := a["value"].(float64)
	return a["op"] == "SCMP_CMP_EQ" && index == 0 && value == seccompAFUnix
}

// pinSeccompBytes pins profile bytes plimsoll made itself (the derived variant), as
// pinSeccompProfile pins a file's.
func pinSeccompBytes(raw []byte, dir string) (pinned, id string, err error) {
	tmp, err := os.CreateTemp(dir, "seccomp-*.src")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		return "", "", err
	}
	return pinSeccompProfile(tmp.Name(), dir)
}

// pinSeccompProfile reads the profile at path, digests it, and writes a copy named by
// the digest into dir (made if a copy with that name is not already there), so that what
// docker applies is exactly what the digest names. It returns the copy's path and the
// policy identity.
func pinSeccompProfile(path, dir string) (pinned, id string, err error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", "", err
	}
	if len(raw) == 0 {
		return "", "", errors.New("the profile is empty")
	}
	sum := sha256.Sum256(raw)
	digest := hex.EncodeToString(sum[:])
	pinned = filepath.Join(dir, digest+".json")
	if existing, err := os.ReadFile(pinned); err == nil && string(existing) == string(raw) {
		return pinned, seccompPolicyDigestPrefix + digest, nil
	}
	// Written whole under a private name, then moved into place: a reader (docker,
	// another Preflight) never sees a partial copy. The daemon reads it as root or as
	// the docker user, so it is world-readable; the directory is plimsoll's own.
	tmp, err := os.CreateTemp(dir, "seccomp-*.tmp")
	if err != nil {
		return "", "", err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	if err := tmp.Chmod(0o644); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	if err := os.Rename(tmp.Name(), pinned); err != nil {
		_ = os.Remove(tmp.Name())
		return "", "", err
	}
	return pinned, seccompPolicyDigestPrefix + digest, nil
}

// ErrNoSDKSeccomp is a run whose grant asks for the local address (sdk_env) on a
// provider whose configured seccomp profile denies the IPv4 sockets it needs and no
// variant is configured beside it. The operator's profile is never replaced, so the run
// is refused before dispatch (reason environment).
var ErrNoSDKSeccomp = errors.New("sandbox: no seccomp profile for a run with sdk_env")

// seccompFor is the per-dispatch selection: the profile docker applies to this run and
// the identity its record names. Under runsc no host profile is applied (gVisor filters
// syscalls itself) and the identity says so. A grant that asks for the local address
// gets the variant when one is configured; with docker's built-in profile or unconfined
// as the default it gets that default, which already allows the sockets; with a profile
// file and no variant it is refused. Every other run gets the default.
func (s dockerSeccomp) seccompFor(grant *HostAPIGrant, runtime string) (path, id string, err error) {
	if runtime == "runsc" {
		return "", seccompPolicySkippedRunsc, nil
	}
	if !grant.WantsLoopback() {
		return s.defaultPath, s.defaultID, nil
	}
	switch {
	case s.sdkPath != "":
		return s.sdkPath, s.sdkID, nil
	case s.defaultPath == "" || s.defaultPath == "unconfined":
		return s.defaultPath, s.defaultID, nil
	default:
		return "", "", NotDispatched(RefusalEnvironment, fmt.Errorf("%w: the configured profile (SANDBOX_DOCKER_SECCOMP) allows Unix sockets only, and SANDBOX_DOCKER_SECCOMP_SDK names no profile for runs whose grant sets sdk_env; set it to %q, which derives one from the default adding IPv4 TCP sockets and nothing else, or to a profile file of your own (docs/seccomp.md)", ErrNoSDKSeccomp, SeccompSDKDerived))
	}
}

// sessionPolicy is the identity of the profile a session's container applies for its
// life: the default's, since a session never gets the sdk_env variant
// (CheckSessionGrant), or skipped under runsc. Every call in the session states it.
func (st dockerExecutionState) sessionPolicy() string {
	_, id, _ := st.seccomp.seccompFor(nil, st.runtime)
	return id
}

// describe is what Describe states as the provider's policy: the default profile's
// identity and, when a variant is configured, the one a run whose grant sets sdk_env
// gets instead, so a caller can tell the two apart in records. Under runsc both are
// skipped.
func (s dockerSeccomp) describe(runtime string) string {
	if runtime == "runsc" {
		return seccompPolicySkippedRunsc
	}
	if s.sdkPath == "" {
		return s.defaultID
	}
	return s.defaultID + " sdk_env:" + s.sdkID
}
