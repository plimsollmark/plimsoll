package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// seccompRule is one allow rule of a profile as the tests read it.
type seccompRule struct {
	Names  []string `json:"names"`
	Action string   `json:"action"`
	Args   []struct {
		Index    int    `json:"index"`
		Value    uint64 `json:"value"`
		ValueTwo uint64 `json:"valueTwo"`
		Op       string `json:"op"`
	} `json:"args"`
	ErrnoRet int `json:"errnoRet"`
}

type seccompProfile struct {
	DefaultAction string        `json:"defaultAction"`
	Syscalls      []seccompRule `json:"syscalls"`
}

func readSeccompProfile(t *testing.T, path string) seccompProfile {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var p seccompProfile
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return p
}

// allows evaluates the profile as the kernel would for one call: an allow rule whose
// every argument comparison holds (SCMP_CMP_EQ, SCMP_CMP_MASKED_EQ: (arg & value) ==
// valueTwo) allows it; otherwise the default action refuses. Only these two operators
// appear in the shipped profiles; another fails the test rather than being guessed at.
func (p seccompProfile) allows(t *testing.T, name string, args ...uint64) bool {
	t.Helper()
	for _, r := range p.Syscalls {
		if r.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		found := false
		for _, n := range r.Names {
			if n == name {
				found = true
			}
		}
		if !found {
			continue
		}
		match := true
		for _, a := range r.Args {
			var got uint64
			if a.Index < len(args) {
				got = args[a.Index]
			}
			switch a.Op {
			case "SCMP_CMP_EQ":
				match = match && got == a.Value
			case "SCMP_CMP_MASKED_EQ":
				match = match && (got&a.Value) == a.ValueTwo
			default:
				t.Fatalf("rule for %v uses %s, which this test does not evaluate", r.Names, a.Op)
			}
		}
		if match {
			return true
		}
	}
	return false
}

const (
	afUnix, afInet, afInet6, afNetlink, afPacket, afAlg = 1, 2, 10, 16, 17, 38
	sockStream, sockDgram, sockRaw                      = 1, 2, 3
	sockNonblock, sockCloexec                           = 0o4000, 0o2000000
	ipprotoTCP, ipprotoUDP, ipprotoRaw, ipprotoSCTP     = 6, 17, 255, 132
	ipprotoMPTCP                                        = 262
	solSocket, solTLS                                   = 1, 282
	soReuseaddr, soType, soError, soKeepalive           = 2, 3, 4, 9
	soAttachFilter, soAttachBPF                         = 26, 50
	soAttachReuseportCBPF, soAttachReuseportEBPF        = 51, 52
	tcpNodelay, tcpKeepidle, tcpKeepintvl, tcpKeepcnt   = 1, 4, 5, 6
	tcpULP                                              = 31
)

// TestShippedSeccompDefaultRefusesIPv4: the audited default stays Unix-only, so a run
// without sdk_env cannot create an IPv4 socket of any kind.
func TestShippedSeccompDefaultRefusesIPv4(t *testing.T) {
	t.Parallel()
	p := readSeccompProfile(t, "../docker/seccomp.json")
	if !p.allows(t, "socket", afUnix, sockStream, 0) || !p.allows(t, "socketpair", afUnix, sockStream, 0) {
		t.Fatal("the default profile refuses Unix sockets, which the broker needs")
	}
	for _, c := range [][]uint64{{afInet, sockStream, 0}, {afInet, sockStream, ipprotoTCP}, {afInet, sockDgram, 0}, {afInet6, sockStream, 0}, {afAlg, 5, 0}} {
		if p.allows(t, "socket", c...) {
			t.Errorf("the default profile allows socket(%v)", c)
		}
	}
	if !p.allows(t, "setsockopt", 0, solTLS, 1) || !p.allows(t, "getsockopt", 0, solSocket, soError) {
		t.Fatal("the default profile's setsockopt and getsockopt are unrestricted today; if that changed, update TestShippedSeccompSDKVariant's expectation of the difference")
	}
}

// TestShippedSeccompSDKVariant: the profile a run with sdk_env gets allows exactly
// IPv4 stream sockets with protocol 0 or TCP (SOCK_NONBLOCK and SOCK_CLOEXEC may be
// added, nothing else), refuses UDP, raw, SCTP, MPTCP and every other family, limits
// setsockopt and getsockopt to the options the forwarder and the client transports
// set, and refuses the kernel TLS, ULP and socket-filter options.
func TestShippedSeccompSDKVariant(t *testing.T) {
	t.Parallel()
	p := derivedSeccompProfile(t)
	if p.DefaultAction != "SCMP_ACT_ERRNO" {
		t.Fatalf("defaultAction = %q, want deny by default", p.DefaultAction)
	}
	for _, flags := range []uint64{0, sockNonblock, sockCloexec, sockNonblock | sockCloexec} {
		for _, proto := range []uint64{0, ipprotoTCP} {
			if !p.allows(t, "socket", afInet, sockStream|flags, proto) {
				t.Errorf("the variant refuses socket(AF_INET, SOCK_STREAM|%#o, %d)", flags, proto)
			}
		}
	}
	if !p.allows(t, "socket", afUnix, sockStream, 0) || !p.allows(t, "socketpair", afUnix, sockStream, 0) {
		t.Error("the variant refuses Unix sockets")
	}
	for _, c := range [][]uint64{
		{afInet, sockDgram, 0}, {afInet, sockDgram, ipprotoUDP}, {afInet, sockRaw, ipprotoRaw}, {afInet, sockRaw, ipprotoTCP},
		{afInet, sockStream, ipprotoSCTP}, {afInet, sockStream, ipprotoMPTCP}, {afInet, sockStream | 0x100, 0},
		{afInet6, sockStream, 0}, {afInet6, sockStream, ipprotoTCP}, {afNetlink, sockRaw, 0}, {afPacket, sockRaw, 0}, {afAlg, 5, 0},
	} {
		if p.allows(t, "socket", c...) {
			t.Errorf("the variant allows socket(%v)", c)
		}
	}
	if p.allows(t, "socketpair", afInet, sockStream, 0) {
		t.Error("the variant allows socketpair(AF_INET)")
	}
	for _, c := range [][]uint64{{solSocket, soReuseaddr}, {solSocket, soKeepalive}, {ipprotoTCP, tcpNodelay}, {ipprotoTCP, tcpKeepidle}, {ipprotoTCP, tcpKeepintvl}, {ipprotoTCP, tcpKeepcnt}} {
		if !p.allows(t, "setsockopt", 0, c[0], c[1]) {
			t.Errorf("the variant refuses setsockopt(level %d, option %d), which the forwarder or a client transport sets", c[0], c[1])
		}
	}
	for _, c := range [][]uint64{{ipprotoTCP, tcpULP}, {solTLS, 1}, {solTLS, 2}, {solSocket, soAttachFilter}, {solSocket, soAttachBPF}, {solSocket, soAttachReuseportCBPF}, {solSocket, soAttachReuseportEBPF}, {solSocket, 27}} {
		if p.allows(t, "setsockopt", 0, c[0], c[1]) {
			t.Errorf("the variant allows setsockopt(level %d, option %d)", c[0], c[1])
		}
	}
	if !p.allows(t, "getsockopt", 0, solSocket, soError) {
		t.Error("the variant refuses getsockopt(SO_ERROR), which libuv reads after a connect")
	}
	if !p.allows(t, "getsockopt", 0, solSocket, soType) {
		t.Error("the variant refuses getsockopt(SO_TYPE), which libuv reads to classify a child's socketpair stdio (a node started by node)")
	}
	for _, c := range [][]uint64{{ipprotoTCP, tcpULP}, {solTLS, 1}, {solSocket, soAttachFilter}} {
		if p.allows(t, "getsockopt", 0, c[0], c[1]) {
			t.Errorf("the variant allows getsockopt(level %d, option %d)", c[0], c[1])
		}
	}
}

// TestShippedSeccompSDKVariantDiffersFromDefaultByExactlyItsRules: the variant is the
// default with setsockopt and getsockopt taken out of the unrestricted list, the socket
// rule split into the Unix rule and the two IPv4 TCP rules, and the option rules added,
// and nothing else, so the audit of the default carries over.
func TestShippedSeccompSDKVariantDiffersFromDefaultByExactlyItsRules(t *testing.T) {
	t.Parallel()
	def := readSeccompProfile(t, "../docker/seccomp.json")
	sdk := derivedSeccompProfile(t)
	if def.DefaultAction != sdk.DefaultAction {
		t.Fatalf("defaultAction %q vs %q", def.DefaultAction, sdk.DefaultAction)
	}
	canon := func(r seccompRule) string {
		b, _ := json.Marshal(r)
		return string(b)
	}
	// What the default would be with the two names removed and its socket rule dropped.
	var expect []string
	for _, r := range def.Syscalls {
		if len(r.Names) == 2 && r.Names[0] == "socket" && r.Names[1] == "socketpair" {
			continue
		}
		names := make([]string, 0, len(r.Names))
		for _, n := range r.Names {
			if n != "setsockopt" && n != "getsockopt" {
				names = append(names, n)
			}
		}
		r.Names = names
		expect = append(expect, canon(r))
	}
	var got, added []string
	for _, r := range sdk.Syscalls {
		switch {
		case r.Names[0] == "socket" || r.Names[0] == "socketpair" || r.Names[0] == "setsockopt" || r.Names[0] == "getsockopt":
			added = append(added, canon(r))
		default:
			got = append(got, canon(r))
		}
	}
	if strings.Join(got, "\n") != strings.Join(expect, "\n") {
		t.Fatalf("the variant's other rules differ from the default's:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(expect, "\n"))
	}
	// The added rules are exactly: the Unix socket rule, two IPv4 TCP socket rules, six
	// setsockopt rules and two getsockopt rules, each with a single-family or
	// single-option filter (checked for effect by TestShippedSeccompSDKVariant).
	kinds := map[string]int{}
	for _, r := range sdk.Syscalls {
		if r.Names[0] == "socket" || r.Names[0] == "socketpair" || r.Names[0] == "setsockopt" || r.Names[0] == "getsockopt" {
			kinds[strings.Join(r.Names, ",")]++
			if len(r.Args) == 0 {
				t.Errorf("rule %v has no argument filter", r.Names)
			}
		}
	}
	if kinds["socket,socketpair"] != 1 || kinds["socket"] != 2 || kinds["setsockopt"] != 6 || kinds["getsockopt"] != 2 || len(added) != 11 {
		t.Fatalf("added rules by kind = %v (%d in all), want one Unix, two IPv4 socket, six setsockopt, two getsockopt", kinds, len(added))
	}
}

func seccompDigest(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return seccompBytesID(raw)
}

func seccompBytesID(raw []byte) string {
	sum := sha256.Sum256(raw)
	return seccompPolicyDigestPrefix + hex.EncodeToString(sum[:])
}

// derivedSeccompBytes is the sdk_env variant as the daemon derives it from the shipped
// default (SANDBOX_DOCKER_SECCOMP_SDK=derived).
func derivedSeccompBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("../docker/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	derived, err := deriveSDKSeccomp(raw)
	if err != nil {
		t.Fatalf("deriving the variant from the shipped default: %v", err)
	}
	return derived
}

func derivedSeccompProfile(t *testing.T) seccompProfile {
	t.Helper()
	var p seccompProfile
	if err := json.Unmarshal(derivedSeccompBytes(t), &p); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestDeriveSDKSeccompIsDeterministicAndRefusesOtherShapes: the derivation gives the same
// bytes every time (so the digest names it), and refuses a default that lacks the shape it
// edits: no deny-by-default, no AF_UNIX socket rule, or no unfiltered setsockopt.
func TestDeriveSDKSeccompIsDeterministicAndRefusesOtherShapes(t *testing.T) {
	t.Parallel()
	a, b := derivedSeccompBytes(t), derivedSeccompBytes(t)
	if string(a) != string(b) {
		t.Fatal("two derivations of the same default differ")
	}
	if !strings.Contains(string(a), `"//sdk_env"`) {
		t.Fatal("the derived profile does not say what it is")
	}
	for name, raw := range map[string]string{
		"allow by default":    `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}`,
		"no socket rule":      `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","setsockopt","getsockopt"],"action":"SCMP_ACT_ALLOW"}]}`,
		"socket unfiltered":   `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","setsockopt","getsockopt"],"action":"SCMP_ACT_ALLOW"},{"names":["socket","socketpair"],"action":"SCMP_ACT_ALLOW"}]}`,
		"setsockopt filtered": `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","getsockopt"],"action":"SCMP_ACT_ALLOW"},{"names":["socket","socketpair"],"action":"SCMP_ACT_ALLOW","args":[{"index":0,"value":1,"op":"SCMP_CMP_EQ"}]}]}`,
		"not json":            `{`,
	} {
		if _, err := deriveSDKSeccomp([]byte(raw)); err == nil {
			t.Errorf("%s: derived a variant from a default of another shape", name)
		}
	}

	// A default that also allows setsockopt in a rule of its own, written with docker's
	// older singular "name", must not leave the variant an unrestricted setsockopt.
	shipped, err := os.ReadFile("../docker/seccomp.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(shipped, &doc); err != nil {
		t.Fatal(err)
	}
	doc["syscalls"] = append(doc["syscalls"].([]any), map[string]any{"name": "setsockopt", "action": "SCMP_ACT_ALLOW"})
	extra, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	derived, err := deriveSDKSeccomp(extra)
	if err != nil {
		t.Fatal(err)
	}
	var variant map[string]any
	if err := json.Unmarshal(derived, &variant); err != nil {
		t.Fatal(err)
	}
	for _, r := range variant["syscalls"].([]any) {
		rule := r.(map[string]any)
		names := seccompNames(rule["names"]) // both spellings, read here, not by the code under test
		if n, _ := rule["name"].(string); n != "" {
			names = append(names, n)
		}
		if rule["action"] == "SCMP_ACT_ALLOW" && rule["args"] == nil && slices.Contains(names, "setsockopt") {
			t.Fatalf("the variant kept an unrestricted setsockopt: %v", rule)
		}
	}
	if err := checkSDKSeccompShape([]byte(`{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"read","names":["write"],"action":"SCMP_ACT_ERRNO"}]}`)); err == nil {
		t.Fatal("a refused rule that sets both name and names passed; docker refuses the whole profile")
	}
}

// TestVerifySeccompDerivesTheVariant: SANDBOX_DOCKER_SECCOMP_SDK=derived pins the
// derivation beside the default, under the digest of the derived bytes.
func TestVerifySeccompDerivesTheVariant(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	def, _ := filepath.Abs("../docker/seccomp.json")
	s, err := verifySeccomp(def, SeccompSDKDerived, dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.defaultID != seccompDigest(t, def) || s.sdkID != seccompBytesID(derivedSeccompBytes(t)) || s.sdkPath == "" || filepath.Dir(s.sdkPath) != dir {
		t.Fatalf("derived variant: %+v", s)
	}
	pinned, err := os.ReadFile(s.sdkPath)
	if err != nil || string(pinned) != string(derivedSeccompBytes(t)) {
		t.Fatalf("the pinned copy differs from the derivation: %v", err)
	}
}

// TestVerifySeccompRefusesAWideVariantFile: an operator's own sdk_env variant must keep
// the derived variant's floor (deny by default, socket bound to a family, no socketcall);
// the derived bytes written out pass, so a file may be the derivation itself.
func TestVerifySeccompRefusesAWideVariantFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	def, _ := filepath.Abs("../docker/seccomp.json")
	write := func(name, body string) string {
		p := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, c := range []struct{ name, body, want string }{
		{"allow by default", `{"defaultAction":"SCMP_ACT_ALLOW","syscalls":[]}`, "not deny-by-default"},
		{"no list", `{"defaultAction":"SCMP_ACT_ERRNO"}`, "no syscalls list"},
		{"socket for every family", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["read","socket"],"action":"SCMP_ACT_ALLOW"}]}`, "address family"},
		{"socket filtered on its type only", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["socket"],"action":"SCMP_ACT_ALLOW","args":[{"index":1,"value":1,"op":"SCMP_CMP_EQ"}]}]}`, "address family"},
		{"socket logged", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["socket"],"action":"SCMP_ACT_LOG"}]}`, "address family"},
		{"socketcall", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["socketcall"],"action":"SCMP_ACT_ALLOW"}]}`, "socketcall"},
		// Docker still reads a rule's older singular "name" (moby/profiles), so the check must too.
		{"socket by its singular name", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"socket","action":"SCMP_ACT_ALLOW"}]}`, "address family"},
		{"socketcall by its singular name", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"socketcall","action":"SCMP_ACT_ALLOW"}]}`, "socketcall"},
		{"name and names both", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"name":"read","names":["write"],"action":"SCMP_ACT_ALLOW"}]}`, "both"},
		{"not JSON", `{`, "not valid JSON"},
	} {
		if _, err := verifySeccomp(def, write(c.name+".json", c.body), dir); err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), SeccompSDKDerived) {
			t.Errorf("%s: %v, want a refusal saying %q and pointing at %q", c.name, err, c.want, SeccompSDKDerived)
		}
	}
	s, err := verifySeccomp(def, write("derived.json", string(derivedSeccompBytes(t))), dir)
	if err != nil || s.sdkID != seccompBytesID(derivedSeccompBytes(t)) {
		t.Fatalf("the derived bytes as a file: %+v, %v", s, err)
	}
	// A refused socket rule that errors stays fine: only rules that let the call through count.
	if _, err := verifySeccomp(def, write("errno.json", `{"defaultAction":"SCMP_ACT_ERRNO","syscalls":[{"names":["socket","socketcall"],"action":"SCMP_ACT_ERRNO"}]}`), dir); err != nil {
		t.Fatalf("a variant that refuses socket and socketcall outright: %v", err)
	}
}

// TestVerifySeccompPinsAndRefuses: the two settings are checked against each other at
// Preflight, and a profile file is pinned by a copy named by its digest.
func TestVerifySeccompPinsAndRefuses(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	def, _ := filepath.Abs("../docker/seccomp.json")
	// An operator's own variant file: here the derived bytes written out.
	sdk := filepath.Join(t.TempDir(), "variant.json")
	if err := os.WriteFile(sdk, derivedSeccompBytes(t), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct{ def, sdk, want string }{
		{"", sdk, "SANDBOX_DOCKER_SECCOMP is"},
		{"", SeccompSDKDerived, "SANDBOX_DOCKER_SECCOMP is"},
		{"default", sdk, "SANDBOX_DOCKER_SECCOMP is"},
		{"unconfined", SeccompSDKDerived, "SANDBOX_DOCKER_SECCOMP is"},
		{def, "unconfined", "must be"},
		{def, filepath.Join(dir, "missing.json"), "no such file"},
		{filepath.Join(dir, "missing.json"), "", "no such file"},
		{filepath.Join(dir, "missing.json"), SeccompSDKDerived, "no such file"},
	} {
		if _, err := verifySeccomp(c.def, c.sdk, dir); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("verifySeccomp(%q, %q) = %v, want an error containing %q", c.def, c.sdk, err, c.want)
		}
	}
	s, err := verifySeccomp("", "", dir)
	if err != nil || s.defaultPath != "" || s.defaultID != seccompPolicyDockerDefault || s.sdkPath != "" {
		t.Fatalf("docker default: %+v, %v", s, err)
	}
	s, err = verifySeccomp("unconfined", "", dir)
	if err != nil || s.defaultPath != "unconfined" || s.defaultID != seccompPolicyUnconfined {
		t.Fatalf("unconfined: %+v, %v", s, err)
	}
	s, err = verifySeccomp(def, sdk, dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.defaultID != seccompDigest(t, def) || s.sdkID != seccompDigest(t, sdk) || s.defaultID == s.sdkID {
		t.Fatalf("identities %+v", s)
	}
	for _, p := range []struct{ pinned, src string }{{s.defaultPath, def}, {s.sdkPath, sdk}} {
		if filepath.Dir(p.pinned) != dir {
			t.Fatalf("pinned copy %q is not in %q", p.pinned, dir)
		}
		a, _ := os.ReadFile(p.pinned)
		b, _ := os.ReadFile(p.src)
		if string(a) != string(b) || len(a) == 0 {
			t.Fatalf("pinned copy %q differs from %q", p.pinned, p.src)
		}
		if info, err := os.Stat(p.pinned); err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("pinned copy mode %v, %v", info.Mode(), err)
		}
	}
	// A second Preflight finds the copies and keeps them.
	again, err := verifySeccomp(def, sdk, dir)
	if err != nil || again != s {
		t.Fatalf("second verification %+v, %v differs from %+v", again, err, s)
	}
}

// TestSeccompForSelectsPerDispatch: the profile a run applies follows its grant and the
// runtime, never a shared setting: runsc skips every profile and says so; a grant with
// sdk_env gets the variant, or docker's own profile when that is the default, or a
// refusal before dispatch when a profile file has no variant beside it; everything else
// gets the default.
func TestSeccompForSelectsPerDispatch(t *testing.T) {
	t.Parallel()
	plain := &HostAPIGrant{BaseURL: "https://api.internal"}
	sdk := &HostAPIGrant{BaseURL: "https://api.internal", SDKEnv: map[string]string{"OPENAI_BASE_URL": "{origin}/v1"}}
	both := dockerSeccomp{defaultPath: "/pin/a.json", defaultID: "seccomp:sha256:a", sdkPath: "/pin/b.json", sdkID: "seccomp:sha256:b"}
	only := dockerSeccomp{defaultPath: "/pin/a.json", defaultID: "seccomp:sha256:a"}
	dockerDefault := dockerSeccomp{defaultID: seccompPolicyDockerDefault}
	unconfined := dockerSeccomp{defaultPath: "unconfined", defaultID: seccompPolicyUnconfined}
	for _, c := range []struct {
		name     string
		s        dockerSeccomp
		grant    *HostAPIGrant
		runtime  string
		path, id string
	}{
		{"no grant, default", both, nil, "", "/pin/a.json", "seccomp:sha256:a"},
		{"plain grant, default", both, plain, "", "/pin/a.json", "seccomp:sha256:a"},
		{"sdk grant, variant", both, sdk, "", "/pin/b.json", "seccomp:sha256:b"},
		{"sdk grant, docker's own profile", dockerDefault, sdk, "", "", seccompPolicyDockerDefault},
		{"sdk grant, unconfined", unconfined, sdk, "", "unconfined", seccompPolicyUnconfined},
		{"runsc skips the default", both, plain, "runsc", "", seccompPolicySkippedRunsc},
		{"runsc skips the variant", both, sdk, "runsc", "", seccompPolicySkippedRunsc},
		{"runsc, no profile configured", dockerDefault, nil, "runsc", "", seccompPolicySkippedRunsc},
	} {
		path, id, err := c.s.seccompFor(c.grant, c.runtime)
		if err != nil || path != c.path || id != c.id {
			t.Errorf("%s: (%q, %q, %v), want (%q, %q)", c.name, path, id, err, c.path, c.id)
		}
	}
	_, _, err := only.seccompFor(sdk, "")
	reason, marked := NotDispatchedReason(err)
	if !errors.Is(err, ErrNoSDKSeccomp) || !marked || reason != RefusalEnvironment {
		t.Fatalf("sdk grant with a profile file and no variant: %v (reason %v, marked %v)", err, reason, marked)
	}
	if got := both.describe(""); got != "seccomp:sha256:a sdk_env:seccomp:sha256:b" {
		t.Errorf("describe = %q", got)
	}
	if got := only.describe(""); got != "seccomp:sha256:a" {
		t.Errorf("describe without a variant = %q", got)
	}
	if got := both.describe("runsc"); got != seccompPolicySkippedRunsc {
		t.Errorf("describe under runsc = %q", got)
	}
}

// TestGrantGuestEnvAndRunnerFollowSDKEnv: only a grant with sdk_env gets the forwarder's
// address and the client's environment; a plain grant gets the socket alone and the
// bare runner, so the default profile suffices for it.
func TestGrantGuestEnvAndRunnerFollowSDKEnv(t *testing.T) {
	t.Parallel()
	d := DefaultDocker("")
	plain := &HostAPIGrant{BaseURL: "https://api.internal"}
	if env := d.grantGuestEnv(plain); len(env) != 1 || env[0] != HostAPISocketEnv+"="+containerSocketPath {
		t.Fatalf("plain grant env = %q", env)
	}
	sdk := &HostAPIGrant{BaseURL: "https://api.internal", SDKEnv: map[string]string{"OPENAI_BASE_URL": "{origin}/v1"}}
	env := d.grantGuestEnv(sdk)
	if len(env) != 3 || env[1] != HostAPIListenEnv+"="+hostAPIListen || env[2] != "OPENAI_BASE_URL=http://"+hostAPIListen+"/v1" {
		t.Fatalf("sdk grant env = %q", env)
	}
	argv, err := dockerForwardingRunnerArgv("", "127.0.0.1:1")
	if err != nil || !strings.Contains(strings.Join(argv, " "), "--eval") || !strings.Contains(strings.Join(argv, " "), " 127.0.0.1:1 ") {
		t.Fatalf("forwarding runner argv = %q, %v", argv, err)
	}
}
