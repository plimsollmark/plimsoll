package openshell

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/plimsollmark/plimsoll/gen/go/openshell/sandboxv1"
)

const (
	// runnerPath is the in-image project runner (docker/runner.mjs); the image must
	// carry it.
	runnerPath = "/runner.mjs"
	// workDir is where a project run's files are written and its steps run. It lives
	// under /tmp because /tmp is the only writable directory the policy grants.
	// OpenShell v0.1.2 does not create a read_write path the image lacks (its
	// prepare_filesystem has no caller), and Landlock skips a rule for a missing
	// path, so a directory such as /sandbox/work can never be granted on an image
	// that does not already contain it (measured 2026-09-28: ENOENT, and the runner
	// failed with "spawnSync sh ENOENT").
	workDir = "/tmp/work"
)

// runPolicy is the policy every sandbox is created with and must read back unchanged.
//
//   - No network rules: the gateway's default for a sandbox is deny-all egress, and a
//     name is resolved upstream only once a rule makes it eligible, so no rule means no
//     egress and no upstream DNS.
//   - Filesystem: the system paths node and sh need, /sys/fs/cgroup (so the smoke test
//     can read the sandbox's own memory and CPU limits) and the runner, read-only; /tmp
//     and /dev/null read-write; nothing else. The workdir (/sandbox) is not included,
//     so the sandbox user's home is neither readable nor writable.
//   - Landlock hard_requirement: a kernel or runtime without Landlock fails the exec
//     instead of running it unrestricted, which best_effort would do silently.
func runPolicy() *sandboxv1.SandboxPolicy {
	return &sandboxv1.SandboxPolicy{
		Version: 1,
		Filesystem: &sandboxv1.FilesystemPolicy{
			ReadOnly:  []string{"/bin", "/usr", "/lib", "/etc", "/proc", "/dev/urandom", "/sys/fs/cgroup", runnerPath},
			ReadWrite: []string{"/tmp", "/dev/null"},
		},
		Landlock: &sandboxv1.LandlockPolicy{Compatibility: "hard_requirement"},
	}
}

// policyHash is the SHA-256 the gateway reports for a policy in
// GetSandboxConfig.policy_hash, so a run can compare the read-back hash with the hash
// of the policy it sent rather than only with another read.
//
// It reproduces deterministic_policy_hash in OpenShell's openshell-core
// (policy_identity.rs at v0.1.2): the protobuf encoding of the policy with its two
// maps cleared, then each map as a label and its sorted entries, every part prefixed
// with its length as a little-endian uint64. plimsoll never sends map entries, so a
// policy with any is refused here rather than hashed.
func policyHash(p *sandboxv1.SandboxPolicy) (string, error) {
	if len(p.GetNetworkPolicies()) > 0 || len(p.GetNetworkMiddlewares()) > 0 {
		return "", errors.New("openshell policy hash: network policies and middlewares are not supported")
	}
	enc, err := proto.MarshalOptions{Deterministic: true}.Marshal(p)
	if err != nil {
		return "", err
	}
	var out []byte
	field := func(b []byte) {
		out = binary.LittleEndian.AppendUint64(out, uint64(len(b)))
		out = append(out, b...)
	}
	field(enc)
	field([]byte("network_policies"))
	out = binary.LittleEndian.AppendUint64(out, 0)
	field([]byte("network_middlewares"))
	out = binary.LittleEndian.AppendUint64(out, 0)
	sum := sha256.Sum256(out)
	return hex.EncodeToString(sum[:]), nil
}

// resourceLimits is the template's resources value: Kubernetes-style limits, which
// the docker driver applies as the container's memory and CPU limits. The gateway
// reads only string quantities.
func resourceLimits(memoryMB int, cpus float64) (*structpb.Struct, error) {
	return structpb.NewStruct(map[string]any{"limits": map[string]any{
		"memory": strconv.Itoa(memoryMB) + "Mi",
		"cpu":    strconv.FormatFloat(cpus, 'f', -1, 64),
	}})
}
