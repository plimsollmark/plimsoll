package agentsandbox

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math"
	"net"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// readPolicies retains the complete policy spec for pinning, including fields this
// version's semantic checker does not decode. Metadata-only updates do not change it.
// Pin the whole namespace set: a newly selecting policy can widen an additive allow list.
func (p *Provider) readPolicies(ctx context.Context) ([]networkPolicy, string, error) {
	var list struct {
		Items []json.RawMessage `json:"items"`
	}
	if err := p.kube.get(ctx, networkPoliciesPath(p.cfg.Namespace), &list); err != nil {
		return nil, "", fmt.Errorf("agentsandbox: list network policies: %w", err)
	}
	policies := make([]networkPolicy, 0, len(list.Items))
	identities := map[string]string{}
	for _, raw := range list.Items {
		var np networkPolicy
		var whole struct {
			Spec map[string]any `json:"spec"`
		}
		if err := json.Unmarshal(raw, &np); err != nil {
			return nil, "", err
		}
		d := json.NewDecoder(bytes.NewReader(raw))
		d.UseNumber()
		if err := d.Decode(&whole); err != nil {
			return nil, "", err
		}
		if !validName(np.Meta.Name) || np.Meta.UID == "" || whole.Spec == nil {
			return nil, "", fmt.Errorf("agentsandbox: network policy %q lacks a valid name, UID or spec", np.Meta.Name)
		}
		if _, exists := identities[np.Meta.Name]; exists {
			return nil, "", fmt.Errorf("agentsandbox: duplicate network policy %s", np.Meta.Name)
		}
		// UseNumber retains even unknown numeric fields exactly. Marshaling the decoded
		// map sorts keys recursively, so formatting and object order are immaterial.
		spec, err := json.Marshal(whole.Spec)
		if err != nil {
			return nil, "", err
		}
		sum := sha256.Sum256(append([]byte(np.Meta.UID+"\n"), spec...))
		identities[np.Meta.Name] = hex.EncodeToString(sum[:])
		policies = append(policies, np)
	}
	raw, err := json.Marshal(identities)
	if err != nil {
		return nil, "", err
	}
	sum := sha256.Sum256(raw)
	return policies, hex.EncodeToString(sum[:]), nil
}

func (p *Provider) checkPolicySet(sum string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.policyChanged || p.policySum != "" && sum != p.policySum {
		p.policyChanged = true
		return errors.New("agentsandbox: network policy set changed from the UIDs and specs bound to the startup smoke test; restart plimsolld to prove the new set")
	}
	return nil
}

// bindPolicies fixes the candidate before any behavioural test, and checks it again
// after both tests. It never replaces a set already bound to this provider instance.
func (p *Provider) bindPolicies(ctx context.Context) error {
	_, sum, err := p.readPolicies(ctx)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.policySum == "" {
		p.policySum = sum
	}
	p.mu.Unlock()
	return p.checkPolicySet(sum)
}

// The read-back: what the template and every claimed pod must show before plimsoll sends
// it code. The template is checked at Preflight, so a misconfigured one fails at startup;
// the pod is checked again before each run, since a pod is the template as the cluster
// actually ran it (and a debug container can be attached to a running pod).

// fixedNameserver is the resolver every pod must be given, and nothing else: one
// loopback nameserver and no search domain, as the docker provider's fixed resolv.conf.
// Kubernetes' default (ClusterFirst) writes the cluster's DNS and the node's search
// domains into the pod, which the spike found leaking this host's (2026-10-17).
const fixedNameserver = "127.0.0.1"

// allowedCaps are the capabilities sandboxd may keep: it runs as root and drops each
// command to the guest uid, which needs these two and nothing else (the spike measured
// CapEff 00000000000000c0 under gVisor).
var allowedCaps = []string{"SETUID", "SETGID"}

// checkPodSpec checks the template's pod spec, or a pod's, for a runtime of the given
// tier.
func (p *Provider) checkPodSpec(s podSpec, tier sandbox.IsolationClass) error {
	switch {
	case s.RuntimeClassName == nil || *s.RuntimeClassName != p.cfg.RuntimeClass:
		return fmt.Errorf("the runtime class is %s, not %q", strOrUnset(s.RuntimeClassName), p.cfg.RuntimeClass)
	case s.AutomountServiceAccountToken == nil || *s.AutomountServiceAccountToken:
		return errors.New("automountServiceAccountToken is not false: the guest would hold an API token")
	case s.HostNetwork || s.HostPID || s.HostIPC:
		return errors.New("the pod shares the node's network, process or IPC namespace")
	case s.ShareProcessNamespace != nil && *s.ShareProcessNamespace:
		return errors.New("shareProcessNamespace is set")
	case s.DNSPolicy != "None" || s.DNSConfig == nil || !slices.Equal(s.DNSConfig.Nameservers, []string{fixedNameserver}) ||
		len(s.DNSConfig.Searches) > 0 || len(s.DNSConfig.Options) > 0:
		return fmt.Errorf("DNS is not fixed: want dnsPolicy None with the one nameserver %s and no search domain or option", fixedNameserver)
	case len(s.InitContainers) > 0 || len(s.EphemeralContainers) > 0:
		return errors.New("the pod has an init or ephemeral container")
	case len(s.Containers) != 1:
		return fmt.Errorf("%d containers, want one (sandboxd)", len(s.Containers))
	}
	sizes, err := volumeSizes(s)
	if err != nil {
		return err
	}
	if tier == sandbox.IsolationVM && p.cfg.DiskMB > 0 {
		return fmt.Errorf("SANDBOX_DISK_MB is %d, but under the vm tier no volume's size limit holds: Kata mounts each memory-backed emptyDir as a tmpfs of the VM's own, bounded only by its memory, so no disk budget can be promised", p.cfg.DiskMB)
	}
	if err := p.checkDiskBudget(sizes); err != nil {
		return err
	}
	c := s.Containers[0]
	if err := checkHandlers(c); err != nil {
		return err
	}
	for _, port := range c.Ports {
		if port.HostPort != 0 || port.HostIP != "" {
			return errors.New("the container exposes a host port or host IP")
		}
	}
	if c.Image != p.cfg.Image {
		return fmt.Errorf("the container runs %q, not %q", c.Image, p.cfg.Image)
	}
	if err := checkSecurityContext(c.SecurityContext); err != nil {
		return err
	}
	if err := checkSeccomp(s, c, tier); err != nil {
		return err
	}
	key, err := findKeyVolume(s)
	if err != nil {
		return err
	}
	if err := p.checkKeyAttributes(key); err != nil {
		return err
	}
	if err := checkMounts(c, key.Volume); err != nil {
		return err
	}
	if err := checkTerminationLog(c); err != nil {
		return err
	}
	// The command is named, not left to the image's entrypoint, which the read-back
	// cannot see: the TLS terminator, which starts sandboxd with the rest as its flags.
	if len(c.Command) == 0 || c.Command[0] != frontPath {
		return fmt.Errorf("the container's command is %q, not %s (the TLS terminator, followed by sandboxd's flags)", c.Command, frontPath)
	}
	if err := p.checkSandboxdArgs(append(slices.Clone(c.Command[1:]), c.Args...)); err != nil {
		return err
	}
	mem, err := memoryBytes(c.Resources.Limits["memory"])
	if err != nil || mem != int64(p.cfg.memoryMB())<<20 {
		return fmt.Errorf("the memory limit is %q, not %d MiB", c.Resources.Limits["memory"], p.cfg.memoryMB())
	}
	cpu, err := milliCPU(c.Resources.Limits["cpu"])
	if err != nil || cpu != int64(math.Round(p.cfg.cpus()*1000)) {
		return fmt.Errorf("the CPU limit is %q, not %g", c.Resources.Limits["cpu"], p.cfg.cpus())
	}
	return nil
}

// checkDiskBudget holds the volumes to SANDBOX_DISK_MB when it is set: their size limits
// must sum to no more than it, as docker's writable mounts must. /dev/shm is outside the
// sum, as the read-back cannot size it: under runc the runtime's own tmpfs (64 MiB
// measured), under gVisor bounded only by the pod's memory, in memory either way.
func (p *Provider) checkDiskBudget(sizes map[string]int64) error {
	if p.cfg.DiskMB <= 0 {
		return nil
	}
	var sum int64
	for _, size := range sizes {
		sum += size
	}
	if sum > int64(p.cfg.DiskMB)<<20 {
		return fmt.Errorf("the volumes' size limits sum to %d MiB, over SANDBOX_DISK_MB's %d", sum>>20, p.cfg.DiskMB)
	}
	return nil
}

func strOrUnset(s *string) string {
	if s == nil {
		return "unset"
	}
	return strconv.Quote(*s)
}

// checkSeccomp requires a syscall filter under runc, the container tier, where the
// guest's system calls reach the host kernel: the runtime's default profile or one of the
// node's own. Under gVisor the guest's calls reach gVisor's kernel, and under Kata the VM's
// own, so none is required (Kata applies none in the guest unless its configuration sets
// disable_guest_seccomp to false; measured on kind, Seccomp 0 under RuntimeDefault).
// The container's profile wins over the pod's, as the kubelet applies them.
func checkSeccomp(s podSpec, c container, tier sandbox.IsolationClass) error {
	if tier != sandbox.IsolationContainer {
		return nil
	}
	prof := (*seccompProfile)(nil)
	if s.SecurityContext != nil {
		prof = s.SecurityContext.SeccompProfile
	}
	if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil {
		prof = c.SecurityContext.SeccompProfile
	}
	if prof == nil || (prof.Type != "RuntimeDefault" && prof.Type != "Localhost") {
		return errors.New("under runc the pod must set a seccomp profile (RuntimeDefault or Localhost); without one the guest's system calls reach the host kernel unfiltered")
	}
	return nil
}

// volumeSizes checks every volume is a memory-backed emptyDir with a size limit and
// returns each one's limit in bytes by name. A memory-backed emptyDir is a tmpfs the
// kubelet sizes to its limit, a hard cap on what the guest can write there (the smoke test
// fills each one to prove it); a disk-backed one is capped only when the kubelet's periodic eviction
// notices, so a run could fill the node's disk for its whole duration (measured
// 2026-10-17: 64 MiB to a node file in a quarter of a second). Under Kata a disk-backed
// one is a virtio-fs share of the node's directory, the same channel, and a memory-backed
// one a tmpfs of the VM's own that ignores its limit (measured 2026-10-18 under both of
// Kata's runtimes), so the vm tier keeps the rule and promises no cap but the VM's memory.
//
// The one other volume is the key volume (findKeyVolume), which holds no guest data and
// is outside the writable roots and the disk budget. A Secret volume, which earlier
// releases took for one key shared by every pod, is refused like any other source.
func volumeSizes(s podSpec) (map[string]int64, error) {
	key, err := findKeyVolume(s)
	if err != nil {
		return nil, err
	}
	sizes := map[string]int64{}
	for _, v := range s.Volumes {
		var name string
		if v["csi"] != nil && json.Unmarshal(v["name"], &name) == nil && name == key.Volume {
			continue
		}
		var dir struct {
			Medium    string `json:"medium"`
			SizeLimit string `json:"sizeLimit"`
		}
		if len(v) != 2 || v["emptyDir"] == nil || json.Unmarshal(v["name"], &name) != nil || json.Unmarshal(v["emptyDir"], &dir) != nil {
			return nil, fmt.Errorf("volume %s is not an emptyDir", v["name"])
		}
		size, err := memoryBytes(dir.SizeLimit)
		if dir.Medium != "Memory" || err != nil {
			return nil, fmt.Errorf("volume %s is not a memory-backed emptyDir with a sizeLimit (medium %q, sizeLimit %q): only a tmpfs caps what a run writes", name, dir.Medium, dir.SizeLimit)
		}
		sizes[name] = size
	}
	return sizes, nil
}

// The pod's key volume: where the pod's own key and certificate come from. An issuer in
// the cluster signs a certificate for each pod as it is mounted, with the pod's identity
// in it (channel.go), and the key is made on the node for that pod alone. The read-back
// accepts one source of it today, a CSI volume of keyDriver (the driver of cert-manager's
// csi-driver project) with a closed list of attributes. Another source, such as
// Kubernetes' own pod certificate projection, would be one more case here under the same
// contract: the files tls.crt and tls.key at tlsMountPath, the certificate naming the one
// DNS name and the pod's identity alone, chained to the operator's CA.
const (
	keyDriver = "csi.cert-manager.io"
	keyAttr   = keyDriver + "/"
)

// keyVolume is the key volume as the read-back accepts it; the boundary digest binds it
// whole, attributes included, so a pod whose issuer, identity or key settings differ from
// the proven template's is refused.
type keyVolume struct {
	Volume     string
	Driver     string
	Attributes map[string]string
}

// refusedKeyAttrs are attributes the driver offers that would undo what the read-back
// relies on, each with the reason given to the operator. Any other attribute outside
// checkKeyAttributes' list is refused too, as unknown.
var refusedKeyAttrs = map[string]string{
	"fs-group":          "it makes the key readable by a group of its choosing, which the guest could hold",
	"pkcs12-enable":     "it writes a second copy of the key in another file",
	"pkcs12-filename":   "it writes a second copy of the key in another file",
	"pkcs12-password":   "it writes a second copy of the key in another file",
	"reuse-private-key": "a renewed certificate must come with a new key",
	"certificate-file":  "the terminator reads tls.crt and tls.key, and nothing else",
	"privatekey-file":   "the terminator reads tls.crt and tls.key, and nothing else",
	"ca-file":           "the terminator reads tls.crt and tls.key, and nothing else",
	"ip-sans":           "the certificate names the pod by its identity alone; an address is not an identity",
	"common-name":       "the certificate names the pod by its identity alone",
	"is-ca":             "a pod's certificate signs nothing",
}

// findKeyVolume finds the pod's one key volume and checks its shape: exactly one CSI
// volume, of keyDriver, read-only, giving the driver, readOnly and its attributes and
// nothing else (no filesystem type, no node publish secret), mounted once, read-only and
// whole at tlsMountPath, with no other volume mounted over, at or inside tlsGuardDir,
// which the image makes root's, mode 0700. The driver writes its files mode 0440, owner
// and group root (measured 2026-11-24), so the guest, another uid with no group and no
// capability, cannot reach the key; the smoke test proves it from inside, and the
// pod-level fsGroup that would change the group is refused by the closed pod schema. The
// attributes are held to the configuration by checkKeyAttributes.
func findKeyVolume(s podSpec) (keyVolume, error) {
	var found []keyVolume
	for _, v := range s.Volumes {
		if v["csi"] == nil {
			continue
		}
		var k keyVolume
		if len(v) != 2 || json.Unmarshal(v["name"], &k.Volume) != nil {
			return keyVolume{}, fmt.Errorf("volume %s is a CSI volume with another source beside it or no name", v["name"])
		}
		var src struct {
			Driver           string            `json:"driver"`
			ReadOnly         *bool             `json:"readOnly"`
			VolumeAttributes map[string]string `json:"volumeAttributes"`
		}
		d := json.NewDecoder(bytes.NewReader(v["csi"]))
		d.DisallowUnknownFields()
		if err := d.Decode(&src); err != nil {
			return keyVolume{}, fmt.Errorf("CSI volume %s: %w (only driver, readOnly and volumeAttributes are accepted)", k.Volume, err)
		}
		switch {
		case src.Driver != keyDriver:
			return keyVolume{}, fmt.Errorf("CSI volume %s is of driver %q; the pod's key volume is %s's, and no other CSI volume is accepted", k.Volume, truncate(src.Driver, 80), keyDriver)
		case src.ReadOnly == nil || !*src.ReadOnly:
			return keyVolume{}, fmt.Errorf("CSI volume %s does not set readOnly: true, so the driver would mount the key pair writable", k.Volume)
		}
		k.Driver, k.Attributes = src.Driver, src.VolumeAttributes
		found = append(found, k)
	}
	if len(found) != 1 {
		return keyVolume{}, fmt.Errorf("%d key volumes, want one: a CSI volume of %s holding the pod's own key pair, which its TLS terminator serves, mounted at %s", len(found), keyDriver, tlsMountPath)
	}
	if len(s.Containers) != 1 {
		return keyVolume{}, errors.New("the execution boundary requires one container")
	}
	k, mounted := found[0], 0
	for _, m := range s.Containers[0].VolumeMounts {
		if m.Name == k.Volume {
			if m.MountPath != tlsMountPath || !m.ReadOnly || m.SubPath != "" {
				return keyVolume{}, fmt.Errorf("the key volume is mounted at %q (read-only %t, subPath %q); mount it whole and read-only at %s", m.MountPath, m.ReadOnly, m.SubPath, tlsMountPath)
			}
			mounted++
			continue
		}
		if m.MountPath == tlsGuardDir || strings.HasPrefix(m.MountPath, tlsGuardDir+"/") || strings.HasPrefix(tlsGuardDir, m.MountPath+"/") {
			return keyVolume{}, fmt.Errorf("volume %s is mounted at %s, at, over or inside %s, which must stay the image's root-only directory around the TLS key", m.Name, m.MountPath, tlsGuardDir)
		}
	}
	if mounted != 1 {
		return keyVolume{}, fmt.Errorf("the key volume is mounted %d times, want once at %s", mounted, tlsMountPath)
	}
	return k, nil
}

// requiredKeyAttrs are the attributes every key volume must set.
var requiredKeyAttrs = []string{"issuer-name", "issuer-kind", "dns-names", "uri-sans", "key-algorithm", "key-size", "key-encoding", "key-usages"}

// checkKeyAttributes holds the key volume's attributes to a closed list (measured on the
// driver, 2026-11-24): the issuer, by name and kind (and group, for an issuer outside
// cert-manager's own API group); the certificate's names, exactly the configured DNS name
// and the pod's identity in the configured trust domain, which the driver fills from the
// pod being mounted, never from anything the pod says; the key, ECDSA P-256 in PKCS#8,
// fixed whole, since the driver's defaults are RSA 2048 with no server-auth use; the
// usages server auth and digital signature, exactly; and, optionally, the certificate's
// lifetime. Every other attribute is refused, those in refusedKeyAttrs with their reason.
func (p *Provider) checkKeyAttributes(k keyVolume) error {
	exact := map[string]string{
		"dns-names":     p.cfg.serverName(),
		"uri-sans":      identityTemplate(p.cfg.SandboxdTrustDomain),
		"key-algorithm": "ECDSA",
		"key-size":      "256",
		"key-encoding":  "PKCS8",
	}
	seen := map[string]bool{}
	for _, full := range slices.Sorted(maps.Keys(k.Attributes)) {
		value := k.Attributes[full]
		attr, ok := strings.CutPrefix(full, keyAttr)
		if !ok {
			return fmt.Errorf("key volume %s sets the attribute %q, outside %s's", k.Volume, truncate(full, 80), keyDriver)
		}
		if why, refused := refusedKeyAttrs[attr]; refused {
			return fmt.Errorf("key volume %s sets %s, which is refused: %s", k.Volume, full, why)
		}
		seen[attr] = true
		switch attr {
		case "issuer-name", "issuer-group":
			if !validName(value) {
				return fmt.Errorf("key volume %s: %s is %q, not a name", k.Volume, full, truncate(value, 80))
			}
		case "issuer-kind":
			// A namespaced issuer only. A ClusterIssuer signs requests made in every namespace, so
			// anyone who may create a pod anywhere in the cluster could mount this driver with the
			// pool pod's identity written out literally and pass for it (security scan of
			// 2026-11-25, F1 and F2).
			if value != "Issuer" {
				return fmt.Errorf("key volume %s: %s is %q; only a namespaced Issuer, in the pool's namespace, is accepted (a ClusterIssuer signs for pods in every namespace)", k.Volume, full, truncate(value, 80))
			}
		case "key-usages":
			usages := strings.Split(value, ",")
			for i := range usages {
				usages[i] = strings.TrimSpace(usages[i])
			}
			slices.Sort(usages)
			if !slices.Equal(usages, []string{"digital signature", "server auth"}) {
				return fmt.Errorf("key volume %s: %s is %q; want exactly server auth and digital signature", k.Volume, full, truncate(value, 80))
			}
		case "duration":
			if d, err := time.ParseDuration(value); err != nil || d <= 0 {
				return fmt.Errorf("key volume %s: %s is %q, not a positive duration", k.Volume, full, truncate(value, 80))
			}
		default:
			want, known := exact[attr]
			if !known {
				return fmt.Errorf("key volume %s sets %s, which plimsoll does not accept (it accepts %s, issuer-group and duration)", k.Volume, truncate(full, 80), strings.Join(requiredKeyAttrs, ", "))
			}
			if value != want {
				return fmt.Errorf("key volume %s: %s is %q, want %q", k.Volume, full, truncate(value, 200), want)
			}
		}
	}
	for _, attr := range requiredKeyAttrs {
		if !seen[attr] {
			return fmt.Errorf("key volume %s does not set %s%s, which plimsoll requires", k.Volume, keyAttr, attr)
		}
	}
	return nil
}

// checkMounts requires every volume the container mounts to be mounted whole and
// writable at a distinct absolute path, so the smoke test's writable set is exactly
// these paths; the key volume's mount, findKeyVolume's to check, is the one read-only mount.
func checkMounts(c container, keyName string) error {
	seen := map[string]bool{}
	for _, m := range c.VolumeMounts {
		if m.Name == keyName {
			continue
		}
		switch {
		case !path.IsAbs(m.MountPath) || path.Clean(m.MountPath) != m.MountPath || m.MountPath == "/":
			return fmt.Errorf("volume %s is mounted at %q, not a clean absolute path", m.Name, m.MountPath)
		case m.SubPath != "":
			return fmt.Errorf("volume %s is mounted with a subPath", m.Name)
		case seen[m.MountPath]:
			return fmt.Errorf("two volumes are mounted at %s", m.MountPath)
		case m.ReadOnly:
			// The comment above promised writable; the check did not read the flag, and the
			// smoke's fill catches it only below the vm tier (review, 2026-10-26).
			return fmt.Errorf("volume %s is mounted read-only at %s", m.Name, m.MountPath)
		}
		seen[m.MountPath] = true
	}
	return nil
}

func checkSecurityContext(sc *securityContext) error {
	if sc == nil {
		return errors.New("the container has no security context")
	}
	switch {
	case sc.RunAsUser != nil && *sc.RunAsUser != 0 || sc.RunAsGroup != nil && *sc.RunAsGroup != 0:
		return errors.New("sandboxd must start as root to drop commands to the guest uid")
	case sc.Privileged != nil && *sc.Privileged:
		return errors.New("the container is privileged")
	case sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation:
		return errors.New("allowPrivilegeEscalation is not false")
	case sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem:
		return errors.New("the root filesystem is not read-only")
	case sc.Capabilities == nil || !slices.ContainsFunc(sc.Capabilities.Drop, func(c string) bool { return strings.EqualFold(c, "ALL") }):
		return errors.New("the container does not drop ALL capabilities")
	}
	for _, c := range sc.Capabilities.Add {
		if !slices.Contains(allowedCaps, strings.TrimPrefix(strings.ToUpper(c), "CAP_")) {
			return fmt.Errorf("the container adds capability %s", c)
		}
	}
	return nil
}

// A kubelet exec handler runs with sandboxd's root identity and uid-changing capabilities.
// It could execute a guest-written file without plimsoll's uid drop.
func checkHandlers(c container) error {
	for name, probe := range map[string]*probe{"readinessProbe": c.ReadinessProbe, "livenessProbe": c.LivenessProbe, "startupProbe": c.StartupProbe} {
		if probe != nil && len(probe.Exec) != 0 {
			return fmt.Errorf("%s has an exec handler: kubelet would run it as sandboxd's root", name)
		}
	}
	if c.Lifecycle != nil {
		for name, h := range map[string]*handler{"postStart": c.Lifecycle.PostStart, "preStop": c.Lifecycle.PreStop} {
			if h != nil && len(h.Exec) != 0 {
				return fmt.Errorf("lifecycle.%s has an exec handler: kubelet would run it as sandboxd's root", name)
			}
		}
	}
	return nil
}

// defaultTerminationLog is where the kubelet puts a container's termination message
// unless the spec says otherwise, and what the API server writes into a pod that says
// nothing.
const defaultTerminationLog = "/dev/termination-log"

// checkTerminationLog requires the container's termination message file somewhere the
// guest cannot write. The kubelet bind-mounts that file from the node's disk, mode 0666,
// so at the default any user in the container can append to the node's disk for as long
// as the run lasts (measured 2026-10-17: 64 MiB in a quarter of a second). The path must
// be set, absolute and clean, not the default, and outside /tmp, /dev and every volume.
// That the directory holding it is closed to the guest (/root, mode 0700 in the image) is
// what the smoke test's write sweep proves; this check holds every pod to the same path,
// a warm pod made from an older template included.
func checkTerminationLog(c container) error {
	p := c.TerminationMessagePath
	if p == "" || p == defaultTerminationLog {
		return fmt.Errorf("terminationMessagePath is %q: the kubelet mounts that file from the node's disk, writable by every user in the container; set one in a directory the guest cannot reach, such as /root/termination-log", p)
	}
	if !path.IsAbs(p) || path.Clean(p) != p {
		return fmt.Errorf("terminationMessagePath %q is not a clean absolute path", p)
	}
	roots := []string{"/tmp", "/dev"}
	for _, m := range c.VolumeMounts {
		roots = append(roots, m.MountPath)
	}
	for _, r := range roots {
		if p == r || strings.HasPrefix(p, strings.TrimSuffix(r, "/")+"/") {
			return fmt.Errorf("terminationMessagePath %q is inside %s, where the guest can write", p, r)
		}
	}
	return nil
}

// sandboxdFlag is the one form a sandboxd argument may take: --name=value (or -name=value).
// sandboxd parses its arguments with Go's flag package, which stops at "--" or at the
// first argument that is not a flag, and lets a flag given without "=" take the next
// argument as its value; any of those would make sandboxd read other flags than this check
// does, an --auth-token-sha256 it never applies among them.
var sandboxdFlag = regexp.MustCompile(`^--?[A-Za-z][A-Za-z0-9_.-]*=`)

// sandboxdFlagsCommit is the agent-sandbox commit whose sandboxd sandboxdFlags was read
// from: docker/agentsandbox.Dockerfile's AGENT_SANDBOX_COMMIT, which a test holds it to.
const sandboxdFlagsCommit = "807cc37107bd7c012115afac9fa9c3b77b8365c2"

// sandboxdFlags is every flag that sandboxd takes, as its own -h listed them (2026-11-24,
// the image built from sandboxdFlagsCommit): its own flags, controller-runtime's zap
// logging flags and its kubeconfig flag. An argument naming any other is refused, so a
// flag a later sandboxd adds (one that loosens its token check, say) cannot pass the
// read-back unread. The TLS terminator (docker/sandboxdtls) keeps the same list, and a
// test holds the two lists and the pin together.
var sandboxdFlags = map[string]bool{
	"auth-token-file": true, "auth-token-sha256": true, "grpc-port": true, "http-idle-timeout": true,
	"kubeconfig": true, "listen-host": true, "metadata-env-prefix": true, "rest-port": true,
	"root-dir": true, "shutdown-timeout": true, "stream-chunk-size": true, "version": true,
	"zap-devel": true, "zap-encoder": true, "zap-log-level": true, "zap-stacktrace-level": true,
	"zap-time-encoding": true,
}

// checkSandboxdArgs requires sandboxd to check plimsoll's token: exactly one
// --auth-token-sha256=<hex> naming this token's digest, and no token file, whose content
// the read-back cannot see. Without a token, guest code could call the root sandboxd on
// loopback and run a command as root, undoing the uid drop. sandboxd must also listen on
// loopback alone, at the port the pod's TLS terminator forwards to: exactly one
// --listen-host=127.0.0.1 and one --grpc-port=9091, the terminator's own rule, so the
// only way to sandboxd from outside the pod is the pinned TLS channel. Every argument is a
// --name=value flag the pinned sandboxd takes (sandboxdFlags).
func (p *Provider) checkSandboxdArgs(argv []string) error {
	for _, a := range argv {
		if !sandboxdFlag.MatchString(a) {
			return fmt.Errorf("sandboxd's argument %q is not a --name=value flag, so sandboxd could read its flags otherwise than plimsoll does", a)
		}
		name, _, _ := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(a, "-"), "-"), "=")
		if !sandboxdFlags[name] {
			return fmt.Errorf("sandboxd is started with --%s, a flag the pinned sandboxd does not take, so plimsoll cannot say what it does", name)
		}
	}
	want := "--auth-token-sha256=" + p.tokenDigest
	found, listen, port := 0, 0, 0
	for _, a := range argv {
		name, value, _ := strings.Cut(a, "=")
		switch strings.TrimPrefix(name, "-") {
		case "-auth-token-sha256", "auth-token-sha256":
			if a != want && !(name == "-auth-token-sha256" && a[1:] == want[2:]) {
				return errors.New("sandboxd checks another token than plimsoll's")
			}
			found++
		case "-auth-token-file", "auth-token-file":
			return errors.New("sandboxd reads its token from a file; plimsoll requires --auth-token-sha256")
		case "-listen-host", "listen-host":
			if value != loopbackHost {
				return fmt.Errorf("sandboxd listens on %q; it must listen on %s alone, behind the TLS terminator", value, loopbackHost)
			}
			listen++
		case "-grpc-port", "grpc-port":
			if value != strconv.Itoa(sandboxdPort) {
				return fmt.Errorf("sandboxd's gRPC port is %q, not %d, where the TLS terminator forwards", value, sandboxdPort)
			}
			port++
		}
	}
	switch {
	case found != 1:
		return fmt.Errorf("sandboxd is started with %d --auth-token-sha256 arguments, want one", found)
	case listen != 1 || port != 1:
		return fmt.Errorf("sandboxd needs exactly one --listen-host=%s and one --grpc-port=%d (got %d and %d), so it is reached only through the TLS terminator", loopbackHost, sandboxdPort, listen, port)
	}
	return nil
}

// checkNetworkPolicies checks every network policy in the pod's namespace that selects
// it. Policies are additive, so it is not enough that the template's own policy denies
// egress: none of them may allow any, at least one must deny it, and ingress must be
// limited to sandboxd's gRPC port from named sources. It sees only Kubernetes
// NetworkPolicy objects: a cluster-scoped admin policy or a network plugin's own kinds
// can allow traffic too, which only the behavioural boundary test catches.
func (p *Provider) checkNetworkPolicies(labels map[string]string, policies []networkPolicy) error {
	egressDenied, ingressLimited := false, false
	for _, np := range policies {
		selects, err := np.Spec.PodSelector.matches(labels)
		if err != nil {
			return fmt.Errorf("network policy %s: %w", np.Meta.Name, err)
		}
		if !selects {
			continue
		}
		types := np.Spec.PolicyTypes
		if len(types) == 0 { // the API server's default
			types = []string{"Ingress"}
			if len(np.Spec.Egress) > 0 {
				types = append(types, "Egress")
			}
		}
		if len(np.Spec.Egress) > 0 {
			return fmt.Errorf("network policy %s allows egress", np.Meta.Name)
		}
		egressDenied = egressDenied || slices.Contains(types, "Egress")
		ingressLimited = ingressLimited || slices.Contains(types, "Ingress")
		for _, r := range np.Spec.Ingress {
			if err := p.checkIngressRule(r); err != nil {
				return fmt.Errorf("network policy %s: %w", np.Meta.Name, err)
			}
		}
	}
	switch {
	case !egressDenied:
		return errors.New("no network policy denies the pod's egress")
	case !ingressLimited:
		return errors.New("no network policy limits the pod's ingress")
	}
	return nil
}

func (p *Provider) checkIngressRule(r ingressRule) error {
	if len(r.From) == 0 {
		return errors.New("an ingress rule admits every source")
	}
	for _, raw := range r.From {
		// A source is named when it is an address block narrower than everything, a
		// pod selector with a term, or a namespace selector with a term: 0.0.0.0/0, {}
		// and {} each admit every pod, and used to pass as "named" (review, 2026-10-26).
		var peer struct {
			IPBlock *struct {
				CIDR string `json:"cidr"`
			} `json:"ipBlock"`
			PodSelector       *labelSelector `json:"podSelector"`
			NamespaceSelector *labelSelector `json:"namespaceSelector"`
		}
		if err := json.Unmarshal(raw, &peer); err != nil {
			return fmt.Errorf("an ingress rule's source cannot be read: %w", err)
		}
		named := peer.IPBlock != nil && !strings.HasSuffix(strings.TrimSpace(peer.IPBlock.CIDR), "/0") ||
			peer.PodSelector != nil && !peer.PodSelector.empty() ||
			peer.NamespaceSelector != nil && !peer.NamespaceSelector.empty()
		if !named {
			return errors.New("an ingress rule's source admits every address, pod or namespace; a source must be named")
		}
	}
	if len(r.Ports) != 1 || r.Ports[0].EndPort != nil || (r.Ports[0].Protocol != "" && r.Ports[0].Protocol != "TCP") {
		return fmt.Errorf("an ingress rule admits other ports than TCP %d", frontPort)
	}
	var port int
	if err := json.Unmarshal(r.Ports[0].Port, &port); err != nil || port != frontPort {
		return fmt.Errorf("an ingress rule admits port %s, not %d", r.Ports[0].Port, frontPort)
	}
	return nil
}

// empty reports a selector with no term, which selects every pod or namespace.
func (s labelSelector) empty() bool { return len(s.MatchLabels) == 0 && len(s.MatchExpressions) == 0 }

// matches reports whether the selector selects a pod with these labels, as the API server
// reads one: every matchLabels pair and every expression must hold, and an empty selector
// selects every pod. An operator it does not know is an error rather than a guess.
func (sel labelSelector) matches(labels map[string]string) (bool, error) {
	for k, v := range sel.MatchLabels {
		if got, ok := labels[k]; !ok || got != v {
			return false, nil
		}
	}
	for _, e := range sel.MatchExpressions {
		v, ok := labels[e.Key]
		switch e.Operator {
		case "In":
			if !ok || !slices.Contains(e.Values, v) {
				return false, nil
			}
		case "NotIn":
			if ok && slices.Contains(e.Values, v) {
				return false, nil
			}
		case "Exists":
			if !ok {
				return false, nil
			}
		case "DoesNotExist":
			if ok {
				return false, nil
			}
		default:
			return false, fmt.Errorf("selector operator %q", e.Operator)
		}
	}
	return true, nil
}

// podIP returns the pod's IP when the claim and the pod agree on it.
func podIP(c claim, pd pod) (string, error) {
	ip := net.ParseIP(pd.Status.PodIP)
	if ip == nil || len(c.Status.Sandbox.PodIPs) == 0 || c.Status.Sandbox.PodIPs[0] != pd.Status.PodIP {
		return "", fmt.Errorf("the pod's IP %q is not the claim's %v", pd.Status.PodIP, c.Status.Sandbox.PodIPs)
	}
	return ip.String(), nil
}

// memoryBytes parses a Kubernetes memory quantity in the forms a template writes: an
// integer with an optional Ki, Mi, Gi, k, M or G suffix.
func memoryBytes(q string) (int64, error) {
	mult := int64(1)
	for _, s := range []struct {
		suffix string
		mult   int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}, {"k", 1e3}, {"M", 1e6}, {"G", 1e9}} {
		if strings.HasSuffix(q, s.suffix) {
			q, mult = strings.TrimSuffix(q, s.suffix), s.mult
			break
		}
	}
	n, err := strconv.ParseInt(q, 10, 64)
	if err != nil || n <= 0 || n > math.MaxInt64/mult {
		return 0, fmt.Errorf("memory quantity %q", q)
	}
	return n * mult, nil
}

// milliCPU parses a CPU quantity: an integer or decimal number of CPUs, or millicores
// with an m suffix.
func milliCPU(q string) (int64, error) {
	if m, ok := strings.CutSuffix(q, "m"); ok {
		n, err := strconv.ParseInt(m, 10, 64)
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("CPU quantity %q", q)
		}
		return n, nil
	}
	f, err := strconv.ParseFloat(q, 64)
	if err != nil || f <= 0 || f > 1e6 || math.Round(f*1000) != f*1000 {
		return 0, fmt.Errorf("CPU quantity %q", q)
	}
	return int64(f * 1000), nil
}
