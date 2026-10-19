package agentsandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"

	"github.com/plimsollmark/plimsoll/sandbox"
)

// podBoundary binds what the startup filesystem proof depends on. The generic
// read-back separately fixes DNS, namespace access, credentials and resource limits.
// Scheduling, resource requests, probe defaults and termination-message policy can
// be defaulted by Kubernetes without changing this boundary. Exec handlers and
// unknown fields are still refused by the closed schema and checkPodSpec.
func podBoundary(s podSpec) (string, error) {
	if len(s.Containers) != 1 {
		return "", errors.New("the execution boundary requires one container")
	}
	c := s.Containers[0]
	volumes, err := volumeSizes(s)
	if err != nil {
		return "", err
	}
	mounts := slices.Clone(c.VolumeMounts)
	slices.SortFunc(mounts, func(a, b volumeMount) int {
		if a.MountPath < b.MountPath {
			return -1
		}
		if a.MountPath > b.MountPath {
			return 1
		}
		return 0
	})
	sc := c.SecurityContext
	if sc != nil {
		copy := *sc
		if sc.Capabilities != nil {
			caps := *sc.Capabilities
			caps.Add, caps.Drop = slices.Clone(caps.Add), slices.Clone(caps.Drop)
			slices.Sort(caps.Add)
			slices.Sort(caps.Drop)
			copy.Capabilities = &caps
		}
		sc = &copy
	}
	var podSeccomp *seccompProfile
	if s.SecurityContext != nil {
		podSeccomp = s.SecurityContext.SeccompProfile
	}
	raw, err := json.Marshal(struct {
		Image                  string
		Command, Args          []string `json:",omitempty"`
		SecurityContext        *securityContext
		PodSeccomp             *seccompProfile
		Volumes                map[string]int64
		Mounts                 []volumeMount
		TerminationMessagePath string
	}{c.Image, c.Command, c.Args, sc, podSeccomp, volumes, mounts, c.TerminationMessagePath})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func podMounts(s podSpec) (map[string]int64, error) {
	sizes, err := volumeSizes(s)
	if err != nil {
		return nil, err
	}
	if len(s.Containers) != 1 {
		return nil, errors.New("the execution boundary requires one container")
	}
	mounts := map[string]int64{}
	for _, m := range s.Containers[0].VolumeMounts {
		size, ok := sizes[m.Name]
		if !ok {
			return nil, fmt.Errorf("volume %s is mounted but not declared", m.Name)
		}
		mounts[m.MountPath] = size
	}
	return mounts, nil
}

func (p *Provider) checkPodBoundary(s podSpec) error {
	sum, err := podBoundary(s)
	if err != nil {
		return err
	}
	p.mu.Lock()
	want := p.boundarySum
	p.mu.Unlock()
	if want == "" || sum != want {
		return errors.New("the actual pod's execution boundary differs from the checked template")
	}
	return nil
}

// Every accepted pod uses the first pod's content digest, including the two startup
// smoke-test claims. A mutable tag cannot substitute another image after that proof.
func (p *Provider) checkPodImage(digest string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.podImage == "" {
		p.podImage = digest
	}
	if p.podImage != digest {
		return errors.New("the actual pod's image differs from the first checked pod; restart to prove the new image")
	}
	return nil
}

// checkPodMounts checks the visible boundary at each tier. gVisor presents
// Kubernetes' host-backed memory volumes as 9p shares, hiding their backing type;
// their memory declaration and limits are bound to the startup-tested template.
// All tiers still refuse a mount nested beneath an actual writable root.
func checkPodMounts(tier sandbox.IsolationClass, mounts, roots []string) error {
	allowed := []string{"tmpfs"}
	if tier == sandbox.IsolationKernel {
		allowed = append(allowed, "9p")
	}
	return errors.Join(checkNestedMounts(mounts, roots), checkRootMountKinds(mounts, roots, allowed))
}
