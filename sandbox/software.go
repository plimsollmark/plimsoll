package sandbox

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SoftwareMode is a caller's explicit rule for the software selected to run.
type SoftwareMode string

const (
	SoftwareExact    SoftwareMode = "exact"
	SoftwareApproved SoftwareMode = "approved"
)

// SoftwareRule is an exact image pin or a set of approved image identities.
// The zero value imposes no software rule. Identities include their kind and
// platform, for example oci-manifest:linux/amd64@sha256:<digest>.
type SoftwareRule struct {
	Mode       SoftwareMode
	Identities []string
}

var ErrSoftwareMismatch = errors.New("selected software does not meet the request's rule")

// Validate refuses malformed rules before any code is dispatched.
func (r SoftwareRule) Validate() error {
	if r.Mode == "" && len(r.Identities) == 0 {
		return nil
	}
	if (r.Mode != SoftwareExact && r.Mode != SoftwareApproved) || len(r.Identities) == 0 || len(r.Identities) > 32 ||
		(r.Mode == SoftwareExact && len(r.Identities) != 1) {
		return NotDispatched(RefusalRequest, fmt.Errorf("%w: software rule needs exact with one identity or approved with 1 to 32 identities", ErrInvalidRequest))
	}
	seen := make(map[string]bool, len(r.Identities))
	for _, id := range r.Identities {
		if len(id) == 0 || len(id) > 256 || seen[id] {
			return NotDispatched(RefusalRequest, fmt.Errorf("%w: software identity is empty, too long or duplicated", ErrInvalidRequest))
		}
		for _, c := range id {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("._:/@+-", c)) {
				return NotDispatched(RefusalRequest, fmt.Errorf("%w: software identity contains an invalid character", ErrInvalidRequest))
			}
		}
		seen[id] = true
	}
	return nil
}

// Allows reports whether the selected software satisfies this rule. An empty
// identity never satisfies a required rule.
func (r SoftwareRule) Allows(identity string) bool {
	if r.Mode == "" {
		return true
	}
	return identity != "" && slices.Contains(r.Identities, identity)
}

// Check fails closed before dispatch when the chosen software is unknown or
// outside the rule. Another backend may meet the same rule.
func (r SoftwareRule) Check(identity string) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if !r.Allows(identity) {
		return NotDispatched(RefusalEnvironment, fmt.Errorf("%w: selected identity %q", ErrSoftwareMismatch, identity))
	}
	return nil
}

// ID is the stable, compact description put in a run record. The full list is
// bound by the request digest; the approved set's ID is order-independent. A rule
// with one identity allows exactly that identity whatever its mode, so it has the
// exact rule's ID: MergeSoftwareRules narrows a one-identity intersection to exact,
// and a session call's rule must keep the ID of the rule it was opened with.
func (r SoftwareRule) ID() string {
	if r.Mode == "" {
		return ""
	}
	if len(r.Identities) == 1 {
		return "exact:" + r.Identities[0]
	}
	ids := slices.Clone(r.Identities)
	slices.Sort(ids)
	sum := sha256.Sum256([]byte(strings.Join(ids, "\x00")))
	return "approved:sha256:" + hex.EncodeToString(sum[:])
}

// MergeSoftwareRules applies both a payload rule and a placement rule. Neither
// caller restriction can be weakened; an empty intersection is invalid.
func MergeSoftwareRules(a, b SoftwareRule) (SoftwareRule, error) {
	if err := a.Validate(); err != nil {
		return SoftwareRule{}, err
	}
	if err := b.Validate(); err != nil {
		return SoftwareRule{}, err
	}
	if a.Mode == "" {
		return b, nil
	}
	if b.Mode == "" {
		return a, nil
	}
	var ids []string
	for _, id := range a.Identities {
		if slices.Contains(b.Identities, id) {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return SoftwareRule{}, NotDispatched(RefusalRequest, fmt.Errorf("%w: payload and placement software rules have no common identity", ErrInvalidRequest))
	}
	mode := SoftwareApproved
	if len(ids) == 1 {
		mode = SoftwareExact
	}
	return SoftwareRule{Mode: mode, Identities: ids}, nil
}
