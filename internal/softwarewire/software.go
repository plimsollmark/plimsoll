// Package softwarewire maps the transport-neutral software admission rule to
// its wire form without changing its meaning.
package softwarewire

import (
	"slices"

	plimsollv1 "github.com/plimsollmark/plimsoll/gen/go/plimsoll/v1"
	"github.com/plimsollmark/plimsoll/sandbox"
)

func ToWire(r sandbox.SoftwareRule) *plimsollv1.SoftwareRule {
	if r.Mode == "" && len(r.Identities) == 0 {
		return nil
	}
	return &plimsollv1.SoftwareRule{Mode: string(r.Mode), Identities: slices.Clone(r.Identities)}
}

func FromWire(r *plimsollv1.SoftwareRule) sandbox.SoftwareRule {
	if r == nil {
		return sandbox.SoftwareRule{}
	}
	return sandbox.SoftwareRule{Mode: sandbox.SoftwareMode(r.GetMode()), Identities: slices.Clone(r.GetIdentities())}
}
