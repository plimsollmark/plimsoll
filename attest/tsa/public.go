package tsa

import _ "embed"

// Public are the public time-stamp authorities plimsoll's examples and tools pin: two
// independent operators, so that neither is load-bearing alone. DigiCert's responder
// signs under its Trusted Root G4; FreeTSA is a community-run authority with no legal
// entity behind it, a second witness rather than the only one. Their roots, fetched on
// 2026-10-21 from each operator's own site, are PublicRootsPEM; a token from either must
// chain to the pinned root, so a changed root is refused, not trusted. Each request sends
// one digest and a random nonce, nothing else.
var Public = []Authority{
	{Name: "DigiCert", URL: "http://timestamp.digicert.com", RootSHA256: "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"},
	{Name: "FreeTSA", URL: "https://freetsa.org/tsr", RootSHA256: "a6379e7cecc05faa3cbf076013d745e327bbbaa38c0b9af22469d4701d18aabc"},
}

//go:embed roots/digicert-trusted-root-g4.pem
var digicertRootPEM []byte

//go:embed roots/freetsa-root.pem
var freetsaRootPEM []byte

// PublicRootsPEM holds the roots of Public, in the same order, as PEM.
var PublicRootsPEM = append(append([]byte{}, digicertRootPEM...), freetsaRootPEM...)
