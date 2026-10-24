// Package tsa is a time witness from an RFC 3161 time-stamp authority.
//
// A time witness is a third party's signed statement that a hash existed by a time. The
// requester sends the SHA-256 of some bytes and a random nonce to the authority
// (NewRequest encodes the request); the authority answers
// with a token: a CMS SignedData over a TSTInfo holding the hash, the nonce, its clock's
// time and a serial number, signed under a certificate reserved for time-stamping. Verify
// checks a token offline against roots the caller pins, so a reader years later needs the
// token, the hash and the roots, and nothing from the authority.
//
// What a token proves: the hash existed by the token's time, on the authority's clock.
// What it does not prove: when the bytes were made (any time before), or anything about
// their content (the authority sees only a hash). An authority that colludes with the
// requester, or whose key is compromised, can witness any time. Different certificates
// do not establish independently controlled authorities.
//
// Verify checks, in order: the response says granted; the token is one SignedData over a
// TSTInfo with exactly one signer; the signed attributes name the TSTInfo content type and
// its digest, and the signing-certificate attribute names the signer's certificate (RFC
// 5035 or RFC 2634); the signature verifies under the signer's certificate, which the
// token carries; the TSTInfo's imprint is SHA-256 and equals the digest given, and its
// nonce equals the one given; the signer's certificate chains to one of the pinned roots,
// is valid at the token's own time, and carries the time-stamping purpose as a critical
// extension. Only the standard library is used.
package tsa

import (
	"bytes"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"time"

	_ "crypto/sha1" // the RFC 2634 signing-certificate attribute names the certificate by SHA-1
	_ "crypto/sha512"
)

// MaxResponse caps encoded timestamp responses at 64 KiB before ASN.1 parsing.
// It bounds certificate and attribute processing while accommodating ordinary chains.
const MaxResponse = 64 << 10

var (
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCert   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}

	oidRSA         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidRSASHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidRSASHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidRSASHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidECPublicKey = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSASHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSASHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSASHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519     = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidExtKeyUsage = asn1.ObjectIdentifier{2, 5, 29, 37}
)

// Token is a verified time-stamp token.
type Token struct {
	// Time is the authority's time; Accuracy is how far its clock may be off by its own
	// statement, zero when it states none.
	Time     time.Time
	Accuracy time.Duration
	// Digest is the SHA-256 the token covers; Nonce the request's nonce it echoes, nil when
	// it carries none.
	Digest []byte
	Nonce  *big.Int
	Serial *big.Int
	Policy asn1.ObjectIdentifier
	// Signer is the authority's time-stamping certificate; Root the pinned root it chains
	// to, and RootSHA256 that root's DER digest in lowercase hex.
	Signer     *x509.Certificate
	Root       *x509.Certificate
	RootSHA256 string
}

// Verify checks a time-stamp response offline. digest is the SHA-256 the token must cover;
// nonce, when not nil, is the request's nonce the token must echo; roots are the authority
// roots the caller trusts, and the token's signer must chain to one of them.
func Verify(response, digest []byte, nonce *big.Int, roots []*x509.Certificate) (Token, error) {
	if len(response) > MaxResponse {
		return Token{}, errors.New("tsa: response exceeds 64 KiB")
	}
	if len(roots) == 0 {
		return Token{}, errors.New("tsa: no pinned root")
	}
	for _, root := range roots {
		if root == nil {
			return Token{}, errors.New("tsa: nil pinned root")
		}
	}
	if len(digest) != sha256.Size {
		return Token{}, fmt.Errorf("tsa: the digest is %d bytes, want a SHA-256", len(digest))
	}
	tokenDER, err := grantedToken(response)
	if err != nil {
		return Token{}, err
	}
	sd, err := parseSignedData(tokenDER)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	if !sd.contentType.Equal(oidTSTInfo) || len(sd.content) == 0 {
		return Token{}, errors.New("tsa: the token's content is not a TSTInfo")
	}
	if len(sd.signers) != 1 {
		return Token{}, fmt.Errorf("tsa: %d signers, a token has exactly one", len(sd.signers))
	}
	si := sd.signers[0]
	if len(sd.digests) != 1 || !sd.digests[0].Algorithm.Equal(si.digest.Algorithm) {
		return Token{}, errors.New("tsa: SignedData must declare the signer's one digest algorithm")
	}
	if len(si.signedAttrs.FullBytes) == 0 {
		return Token{}, errors.New("tsa: the signer has no signed attributes")
	}
	setDER, attrs, err := signedAttributes(si.signedAttrs)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: signed attributes: %w", err)
	}
	alg, h, err := signatureAlgorithm(si.sigAlg, si.digest)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	if err := checkAttributes(attrs, sd.content, h); err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	signer, err := signerCertificate(si.sid, sd.certificates)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	if err := checkSigningCertificate(attrs, signer); err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	if err := signer.CheckSignature(alg, setDER, si.signature); err != nil {
		return Token{}, fmt.Errorf("tsa: the signature does not verify under the signer's certificate: %w", err)
	}
	info, err := parseTSTInfo(sd.content)
	if err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	if !info.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) {
		return Token{}, errors.New("tsa: the token's imprint is not a SHA-256")
	}
	if !bytes.Equal(info.MessageImprint.HashedMessage, digest) {
		return Token{}, errors.New("tsa: the token covers another digest")
	}
	if nonce != nil && (info.Nonce == nil || info.Nonce.Cmp(nonce) != 0) {
		return Token{}, errors.New("tsa: the token does not echo the request's nonce")
	}
	if err := checkTimeStampingPurpose(signer); err != nil {
		return Token{}, fmt.Errorf("tsa: %w", err)
	}
	rootPool, interPool := x509.NewCertPool(), x509.NewCertPool()
	for _, r := range roots {
		rootPool.AddCert(r)
	}
	for _, c := range sd.certificates {
		interPool.AddCert(c)
	}
	chains, err := signer.Verify(x509.VerifyOptions{
		Roots: rootPool, Intermediates: interPool, CurrentTime: info.GenTime,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	})
	if err != nil {
		return Token{}, fmt.Errorf("tsa: the signer's certificate does not chain to a pinned root at the token's time: %w", err)
	}
	root := chains[0][len(chains[0])-1]
	return Token{
		Time: info.GenTime, Accuracy: info.Accuracy.duration(), Digest: info.MessageImprint.HashedMessage,
		Nonce: info.Nonce, Serial: info.SerialNumber, Policy: info.Policy,
		Signer: signer, Root: root, RootSHA256: CertSHA256(root),
	}, nil
}

// CertSHA256 is the lowercase hex SHA-256 of a certificate's DER, how a root is pinned.
func CertSHA256(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// ParseRoots reads every CERTIFICATE block of a PEM file.
func ParseRoots(pemBytes []byte) ([]*x509.Certificate, error) {
	var roots []*x509.Certificate
	for rest := pemBytes; ; {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("tsa: roots: %w", err)
		}
		roots = append(roots, c)
	}
	if len(roots) == 0 {
		return nil, errors.New("tsa: roots: no certificate")
	}
	return roots, nil
}

// grantedToken reads a TimeStampResp and returns its token's DER when the status is
// granted or granted with modifications.
func grantedToken(response []byte) ([]byte, error) {
	var resp struct {
		Status asn1.RawValue
		Token  asn1.RawValue `asn1:"optional"`
	}
	rest, err := asn1.Unmarshal(response, &resp)
	if err != nil {
		return nil, fmt.Errorf("tsa: the response is not a TimeStampResp: %w", err)
	}
	if len(rest) != 0 {
		return nil, errors.New("tsa: data after the response")
	}
	var status struct{ Status int }
	if _, err := asn1.Unmarshal(resp.Status.FullBytes, &status); err != nil {
		return nil, fmt.Errorf("tsa: the response's status: %w", err)
	}
	if status.Status != 0 && status.Status != 1 {
		return nil, fmt.Errorf("tsa: the authority did not grant the request (status %d)", status.Status)
	}
	var ci struct {
		ContentType asn1.ObjectIdentifier
		Content     asn1.RawValue `asn1:"tag:0,explicit"`
	}
	rest, err = asn1.Unmarshal(resp.Token.FullBytes, &ci)
	if err != nil || len(rest) != 0 {
		return nil, errors.New("tsa: the token is not a ContentInfo")
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, errors.New("tsa: the token is not a SignedData")
	}
	return ci.Content.Bytes, nil
}

type signedData struct {
	digests      []pkix.AlgorithmIdentifier
	contentType  asn1.ObjectIdentifier
	content      []byte
	certificates []*x509.Certificate
	signers      []signerInfo
}

type signerInfo struct {
	sid         asn1.RawValue
	digest      pkix.AlgorithmIdentifier
	signedAttrs asn1.RawValue
	sigAlg      pkix.AlgorithmIdentifier
	signature   []byte
}

// element reads the next DER element of b.
func element(b []byte) (asn1.RawValue, []byte, error) {
	var rv asn1.RawValue
	rest, err := asn1.Unmarshal(b, &rv)
	return rv, rest, err
}

func universal(rv asn1.RawValue, tag int) bool {
	return rv.Class == asn1.ClassUniversal && rv.Tag == tag && rv.IsCompound
}

// parseSignedData reads a CMS SignedData element by element: the fields after the content
// are optional and tagged, which encoding/asn1 cannot parse into a struct (a RawValue field
// takes whatever element comes next).
func parseSignedData(der []byte) (signedData, error) {
	var sd signedData
	seq, rest, err := element(der)
	if err != nil || len(rest) != 0 || !universal(seq, asn1.TagSequence) {
		return sd, errors.New("SignedData is not one sequence")
	}
	b := seq.Bytes
	var version int
	if b, err = asn1.Unmarshal(b, &version); err != nil {
		return sd, fmt.Errorf("SignedData version: %w", err)
	}
	if version != 3 {
		return sd, errors.New("SignedData version must be 3 for TSTInfo")
	}
	var algorithms []pkix.AlgorithmIdentifier
	if b, err = asn1.UnmarshalWithParams(b, &algorithms, "set"); err != nil {
		return sd, fmt.Errorf("SignedData digest algorithms: %w", err)
	}
	sd.digests = algorithms
	var eci struct {
		Type    asn1.ObjectIdentifier
		Content []byte `asn1:"tag:0,explicit,optional"`
	}
	if b, err = asn1.Unmarshal(b, &eci); err != nil {
		return sd, fmt.Errorf("SignedData content: %w", err)
	}
	sd.contentType, sd.content = eci.Type, eci.Content
	lastTag := -1
	for range 2 {
		if len(b) == 0 {
			break
		}
		rv, after, err := element(b)
		if err != nil {
			return sd, fmt.Errorf("SignedData: %w", err)
		}
		if rv.Class != asn1.ClassContextSpecific {
			break
		}
		if !rv.IsCompound || rv.Tag > 1 || rv.Tag <= lastTag {
			return sd, errors.New("invalid or repeated SignedData optional field")
		}
		lastTag = rv.Tag
		if rv.Tag == 0 {
			if sd.certificates, err = x509.ParseCertificates(rv.Bytes); err != nil {
				return sd, fmt.Errorf("SignedData certificates: %w", err)
			}
		}
		b = after // tag 1 is the CRL list, not needed
	}
	set, after, err := element(b)
	if err != nil || len(after) != 0 || !universal(set, asn1.TagSet) {
		return sd, errors.New("SignedData signerInfos is not a set")
	}
	for b := set.Bytes; len(b) > 0; {
		rv, after, err := element(b)
		if err != nil {
			return sd, fmt.Errorf("SignerInfo: %w", err)
		}
		si, err := parseSignerInfo(rv)
		if err != nil {
			return sd, fmt.Errorf("SignerInfo: %w", err)
		}
		sd.signers = append(sd.signers, si)
		b = after
	}
	return sd, nil
}

func parseSignerInfo(seq asn1.RawValue) (signerInfo, error) {
	var si signerInfo
	if !universal(seq, asn1.TagSequence) {
		return si, errors.New("not a sequence")
	}
	b := seq.Bytes
	var version int
	var err error
	if b, err = asn1.Unmarshal(b, &version); err != nil {
		return si, err
	}
	if si.sid, b, err = element(b); err != nil {
		return si, err
	}
	if (universal(si.sid, asn1.TagSequence) && version != 1) ||
		(si.sid.Class == asn1.ClassContextSpecific && si.sid.Tag == 0 && (version != 3 || si.sid.IsCompound)) {
		return si, errors.New("signer version or identifier encoding disagrees")
	}
	if b, err = asn1.Unmarshal(b, &si.digest); err != nil {
		return si, err
	}
	rv, after, err := element(b)
	if err != nil {
		return si, err
	}
	if rv.Class == asn1.ClassContextSpecific && rv.Tag == 0 {
		si.signedAttrs, b = rv, after
	}
	if b, err = asn1.Unmarshal(b, &si.sigAlg); err != nil {
		return si, err
	}
	if b, err = asn1.Unmarshal(b, &si.signature); err != nil {
		return si, err
	}
	if len(b) != 0 {
		// This profile deliberately refuses unsigned attributes.
		return si, errors.New("unsupported data after SignerInfo signature")
	}
	return si, nil
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// signedAttributes re-encodes the [0] IMPLICIT signed attributes as the SET OF they are
// signed as (RFC 5652 section 5.4) and parses them.
func signedAttributes(raw asn1.RawValue) ([]byte, []attribute, error) {
	setDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: raw.Bytes})
	if err != nil {
		return nil, nil, err
	}
	var attrs []attribute
	rest, err := asn1.UnmarshalWithParams(setDER, &attrs, "set")
	if err != nil {
		return nil, nil, err
	}
	if len(rest) != 0 {
		return nil, nil, errors.New("data after the attributes")
	}
	return setDER, attrs, nil
}

// attributeValue is the one value of the one attribute of type oid.
func attributeValue(attrs []attribute, oid asn1.ObjectIdentifier) (asn1.RawValue, bool, error) {
	var found []asn1.RawValue
	for _, a := range attrs {
		if a.Type.Equal(oid) {
			found = append(found, a.Values...)
			if len(a.Values) != 1 {
				return asn1.RawValue{}, true, fmt.Errorf("attribute %v has %d values, want one", oid, len(a.Values))
			}
		}
	}
	switch len(found) {
	case 0:
		return asn1.RawValue{}, false, nil
	case 1:
		return found[0], true, nil
	}
	return asn1.RawValue{}, true, fmt.Errorf("attribute %v appears %d times", oid, len(found))
}

func checkAttributes(attrs []attribute, content []byte, h crypto.Hash) error {
	v, ok, err := attributeValue(attrs, oidAttrContentType)
	if err != nil {
		return err
	}
	var ct asn1.ObjectIdentifier
	if !ok {
		return errors.New("no content-type attribute")
	}
	if _, err := asn1.Unmarshal(v.FullBytes, &ct); err != nil || !ct.Equal(oidTSTInfo) {
		return errors.New("the content-type attribute does not name a TSTInfo")
	}
	v, ok, err = attributeValue(attrs, oidAttrMessageDigest)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("no message-digest attribute")
	}
	var md []byte
	if _, err := asn1.Unmarshal(v.FullBytes, &md); err != nil {
		return errors.New("the message-digest attribute is not an octet string")
	}
	hh := h.New()
	hh.Write(content)
	if !bytes.Equal(md, hh.Sum(nil)) {
		return errors.New("the message-digest attribute is not the digest of the TSTInfo")
	}
	return nil
}

// checkSigningCertificate requires the signing-certificate attribute (RFC 5035, or the
// SHA-1 form of RFC 2634) to name the signer's certificate, as RFC 3161 requires of a
// token.
func checkSigningCertificate(attrs []attribute, signer *x509.Certificate) error {
	if v, ok, err := attributeValue(attrs, oidAttrSigningCertV2); err != nil {
		return err
	} else if ok {
		var sc struct {
			Certs []struct {
				HashAlgorithm pkix.AlgorithmIdentifier `asn1:"optional"`
				CertHash      []byte
			}
		}
		if _, err := asn1.Unmarshal(v.FullBytes, &sc); err != nil || len(sc.Certs) == 0 {
			return errors.New("the signing-certificate-v2 attribute is malformed")
		}
		h := crypto.SHA256
		if sc.Certs[0].HashAlgorithm.Algorithm != nil {
			if h, err = hashOf(sc.Certs[0].HashAlgorithm.Algorithm); err != nil {
				return fmt.Errorf("signing-certificate-v2: %w", err)
			}
		}
		if !bytes.Equal(sc.Certs[0].CertHash, digestWith(h, signer.Raw)) {
			return errors.New("the signing-certificate-v2 attribute names another certificate")
		}
		return nil
	}
	if v, ok, err := attributeValue(attrs, oidAttrSigningCert); err != nil {
		return err
	} else if ok {
		var sc struct {
			Certs []struct{ CertHash []byte }
		}
		if _, err := asn1.Unmarshal(v.FullBytes, &sc); err != nil || len(sc.Certs) == 0 {
			return errors.New("the signing-certificate attribute is malformed")
		}
		if !bytes.Equal(sc.Certs[0].CertHash, digestWith(crypto.SHA1, signer.Raw)) {
			return errors.New("the signing-certificate attribute names another certificate")
		}
		return nil
	}
	return errors.New("no signing-certificate attribute names the signer's certificate")
}

func digestWith(h crypto.Hash, b []byte) []byte {
	hh := h.New()
	hh.Write(b)
	return hh.Sum(nil)
}

// signerCertificate finds the signer among the token's certificates by its
// SignerIdentifier: an issuer and serial number, or a subject key identifier.
func signerCertificate(sid asn1.RawValue, certs []*x509.Certificate) (*x509.Certificate, error) {
	switch {
	case universal(sid, asn1.TagSequence):
		var ias struct {
			Issuer asn1.RawValue
			Serial *big.Int
		}
		if _, err := asn1.Unmarshal(sid.FullBytes, &ias); err != nil {
			return nil, fmt.Errorf("the signer identifier: %w", err)
		}
		for _, c := range certs {
			if bytes.Equal(c.RawIssuer, ias.Issuer.FullBytes) && c.SerialNumber.Cmp(ias.Serial) == 0 {
				return c, nil
			}
		}
	case sid.Class == asn1.ClassContextSpecific && sid.Tag == 0:
		for _, c := range certs {
			if len(c.SubjectKeyId) > 0 && bytes.Equal(c.SubjectKeyId, sid.Bytes) {
				return c, nil
			}
		}
	default:
		return nil, errors.New("the signer identifier is neither an issuer and serial nor a key identifier")
	}
	return nil, errors.New("the token does not carry the signer's certificate")
}

func hashOf(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	}
	return 0, fmt.Errorf("digest algorithm %v is not SHA-256, SHA-384 or SHA-512", oid)
}

// signatureAlgorithm maps the signer's signature and digest algorithms to the x509
// algorithm that checks them, refusing a pair that disagree.
func signatureAlgorithm(sig, digest pkix.AlgorithmIdentifier) (x509.SignatureAlgorithm, crypto.Hash, error) {
	if !nullOrAbsent(digest.Parameters) {
		return 0, 0, errors.New("unsupported digest algorithm parameters")
	}
	if sig.Algorithm.Equal(oidEd25519) {
		if !digest.Algorithm.Equal(oidSHA512) || len(sig.Parameters.FullBytes) != 0 {
			return 0, 0, errors.New("Ed25519 requires SHA-512 and absent signature parameters")
		}
		return x509.PureEd25519, crypto.SHA512, nil
	}
	if sig.Algorithm.Equal(oidRSAPSS) {
		return 0, 0, errors.New("RSA-PSS timestamp parameters are not supported")
	}
	if sig.Algorithm.Equal(oidECPublicKey) || !nullOrAbsent(sig.Parameters) {
		return 0, 0, errors.New("unsupported signature algorithm or parameters")
	}
	h, err := hashOf(digest.Algorithm)
	if err != nil {
		return 0, 0, err
	}
	pick := func(sha256, sha384, sha512 x509.SignatureAlgorithm) x509.SignatureAlgorithm {
		switch h {
		case crypto.SHA384:
			return sha384
		case crypto.SHA512:
			return sha512
		}
		return sha256
	}
	implied := func(want crypto.Hash, alg x509.SignatureAlgorithm) (x509.SignatureAlgorithm, crypto.Hash, error) {
		if h != want {
			return 0, 0, fmt.Errorf("the signature algorithm %v implies %v, the digest algorithm is %v", sig.Algorithm, want, h)
		}
		return alg, h, nil
	}
	a := sig.Algorithm
	switch {
	case a.Equal(oidRSA):
		return pick(x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA), h, nil
	case a.Equal(oidRSASHA256):
		return implied(crypto.SHA256, x509.SHA256WithRSA)
	case a.Equal(oidRSASHA384):
		return implied(crypto.SHA384, x509.SHA384WithRSA)
	case a.Equal(oidRSASHA512):
		return implied(crypto.SHA512, x509.SHA512WithRSA)
	case a.Equal(oidECDSASHA256):
		return implied(crypto.SHA256, x509.ECDSAWithSHA256)
	case a.Equal(oidECDSASHA384):
		return implied(crypto.SHA384, x509.ECDSAWithSHA384)
	case a.Equal(oidECDSASHA512):
		return implied(crypto.SHA512, x509.ECDSAWithSHA512)
	}
	return 0, 0, fmt.Errorf("signature algorithm %v is not supported", a)
}

func nullOrAbsent(v asn1.RawValue) bool {
	return len(v.FullBytes) == 0 || bytes.Equal(v.FullBytes, asn1.NullBytes)
}

// checkTimeStampingPurpose requires the extended key usage extension, marked critical,
// to name time-stamping (RFC 3161 section 2.3); the chain check requires the purpose
// along the chain.
func checkTimeStampingPurpose(signer *x509.Certificate) error {
	for _, e := range signer.Extensions {
		if e.Id.Equal(oidExtKeyUsage) {
			if !e.Critical {
				return errors.New("the signer's extended key usage is not marked critical")
			}
			if len(signer.ExtKeyUsage) == 1 && signer.ExtKeyUsage[0] == x509.ExtKeyUsageTimeStamping && len(signer.UnknownExtKeyUsage) == 0 {
				return nil
			}
			return errors.New("the signer's extended key usage must be exclusively time-stamping")
		}
	}
	return errors.New("the signer's certificate states no extended key usage")
}

type messageImprint struct {
	HashAlgorithm pkix.AlgorithmIdentifier
	HashedMessage []byte
}

type accuracy struct {
	Seconds int `asn1:"optional"`
	Millis  int `asn1:"tag:0,optional"`
	Micros  int `asn1:"tag:1,optional"`
}

func (a accuracy) duration() time.Duration {
	return time.Duration(a.Seconds)*time.Second + time.Duration(a.Millis)*time.Millisecond + time.Duration(a.Micros)*time.Microsecond
}

// tstInfo is RFC 3161's TSTInfo up to the nonce; the optional tsa name and extensions
// that may follow are trailing elements, which encoding/asn1 allows.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time        `asn1:"generalized"`
	Accuracy       accuracy         `asn1:"optional"`
	Ordering       bool             `asn1:"optional"`
	Nonce          *big.Int         `asn1:"optional"`
	TSA            asn1.RawValue    `asn1:"tag:0,optional"`
	Extensions     []pkix.Extension `asn1:"tag:1,optional"`
}

func parseTSTInfo(content []byte) (tstInfo, error) {
	var info tstInfo
	if err := checkTSTFields(content); err != nil {
		return info, err
	}
	rest, err := asn1.Unmarshal(content, &info)
	if err != nil {
		return info, fmt.Errorf("the TSTInfo: %w", err)
	}
	if len(rest) != 0 {
		return info, errors.New("data after the TSTInfo")
	}
	if info.Version != 1 {
		return info, fmt.Errorf("TSTInfo version %d, want 1", info.Version)
	}
	if info.GenTime.IsZero() {
		return info, errors.New("the TSTInfo has no time")
	}
	a := info.Accuracy
	if a.Seconds < 0 || int64(a.Seconds) > (1<<63-1)/int64(time.Second)-1 || a.Millis < 0 || a.Millis > 999 || a.Micros < 0 || a.Micros > 999 {
		return info, errors.New("the TSTInfo accuracy is out of range")
	}
	for _, extension := range info.Extensions {
		if extension.Critical {
			return info, errors.New("unsupported critical TSTInfo extension")
		}
	}
	return info, nil
}

// Check optional field order and refuse trailing fields that encoding/asn1 would
// otherwise ignore when decoding a struct. GeneralName is only an identity hint;
// the signer is authenticated by its ESS certificate identifier and pinned chain.
func checkTSTFields(der []byte) error {
	seq, rest, err := element(der)
	if err != nil || len(rest) != 0 || !universal(seq, asn1.TagSequence) {
		return errors.New("the TSTInfo is not one sequence")
	}
	b := seq.Bytes
	for range 5 {
		_, after, err := element(b)
		if err != nil {
			return err
		}
		b = after
	}
	last := -1
	for len(b) > 0 {
		rv, after, err := element(b)
		if err != nil {
			return err
		}
		index := -1
		switch {
		case universal(rv, asn1.TagSequence):
			index = 0
		case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagBoolean:
			index = 1
		case rv.Class == asn1.ClassUniversal && rv.Tag == asn1.TagInteger:
			index = 2
		case rv.Class == asn1.ClassContextSpecific && rv.Tag == 0:
			index = 3
		case rv.Class == asn1.ClassContextSpecific && rv.Tag == 1:
			index = 4
		}
		if index < 0 || index <= last {
			return errors.New("unsupported or repeated TSTInfo field")
		}
		last, b = index, after
	}
	return nil
}
