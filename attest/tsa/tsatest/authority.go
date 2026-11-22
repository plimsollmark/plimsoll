// Package tsatest is a time-stamp authority for tests: a root and a time-stamping
// certificate made when it is built, a clock the test sets, and a token for any request,
// so no test needs the network or a real authority. Its encoder is written independently
// of the verifier's decoder, so a token it issues is a check on both.
package tsatest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/plimsollmark/plimsoll/attest/tsa"
)

var (
	oidSHA256            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384            = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidAttrContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningCertV2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidECDSASHA256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidTimeStamping      = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}
	oidExtKeyUsage       = asn1.ObjectIdentifier{2, 5, 29, 37}
	// Policy is the policy every test token states.
	Policy = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 3161, 1}
)

// Authority is the test authority.
type Authority struct {
	Root    *x509.Certificate
	RootPEM []byte
	Signer  *x509.Certificate
	key     *ecdsa.PrivateKey
	// Now is the authority's clock; tests set it to issue tokens at chosen times.
	Now func() time.Time

	flaw Flaw

	mu     sync.Mutex
	serial int64
}

// Option changes how New builds the authority.
type Option func(*options)

type options struct {
	noPurpose, nonCritical bool
	flaw                   Flaw
}

// WithoutTimeStampingPurpose issues the signing certificate with no extended key usage,
// which a verifier must refuse.
func WithoutTimeStampingPurpose() Option { return func(o *options) { o.noPurpose = true } }

// WithNonCriticalPurpose issues the signing certificate with its time-stamping extended
// key usage not marked critical, which RFC 3161 section 2.3 requires and a verifier must
// refuse.
func WithNonCriticalPurpose() Option { return func(o *options) { o.nonCritical = true } }

// Flaw is one defect every token of an authority is issued with. Each is one a verifier
// must refuse, though the token is signed over it.
type Flaw int

const (
	// NoFlaw issues ordinary tokens.
	NoFlaw Flaw = iota
	// NoSigningCertificate leaves the signing-certificate attribute out.
	NoSigningCertificate
	// WrongSigningCertificate names the root's certificate in the signing-certificate
	// attribute instead of the signer's.
	WrongSigningCertificate
	// NonceBeforeAccuracy writes the TSTInfo's nonce before its accuracy, out of RFC
	// 3161's order.
	NonceBeforeAccuracy
	// TwoDigestAlgorithms declares SHA-384 beside the signer's SHA-256 in the SignedData.
	TwoDigestAlgorithms
	// SignerVersionThree states SignerInfo version 3, which RFC 5652 reserves for a
	// key-identifier signer, beside an issuer-and-serial identifier.
	SignerVersionThree
)

// WithFlaw issues every token with flaw f.
func WithFlaw(f Flaw) Option { return func(o *options) { o.flaw = f } }

// New builds an authority whose certificates are valid from 2000 to 2100.
func New(t testing.TB, opts ...Option) *Authority {
	t.Helper()
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	notBefore, notAfter := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2100, 1, 1, 0, 0, 0, 0, time.UTC)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tsatest root"},
		NotBefore: notBefore, NotAfter: notAfter,
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "tsatest time-stamping"},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if !o.noPurpose {
		eku, err := asn1.Marshal([]asn1.ObjectIdentifier{oidTimeStamping})
		if err != nil {
			t.Fatal(err)
		}
		template.ExtraExtensions = []pkix.Extension{{Id: oidExtKeyUsage, Critical: !o.nonCritical, Value: eku}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &Authority{
		Root: root, RootPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}),
		Signer: signer, key: key, Now: time.Now, flaw: o.flaw,
	}
}

// Respond answers an encoded request with a granted token at Now, with the next serial
// number and an accuracy of one second.
func (a *Authority) Respond(requestDER []byte) ([]byte, error) {
	req, err := tsa.ParseRequest(requestDER)
	if err != nil {
		return nil, err
	}
	a.mu.Lock()
	a.serial++
	serial := a.serial
	a.mu.Unlock()
	return a.Issue(req.Digest, req.Nonce, big.NewInt(serial), a.Now().UTC().Truncate(time.Second))
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

type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Accuracy       accuracy  `asn1:"optional"`
	Nonce          *big.Int  `asn1:"optional"`
}

// tstInfoNonceFirst is tstInfo with the nonce before the accuracy (NonceBeforeAccuracy).
type tstInfoNonceFirst struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time `asn1:"generalized"`
	Nonce          *big.Int  `asn1:"optional"`
	Accuracy       accuracy  `asn1:"optional"`
}

type attribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

type issuerAndSerial struct {
	Issuer asn1.RawValue
	Serial *big.Int
}

type signerInfo struct {
	Version            int
	SID                issuerAndSerial
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type encapsulated struct {
	Type    asn1.ObjectIdentifier
	Content []byte `asn1:"tag:0,explicit"`
}

type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapsulated
	Certificates     asn1.RawValue
	SignerInfos      []signerInfo `asn1:"set"`
}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue
}

type response struct {
	Status struct{ Status int }
	Token  asn1.RawValue
}

func raw(v any) (asn1.RawValue, error) {
	b, err := asn1.Marshal(v)
	return asn1.RawValue{FullBytes: b}, err
}

// Issue encodes and signs a granted token over digest at genTime, echoing nonce when it
// is not nil.
func (a *Authority) Issue(digest []byte, nonce *big.Int, serial *big.Int, genTime time.Time) ([]byte, error) {
	sha256ID := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	info := tstInfo{
		Version: 1, Policy: Policy,
		MessageImprint: messageImprint{HashAlgorithm: sha256ID, HashedMessage: digest},
		SerialNumber:   serial, GenTime: genTime.UTC(), Accuracy: accuracy{Seconds: 1}, Nonce: nonce,
	}
	var tst []byte
	var err error
	if a.flaw == NonceBeforeAccuracy {
		tst, err = asn1.Marshal(tstInfoNonceFirst{Version: info.Version, Policy: info.Policy, MessageImprint: info.MessageImprint,
			SerialNumber: info.SerialNumber, GenTime: info.GenTime, Nonce: info.Nonce, Accuracy: info.Accuracy})
	} else {
		tst, err = asn1.Marshal(info)
	}
	if err != nil {
		return nil, err
	}
	tstDigest := sha256.Sum256(tst)
	certHash := sha256.Sum256(a.Signer.Raw)
	if a.flaw == WrongSigningCertificate {
		certHash = sha256.Sum256(a.Root.Raw)
	}
	contentType, err := raw(oidTSTInfo)
	if err != nil {
		return nil, err
	}
	messageDigest, err := raw(tstDigest[:])
	if err != nil {
		return nil, err
	}
	signingCert, err := raw(struct {
		Certs []struct{ CertHash []byte }
	}{Certs: []struct{ CertHash []byte }{{CertHash: certHash[:]}}})
	if err != nil {
		return nil, err
	}
	attrs := []attribute{
		{Type: oidAttrContentType, Values: []asn1.RawValue{contentType}},
		{Type: oidAttrMessageDigest, Values: []asn1.RawValue{messageDigest}},
	}
	if a.flaw != NoSigningCertificate {
		attrs = append(attrs, attribute{Type: oidAttrSigningCertV2, Values: []asn1.RawValue{signingCert}})
	}
	setDER, err := asn1.MarshalWithParams(attrs, "set")
	if err != nil {
		return nil, err
	}
	var set asn1.RawValue
	if _, err := asn1.Unmarshal(setDER, &set); err != nil {
		return nil, err
	}
	signed := sha256.Sum256(setDER)
	signature, err := ecdsa.SignASN1(rand.Reader, a.key, signed[:])
	if err != nil {
		return nil, err
	}
	digestAlgorithms := []pkix.AlgorithmIdentifier{sha256ID}
	if a.flaw == TwoDigestAlgorithms {
		digestAlgorithms = append(digestAlgorithms, pkix.AlgorithmIdentifier{Algorithm: oidSHA384, Parameters: asn1.NullRawValue})
	}
	signerVersion := 1
	if a.flaw == SignerVersionThree {
		signerVersion = 3
	}
	sd, err := asn1.Marshal(signedData{
		Version:          3,
		DigestAlgorithms: digestAlgorithms,
		EncapContentInfo: encapsulated{Type: oidTSTInfo, Content: tst},
		Certificates:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: a.Signer.Raw},
		SignerInfos: []signerInfo{{
			Version:            signerVersion,
			SID:                issuerAndSerial{Issuer: asn1.RawValue{FullBytes: a.Signer.RawIssuer}, Serial: a.Signer.SerialNumber},
			DigestAlgorithm:    sha256ID,
			SignedAttrs:        asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: set.Bytes},
			SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidECDSASHA256},
			Signature:          signature,
		}},
	})
	if err != nil {
		return nil, err
	}
	ci, err := asn1.Marshal(contentInfo{Type: oidSignedData, Content: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: sd}})
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(response{Token: asn1.RawValue{FullBytes: ci}})
}
