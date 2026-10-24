package tsa

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// Request is a time-stamp request over a SHA-256 digest.
type Request struct {
	Digest []byte
	// Nonce is the request's random nonce, which the token must echo; nil when the
	// request carries none.
	Nonce *big.Int
	// CertReq is whether the request asks the authority to include its certificate.
	CertReq bool
	// DER is the encoded request, what is sent.
	DER []byte
}

// timeStampReq is RFC 3161's TimeStampReq without extensions.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	ReqPolicy      asn1.ObjectIdentifier `asn1:"optional"`
	Nonce          *big.Int              `asn1:"optional"`
	CertReq        bool                  `asn1:"optional"`
}

// NewRequest builds a request over digest, a SHA-256, with a fresh 128-bit nonce, asking
// the authority to include its certificate.
func NewRequest(digest []byte) (Request, error) {
	if len(digest) != sha256.Size {
		return Request{}, fmt.Errorf("tsa: the digest is %d bytes, want a SHA-256", len(digest))
	}
	var nb [16]byte
	if _, err := io.ReadFull(rand.Reader, nb[:]); err != nil {
		return Request{}, err
	}
	nonce := new(big.Int).SetBytes(nb[:])
	der, err := asn1.Marshal(timeStampReq{
		Version:        1,
		MessageImprint: messageImprint{HashAlgorithm: pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}, HashedMessage: digest},
		Nonce:          nonce,
		CertReq:        true,
	})
	if err != nil {
		return Request{}, err
	}
	return Request{Digest: bytes.Clone(digest), Nonce: nonce, CertReq: true, DER: der}, nil
}

// ParseRequest reads an encoded request whose imprint is a SHA-256.
func ParseRequest(der []byte) (Request, error) {
	var req timeStampReq
	rest, err := asn1.Unmarshal(der, &req)
	if err != nil {
		return Request{}, fmt.Errorf("tsa: the request: %w", err)
	}
	if len(rest) != 0 {
		return Request{}, errors.New("tsa: data after the request")
	}
	if req.Version != 1 {
		return Request{}, fmt.Errorf("tsa: request version %d, want 1", req.Version)
	}
	if !req.MessageImprint.HashAlgorithm.Algorithm.Equal(oidSHA256) || len(req.MessageImprint.HashedMessage) != sha256.Size {
		return Request{}, errors.New("tsa: the request's imprint is not a SHA-256")
	}
	return Request{Digest: req.MessageImprint.HashedMessage, Nonce: req.Nonce, CertReq: req.CertReq, DER: der}, nil
}
