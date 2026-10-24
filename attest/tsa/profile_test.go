package tsa

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestTimestampProfileConstraints(t *testing.T) {
	if err := checkTimeStampingPurpose(&x509.Certificate{
		Extensions:  []pkix.Extension{{Id: oidExtKeyUsage, Critical: true}},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping, x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Fatal("accepted multi-purpose certificate")
	}
	sha256ID := pkix.AlgorithmIdentifier{Algorithm: oidSHA256, Parameters: asn1.NullRawValue}
	for _, sig := range []pkix.AlgorithmIdentifier{
		{Algorithm: oidRSAPSS}, {Algorithm: oidECPublicKey}, {Algorithm: oidEd25519},
		{Algorithm: oidRSASHA384},
		{Algorithm: oidECDSASHA256, Parameters: asn1.RawValue{FullBytes: []byte{4, 1, 0}}},
	} {
		if _, _, err := signatureAlgorithm(sig, sha256ID); err == nil {
			t.Fatalf("accepted algorithm %v", sig)
		}
	}
	for _, a := range []accuracy{{Seconds: -1}, {Seconds: 1 << 40}, {Millis: 1000}, {Micros: -1}} {
		info := tstInfo{Version: 1, Policy: oidTSTInfo, MessageImprint: messageImprint{HashAlgorithm: sha256ID, HashedMessage: make([]byte, 32)}, SerialNumber: big.NewInt(1), GenTime: time.Now().UTC(), Accuracy: a}
		der, err := asn1.Marshal(info)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseTSTInfo(der); err == nil {
			t.Fatalf("accepted accuracy %+v", a)
		}
	}
	info := tstInfo{Version: 1, Policy: oidTSTInfo, MessageImprint: messageImprint{HashAlgorithm: sha256ID, HashedMessage: make([]byte, 32)}, SerialNumber: big.NewInt(1), GenTime: time.Now().UTC(), Extensions: []pkix.Extension{{Id: oidTSTInfo, Critical: true, Value: []byte{0}}}}
	der, err := asn1.Marshal(info)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseTSTInfo(der); err == nil {
		t.Fatal("accepted unknown critical extension")
	}
}
