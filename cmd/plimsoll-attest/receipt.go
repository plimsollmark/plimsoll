package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/plimsollmark/plimsoll/attest/receipt"
	"github.com/plimsollmark/plimsoll/internal/printable"
)

func verifyReceipt(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("verify-receipt", flag.ContinueOnError)
	policyPath := fs.String("policy", "", "independently trusted role keys, subject and timestamp roots")
	artifactPath := fs.String("artifact", "", "artifact file whose SHA-256 must match the expected subject")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *policyPath == "" || *artifactPath == "" || fs.NArg() != 1 {
		return errors.New("verify-receipt needs -policy TRUSTED_POLICY.json -artifact FILE RECEIPT.json")
	}
	policy, err := readReceiptInput(*policyPath)
	if err != nil {
		return err
	}
	evidence, err := readReceiptInput(fs.Arg(0))
	if err != nil {
		return err
	}
	report, err := receipt.Verify(evidence, policy)
	if err != nil {
		return err
	}
	artifact, err := os.Open(*artifactPath)
	if err != nil {
		return err
	}
	defer artifact.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, artifact); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != report.Subject.Digest["sha256"] {
		return errors.New("artifact bytes do not match the policy's expected SHA-256 digest")
	}
	// The report holds the receipt's own strings: their characters that could rewrite a
	// terminal are written as JSON escapes, which read as the same value (the security scan of 2026-11-20, F8 and F11).
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	_, err = stdout.Write(printable.JSON(append(data, '\n')))
	return err
}

func readReceiptInput(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, receipt.MaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(b) > receipt.MaxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes, the most a receipt or policy may be", path, receipt.MaxBytes)
	}
	return b, nil
}
