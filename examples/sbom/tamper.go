package main

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// Change the first byte of the first subject's digest, keeping all other signed
// bytes and JSON syntax intact. The location is selected by the statement field.
func changeSubjectByte(raw []byte) ([]byte, int, error) {
	var s struct {
		Subject []struct {
			Digest map[string]string `json:"digest"`
		} `json:"subject"`
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, 0, err
	}
	if len(s.Subject) != 1 || len(s.Subject[0].Digest["sha256"]) != 64 {
		return nil, 0, fmt.Errorf("expected one SHA-256 subject")
	}
	needle, _ := json.Marshal(s.Subject[0].Digest["sha256"])
	at := bytes.Index(raw, needle)
	if at < 0 {
		return nil, 0, fmt.Errorf("subject digest not found")
	}
	at++ // the first character inside the quoted digest
	changed := bytes.Clone(raw)
	changed[at] = changeHex(string(changed[at : at+1]))[0]
	return changed, at, nil
}
