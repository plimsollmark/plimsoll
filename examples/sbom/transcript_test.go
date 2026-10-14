package main

import (
	"bytes"
	"testing"
)

func TestTranscriptPairUsesHeadersAndRefusesUnknownPair(t *testing.T) {
	runs, _, _ := fixtures(t)
	raw := []byte("# record: " + runs[0].Record.SHA256 + "\n# step: " + runs[0].Response.GetProject().GetSteps()[0].GetCommand() + "\nunsigned comparison\n")
	id, command, err := transcriptPair(raw, runs)
	if err != nil || id != runs[0].Record.SHA256 || command == "" {
		t.Fatalf("pair: %s %s %v", id, command, err)
	}
	for _, changed := range [][]byte{bytes.Replace(raw, []byte(id), []byte(changeHex(id)), 1), bytes.Replace(raw, []byte(command), []byte("unknown"), 1), []byte("no headers")} {
		if _, _, err := transcriptPair(changed, runs); err == nil {
			t.Fatal("unknown pair accepted")
		}
	}
}
