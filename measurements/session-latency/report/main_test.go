package main

import (
	"bytes"
	"os"
	"testing"
)

func TestCommittedPageMatchesData(t *testing.T) {
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir("../../.."); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	})

	var rendered bytes.Buffer
	if err := render(&rendered); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile("docs/measurements/session-latency/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rendered.Bytes(), committed) {
		t.Fatalf("committed session-latency page differs from rendered data (%d rendered bytes, %d committed bytes)", rendered.Len(), len(committed))
	}
}
