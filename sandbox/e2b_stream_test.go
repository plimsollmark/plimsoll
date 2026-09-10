package sandbox

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

// frame builds one Connect stream envelope: [flags:1][len:4 big-endian][payload].
func frame(flags byte, payload []byte) []byte {
	b := make([]byte, 5+len(payload))
	b[0] = flags
	binary.BigEndian.PutUint32(b[1:5], uint32(len(payload)))
	copy(b[5:], payload)
	return b
}

func TestReadConnectStreamNormal(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(0, []byte(`{"a":1}`)))
	buf.Write(frame(0, []byte(`{"b":2}`)))
	buf.Write(frame(0x2, []byte(`{}`))) // end-of-stream, no error

	var msgs []string
	err := readConnectStream(&buf, func(m []byte) error {
		msgs = append(msgs, string(m))
		return nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(msgs) != 2 || msgs[0] != `{"a":1}` || msgs[1] != `{"b":2}` {
		t.Fatalf("messages = %v, want the two data frames (EOS not delivered to fn)", msgs)
	}
}

func TestReadConnectStreamErrorTrailer(t *testing.T) {
	var buf bytes.Buffer
	buf.Write(frame(0, []byte(`{"ok":true}`)))
	buf.Write(frame(0x2, []byte(`{"error":{"code":"internal","message":"boom"}}`)))

	err := readConnectStream(&buf, func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("err = %v, want it to surface the trailer error", err)
	}
}

func TestReadConnectStreamRejectsOversizedFrame(t *testing.T) {
	// A header claiming a frame larger than the cap must be rejected BEFORE the
	// body is allocated/read — this is the OOM-DoS guard.
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:5], maxConnectFrameBytes+1)
	err := readConnectStream(bytes.NewReader(header), func([]byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("err = %v, want 'frame too large'", err)
	}
}

func TestReadConnectStreamCleanEOF(t *testing.T) {
	if err := readConnectStream(bytes.NewReader(nil), func([]byte) error { return nil }); err != nil {
		t.Fatalf("empty stream should be a clean nil, got %v", err)
	}
}

func TestReadConnectStreamTruncatedBody(t *testing.T) {
	// Header says 100 bytes, but only 3 follow.
	header := make([]byte, 5)
	binary.BigEndian.PutUint32(header[1:5], 100)
	data := append(header, []byte("abc")...)
	if err := readConnectStream(bytes.NewReader(data), func([]byte) error { return nil }); err == nil {
		t.Fatal("truncated body should error, got nil")
	}
}
