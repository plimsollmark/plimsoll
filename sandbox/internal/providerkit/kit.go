package providerkit

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Capture keeps the first Limit bytes written to it and records whether it dropped any,
// so a runaway program cannot exhaust memory through its output. Truncation is reported
// out of band (Truncated): the retained prefix is never annotated in band, so a consumer
// sees exactly the bytes the program wrote. Write always reports the whole of p as
// written, so the writer on the other end of a pipe is never blocked. A Limit of zero or
// less keeps nothing.
type Capture struct {
	Limit   int
	buf     []byte
	dropped bool
}

// Write keeps what fits under Limit and drops the rest.
func (c *Capture) Write(p []byte) (int, error) {
	if room := c.Limit - len(c.buf); room > 0 {
		if len(p) > room {
			c.buf = append(c.buf, p[:room]...)
			c.dropped = true
		} else {
			c.buf = append(c.buf, p...)
		}
	} else if len(p) > 0 {
		c.dropped = true
	}
	return len(p), nil
}

// Bytes is the retained prefix; it aliases the buffer, as bytes.Buffer.Bytes does.
func (c *Capture) Bytes() []byte { return c.buf }

// String is the retained prefix as a string.
func (c *Capture) String() string { return string(c.buf) }

// Truncated reports whether the cap dropped any bytes.
func (c *Capture) Truncated() bool { return c.dropped }

// ClampTimeout is the request's timeout, def when it asks for none, and never past max.
// Each provider passes its own default and ceiling, with its own fallbacks for a
// configuration that leaves them zero.
func ClampTimeout(req, def, max time.Duration) time.Duration {
	if req <= 0 {
		req = def
	}
	return min(req, max)
}

// RandHex is n bytes from crypto/rand in hexadecimal: a name no other sandbox, session or
// socket of this process will take. crypto/rand.Read never returns an error (it crashes
// the program instead, Go 1.24 on), so there is none to handle.
func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
