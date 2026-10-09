// Package unreadbody keeps an HTTP/1.x server from waiting on a request body its
// handler answered without reading.
//
// Go's HTTP/1.x server reads up to 256 KiB of a body its handler left unread before
// it writes the response, so that the connection can carry another request, and a
// handler's Body.Close reads it the same way. A client that declares a small body and
// sends it slowly therefore holds every refusal that never reads the body (a bad
// credential, a full queue, an unknown path) until the body arrives or the server's
// read timeout ends it. Handler marks the response "Connection: close" as soon as it
// starts before the body has been read to its end: the server then writes the
// response at once, reads what is left of the body for at most Grace, and closes the
// connection. HTTP/2 needs none of this, because its server resets the stream of a
// body the handler did not read.
package unreadbody

import (
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// Grace bounds how long the server goes on reading an abandoned body once the
// response has been written. It is the delay Go's own server waits before closing a
// connection whose oversized body it refused (rstAvoidanceDelay in net/http): long
// enough for a body the client has already sent to arrive, so that closing does not
// reset the connection under a response the client is still reading.
const Grace = 500 * time.Millisecond

// Handler wraps next so that an HTTP/1.x response started before the request body
// was read to its end closes the connection instead of draining the body first. A
// body read to its end keeps the connection reusable. Wrapping twice is harmless.
func Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 1 || r.Body == nil || r.Body == http.NoBody {
			next.ServeHTTP(w, r)
			return
		}
		if _, wrapped := r.Body.(*body); wrapped {
			next.ServeHTTP(w, r)
			return
		}
		a := &abandoner{w: w}
		b := &body{ReadCloser: r.Body, a: a}
		a.body = b
		r2 := new(http.Request)
		*r2 = *r
		r2.Body = b
		next.ServeHTTP(&writer{ResponseWriter: w, a: a}, r2)
		// A handler that wrote nothing gets the server's 200 after this returns.
		a.abandon()
	})
}

// abandoner closes the connection of a response whose body was not read to its end.
type abandoner struct {
	w    http.ResponseWriter
	body *body
	once sync.Once
}

func (a *abandoner) abandon() {
	a.once.Do(func() {
		if a.body.eof.Load() {
			return
		}
		// Must precede the response header: the server reads it when the header is
		// written, and "close" is what skips its drain. Not every writer supports a
		// read deadline (a test's recorder does not); the server's read timeout
		// still bounds those.
		a.w.Header().Set("Connection", "close")
		_ = http.NewResponseController(a.w).SetReadDeadline(time.Now().Add(Grace))
	})
}

// body records whether the request body was read to its end. Closing it early does
// not close the server's body, which would drain it; the server closes that itself,
// after the response, under the deadline abandon set.
type body struct {
	io.ReadCloser
	a      *abandoner
	eof    atomic.Bool
	closed atomic.Bool
}

func (b *body) Read(p []byte) (int, error) {
	if b.closed.Load() {
		return 0, http.ErrBodyReadAfterClose
	}
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.eof.Store(true)
	}
	return n, err
}

func (b *body) Close() error {
	b.closed.Store(true)
	if b.eof.Load() {
		return b.ReadCloser.Close()
	}
	b.a.abandon()
	return nil
}

// writer abandons an unread body before anything of the response is written.
type writer struct {
	http.ResponseWriter
	a *abandoner
}

func (w *writer) WriteHeader(code int) {
	w.a.abandon()
	w.ResponseWriter.WriteHeader(code)
}

func (w *writer) Write(p []byte) (int, error) {
	w.a.abandon()
	return w.ResponseWriter.Write(p)
}

func (w *writer) Flush() {
	w.a.abandon()
	_ = http.NewResponseController(w.ResponseWriter).Flush()
}

// Unwrap lets http.ResponseController reach the server's writer.
func (w *writer) Unwrap() http.ResponseWriter { return w.ResponseWriter }
