package sandbox

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"strings"
	"unicode/utf8"
)

// Method and path override. The broker checks each call's method and path against the
// grant's routes, but common web frameworks act on a method or path named somewhere
// else in the request: a header (X-HTTP-Method-Override, which Symfony reads on every
// POST, Rack, ASP.NET Core and Express read when their override is on; X-Original-URL,
// which IIS URL Rewrite sets and Symfony read until 2018) or a body field (_method,
// which Laravel and Express take from a JSON body). A grant of only a create route would
// then let the guest delete, and the trace would still name the create route. The broker
// refuses the headers at profile load and never forwards one from the guest, and refuses
// a JSON body whose top level names _method. It does not read a form or multipart body:
// one is forwarded unread on a route an operator opened for it
// (TestBrokerForwardsFormAndUploadBodiesUnread). The operator's account:
// docs/capability-grants.md, "Method and path override".

// overrideHeaders is every request header a framework or server in use reads as the
// request's method or its path, lowercase. A grant may neither pass nor set one
// (passHeaderRefused), so no such header reaches the API from the broker: the broker's
// own headers are Accept, Content-Type and the credential, and the guest's reach the
// API only through PassHeaders.
var overrideHeaders = map[string]string{
	// Method: Symfony's Request::getMethod, Rack::MethodOverride, ASP.NET Core's
	// HttpMethodOverrideMiddleware, Express method-override (default getter), Google APIs.
	"x-http-method-override": "method",
	// Method: SharePoint's REST service and OData clients tunnel MERGE, PUT and DELETE in it.
	"x-http-method": "method",
	// Method: the third name the OWASP testing guide lists for method overriding.
	"x-method-override": "method",
	// Path: IIS URL Rewrite sets it; Symfony read it until CVE-2018-14773, Zend Framework too.
	"x-original-url": "path",
	// Path: the same family (IIS, older Symfony and Zend); removed for the same reason.
	"x-rewrite-url": "path",
}

// overrideHeaderKind reports whether name is an override header and which: "method" or
// "path". Matched without regard to case, as HTTP field names are, and with "_" read as
// "-" (hunt-security-15): a CGI-style server (PHP's, and the Ruby servers that build a
// Rack environment) turns X_HTTP_METHOD_OVERRIDE and X-HTTP-Method-Override alike into
// HTTP_X_HTTP_METHOD_OVERRIDE, the variable Symfony and Rack read.
func overrideHeaderKind(name string) (string, bool) {
	kind, ok := overrideHeaders[strings.ReplaceAll(strings.ToLower(name), "_", "-")]
	return kind, ok
}

// overrideField is the body field the frameworks read as the request's method. It is
// the only one in real use: Laravel, Symfony, Rack (Rails, Sinatra), CakePHP and the
// Express method-override README's body getter all name it _method.
const overrideField = "_method"

// isOverrideName reports whether a decoded top-level JSON key is the override field,
// compared without regard to ASCII case (no JSON reader measured ignores case, so this
// refuses more than any reads).
func isOverrideName(name string) bool {
	return len(name) == len(overrideField) && asciiKey(name) && strings.EqualFold(name, overrideField)
}

// holdsJSONMark is the broker's one rule for what is JSON: lowercase text that holds
// "/json" or "+json", the test Laravel's isJson makes of a whole Content-Type header.
// Asked of a media type with no parameters, it says whether the broker reads the body as
// JSON; asked of the whole header the broker sends, it says whether such a framework
// would (requestContentType refuses a header on which the two differ). The rule was
// written in both places until 2026-11-20 (hunt-quality-66).
func holdsJSONMark(lower string) bool {
	return strings.Contains(lower, "/json") || strings.Contains(lower, "+json")
}

// isJSONContentType reports whether a Content-Type the broker built is a JSON type (the
// broker builds every type it sends, so an unparsable one never leaves it).
func isJSONContentType(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && holdsJSONMark(mediaType)
}

// Refusals the override check makes. Each is the broker's own answer. A buffered body's
// is made before the request is built: it is counted as a denied call in the trace, with
// no call row, and the route's cap is not charged. A streamed body's is made while the
// request is under way, after its headers went (the transport sends them before it
// reads the body, and an API's handler runs on them), so it keeps the route's charge
// and has a call row with the bytes sent, none or some: an API can act on the headers,
// and one that reads JSON as it arrives on the pieces before the broken-off request
// ends (findings hunt-security-31 and release-98).
var (
	errOverrideField = errors.New("host api request names a method override field (_method), which the route check cannot see")
	errBodyNotJSON   = errors.New("host api request body is sent as JSON and is not JSON")
)

// overrideRefusal is the broker answer for one of the errors above.
func overrideRefusal(err error) brokerResponse {
	if errors.Is(err, errOverrideField) {
		return brokerError(http.StatusForbidden, err.Error())
	}
	return brokerError(http.StatusBadRequest, err.Error())
}

// utf8BOM is the byte order mark a JSON parser may skip (Express's body-parser decodes
// through iconv-lite, which drops it), so the broker skips it too before it reads, and
// sends the body as written: Express reads the rest, which is what the broker read, and
// PHP's json_decode answers null for the whole body.
var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// utf8Check validates UTF-8 a byte at a time, as utf8.Valid does whole (the same
// accepted ranges: no overlong forms, no surrogates, nothing past U+10FFFF). A JSON body
// must be valid UTF-8 (hunt-security-16): the broker sends JSON with no charset, so a
// parser decodes it as UTF-8, and the bytes the broker read are the text it reads.
type utf8Check struct {
	need   int  // continuation bytes still to come
	lo, hi byte // the range the next one must fall in
}

// next reports whether c can follow the bytes before it.
func (u *utf8Check) next(c byte) bool {
	if u.need > 0 {
		if c < u.lo || c > u.hi {
			return false
		}
		u.need--
		u.lo, u.hi = 0x80, 0xbf
		return true
	}
	u.lo, u.hi = 0x80, 0xbf
	switch {
	case c < 0x80:
	case c >= 0xc2 && c <= 0xdf:
		u.need = 1
	case c == 0xe0:
		u.need, u.lo = 2, 0xa0
	case c >= 0xe1 && c <= 0xec, c == 0xee, c == 0xef:
		u.need = 2
	case c == 0xed:
		u.need, u.hi = 2, 0x9f
	case c == 0xf0:
		u.need, u.lo = 3, 0x90
	case c >= 0xf1 && c <= 0xf3:
		u.need = 3
	case c == 0xf4:
		u.need, u.hi = 3, 0x8f
	default:
		return false
	}
	return true
}

// checkBufferedBody refuses a JSON body the broker holds whole when its top level names
// the override field. JSON is read by encoding/json (the first value; a body that is not
// JSON is refused, so a parser that is looser than Go's cannot find a field Go missed).
// A body of any other type is not read.
func checkBufferedBody(contentType string, body []byte) error {
	if isJSONContentType(contentType) {
		return checkJSONBody(body)
	}
	return nil
}

// checkJSONBody reads the top level of the first JSON value of body. Every key of a
// top-level object is checked, a duplicate included; a key nested deeper is no
// override in any framework read, and passes.
func checkJSONBody(body []byte) error {
	if !utf8.Valid(body) {
		return errBodyNotJSON // Go's decoder would read it, putting U+FFFD for the bad bytes
	}
	body = bytes.TrimPrefix(body, utf8BOM)
	if len(bytes.TrimSpace(body)) == 0 {
		return nil
	}
	var first json.RawMessage
	if err := json.NewDecoder(bytes.NewReader(body)).Decode(&first); err != nil {
		return errBodyNotJSON
	}
	if first[0] != '{' {
		return nil // an array or a scalar names no field
	}
	dec := json.NewDecoder(bytes.NewReader(first))
	if _, err := dec.Token(); err != nil { // the "{"
		return errBodyNotJSON
	}
	for dec.More() {
		keyTok, err := dec.Token()
		if err != nil {
			return errBodyNotJSON
		}
		if key, _ := keyTok.(string); asciiKey(key) && isOverrideName(key) {
			return errOverrideField
		}
		var skip json.RawMessage
		if err := dec.Decode(&skip); err != nil {
			return errBodyNotJSON
		}
	}
	return nil
}

// asciiKey reports whether a decoded key is ASCII; a key with any other character is
// never the override field (the streamed scanner reads it the same way).
func asciiKey(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// overrideScanner reads a body as it passes through, a piece at a time, and reports an
// override field as soon as the piece that completes its name arrives, so the piece can
// be withheld and the API never receives a whole request that names one.
type overrideScanner interface {
	// feed reads the next piece: errOverrideField once the body has named the override
	// field, errBodyNotJSON once it is not JSON, and the same answer for every piece after.
	feed(p []byte) error
	// end is told the body has ended, and may still refuse it.
	end() error
}

// streamScannerFor is the scanner for a passed-through body of contentType: the JSON
// scanner for a JSON type, nil (nothing read) for any other.
func streamScannerFor(contentType string) overrideScanner {
	if isJSONContentType(contentType) {
		return &jsonOverrideScanner{}
	}
	return nil
}

// jsonOverrideScanner finds a top-level object key equal to the override field in JSON
// fed in pieces, holding a few bytes of state and never the body. It tracks strings,
// escapes and nesting only: on valid JSON it reads exactly the keys encoding/json reads
// (FuzzJSONOverrideScannerAgreesWithDecoder), and a body that is not JSON is one no
// framework read acts on (PHP's json_decode answers null for it, Express refuses it).
// Every top-level value is read, so a second value after the first is checked too. The
// body must be valid UTF-8 with no control byte but tab, line feed and carriage return
// outside a string and none inside one, as JSON requires; anything else is refused with
// errBodyNotJSON at the piece that holds it (so UTF-16, whose ASCII letters come with a
// NUL each, never reaches a parser that would decode it).
type jsonOverrideScanner struct {
	utf8     utf8Check
	err      error // errBodyNotJSON, once refused
	bom      int   // bytes of a leading byte order mark matched so far
	started  bool  // past the start of the body
	depth    int
	topObj   bool // the depth-1 container is an object
	wantKey  bool // the next string at depth 1 is a key
	inString bool
	isKey    bool
	esc      bool
	hex      int  // hex digits of a \u escape still to come
	hexVal   rune // the escape's value so far
	key      [len(overrideField)]byte
	keyLen   int
	keyLong  bool // the key is longer than the field or holds a non-ASCII character
	found    bool
}

func (s *jsonOverrideScanner) feed(p []byte) error {
	if s.err != nil {
		return s.err
	}
	for _, c := range p {
		if s.found {
			return errOverrideField
		}
		if !s.utf8.next(c) || (c < 0x20 && (s.inString || (c != '\t' && c != '\n' && c != '\r'))) {
			s.err = errBodyNotJSON
			return s.err
		}
		if !s.started {
			if s.bom < len(utf8BOM) && c == utf8BOM[s.bom] {
				s.bom++
				continue
			}
			s.started = true
		}
		if s.inString {
			s.stringByte(c)
			continue
		}
		switch c {
		case '{', '[':
			s.depth++
			if s.depth == 1 {
				s.topObj = c == '{'
				s.wantKey = s.topObj
			}
		case '}', ']':
			if s.depth > 0 {
				s.depth--
			}
		case ',':
			if s.depth == 1 && s.topObj {
				s.wantKey = true
			}
		case '"':
			s.inString = true
			s.isKey = s.depth == 1 && s.topObj && s.wantKey
			s.wantKey = false
			s.keyLen, s.keyLong, s.esc, s.hex = 0, false, false, 0
		}
	}
	if s.found {
		return errOverrideField
	}
	return nil
}

// end: a JSON body's end names no key the pieces did not; it is refused when it cuts a
// UTF-8 character short.
func (s *jsonOverrideScanner) end() error {
	if s.err == nil && s.utf8.need > 0 {
		s.err = errBodyNotJSON
	}
	return s.err
}

func (s *jsonOverrideScanner) stringByte(c byte) {
	switch {
	case s.hex > 0:
		v, ok := hexValue(c)
		if !ok {
			s.hex = 0
			s.keyLong = true // not JSON; whatever it is, no key it names is ours
			return
		}
		s.hexVal = s.hexVal<<4 | v
		s.hex--
		if s.hex == 0 {
			s.keyRune(s.hexVal)
		}
	case s.esc:
		s.esc = false
		switch c {
		case 'u':
			s.hex, s.hexVal = 4, 0
		case '"', '\\', '/':
			s.keyRune(rune(c))
		case 'b', 'f', 'n', 'r', 't':
			s.keyRune(0) // a control character: never in the field's name
		default:
			s.keyLong = true
		}
	case c == '\\':
		s.esc = true
	case c == '"':
		s.inString = false
		if s.isKey && !s.keyLong && s.keyLen == len(overrideField) && isOverrideName(string(s.key[:s.keyLen])) {
			s.found = true
		}
	default:
		s.keyRune(rune(c))
	}
}

func (s *jsonOverrideScanner) keyRune(r rune) {
	if !s.isKey || s.keyLong {
		return
	}
	if r == 0 || r >= 0x80 || s.keyLen == len(s.key) {
		s.keyLong = true
		return
	}
	s.key[s.keyLen] = byte(r)
	s.keyLen++
}

func hexValue(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}
