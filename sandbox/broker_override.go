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
	// errKeyNotPlain refuses a top-level key that holds an escaped control character
	// (U+0000 to U+001F, the characters JSON requires be escaped) or an escaped half of a
	// surrogate pair with no other half (hunt-security-19). The broker forwards the
	// guest's bytes as written, so the API's parser reads each key itself, and parsers
	// differ on such a key: one may cut it at a NUL or drop a lone surrogate, Go's puts
	// U+FFFD for the surrogate, PHP's refuses the body. "_method" followed by an escaped
	// NUL is not the field to the broker and could be to such a parser. No honest client
	// is known to write either kind of key, so the broker refuses them rather than model
	// each parser.
	errKeyNotPlain = errors.New("host api request body has a top-level JSON key with an escaped control character or an unpaired surrogate, which JSON parsers read differently")
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
		before := dec.InputOffset()
		keyTok, err := dec.Token()
		if err != nil {
			return errBodyNotJSON
		}
		// The key as written: what follows the previous value (white space, a comma, white
		// space), then the quoted key the decoder has just read.
		if !plainJSONKey(bytes.TrimLeft(first[before:dec.InputOffset()], " \t\r\n,")) {
			return errKeyNotPlain
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

// plainJSONKey reports whether quoted, a JSON string as written (quotes included) that
// encoding/json has accepted, holds no escaped control character and no escaped
// surrogate outside a high-then-low pair (errKeyNotPlain). The streamed scanner makes the
// same check a byte at a time (stringByte); FuzzJSONOverrideScannerAgreesWithDecoder holds
// the two to each other.
func plainJSONKey(quoted []byte) bool {
	if len(quoted) < 2 || quoted[0] != '"' || quoted[len(quoted)-1] != '"' {
		return false
	}
	s := quoted[1 : len(quoted)-1]
	hex4 := func(i int) (rune, bool) { // the four hex digits of an escape at s[i:]
		if i+4 > len(s) {
			return 0, false
		}
		var v rune
		for _, c := range s[i : i+4] {
			d, ok := hexValue(c)
			if !ok {
				return 0, false
			}
			v = v<<4 | d
		}
		return v, true
	}
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			continue
		}
		i++
		if i >= len(s) {
			return false
		}
		switch s[i] {
		case 'b', 'f', 'n', 'r', 't':
			return false
		case 'u':
			v, ok := hex4(i + 1)
			i += 4
			switch {
			case !ok, v < 0x20, v >= 0xdc00 && v <= 0xdfff:
				return false
			case v >= 0xd800 && v <= 0xdbff:
				if i+2 >= len(s) || s[i+1] != '\\' || s[i+2] != 'u' {
					return false
				}
				if low, ok := hex4(i + 3); !ok || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
	}
	return true
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

// maxJSONDepth is the deepest nesting the scanner reads, encoding/json's own limit
// (maxNestingDepth in its scanner.go, and jsontext's in the v2 package): 10000 levels
// are JSON to both checks and 10001 to neither, so the buffered and the streamed check
// agree on deep nesting, and the scanner's nesting record has a fixed size
// (TestStreamedScannerNestingLimitIsEncodingJSONs).
const maxJSONDepth = 10000

// jsonState is where the scanner is in the JSON grammar, outside a string.
type jsonState uint8

const (
	jsTop          jsonState = iota // between top-level values
	jsValue                         // a value must come: after a colon or an array's comma
	jsValueOrClose                  // after "[": a value or "]"
	jsKeyOrClose                    // after "{": a key or "}"
	jsKey                           // after an object's comma: a key
	jsColon                         // after a key: ":"
	jsAfterValue                    // after a value in a container: a comma or its close
	jsLiteral                       // in true, false or null; lit holds the bytes to come
	jsNumMinus                      // after a number's "-": a digit
	jsNumZero                       // after a leading 0: the number may end, or "." or an exponent
	jsNumInt                        // in the integer digits
	jsNumDot                        // after ".": a digit
	jsNumFrac                       // in the fraction digits
	jsNumE                          // after "e" or "E": a sign or a digit
	jsNumESign                      // after the exponent's sign: a digit
	jsNumExp                        // in the exponent digits
)

// jsonOverrideScanner checks JSON fed in pieces, a byte at a time, against the whole
// JSON grammar (RFC 8259: objects, arrays, strings and their escapes, numbers with sign,
// fraction and exponent, true, false and null, commas and colons in their places, white
// space only where JSON allows it), and finds a top-level object key equal to the
// override field, holding a fixed amount of state and never the body. Anything that is
// not JSON is refused with errBodyNotJSON at the piece that holds it, and a body that
// ends inside a value is refused at end (finding release-109: when the scanner tracked
// strings, escapes and nesting only, it passed text, an object cut short, a trailing
// comma and unquoted or single-quoted keys, which a lenient parser reads _method from).
// The body must also be valid UTF-8 with no control byte but tab, line feed and
// carriage return outside a string and none inside one (so UTF-16, whose ASCII letters
// come with a NUL each, never reaches a parser that would decode it).
//
// It refuses at least everything checkBufferedBody refuses as not JSON, and on valid
// JSON it reads exactly the keys encoding/json reads (FuzzJSONOverrideScannerAgreesWithDecoder
// holds both, for any input). Where the two differ it is in this direction, the scanner
// refusing more: it reads every top-level value, white space required between two, so
// text after the first value (which the buffered check does not read) is refused when
// it is not JSON and when it names the field (the known lead in private/hunts/leads.md).
type jsonOverrideScanner struct {
	utf8      utf8Check
	err       error // errBodyNotJSON or errKeyNotPlain, once refused
	bom       int   // bytes of a leading byte order mark matched so far
	started   bool  // past the start of the body
	state     jsonState
	needSpace bool   // a top-level value has ended: white space must come before another
	lit       string // the rest of the literal in jsLiteral
	depth     int
	objects   [(maxJSONDepth + 63) / 64]uint64 // bit d-1: the container at depth d is an object
	inString  bool
	keyString bool // the string is an object's key, at any depth
	isKey     bool // the string is a top-level key, the one place the field counts
	esc       bool
	hex       int  // hex digits of a \u escape still to come
	hexVal    rune // the escape's value so far
	highOpen  bool // the key's last escape was a high surrogate, so a low one must follow
	key       [len(overrideField)]byte
	keyLen    int
	keyLong   bool // the key is longer than the field or holds a non-ASCII character
	found     bool
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
			if s.stringByte(c); s.err != nil {
				return s.err
			}
			continue
		}
		if !s.grammarByte(c) {
			s.err = errBodyNotJSON
			return s.err
		}
	}
	if s.found {
		return errOverrideField
	}
	return nil
}

// end refuses a body that ends inside a value (a string, a container, a literal, or a
// number that cannot end there) or inside a UTF-8 character. A JSON body's end names no
// key the pieces did not.
func (s *jsonOverrideScanner) end() error {
	if s.err != nil || s.found {
		if s.err == nil {
			return errOverrideField
		}
		return s.err
	}
	switch {
	case s.utf8.need > 0, s.inString, s.depth > 0:
		s.err = errBodyNotJSON
	case s.state == jsTop, s.state == jsNumZero, s.state == jsNumInt, s.state == jsNumFrac, s.state == jsNumExp:
	default:
		s.err = errBodyNotJSON
	}
	return s.err
}

// grammarByte reads one byte outside a string and reports whether JSON allows it there.
func (s *jsonOverrideScanner) grammarByte(c byte) bool {
	switch s.state {
	case jsLiteral:
		if c != s.lit[0] {
			return false
		}
		if s.lit = s.lit[1:]; s.lit == "" {
			s.valueDone()
		}
		return true
	case jsNumMinus:
		switch {
		case c == '0':
			s.state = jsNumZero
		case c >= '1' && c <= '9':
			s.state = jsNumInt
		default:
			return false
		}
		return true
	case jsNumZero, jsNumInt, jsNumFrac, jsNumExp:
		switch {
		case c >= '0' && c <= '9' && s.state != jsNumZero:
			return true
		case c == '.' && (s.state == jsNumZero || s.state == jsNumInt):
			s.state = jsNumDot
			return true
		case (c == 'e' || c == 'E') && s.state != jsNumExp:
			s.state = jsNumE
			return true
		}
		// The number has ended; the byte is read after it (a digit after a leading 0 is
		// then refused, as a value straight after a value is).
		s.valueDone()
		return s.grammarByte(c)
	case jsNumDot, jsNumESign:
		if c < '0' || c > '9' {
			return false
		}
		if s.state == jsNumDot {
			s.state = jsNumFrac
		} else {
			s.state = jsNumExp
		}
		return true
	case jsNumE:
		switch {
		case c == '+' || c == '-':
			s.state = jsNumESign
		case c >= '0' && c <= '9':
			s.state = jsNumExp
		default:
			return false
		}
		return true
	}
	if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
		if s.state == jsTop {
			s.needSpace = false
		}
		return true
	}
	switch s.state {
	case jsTop, jsValue, jsValueOrClose:
		if s.state == jsTop && s.needSpace {
			return false
		}
		if s.state == jsValueOrClose && c == ']' {
			s.depth--
			s.valueDone()
			return true
		}
		return s.startValue(c)
	case jsKeyOrClose, jsKey:
		if c == '"' {
			s.startString(true)
			return true
		}
		if c == '}' && s.state == jsKeyOrClose {
			s.depth--
			s.valueDone()
			return true
		}
	case jsColon:
		if c == ':' {
			s.state = jsValue
			return true
		}
	case jsAfterValue:
		obj := s.objects[(s.depth-1)/64]&(1<<((s.depth-1)%64)) != 0
		switch {
		case c == ',' && obj:
			s.state = jsKey
		case c == ',':
			s.state = jsValue
		case c == '}' && obj, c == ']' && !obj:
			s.depth--
			s.valueDone()
		default:
			return false
		}
		return true
	}
	return false
}

// startValue reads the first byte of a value.
func (s *jsonOverrideScanner) startValue(c byte) bool {
	switch {
	case c == '{' || c == '[':
		if s.depth == maxJSONDepth {
			return false // encoding/json refuses the same depth
		}
		word, bit := s.depth/64, uint64(1)<<(s.depth%64)
		if c == '{' {
			s.objects[word] |= bit
			s.state = jsKeyOrClose
		} else {
			s.objects[word] &^= bit
			s.state = jsValueOrClose
		}
		s.depth++
	case c == '"':
		s.startString(false)
	case c == 't':
		s.state, s.lit = jsLiteral, "rue"
	case c == 'f':
		s.state, s.lit = jsLiteral, "alse"
	case c == 'n':
		s.state, s.lit = jsLiteral, "ull"
	case c == '-':
		s.state = jsNumMinus
	case c == '0':
		s.state = jsNumZero
	case c >= '1' && c <= '9':
		s.state = jsNumInt
	default:
		return false
	}
	return true
}

// valueDone moves past a value that has just ended.
func (s *jsonOverrideScanner) valueDone() {
	if s.depth == 0 {
		s.state, s.needSpace = jsTop, true
	} else {
		s.state = jsAfterValue
	}
}

// startString begins a string, an object's key when key is set.
func (s *jsonOverrideScanner) startString(key bool) {
	s.inString, s.keyString, s.isKey = true, key, key && s.depth == 1
	s.keyLen, s.keyLong, s.esc, s.hex, s.highOpen = 0, false, false, 0, false
}

// stringByte reads one byte inside a string. In a top-level key it sets s.err to
// errKeyNotPlain at the byte that shows an escaped control character or an unpaired
// surrogate (plainJSONKey says the same of a whole key, for the buffered check).
func (s *jsonOverrideScanner) stringByte(c byte) {
	switch {
	case s.hex > 0:
		v, ok := hexValue(c)
		if !ok {
			s.err = errBodyNotJSON // a \u escape needs four hex digits
			return
		}
		s.hexVal = s.hexVal<<4 | v
		s.hex--
		if s.hex > 0 {
			return
		}
		r := s.hexVal
		if s.isKey {
			isHigh, isLow := r >= 0xd800 && r <= 0xdbff, r >= 0xdc00 && r <= 0xdfff
			switch {
			case s.highOpen != isLow, r < 0x20:
				s.err = errKeyNotPlain // a lone half of a pair, or an escaped control character
				return
			case isHigh:
				s.highOpen = true
				return
			case isLow:
				s.highOpen = false
				r = 0x10000 // the pair names a character past ASCII; which one does not matter
			}
		}
		s.keyRune(r)
	case s.esc:
		s.esc = false
		if s.isKey && s.highOpen && c != 'u' {
			s.err = errKeyNotPlain // a high surrogate, then an escape that is not \u
			return
		}
		switch c {
		case 'u':
			s.hex, s.hexVal = 4, 0
		case '"', '\\', '/':
			s.keyRune(rune(c))
		case 'b', 'f', 'n', 'r', 't':
			if s.isKey {
				s.err = errKeyNotPlain // an escaped control character
			}
		default:
			s.err = errBodyNotJSON // JSON has no other escape
		}
	case c == '\\':
		s.esc = true
	case s.isKey && s.highOpen:
		s.err = errKeyNotPlain // a high surrogate, then a character or the key's end
	case c == '"':
		s.inString = false
		if s.isKey && !s.keyLong && s.keyLen == len(overrideField) && isOverrideName(string(s.key[:s.keyLen])) {
			s.found = true
		}
		if s.keyString {
			s.state = jsColon
		} else {
			s.valueDone()
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
