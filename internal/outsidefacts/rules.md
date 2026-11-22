# The outside facts table: what it is, the rules of its check, and what to do when the check fails

plimsoll rests on facts it does not own: the words another program prints, the exit code it uses, the form
of its version string, the place it keeps a file, the format of what it answers, a number that has to match
a number in someone else's code, a name a framework keeps private. Each such fact is true until its owner
changes it. `facts.json` is the one list of them: one row for each place in the code that rests on one.

The check (`outsidefacts_test.go`) runs with every `go test ./...`. It does three things:

1. it scans product code for six shapes, and tests for a seventh, and fails for a place that has no row;
2. it fails for a row whose file, declaration or test is no longer there, or that answers a shape the scan
   no longer finds at that place;
3. it fails for a test that waits a fixed time with no reason beside the wait.

`go run ./internal/outsidefacts/list` prints what is missing, with a row to copy for each place.

## The rules of the scan

The scan reads Go files under `ProductRoots` (`scan.go`), not tests, not `testdata`, not the directories in
`SkipDirs` (each has its reason there). Examples and timing programs are demonstrations and are not scanned.

| shape | the rule | why it needs a row |
|---|---|---|
| `error-text` | an error's text (`x.Error()`) tested with `strings.Contains`, `HasPrefix`, `HasSuffix`, `Index`, `EqualFold`, `Cut`, a pattern, `==` or `!=` | the words are someone else's (a library's, a tool's); `errors.Is` and `errors.As` need no row |
| `output-text` | the same tests on an expression whose name holds `stderr`, `stdout` or `output`, against anything but the empty string | a program's printed words change between versions and locales |
| `exit-code` | an expression whose name holds `exit` compared with a number other than 0, or switched on with such a case | which code means what is the other program's choice |
| `version-parse` | the same tests on an expression whose name holds `version`; or, in a function whose name holds `version`, a pattern match, `strconv.Atoi` and its kin, or `fmt.Sscan` | a version's form and what each release can do are its owner's |
| `provider-name` | `==`, `!=` or `case` with a provider's name (`docker`, `e2b`, ...) outside the files in `ProviderTables` | a special case by name where a property of the provider was wanted |
| `platform-case` | `runtime.GOOS` or `runtime.GOARCH` compared with a literal, or switched on | the code does one thing here and another, or nothing, there; which is right on the other system is that system's fact |
| `fixed-wait` | in a test file: `time.Sleep`, or a `<-time.After` that nothing fails on, outside any loop | the wait stands for "the other thing has happened by now" |

Splitting text by a separator (`strings.Split`, `Fields`) is not a test for words and is not scanned. Comparing
with 0 or with the empty string is not scanned. A sleep or a timer inside a loop is a poll's pause and is not
scanned; a timer in a `select` case that fails the test or returns is a limit and is not scanned.

### What the scan cannot see

The rules go by the names of things, so they are few and cheap and they miss:

- words tested on a value named something else (`msg`, `line`, `out`, `body`);
- an exit code compared with a named constant;
- a format read by a decoder (`json.Unmarshal` of another program's answer) or taken apart with `Split`;
- a number that must match a number elsewhere;
- anything in Python, TypeScript, C, shell or a Dockerfile.

Those places get a row written by hand, with no `shapes`. The check holds such a row to its file and
declaration, so it cannot outlive the code it describes, but nothing finds a new one: finding them is a
reviewer's work, and the row is where the review is kept.

## A row

```json
{
  "id": "node-bad-option-words",
  "file": "sandbox/internal/sessionkit/node.go",
  "symbol": "nodeRefusedOption",
  "shapes": ["output-text"],
  "kind": "words",
  "fact": "A node that does not know an option prints \"node: bad option: <option>\" on standard error and exits 9.",
  "owner": "Node.js",
  "version": "node v22 to v26",
  "read": "read 2026-11-20 in the code and its comments",
  "fails": "wrong-error",
  "refusal": "Another wording: the caller's general error for a program that exited 9 ...",
  "real_test": "sandbox/internal/sessionkit/node_real_test.go::TestRealNodeRefusesAnUnknownOptionInTheseWords",
  "boundary": "none",
  "number": "none"
}
```

- `file` and `symbol`: the file and the top-level declaration the code is in (`Func`, `Type.Method`, a var or
  const). Never a line number: lines move. For a file that is not Go, `symbol` is a word that occurs in it.
- `shapes`: the scanned shapes this row answers at that declaration. One row answers every site of a shape in
  one declaration.
- `kind`: `words`, `exit-code`, `version`, `format`, `file-place`, `number`, `price`, `private-api`,
  `behavior`, `provider-name`, `wait`.
- `fact`, `owner`, `version`, `read`: what is relied on, whose it is, the version it was read at, and when
  and how it was learned (measured, and with what; or read, and where).
- `fails`: what the code does when the fact is wrong. `closed`: it refuses or errors, saying what is wrong.
  `wrong-error`: it refuses, with an error that names the wrong cause or none. `open`: it goes on, doing
  what it was meant to stop or passing a check it should fail. A row that fails open names the `finding`
  that tracks it.
- `refusal`: the refusal's words, or what happens instead.
- `real_test`: the test that runs the real thing (the real program, the real library at its pinned
  version, a committed sample of the real output with its source and date), as `path::Name` (`path::*` for
  a file whose tests do so together); or `none: ` and why. A test that feeds the code a string someone
  typed is not one.
- `boundary`: `allow-list` or `refuse-list` for a place that decides what may pass, else `none`. A refuse
  list at a boundary passes whatever its owner adds next; write the list of what plimsoll itself writes or
  names instead, and refuse the rest.
- `number`: for a number that must match one elsewhere, `derived` from its owner, `tested` against it, or
  `copied`; else `none`.
- `hosted`: true for a fact about a hosted service's machines, which only a call to that service can measure
  again.

`facts.local.json`, beside `facts.json` in a checkout that has code it does not publish, holds the rows for
that code and, by row id, when each hosted fact was measured, the command that measures it again and what
that costs. `Load` reads it when it is there.

## When the check fails

**"... rests on a fact plimsoll does not own ... and no row ... says which."** You wrote, or moved, code of
one of the shapes above. First ask whether the code can stop depending on the other program's words: can
plimsoll write its own mark and read that (as `afterMarker` does for docker), use an exit code plimsoll
itself sets, or use `errors.Is`? If so, do that and no row is needed. If not, copy the row the message
prints into `facts.json`, fill it in, and make the wrong-fact case refuse.

**"... is a fixed wait with no reason."** Wait for the thing itself: a channel, or a poll with a limit. If a
fixed wait is right (a fake's own delay; the time is the thing under test; a look for something that must
not happen), say so on the line above: `// fixed-wait: <why>`.

**"row ...: ... declares no ..."** or **"the scan finds no ... any more"**: the code moved or changed. Move
the row to where the code went, or delete it with the code.
