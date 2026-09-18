// Command plimsoll-clients manages caller credentials in an offline registry.
// It writes fingerprints, never plaintext tokens, and never contacts a daemon.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/plimsollmark/plimsoll/internal/clientconfig"
)

const usage = `Usage: plimsoll-clients COMMAND -file clients.json [options]

Commands:
  create  -id NAME [-scope SCOPE ...] -token-stdout
          Generate a token and add a caller. Default scope: code:run.
  import  -id NAME [-scope SCOPE ...]
          Read an existing token from stdin and add a caller.
  list    [-json]
          List configured caller IDs and scopes, without tokens or fingerprints.
  rotate  -id NAME (-token-stdout | -token-stdin)
          Replace a caller's token, preserving its identity and permissions.
  revoke  -id NAME
          Remove a caller from the registry.

Generated tokens go only to explicitly requested stdout. Send them to your
secret manager; do not capture them in logs or commit them. Imported tokens
arrive on stdin, never through an argument. One trailing line ending is allowed.

Changes are offline. Deploy the registry and restart every daemon using it.
Running daemons retain old credentials until stopped; admitted work is not
canceled by editing the file. Revoking the last caller leaves an empty registry,
which the daemon refuses to load. Stop daemons still using the old registry.
`

type scopesFlag []string

func (s *scopesFlag) String() string { return strings.Join(*s, ",") }
func (s *scopesFlag) Set(value string) error {
	*s = append(*s, value)
	return nil
}

func main() {
	// Report a failed secret-output pipe with recovery instructions instead of
	// exiting on SIGPIPE after the fingerprint has already been registered.
	signal.Ignore(syscall.SIGPIPE)
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "plimsoll-clients:", err)
		os.Exit(1)
	}
}

func run(args []string, input io.Reader, output, diagnostic io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		_, err := io.WriteString(output, usage)
		return err
	}
	command := args[0]
	if !slices.Contains([]string{"create", "import", "list", "rotate", "revoke"}, command) {
		return errors.New("unknown command; run plimsoll-clients help")
	}
	flags := flag.NewFlagSet("plimsoll-clients "+command, flag.ContinueOnError)
	flags.SetOutput(diagnostic)
	flags.Usage = func() { _, _ = io.WriteString(diagnostic, usage) }
	path := flags.String("file", "", "caller registry path (required)")
	var id string
	var scopes scopesFlag
	var tokenStdout, tokenStdin, asJSON bool
	if command != "list" {
		flags.StringVar(&id, "id", "", "caller ID (required)")
	}
	if command == "create" || command == "import" {
		flags.Var(&scopes, "scope", "permission name; repeat for multiple scopes (default code:run)")
	}
	if command == "create" || command == "rotate" {
		flags.BoolVar(&tokenStdout, "token-stdout", false, "explicitly send a newly generated secret token to stdout")
	}
	if command == "rotate" {
		flags.BoolVar(&tokenStdin, "token-stdin", false, "replace with an existing token read from stdin")
	}
	if command == "list" {
		flags.BoolVar(&asJSON, "json", false, "emit caller metadata as JSON")
	}
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected arguments; caller tokens must never be passed as arguments")
	}
	if *path == "" {
		return errors.New("-file is required")
	}
	if command == "list" {
		f, _, err := clientconfig.ReadRegular(*path)
		if err != nil {
			return err
		}
		fmt.Fprintln(diagnostic, "Configured callers only; this does not inspect running daemons.")
		return list(f, output, asJSON)
	}
	id = strings.TrimSpace(id)
	if id == "" {
		return errors.New("-id is required")
	}
	if command == "create" && !tokenStdout {
		return errors.New("create requires -token-stdout; route stdout to your secret manager")
	}
	if command == "rotate" && tokenStdout == tokenStdin {
		return errors.New("rotate requires exactly one of -token-stdout or -token-stdin")
	}
	if len(scopes) == 0 {
		scopes = scopesFlag{"code:run"}
	}
	var token string
	if command == "import" || tokenStdin {
		var err error
		token, err = readToken(input)
		if err != nil {
			return err
		}
	}
	remaining := 0
	changed, err := clientconfig.Update(*path, command == "create" || command == "import", func(f *clientconfig.File) error {
		index := slices.IndexFunc(f.Clients, func(c clientconfig.Caller) bool { return c.ID == id })
		adding := command == "create" || command == "import"
		if adding && index >= 0 {
			return fmt.Errorf("caller %q already exists; use rotate to replace its credential", id)
		}
		if !adding && index < 0 {
			return fmt.Errorf("caller %q does not exist", id)
		}
		if tokenStdout {
			var raw [32]byte // 256 random bits, matching the daemon example.
			if _, err := rand.Read(raw[:]); err != nil {
				return errors.New("could not generate a secure random token")
			}
			token = hex.EncodeToString(raw[:])
		}
		switch command {
		case "create", "import":
			f.Clients = append(f.Clients, clientconfig.Caller{ID: id, TokenSHA256: clientconfig.Fingerprint(token), Scopes: []string(scopes)})
		case "rotate":
			fingerprint := clientconfig.Fingerprint(token)
			if fingerprint == f.Clients[index].TokenSHA256 {
				return errors.New("replacement token is unchanged; rotation requires a different token")
			}
			f.Clients[index].TokenSHA256 = fingerprint
		case "revoke":
			f.Clients = slices.Delete(f.Clients, index, index+1)
		}
		remaining = len(f.Clients)
		return nil
	})
	if err != nil {
		if changed {
			return fmt.Errorf("registry was replaced, but completion failed: %w; inspect the file before activation; if a generated token was not delivered, rotate that caller", err)
		}
		return err
	}
	fmt.Fprintf(diagnostic, "%s saved for caller %q in %s.\n", command, id, *path)
	if remaining == 0 {
		fmt.Fprintln(diagnostic, "No callers remain. The daemon refuses to start with an empty registry. Stop every daemon still using the old registry; add a caller before starting it again.")
	} else {
		fmt.Fprintln(diagnostic, "Not active in running daemons. Deploy this file and restart EVERY daemon using it; old credentials remain accepted until those daemons stop.")
	}
	fmt.Fprintln(diagnostic, "Editing this file does not cancel already admitted work.")
	if tokenStdout {
		if _, err := io.WriteString(output, token+"\n"); err != nil {
			return errors.New("registry updated but generated token delivery failed; rotate this caller before activation and check your secret destination")
		}
	}
	return nil
}

// readToken bounds accidental input streams and rejects characters that cannot
// be carried as one HTTP bearer value. The cap is an input safety bound, not a
// claim that a token has sufficient entropy; the importing operator owns that.
func readToken(input io.Reader) (string, error) {
	const maxTokenBytes = 4096
	raw, err := io.ReadAll(io.LimitReader(input, maxTokenBytes+3))
	if err != nil {
		return "", errors.New("could not read caller token from stdin")
	}
	token := strings.TrimSuffix(strings.TrimSuffix(string(raw), "\n"), "\r")
	if len(token) == 0 || len(token) > maxTokenBytes || strings.ContainsFunc(token, func(r rune) bool { return r < 0x21 || r > 0x7e }) {
		return "", errors.New("stdin must contain one nonempty token of at most 4096 visible ASCII bytes, optionally followed by one line ending")
	}
	return token, nil
}

func list(f clientconfig.File, output io.Writer, asJSON bool) error {
	type metadata struct {
		ID     string   `json:"id"`
		Scopes []string `json:"scopes"`
	}
	callers := make([]metadata, 0, len(f.Clients))
	for _, c := range f.Clients {
		callers = append(callers, metadata{c.ID, c.Scopes})
	}
	slices.SortFunc(callers, func(a, b metadata) int { return strings.Compare(a.ID, b.ID) })
	if asJSON {
		enc := json.NewEncoder(output)
		enc.SetIndent("", "  ")
		return enc.Encode(callers)
	}
	w := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CALLER\tSCOPES")
	for _, c := range callers {
		fmt.Fprintf(w, "%s\t%s\n", c.ID, strings.Join(c.Scopes, ", "))
	}
	return w.Flush()
}
