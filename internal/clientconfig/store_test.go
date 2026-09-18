package clientconfig

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func add(id string) func(*File) error {
	return func(f *File) error {
		f.Clients = append(f.Clients, Caller{ID: id, TokenSHA256: Fingerprint("synthetic-" + id), Scopes: []string{"code:run"}})
		return nil
	}
}

func TestConcurrentEditsAndAtomicFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "clients.json")
	started, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		_, err := Update(path, true, func(f *File) error {
			close(started)
			<-release
			return add("first")(f)
		})
		done <- err
	}()
	<-started
	changed, err := Update(path, true, add("second"))
	close(release)
	if firstErr := <-done; firstErr != nil {
		t.Fatal(firstErr)
	}
	if changed || err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatal("concurrent update did not refuse the occupied lock")
	}
	if _, err := Update(path, false, add("second")); err != nil {
		t.Fatal(err)
	}
	f, mode, err := ReadRegular(path)
	if err != nil || len(f.Clients) != 2 || f.Clients[0].ID != "first" || f.Clients[1].ID != "second" {
		t.Fatal("retry lost a completed edit")
	}
	if mode != 0o600 {
		t.Fatalf("new registry permissions = %o, want 600", mode)
	}
	before, _ := os.ReadFile(path)
	for _, edit := range []func(*File) error{add("first"), func(f *File) error { f.Clients = nil; return errors.New("edit rejected") }} {
		changed, err := Update(path, false, edit)
		after, readErr := os.ReadFile(path)
		if changed || err == nil || readErr != nil || !bytes.Equal(before, after) {
			t.Fatal("failed mutation did not leave the original bytes intact")
		}
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 || entries[0].Name() != "clients.json" {
		t.Fatal("completed updates left lock directories or temporary files behind")
	}
}

func TestUnsafeTargetsAndMalformedRegistries(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if _, err := Update(target, true, add("a")); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	malformed := filepath.Join(dir, "malformed.json")
	if err := os.WriteFile(malformed, []byte(`{"clients":[],"unexpected":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{link, malformed, dir, filepath.Join(dir, "missing.json")} {
		changed, err := Update(path, false, add("b"))
		if changed || err == nil {
			t.Fatalf("unsafe target accepted: %s", path)
		}
	}
	f, _, err := ReadRegular(target)
	if err != nil || len(f.Clients) != 1 || f.Clients[0].ID != "a" {
		t.Fatal("symlink mutation modified its target")
	}
}

func TestParseRejectsAmbiguousIdentityAndScopes(t *testing.T) {
	h := Fingerprint("synthetic-token")
	for _, raw := range []string{
		`null`, `{}`, `{"clients":null}`, `{"clients":[]} {}`,
		`{"clients":[{"id":"bad\u0000id","token_sha256":"` + h + `"}]}`,
		`{"clients":[{"id":"a","token_sha256":"` + h + `","scopes":["code:run","code:run"]}]}`,
		`{"clients":[{"id":"a","token_sha256":"` + h + `","scopes":[""]}]}`,
	} {
		if _, err := Parse([]byte(raw)); err == nil {
			t.Fatal("invalid registry was accepted")
		}
	}
	f, err := Parse([]byte(`{"clients":[{"id":" caller ","token_sha256":"` + strings.ToUpper(h) + `"}]}`))
	if err != nil || f.Clients[0].ID != "caller" || f.Clients[0].TokenSHA256 != h {
		t.Fatal("normalization differs from the existing daemon contract")
	}
}
