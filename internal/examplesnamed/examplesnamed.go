// Package examplesnamed finds shipped example programs that no public page names, so an
// example a reader could run never sits in the repository with nothing pointing at it.
//
// An example is each file directly in clients/python/examples/ whose name does not start
// with "_" (those are helpers the examples share), and each directory directly in
// examples/, named as examples/<name>. A page is README.md, clients/<client>/README.md,
// docs/<page>.md, and every .md or .html file under docs/examples/. An example is named
// when its file name (langchain_tool.py) or its path (examples/grant) appears in a page as
// a whole name: examples/fanout does not name examples/fanout-cartpole, and
// clients/typescript/examples/grant does not name examples/grant.
//
// What ships: in a working copy that carries scripts/public-manifest.txt (the export's
// record of what is published), an example or a page counts only when a file of it is
// labeled core there; in the published repository, which carries no manifest, every file
// present ships. Excluded lists the examples that are not meant to be run, each with why.
package examplesnamed

import (
	"bufio"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Excluded holds the examples that need no page, and why. A new entry needs a reason a
// reader would accept: an example someone could run belongs on a page instead.
// Empty today: every shipped example is named (examples/internal, the Go packages the
// example programs share, is named in docs/example-programs.md).
var Excluded = map[string]string{}

// Manifest is the export's record of what is published, relative to the root.
const Manifest = "scripts/public-manifest.txt"

// Missing returns every shipped example under root that no shipped page names, sorted.
func Missing(root string) ([]string, error) {
	shipped, err := shippedFiles(root)
	if err != nil {
		return nil, err
	}
	examples := map[string]bool{}
	var pages []string
	for _, f := range shipped {
		switch {
		case strings.HasPrefix(f, "clients/python/examples/") && !strings.Contains(strings.TrimPrefix(f, "clients/python/examples/"), "/"):
			if !strings.HasPrefix(path.Base(f), "_") {
				examples[f] = true
			}
		case strings.HasPrefix(f, "examples/"):
			if name, _, ok := strings.Cut(strings.TrimPrefix(f, "examples/"), "/"); ok {
				examples["examples/"+name] = true
			}
		}
		if isPage(f) {
			pages = append(pages, f)
		}
	}
	var text strings.Builder
	for _, p := range pages {
		b, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(p)))
		if err != nil {
			return nil, err
		}
		text.Write(b)
		text.WriteByte('\n')
	}
	all := text.String()
	var missing []string
	for ex := range examples {
		if _, ok := Excluded[ex]; ok {
			continue
		}
		if !Named(all, ex) {
			missing = append(missing, ex)
		}
	}
	sort.Strings(missing)
	return missing, nil
}

func isPage(f string) bool {
	switch {
	case f == "README.md":
		return true
	case strings.HasPrefix(f, "clients/") && strings.Count(f, "/") == 2 && path.Base(f) == "README.md":
		return true
	case strings.HasPrefix(f, "docs/") && strings.Count(f, "/") == 1 && path.Ext(f) == ".md":
		return true
	case strings.HasPrefix(f, "docs/examples/") && (path.Ext(f) == ".md" || path.Ext(f) == ".html"):
		return true
	}
	return false
}

// Named reports whether text names the example ex as a whole name. A Python example is
// named by its file name; a directory under examples/ by examples/<name>, not preceded by
// another directory that makes it a different path (clients/python/, clients/typescript/,
// clients/mcp/, docs/).
func Named(text, ex string) bool {
	needle := ex
	python := strings.HasPrefix(ex, "clients/python/examples/")
	if python {
		needle = path.Base(ex)
	}
	for i := 0; ; {
		j := strings.Index(text[i:], needle)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(needle)
		i = start + 1
		if end < len(text) && nameByte(text[end]) || start > 0 && nameByte(text[start-1]) {
			continue
		}
		if python {
			return true
		}
		before := text[:start]
		if strings.HasSuffix(before, "python/") || strings.HasSuffix(before, "typescript/") ||
			strings.HasSuffix(before, "mcp/") || strings.HasSuffix(before, "docs/") {
			continue
		}
		return true
	}
}

// nameByte is a byte that continues a file or directory name.
func nameByte(c byte) bool {
	return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// shippedFiles lists the files that ship, relative to root with forward slashes: the core
// lines of the manifest when root has one, else every file under examples/,
// clients/python/examples/, clients/ and docs/ and README.md.
func shippedFiles(root string) ([]string, error) {
	f, err := os.Open(filepath.Join(root, Manifest))
	if err == nil {
		defer f.Close()
		var out []string
		s := bufio.NewScanner(f)
		for s.Scan() {
			label, file, ok := strings.Cut(strings.TrimSpace(s.Text()), " ")
			if ok && label == "core" {
				if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(file))); err == nil {
					out = append(out, file)
				}
			}
		}
		return out, s.Err()
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	var out []string
	if _, err := os.Stat(filepath.Join(root, "README.md")); err == nil {
		out = append(out, "README.md")
	}
	for _, dir := range []string{"examples", "clients", "docs"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if os.IsNotExist(err) && p == filepath.Join(root, dir) {
					return fs.SkipDir
				}
				return err
			}
			if d.IsDir() && (d.Name() == "node_modules" || d.Name() == "__pycache__") {
				return fs.SkipDir
			}
			if !d.IsDir() {
				rel, err := filepath.Rel(root, p)
				if err != nil {
					return err
				}
				out = append(out, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("examplesnamed: %w", err)
		}
	}
	return out, nil
}
