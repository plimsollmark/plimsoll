// Command publishflows writes the Python packages' publish workflows,
// .github/workflows/publish-<name>.yml, from one table (packages, below) and one template.
//
// PyPI's trusted publishing ties each project to one workflow file: the token a run gets
// covers only the projects whose publisher names that file, so one shared workflow's uploads
// of a second project were refused (crewai-plimsoll, v0.27.1, 2026-11-14). Each package
// therefore keeps a file of its own, and the files were copies that differed only in the
// package's names. A new package is one row here and `make publish-workflows`.
//
// Each file's leading comment is its own prose and is kept as it is; everything from `name:`
// on is generated. A new file gets a header naming its package. The actions' pins are read
// from the workflow files as they are, and must agree across them: Dependabot bumps every
// file in one pull request, which keeps them agreeing, and a pin edited in one file by hand
// fails the check. TestPublishWorkflowsAreGenerated, in this package, fails when a file is
// not what this writes, or when a publish workflow for PyPI has no row.
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"text/template"
)

// A Package is one PyPI project published from this repository.
type Package struct {
	Workflow    string // the file's stem and the workflow's name, which PyPI's trusted publisher names
	Dir         string // the directory python -m build builds
	Dist        string // the PyPI project
	VersionFile string // the file whose __version__ must say the release's version
	// RequiresClient: the package must require plimsoll-client of the same version.
	RequiresClient bool
	// Subject, Mismatch and VersionLabel are how the checks name the package; package rows
	// leave them empty and get "<dist>'s", "<dist>'s version" and the version file's
	// directory and name.
	Subject, Mismatch, VersionLabel string
}

// packages is the table: one row per PyPI project.
var packages = []Package{
	{Workflow: "publish-python", Dir: "clients/python", Dist: "plimsoll-client",
		VersionFile: "clients/python/src/plimsoll_client/_version.py",
		Subject:     "The client's", Mismatch: "the client version", VersionLabel: "_version.py"},
	{Workflow: "publish-langchain", Dir: "clients/python/langchain-plimsoll", Dist: "langchain-plimsoll",
		VersionFile: "clients/python/langchain-plimsoll/src/langchain_plimsoll/__init__.py", RequiresClient: true},
	{Workflow: "publish-crewai", Dir: "clients/python/crewai-plimsoll", Dist: "crewai-plimsoll",
		VersionFile: "clients/python/crewai-plimsoll/src/crewai_plimsoll/__init__.py", RequiresClient: true},
	{Workflow: "publish-agent-framework", Dir: "clients/python/agent-framework-plimsoll", Dist: "agent-framework-plimsoll",
		VersionFile: "clients/python/agent-framework-plimsoll/src/agent_framework_plimsoll/__init__.py", RequiresClient: true},
	{Workflow: "publish-smolagents", Dir: "clients/python/smolagents-plimsoll", Dist: "smolagents-plimsoll",
		VersionFile: "clients/python/smolagents-plimsoll/src/smolagents_plimsoll/__init__.py", RequiresClient: true},
	{Workflow: "publish-pydantic-ai", Dir: "clients/python/pydantic-ai-plimsoll", Dist: "pydantic-ai-plimsoll",
		VersionFile: "clients/python/pydantic-ai-plimsoll/src/pydantic_ai_plimsoll/__init__.py", RequiresClient: true},
}

// The actions the template uses, each written with the pin the workflow files agree on.
var actions = []string{"actions/checkout", "actions/setup-python", "actions/upload-artifact", "actions/download-artifact", "pypa/gh-action-pypi-publish"}

const body = `name: {{.Workflow}}

on:
  release:
    types: [published]
  workflow_dispatch:

permissions:
  contents: read

jobs:
  build:
    runs-on: ubuntu-24.04
    steps:
      - uses: {{pin "actions/checkout"}}
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: {{pin "actions/setup-python"}}
        with:
          python-version: "3.13"
      - name: {{.Subject}} version is a release tag, and the files are the tag's
        run: |
          version="$(python3 -c "import tomllib; print(tomllib.load(open('{{.Dir}}/pyproject.toml', 'rb'))['project']['version'])")"
          tag="v$version"
          if [ "$GITHUB_EVENT_NAME" = release ] && [ "$GITHUB_REF_NAME" != "$tag" ]; then
            echo "::error::release $GITHUB_REF_NAME does not match {{.Mismatch}} $version"
            exit 1
          fi
          git rev-parse -q --verify "refs/tags/$tag" >/dev/null || { echo "::error::no tag $tag"; exit 1; }
          git diff --quiet "$tag" HEAD -- clients/python || { echo "::error::clients/python differs from $tag"; exit 1; }
          grep -qx "__version__ = \"$version\"" {{.VersionFile}} ||
            { echo "::error::{{.VersionLabel}} does not say $version"; exit 1; }
{{- if .RequiresClient}}
          python3 -c "import tomllib, sys; d = tomllib.load(open('{{.Dir}}/pyproject.toml', 'rb'))['project']; sys.exit(0 if 'plimsoll-client==$version' in d['dependencies'] else '{{.Dist}} does not require plimsoll-client==$version')"
{{- end}}
      - run: python3 -m pip install --require-hashes --no-deps -r clients/python/build-requirements.txt
      - run: python3 -m build --no-isolation --outdir dist {{.Dir}}
      - uses: {{pin "actions/upload-artifact"}}
        with:
          name: dist
          path: dist/

  publish:
    needs: build
    runs-on: ubuntu-24.04
    environment:
      name: pypi
      url: https://pypi.org/p/{{.Dist}}
    permissions:
      id-token: write
    steps:
      - uses: {{pin "actions/download-artifact"}}
        with:
          name: dist
          path: dist/
      - uses: {{pin "pypa/gh-action-pypi-publish"}}
`

var usesLine = regexp.MustCompile(`(?m)^\s*(?:- )?uses: ([\w.-]+/[\w./-]+)@([0-9a-f]{40}) # (\S+)$`)

// pins reads each action's pin from the workflow files in dir: the commit and its version
// comment, which every file that uses the action must agree on.
func pins(dir string) (map[string]string, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.yml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)
	got, from := map[string]string{}, map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		for _, m := range usesLine.FindAllStringSubmatch(string(b), -1) {
			pin := m[1] + "@" + m[2] + " # " + m[3]
			if prev, ok := got[m[1]]; ok && prev != pin {
				return nil, fmt.Errorf("%s pins %s, %s pins %s: every workflow uses one pin per action", from[m[1]], prev, f, pin)
			}
			got[m[1]], from[m[1]] = pin, f
		}
	}
	for _, a := range actions {
		if got[a] == "" {
			return nil, fmt.Errorf("no workflow under %s pins %s", dir, a)
		}
	}
	return got, nil
}

// header is the file's leading comment, kept as it is; a new file gets one naming its package.
func header(existing []byte, p Package) []byte {
	if i := bytes.Index(existing, []byte("\nname: ")); i >= 0 && bytes.HasPrefix(existing, []byte("#")) {
		return existing[:i+1]
	}
	return []byte(fmt.Sprintf("# Publishes %s (%s) to PyPI through trusted publishing, from a workflow of its own\n"+
		"# (internal/publishflows says why), by the same release rules as publish-python.yml.\n#\n"+
		"# PyPI side: the %s project's trusted publisher (owner plimsollmark, repository plimsoll,\n"+
		"# workflow %s.yml, environment pypi). Actions are pinned by commit SHA.\n#\n"+
		"# Everything after this comment is written by internal/publishflows from its table (make\n"+
		"# publish-workflows); edit the table, not this file.\n", p.Dist, p.Dir, p.Dist, p.Workflow))
}

// render is the file for p, given its current content (nil for a new file) and the pins.
func render(p Package, existing []byte, pin map[string]string) ([]byte, error) {
	if p.Subject == "" {
		p.Subject = p.Dist + "'s"
	}
	if p.Mismatch == "" {
		p.Mismatch = p.Dist + "'s version"
	}
	if p.VersionLabel == "" {
		p.VersionLabel = filepath.Base(filepath.Dir(p.VersionFile)) + "/" + filepath.Base(p.VersionFile)
	}
	var out bytes.Buffer
	out.Write(header(existing, p))
	t, err := template.New(p.Workflow).Funcs(template.FuncMap{"pin": func(a string) string { return pin[a] }}).Parse(body)
	if err != nil {
		return nil, err
	}
	if err := t.Execute(&out, p); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// generate returns every publish workflow's path and content, as this writes them.
func generate(dir string) (map[string][]byte, error) {
	pin, err := pins(dir)
	if err != nil {
		return nil, err
	}
	out := map[string][]byte{}
	for _, p := range packages {
		path := filepath.Join(dir, p.Workflow+".yml")
		existing, err := os.ReadFile(path)
		if err != nil && !os.IsNotExist(err) {
			return nil, err
		}
		b, err := render(p, existing, pin)
		if err != nil {
			return nil, err
		}
		out[path] = b
	}
	return out, nil
}

func main() {
	files, err := generate(filepath.Join(".github", "workflows"))
	if err != nil {
		fmt.Fprintln(os.Stderr, "publishflows:", err)
		os.Exit(1)
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if old, err := os.ReadFile(p); err == nil && bytes.Equal(old, files[p]) {
			continue
		}
		if err := os.WriteFile(p, files[p], 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "publishflows:", err)
			os.Exit(1)
		}
		fmt.Println("publishflows: wrote", p)
	}
}
