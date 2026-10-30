package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

// census is Terminal-Bench 2 read as data against what a plimsoll session offers today.
// Nothing in the benchmark is run: each task's task.toml, grading script (tests/test.sh)
// and Dockerfile are read as text and matched against the rules below.
type census struct {
	Repo   string `json:"repo"`
	Commit string `json:"commit"`
	Tasks  int    `json:"tasks"`
	// Image: task.toml names a prebuilt image of its own (environment.docker_image). A
	// plimsoll daemon serves the one image its operator configured.
	Image int `json:"image"`
	// Internet: task.toml sets allow_internet = true. A plimsoll sandbox has no network.
	Internet int `json:"internet"`
	// Fetch: the grading script installs or downloads software (apt-get, apt, pip, npm,
	// curl, wget, uv or uvx), which needs the network at grading time.
	Fetch int `json:"fetch"`
	// Logs: the grading script writes /logs/verifier; the session's root file system is
	// read-only, so that path exists only if the image provides it.
	Logs int `json:"logs"`
	// Tests: the grading script reads /tests, staged at the root.
	Tests int `json:"tests"`
	// App: the task's Dockerfile works in /app (WORKDIR /app); a session works in /work.
	App int `json:"app"`
	// Runnable: names no image of its own and its grading script fetches nothing, the two
	// conditions a plimsoll session cannot meet any other way today.
	Runnable int `json:"runnable"`
}

var (
	tomlImage    = regexp.MustCompile(`(?m)^docker_image\s*=\s*"[^"]+"`)
	tomlInternet = regexp.MustCompile(`(?m)^allow_internet\s*=\s*true\b`)
	shFetch      = regexp.MustCompile(`(?m)\b(apt-get|apt|apk|pip3?|npm)\s+(-\S+\s+)*install\b|\b(curl|wget)\s|\buvx?\s`)
	shLogs       = regexp.MustCompile(`/logs/verifier`)
	shTests      = regexp.MustCompile(`(^|[\s"'=])/tests(/|\b)`)
	dockerApp    = regexp.MustCompile(`(?m)^\s*WORKDIR\s+/app/?\s*$`)
)

// takeCensus reads every task directory (one holding a task.toml) under root.
func takeCensus(root, repo, commit string) (census, error) {
	c := census{Repo: repo, Commit: commit}
	entries, err := os.ReadDir(root)
	if err != nil {
		return c, err
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			if _, err := os.Stat(filepath.Join(root, e.Name(), "task.toml")); err == nil {
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	for _, name := range names {
		dir := filepath.Join(root, name)
		toml, err := os.ReadFile(filepath.Join(dir, "task.toml"))
		if err != nil {
			return c, err
		}
		sh, err := os.ReadFile(filepath.Join(dir, "tests", "test.sh"))
		if err != nil && !os.IsNotExist(err) {
			return c, err
		}
		docker, err := os.ReadFile(filepath.Join(dir, "environment", "Dockerfile"))
		if err != nil && !os.IsNotExist(err) {
			return c, err
		}
		c.Tasks++
		image := tomlImage.Match(toml)
		fetch := shFetch.Match(sh)
		count(&c.Image, image)
		count(&c.Internet, tomlInternet.Match(toml))
		count(&c.Fetch, fetch)
		count(&c.Logs, shLogs.Match(sh))
		count(&c.Tests, shTests.Match(sh))
		count(&c.App, dockerApp.Match(docker))
		count(&c.Runnable, !image && !fetch)
	}
	if c.Tasks == 0 {
		return c, fmt.Errorf("no task directories under %s", root)
	}
	return c, nil
}

func count(n *int, yes bool) {
	if yes {
		*n++
	}
}
