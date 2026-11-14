package main

// SARIF output for scan and scan-image: the OASIS Static Analysis Results Interchange
// Format, version 2.1.0, which GitHub code scanning, editors and other CI systems read.
// docs/ship-scan.md ("SARIF output") is the operator's account.
//
// A SARIF file is made to be uploaded, so it names an entry by its label and a find by
// its location, never by what was found: no withheld value, no file content, and no text
// of a scanned file but its path. A path in which the scan finds a withheld value (a file
// named after a seed) is not named either: its results point at the nearest directory
// above it whose path holds none. Before the file is written, the whole of it is scanned
// against the set, and a find there (a label, an image's layer name or a path given on
// the command line holding a value) refuses to write it. The set's digest is not stated:
// for a set of a few short values it can be brute-forced as the values can.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/plimsollmark/plimsoll/internal/withheld"
)

const (
	sarifVersion = "2.1.0"
	sarifSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	sarifInfo    = "https://github.com/plimsollmark/plimsoll/blob/main/docs/ship-scan.md"
)

// The rules, by their index in the driver's rules.
const (
	ruleFind = iota
	ruleUnreadable
)

var sarifRules = []sarifRule{
	ruleFind: {
		ID:               "find",
		Name:             "WithheldMaterialFound",
		ShortDescription: sarifText{"Withheld material is in what ships."},
		FullDescription: sarifText{"An entry of the operator's withheld set (a harness file, a hidden answer, a held-out seed) " +
			"was found in a file, as the ship scan finds it in a call: a file whole, a value as whole runs of letters and " +
			"digits in any letter case, as written, escaped or in base64, or a source file's distinctive lines."},
		Help: sarifText{"Remove the material from what ships, or rebuild the image without it. The result names the entry by " +
			"its label, never by its value. docs/ship-scan.md describes the scan."},
		DefaultConfiguration: sarifConfig{"error"},
	},
	ruleUnreadable: {
		ID:               "unreadable",
		Name:             "NotReadWhole",
		ShortDescription: sarifText{"A file was not read whole."},
		FullDescription: sarifText{"The scan could not read all of a file: an archive past the scan's bounds or in a format " +
			"it does not read (xz, zstd, 7z, rar, an encrypted zip member), or a file of an image larger than 64 MiB. " +
			"Withheld material in the unread part would not be found."},
		Help: sarifText{"Review the file. For an image, record reviewed files with plimsoll-withheld known-unreadable; that " +
			"acknowledges the unread bytes, it does not prove they hold no withheld material."},
		DefaultConfiguration: sarifConfig{"warning"},
	},
}

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool       `json:"tool"`
	Artifacts  []sarifArtifact `json:"artifacts,omitempty"`
	Results    []sarifResult   `json:"results"`
	ColumnKind string          `json:"columnKind"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string      `json:"id"`
	Name                 string      `json:"name"`
	ShortDescription     sarifText   `json:"shortDescription"`
	FullDescription      sarifText   `json:"fullDescription"`
	Help                 sarifText   `json:"help"`
	DefaultConfiguration sarifConfig `json:"defaultConfiguration"`
}

type sarifText struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifArtifact struct {
	Location    *sarifArtifactLocation `json:"location,omitempty"`
	ParentIndex *int                   `json:"parentIndex,omitempty"`
	Description *sarifText             `json:"description,omitempty"`
	Roles       []string               `json:"roles,omitempty"`
}

type sarifArtifactLocation struct {
	URI   string `json:"uri,omitempty"`
	Index *int   `json:"index,omitempty"`
}

type sarifResult struct {
	RuleID     string            `json:"ruleId"`
	RuleIndex  int               `json:"ruleIndex"`
	Level      string            `json:"level"`
	Message    sarifText         `json:"message"`
	Locations  []sarifLocation   `json:"locations"`
	Properties map[string]string `json:"properties,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
}

// sarifPlace is where one find or unreadable part is, as the scan read it.
type sarifPlace struct {
	layer string // the layer's member name in an image archive; "" for a directory scan
	path  string // the file's path (in the layer, for an image); "" for a layer not read
	part  string // withheld.PartContent, PartPath or PartLinkTarget
	line  int    // the first line the entry is found on, 0 when none is known
}

// sarifWriter gathers one scan's results.
type sarifWriter struct {
	set       *withheld.Set
	run       sarifRun
	image     int            // the image's artifact index, -1 for a directory scan
	artifacts map[string]int // "layer\x00path" -> artifact index
	hidden    map[string]string
}

func newSARIF(set *withheld.Set) *sarifWriter {
	driver := sarifDriver{Name: "plimsoll-withheld", InformationURI: sarifInfo, Rules: sarifRules}
	// A release's version; a build from a checkout states none rather than v0.0.0.
	if bi, ok := debug.ReadBuildInfo(); ok && strings.HasPrefix(bi.Main.Version, "v") && !strings.HasPrefix(bi.Main.Version, "v0.0.0") {
		driver.Version = bi.Main.Version
	}
	return &sarifWriter{
		set:       set,
		run:       sarifRun{Tool: sarifTool{Driver: driver}, Results: []sarifResult{}, ColumnKind: "unicodeCodePoints"},
		image:     -1,
		artifacts: map[string]int{},
		hidden:    map[string]string{},
	}
}

// forImage makes the run's root artifact the image read, which the operator named.
func (w *sarifWriter) forImage(what string) {
	w.image = len(w.run.Artifacts)
	w.run.Artifacts = append(w.run.Artifacts, sarifArtifact{Description: &sarifText{what}, Roles: []string{"analysisTarget"}})
}

// hide records that the path of a file in layer holds a withheld value, so no result
// names it: each points at the nearest directory above it whose path holds none.
func (w *sarifWriter) hide(ctx context.Context, layer, p string) error {
	key := layer + "\x00" + p
	if _, ok := w.hidden[key]; ok {
		return nil
	}
	dir := p
	for {
		next := path.Dir(dir)
		if next == dir || next == "." || next == "/" {
			// No directory above it is clean: the current one, or the root.
			dir = ""
			if strings.HasPrefix(p, "/") {
				dir = "/"
			}
			break
		}
		dir = next
		res, err := w.set.Scan(ctx, []withheld.Part{{Where: "dir", Data: []byte(dir)}})
		if err != nil {
			return err
		}
		if len(res.Found) == 0 && len(res.Incomplete) == 0 {
			break
		}
	}
	w.hidden[key] = dir
	return nil
}

// location is a result's location: the file, or for a hidden path the directory above it.
func (w *sarifWriter) location(pl sarifPlace) (sarifLocation, bool) {
	p, region := pl.path, (*sarifRegion)(nil)
	dir, hidden := w.hidden[pl.layer+"\x00"+pl.path]
	if hidden {
		p = dir
	} else if pl.line > 0 {
		region = &sarifRegion{StartLine: pl.line}
	}
	loc := sarifArtifactLocation{URI: sarifURI(p)}
	if w.image >= 0 {
		idx := w.artifact(pl.layer, p)
		loc.Index = &idx
		if p == "" {
			loc.URI = sarifURI(pl.layer)
		}
	}
	return sarifLocation{PhysicalLocation: sarifPhysicalLocation{ArtifactLocation: loc, Region: region}}, hidden
}

// artifact is the index of the artifact for path in layer, nested in its layer's, which
// is nested in the image's; made on first use.
func (w *sarifWriter) artifact(layer, p string) int {
	key := layer + "\x00" + p
	if i, ok := w.artifacts[key]; ok {
		return i
	}
	parent := w.image
	switch {
	case layer != "" && p != "":
		parent = w.artifact(layer, "")
	case layer != "":
		p = layer
	}
	i := len(w.run.Artifacts)
	pi := parent
	w.run.Artifacts = append(w.run.Artifacts, sarifArtifact{Location: &sarifArtifactLocation{URI: sarifURI(p)}, ParentIndex: &pi})
	w.artifacts[key] = i
	return i
}

func (w *sarifWriter) inLayer(pl sarifPlace) string {
	if pl.layer == "" {
		return ""
	}
	return " of layer " + withheld.CleanWhere(pl.layer)
}

// find adds one result for an entry found at pl.
func (w *sarifWriter) find(f withheld.Finding, pl sarifPlace) {
	loc, hidden := w.location(pl)
	entry := fmt.Sprintf("Withheld entry %s (%s mode)", f.Label, f.Mode)
	var msg string
	switch {
	case pl.part == withheld.PartPath:
		msg = entry + " is in the path of a file under this directory" + w.inLayer(pl) + "; that path is not named here, since it holds the entry."
	case hidden:
		msg = entry + " was found in a file under this directory" + w.inLayer(pl) + " whose path holds a withheld value; that path is not named here."
	case pl.part == withheld.PartLinkTarget:
		msg = entry + " is in the target of this symbolic link" + w.inLayer(pl) + "."
	default:
		msg = entry + " was found in this file" + w.inLayer(pl) + "."
	}
	w.run.Results = append(w.run.Results, sarifResult{
		RuleID: sarifRules[ruleFind].ID, RuleIndex: ruleFind, Level: "error",
		Message:    sarifText{msg},
		Locations:  []sarifLocation{loc},
		Properties: map[string]string{"label": f.Label, "mode": string(f.Mode)},
	})
}

// unreadable adds one result for a part not read whole.
func (w *sarifWriter) unreadable(in withheld.Incomplete, pl sarifPlace) {
	loc, hidden := w.location(pl)
	what := "This file" + w.inLayer(pl)
	switch {
	case pl.path == "":
		what = "This layer"
	case hidden:
		what = "A file under this directory" + w.inLayer(pl) + ", whose path holds a withheld value and is not named here,"
	}
	w.run.Results = append(w.run.Results, sarifResult{
		RuleID: sarifRules[ruleUnreadable].ID, RuleIndex: ruleUnreadable, Level: "warning",
		Message:    sarifText{what + " was not read whole: " + in.Bound.Text() + "."},
		Locations:  []sarifLocation{loc},
		Properties: map[string]string{"reason": string(in.Bound)},
	})
}

// bytes is the SARIF file, scanned against the set first: a find in it is an error, and
// nothing is written.
func (w *sarifWriter) bytes(ctx context.Context) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(sarifLog{Schema: sarifSchema, Version: sarifVersion, Runs: []sarifRun{w.run}}); err != nil {
		return nil, err
	}
	res, err := w.set.Scan(ctx, []withheld.Part{{Where: "the SARIF report", Data: buf.Bytes()}})
	if err != nil {
		return nil, err
	}
	if len(res.Found) > 0 {
		labels := make([]string, len(res.Found))
		for i, f := range res.Found {
			labels[i] = f.Label
		}
		return nil, fmt.Errorf("the SARIF report would hold withheld %s (a label, a layer's name or a path given on "+
			"the command line holds it); nothing written", strings.Join(labels, ", "))
	}
	if len(res.Incomplete) > 0 {
		return nil, errors.New("the SARIF report could not be scanned whole against the set; nothing written")
	}
	return buf.Bytes(), nil
}

// sarifURI is p as a URI reference: every byte but an unreserved one (RFC 3986 section
// 2.3) and the path separator percent-encoded, so a ":" in a first segment is not read
// as a scheme; an absolute path becomes a file URI, and an empty one the current
// directory.
func sarifURI(p string) string {
	if p == "" {
		return "."
	}
	var b strings.Builder
	if strings.HasPrefix(p, "/") {
		b.WriteString("file://")
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' || c == '-' || c == '.' || c == '_' || c == '~' || 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

// firstLines is, for each entry found in a line of content on its own, the first such
// line, keyed by label and mode. A value occupies whole runs of letters and digits, which
// no line break is part of, so a value written in a line, or escaped there, is found in
// it, and so is one in a line of wrapped base64 (each line holds whole groups of four);
// one found only across lines (base64 split mid-value, an archive) has no line.
func firstLines(ctx context.Context, set *withheld.Set, content []byte) (map[string]int, error) {
	lines := bytes.Split(content, []byte("\n"))
	parts := make([]withheld.Part, len(lines))
	for i, l := range lines {
		parts[i] = withheld.Part{Where: strconv.Itoa(i + 1), Data: l}
	}
	res, err := set.Scan(ctx, parts)
	if err != nil {
		return nil, err
	}
	out := map[string]int{}
	for _, f := range res.Found {
		n, err := strconv.Atoi(f.Where[0])
		if err != nil {
			return nil, err
		}
		out[f.Label+"\x00"+string(f.Mode)] = n
	}
	return out, nil
}
