package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"strings"
)

//go:embed page.html
var pageHTML string

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	// tail drops the route's shared start, so a table of long routes reads at a glance.
	"tail": func(route string) string {
		const start = "/client/v4/accounts/"
		return strings.TrimPrefix(route, start)
	},
	"inc": func(i int) int { return i + 1 },
	"count": func(reqs []seenRequest, cred string) int {
		n := 0
		for _, r := range reqs {
			if r.Credential == cred {
				n++
			}
		}
		return n
	},
	"refusedRuns": func(scenes []scene) int {
		n := 0
		for _, s := range scenes {
			n += s.Denied
		}
		return n
	},
	"lines": func(s []string) string { return strings.Join(s, "\n") },
}).Parse(pageHTML))

// renderPage renders the page from the run's evidence alone.
func renderPage(ev *evidence) ([]byte, error) {
	var b bytes.Buffer
	if err := pageTemplate.Execute(&b, ev); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
