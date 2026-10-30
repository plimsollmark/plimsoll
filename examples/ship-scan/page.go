package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html/template"
	"strings"
)

//go:embed page.html
var pageHTML string

// The two lines the page quotes from examples/squeeze/argon-scan.txt, the offline
// reconstruction of the hackathon's leak; a test checks the transcript still holds them.
const (
	argonFind  = "seeds.txt:2 (refuse): tmp/argon-scan/before/workspace/tasks/drone/view.mjs"
	argonClean = "clean: 13 files against set 9d537b8d0bc5d3d42ade48900cb164a7648ed55de6ad3bc46bade7ad5d837449"
)

var pageTemplate = template.Must(template.New("page").Funcs(template.FuncMap{
	"logline": func(l LogLine) (string, error) {
		raw, err := json.Marshal(l)
		return string(raw), err
	},
	"short": func(s string) string {
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	"count": func(calls []Call, expect string) int {
		n := 0
		for _, c := range calls {
			if c.Expect == expect {
				n++
			}
		}
		return n
	},
	"join": strings.Join,
}).Parse(pageHTML))

type pageData struct {
	*Evidence
	ArgonFind, ArgonClean string
}

// renderPage renders the page from the evidence alone.
func renderPage(ev *Evidence) ([]byte, error) {
	var b bytes.Buffer
	if err := pageTemplate.Execute(&b, pageData{Evidence: ev, ArgonFind: argonFind, ArgonClean: argonClean}); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
