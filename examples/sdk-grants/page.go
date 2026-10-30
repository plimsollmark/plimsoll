package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"math"
	"strings"
)

//go:embed page.html
var pageTemplate string

type pageData struct {
	Ev                              *evidence
	OpenAI, Anthropic, Plain        *runView
	Chat, OStream, Upload           *callView
	Refused, Messages, AStream      *callView
	OpenAIProfile, AnthropicProfile profileView
	AllPass                         bool
	Passed                          int
	OpenAIPin, AnthropicPin         pin
	OStreamSVG, AStreamSVG          template.HTML
	OpenAIJSON, AnthropicJSON       string
	KeyHits                         int // times a key the daemon held appears in any run's stored request and answer
}

// profileJSON writes a profile as an operator writes it in the grants file, in reading
// order (grants.json itself has its keys sorted).
func profileJSON(p profileView) string {
	type token struct {
		Type string `json:"type"`
		Env  string `json:"env"`
	}
	sdkEnv := map[string]string{}
	for _, kv := range p.SDKEnv {
		sdkEnv[kv[0]] = kv[1]
	}
	v := struct {
		BaseURL     string              `json:"base_url"`
		Allow       []string            `json:"allow"`
		PassHeaders []string            `json:"pass_headers,omitempty"`
		SDKEnv      map[string]string   `json:"sdk_env"`
		RouteBytes  map[string]int64    `json:"route_max_request_bytes,omitempty"`
		RouteTypes  map[string][]string `json:"route_content_types,omitempty"`
		MaxRequest  int64               `json:"max_request_bytes,omitempty"`
		Callers     []string            `json:"allowed_callers"`
		Token       token               `json:"token"`
	}{p.BaseURL, p.Allow, p.PassHeaders, sdkEnv, p.RouteBytes, p.RouteTypes, p.MaxRequest, p.Callers, token{"static", p.TokenEnv}}
	b, _ := json.MarshalIndent(map[string]any{p.Name: v}, "", "  ")
	return string(b)
}

func newPageData(ev *evidence) pageData {
	d := pageData{Ev: ev, AllPass: true}
	for i := range ev.Runs {
		r := &ev.Runs[i]
		switch r.Name {
		case "openai":
			d.OpenAI = r
		case "anthropic":
			d.Anthropic = r
		case "plain":
			d.Plain = r
		}
	}
	callOf := func(r *runView, name string) *callView {
		if r == nil {
			return &callView{}
		}
		for i := range r.Calls {
			if r.Calls[i].Name == name {
				return &r.Calls[i]
			}
		}
		return &callView{}
	}
	d.Chat, d.OStream, d.Upload, d.Refused = callOf(d.OpenAI, "chat"), callOf(d.OpenAI, "stream"), callOf(d.OpenAI, "upload"), callOf(d.OpenAI, "refused")
	d.Messages, d.AStream = callOf(d.Anthropic, "messages"), callOf(d.Anthropic, "stream")
	for _, p := range ev.Profiles {
		switch p.Name {
		case "openai":
			d.OpenAIProfile = p
		case "anthropic":
			d.AnthropicProfile = p
		}
	}
	for _, r := range ev.Runs {
		d.KeyHits += r.KeyInGuest
	}
	for _, c := range ev.Checks {
		if c.Pass {
			d.Passed++
		} else {
			d.AllPass = false
		}
	}
	for _, p := range ev.Pins {
		switch p.Name {
		case "openai":
			d.OpenAIPin = p
		case "anthropic":
			d.AnthropicPin = p
		}
	}
	d.OpenAIJSON, d.AnthropicJSON = profileJSON(d.OpenAIProfile), profileJSON(d.AnthropicProfile)
	d.OStreamSVG = streamSVG(d.OStream.Stream, "oa", "The OpenAI stream: when the stub wrote each piece and when the library handed it over")
	d.AStreamSVG = streamSVG(d.AStream.Stream, "an", "The Anthropic stream: when the stub wrote each event and when the library handed it over")
	return d
}

// streamSVG draws one stream as two rows of marks on one time axis: the stub's writes
// above, the library's arrivals below, each pair joined. A stream buffered whole would
// show every lower mark bunched at the right, after the last upper one.
func streamSVG(s *streamView, id, title string) template.HTML {
	if s == nil || len(s.Pieces) == 0 {
		return ""
	}
	const w, h, left, right = 560.0, 168.0, 96.0, 16.0
	span := s.WrittenSpan
	for _, p := range s.Pieces {
		span = math.Max(span, p.ArrivedMs)
	}
	for _, p := range s.Unpaired {
		span = math.Max(span, p.WrittenMs)
	}
	step := 500.0
	if span > 4000 {
		step = 1000
	}
	end := math.Ceil(span/step) * step
	if end == 0 {
		end = step
	}
	x := func(ms float64) float64 { return left + (w-left-right)*ms/end }
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %.0f %.0f" role="img" aria-labelledby="%sT" class="stream">`, w, h, id)
	fmt.Fprintf(&b, `<title id="%sT">%s</title>`, id, template.HTMLEscapeString(title))
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%.0f" height="%.0f" rx="12" fill="#f4f8f7"/>`, w, h)
	font := `font-family="Inter,Segoe UI,Arial,sans-serif"`
	fmt.Fprintf(&b, `<text x="12" y="48" %s font-size="13" font-weight="700" fill="#33415c">stub wrote</text>`, font)
	fmt.Fprintf(&b, `<text x="12" y="108" %s font-size="13" font-weight="700" fill="#0f766e">library got</text>`, font)
	fmt.Fprintf(&b, `<line x1="%.1f" y1="44" x2="%.1f" y2="44" stroke="#c9c7bf"/>`, left, w-right)
	fmt.Fprintf(&b, `<line x1="%.1f" y1="104" x2="%.1f" y2="104" stroke="#c9c7bf"/>`, left, w-right)
	for t := 0.0; t <= end+0.5; t += step {
		fmt.Fprintf(&b, `<line x1="%.1f" y1="128" x2="%.1f" y2="134" stroke="#8f8d86"/>`, x(t), x(t))
		anchor := "middle"
		if t == 0 {
			anchor = "start"
		} else if t >= end {
			anchor = "end"
		}
		fmt.Fprintf(&b, `<text x="%.1f" y="150" %s font-size="12" text-anchor="%s" fill="#6b6a65">%s</text>`, x(t), font, anchor, axisLabel(t))
	}
	fmt.Fprintf(&b, `<line x1="%.1f" y1="128" x2="%.1f" y2="128" stroke="#8f8d86"/>`, left, w-right)
	for _, p := range s.Pieces {
		fmt.Fprintf(&b, `<line x1="%.1f" y1="49" x2="%.1f" y2="99" stroke="#9aa7b8" stroke-width="1.5"/>`, x(p.WrittenMs), x(p.ArrivedMs))
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="44" r="5" fill="#33415c"><title>piece %d written at %.0f ms</title></circle>`, x(p.WrittenMs), p.N, p.WrittenMs)
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="104" r="5" fill="#0f766e"><title>piece %d handed over at %.0f ms</title></circle>`, x(p.ArrivedMs), p.N, p.ArrivedMs)
	}
	for _, p := range s.Unpaired {
		fmt.Fprintf(&b, `<circle cx="%.1f" cy="44" r="4.5" fill="#fff" stroke="#33415c" stroke-width="2"><title>write %d, %s, at %.0f ms: no piece for the library to hand over</title></circle>`, x(p.WrittenMs), p.N, template.HTMLEscapeString(p.Event), p.WrittenMs)
	}
	b.WriteString(`</svg>`)
	return template.HTML(b.String())
}

func axisLabel(ms float64) string {
	if ms == 0 {
		return "0 ms"
	}
	if math.Mod(ms, 1000) == 0 {
		return fmt.Sprintf("%.0f s", ms/1000)
	}
	return fmt.Sprintf("%.1f s", ms/1000)
}

var funcs = template.FuncMap{
	"short": func(s string) string {
		// A digest with a typed prefix (seccomp:sha256:, docker-image:sha256:, sha256:)
		// is shown by its hex alone.
		if i := strings.LastIndex(s, ":"); i >= 0 {
			s = s[i+1:]
		}
		if len(s) > 12 {
			return s[:12]
		}
		return s
	},
	"ms": func(v float64) string { return fmt.Sprintf("%.0f", v) },
	"mib": func(n int64) string {
		if n%(1<<20) == 0 {
			return fmt.Sprintf("%d MiB", n>>20)
		}
		return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
	},
	"kib": func(n int) string { return fmt.Sprintf("%.1f KiB", float64(n)/1024) },
	"fateClass": func(f string) string {
		switch f {
		case "passed":
			return "f-pass"
		case "replaced", "same", "added":
			return "f-broker"
		case "dropped":
			return "f-drop"
		default:
			return "f-bad"
		}
	},
	"fateWords": func(f string) string {
		return map[string]string{
			"passed":   "passed: the profile lists it",
			"replaced": "set by the broker, in place of the library's",
			"same":     "set by the broker (the same value)",
			"added":    "added by the broker",
			"dropped":  "dropped by the broker",
			"leaked":   "reached the API unlisted (a finding)",
			"altered":  "changed on the way (a finding)",
			"lost":     "listed but not passed (a finding)",
		}[f]
	},
	"secs":  func(v float64) string { return fmt.Sprintf("%.3f s", v) },
	"plus1": func(i int) int { return i + 1 },
	"duration": func(r *runView) string {
		return fmt.Sprintf("%.1f s", float64(r.Record.EndedMs-r.Record.StartedMs)/1000)
	},
	"sockWord": func(s string) string {
		if s == "allowed" {
			return "opens"
		}
		return "refused: " + s
	},
	"join":   strings.Join,
	"slice2": func(a, b *callView) []*callView { return []*callView{a, b} },
}

func render(ev *evidence) ([]byte, error) {
	tmpl, err := template.New("page").Funcs(funcs).Parse(pageTemplate)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	if err := tmpl.Execute(&b, newPageData(ev)); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
