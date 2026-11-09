package main

import (
	"encoding/json"
	"fmt"
	"sort"
)

// The design document is everything a building run holds the same for every rebuild, written
// out before the run: the job, the system prompt, each group's brief and its after-session
// question, the tools, the budgets, the request settings, the scrambled recipes, the code checks
// agents.json applies, and the digest of every course file. -design writes it; a run records its
// SHA-256 in run.json, and -design-sha256 refuses to start a run whose design is not the one
// named, so a run is tied to a design fixed before it.

const designFormat = "plimsoll.squeeze-design/1"

func designDoc(job *Job, api, model string) map[string]any {
	briefs, questions, scrambled, prompts := map[string]string{}, map[string]string{}, map[string]string{}, map[string]string{}
	for _, c := range job.Courses {
		prompts["drone-"+c.ID] = brief(c.ID, "")
		for _, g := range c.Groups {
			if g.Build == 0 {
				continue
			}
			recipe := c.recipeFor(g)
			briefs[c.ID+"/"+g.ID] = brief(c.ID, recipe)
			questions[c.ID+"/"+g.ID] = afterQuestion(recipe)
			if g.Scramble {
				scrambled[c.ID+"/"+g.ID] = recipe
			}
		}
	}
	files := map[string]string{}
	var walk func(dir string)
	walk = func(dir string) {
		es, _ := courseFS.ReadDir(dir)
		for _, e := range es {
			p := dir + "/" + e.Name()
			if e.IsDir() {
				walk(p)
				continue
			}
			b, _ := courseFS.ReadFile(p)
			files[p] = digest(b)
		}
	}
	walk("course")
	// What the shared baseline names by the item patterns itself: the floor every group starts
	// from, which agents.json leaves out by passing over the baseline's identifiers.
	baselineNames := map[string][]string{}
	for _, c := range job.Courses {
		if l, ok := courseItems(c); ok {
			baselineNames[c.ID] = itemsNamed(l.Items, stripComments(courseFile("baselines/stabilizer.js")), nil)
		}
	}
	r := job.Rebuild
	request := map[string]any{"api": api, "model": model, "max_tokens": r.MaxTokens}
	switch api {
	case "messages":
		request["thinking"], request["thinking_display"], request["cache"] = "adaptive", "summarized", "automatic (top-level cache_control, 5-minute)"
		request["effort"], request["temperature"], request["anthropic_version"] = r.Effort, "not set", anthropicVersion
		request["refusal_fallback"] = "none: a refused turn ends the rebuild, so every answer is the named model's"
	default:
		request["temperature"], request["cache"] = 0.2, "none"
	}
	return map[string]any{
		"format": designFormat,
		"job":    job,
		"system": systemPrompt,
		"tools":  rebuildTools(r.FlightsPerFly),
		"budget": map[string]any{"turns": r.Turns, "fly_calls": r.FlyCalls, "flights_per_fly": r.FlightsPerFly, "prompt_cap": r.PromptCap,
			"max_tokens": r.MaxTokens, "cpu_budget_seconds": cpuBudgetSeconds, "max_tool_output_bytes": maxToolOutput},
		"request":         request,
		"prompts":         prompts,
		"briefs":          briefs,
		"after_questions": questions,
		"ask_after":       r.AskAfter,
		"scramble":        map[string]any{"seed": scrambleSeed, "recipes": scrambled},
		"detectors": map[string]any{"rng": rngPattern.String(), "generator_constant": generatorConstant.String(),
			"comments_removed": []string{blockComment.String(), lineComment.String()}, "quoted_min_words": quotedMin,
			"recipe_items": map[string]any{
				"measure":    "recipe words named in code: an item counts when one of its patterns, case ignored, matches an identifier of the final controller's code, comments removed, that baselines/stabilizer.js does not hold",
				"identifier": identifier.String(), "baseline_identifiers_left_out": true, "baseline_names": baselineNames}},
		"course_files": files,
	}
}

// designBytes is the design document as -design writes it and its digest is taken over.
func designBytes(job *Job, api, model string) ([]byte, error) {
	b, err := json.MarshalIndent(designDoc(job, api, model), "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// checkDesign refuses a run whose design is not the one named.
func checkDesign(job *Job, api, model, want string) (string, error) {
	b, err := designBytes(job, api, model)
	if err != nil {
		return "", err
	}
	got := digest(b)
	if want != "" && got != want {
		return got, fmt.Errorf("this run's design is %s, not the %s named by -design-sha256 (write it with -design and compare)", got, want)
	}
	return got, nil
}

// sortedKeys is a map's keys in order.
func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
