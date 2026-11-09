package main

import (
	"fmt"
	"strings"
)

const (
	// account, namespace and profile are the values the operator wrote into the allow
	// list. The account ID is made up: 32 digits, the length of a Cloudflare account ID
	// and the pattern the published document gives the parameter.
	account   = "00000000000000000000000000000042"
	namespace = "support-agent"
	profile   = "customer-42"

	// memoryContent is what the first run stores. It appears in the guest's output and
	// in the fake API's store, and must appear in no trace row.
	memoryContent = "The customer wants replies in Spanish."
)

// head is the first line of every scene: the values the guest addresses the API with.
var head = fmt.Sprintf("var A = %q, NS = %q, ME = %q;\n", account, namespace, profile)

type sceneSpec struct {
	title  string
	note   string // what the run shows, for the page
	code   string
	expect func(scene) error
}

var scenes = []sceneSpec{
	{
		title: "Store a memory, recall it, read it back by its ID",
		note:  "One run stores a memory, asks the API to recall what it holds about the customer's language, and reads the memory back by the ID the recall returned. All three are routes the grant lists. The third shows what the trace does with a wildcard: the request named the memory's ID, and the trace keeps the allow entry, memories/*.",
		code: head + `memory.agent_memory_remember(A, NS, ME, {content: "` + memoryContent + `", sessionId: "chat-7"})
  .then(function (r) {
    console.log("stored " + r.result.id);
    globalThis.lastStored = r.result.id;
    return memory.agent_memory_recall(A, NS, ME, {query: "Which language does the customer want?"});
  })
  .then(function (r) {
    console.log("recalled: " + r.result.answer);
    return memory.agent_memory_memory_get(A, NS, ME, r.result.candidates[0].id);
  })
  .then(function (r) { console.log("read back by ID: " + r.result.content); },
        function (e) { console.log("failed: " + e.message); });
`,
		expect: func(s scene) error {
			return all(
				calls(s, "POST", "POST", "GET"),
				reached(s, 3),
				said(s, 0, "stored 01JFAKEMEM"),
				said(s, 1, "recalled: "+memoryContent),
				said(s, 2, "read back by ID: "+memoryContent),
			)
		},
	},
	{
		title: "A later run, in a fresh sandbox, recalls it",
		note:  "A new run starts a new JavaScript engine, so nothing the first run left in the sandbox is there. The memory is, because it was never in the sandbox: the API holds it, and this run recalls it.",
		code: head + `memory.agent_memory_recall(A, NS, ME, {query: "What language should replies use?"}).then(
  function (r) { console.log(r.result.count + " memory found: " + r.result.answer); },
  function (e) { console.log("failed: " + e.message); });
console.log("left over from the first run: " + (typeof globalThis.lastStored));
`,
		expect: func(s scene) error {
			return all(
				calls(s, "POST"),
				reached(s, 1),
				said(s, 0, "left over from the first run: undefined"),
				said(s, 1, "1 memory found: "+memoryContent),
			)
		},
	},
	{
		title: "Another customer's memory, through the client and around it",
		note:  "The same recall, for customer-43. The client plimsoll put in the sandbox refuses it before any request is made, since its copy of the allow list has no route for that profile. That check is the guest's own JavaScript, which hostile code can skip, so the code then calls the raw host function under the client. The broker, outside the sandbox, refuses that too and counts one denied call. No request reached the API.",
		code: head + `var Q = {query: "Which language does the customer want?"};
memory.agent_memory_recall(A, NS, "customer-43", Q).then(
  function (r) { console.log("client answered: " + JSON.stringify(r)); },
  function (e) {
    console.log("client refused: " + e.message);
    var raw = __coderunner_host_call(JSON.stringify({method: "POST",
      path: "/client/v4/accounts/" + A + "/agent-memory/namespaces/" + NS + "/profiles/customer-43/recall", body: Q}));
    console.log("broker answered: " + raw.status + " " + raw.body);
  });
`,
		expect: refused,
	},
	{
		title: "A route the key could reach and the grant does not list",
		note:  "The generated client has a function for every operation in the document, deleting a namespace among them. Whether the key may delete one is up to its Cloudflare permissions, which plimsoll does not see; the grant does not list the route, so the client and the broker refuse it, as in the third run.",
		code: head + `memory.agent_memory_namespace_delete(A, NS).then(
  function (r) { console.log("client answered: " + JSON.stringify(r)); },
  function (e) {
    console.log("client refused: " + e.message);
    var raw = __coderunner_host_call(JSON.stringify({method: "DELETE",
      path: "/client/v4/accounts/" + A + "/agent-memory/namespaces/" + NS}));
    console.log("broker answered: " + raw.status + " " + raw.body);
  });
`,
		expect: refused,
	},
	{
		// The needle is put together at run time, not written as one literal: the
		// runtime's execArgv holds this snippet's own source, so a scan for a literal
		// would find the scan itself (examples/grant says the same).
		title: "The guest looking for the key",
		note:  "The code searches every global of the engine and every function of the client for the key. One global, execArgv, holds all the source the engine was given, the injected client and the generated one included, so a key anywhere in that source would be named: the example's test plants one in a preamble and this same search names it. Here it finds nothing, because the key never leaves Go: the broker sets it on the request to the API after deciding the call is allowed.",
		code: `var needle = ["fake", "agent", "memory", "token", "held", "by", "the", "broker"].join("-");
function holds(v) { try { return String(v).indexOf(needle) >= 0; } catch (e) { return false; } }
var inGlobals = Object.getOwnPropertyNames(globalThis).filter(function (n) { return holds(globalThis[n]); });
var inClient = Object.keys(memory).filter(function (k) { return holds(memory[k]); });
console.log("functions on memory: " + Object.keys(memory).length);
console.log("globals holding the key: " + (inGlobals.length ? inGlobals.join(",") : "none"));
console.log("client functions holding the key: " + (inClient.length ? inClient.join(",") : "none"));
`,
		expect: func(s scene) error {
			return all(
				calls(s),
				reached(s, 0),
				said(s, 0, "functions on memory: "),
				said(s, 1, "globals holding the key: none"),
				said(s, 2, "client functions holding the key: none"),
			)
		},
	},
}

// refused is what scenes 3 and 4 must show: the client refuses, the broker refuses
// the same call made around the client, and nothing reaches the API.
func refused(s scene) error {
	err := all(calls(s), reached(s, 0), said(s, 0, "client refused: host api call not permitted"), said(s, 1, "broker answered: 403"))
	if err == nil && s.Denied != 1 {
		err = fmt.Errorf("the broker counted %d denied calls, want 1", s.Denied)
	}
	return err
}

func all(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// calls checks the trace holds exactly these methods, each answered 200.
func calls(s scene, methods ...string) error {
	if len(s.Calls) != len(methods) {
		return fmt.Errorf("the trace has %d calls, want %d", len(s.Calls), len(methods))
	}
	for i, row := range s.Calls {
		if row.Method != methods[i] || row.Status != 200 {
			return fmt.Errorf("trace row %d is %s -> %d, want %s -> 200", i+1, row.Method, row.Status, methods[i])
		}
	}
	return nil
}

func reached(s scene, n int) error {
	if len(s.Reached) != n {
		return fmt.Errorf("%d requests reached the API, want %d", len(s.Reached), n)
	}
	return nil
}

func said(s scene, line int, prefix string) error {
	if line >= len(s.Output) || !strings.HasPrefix(s.Output[line], prefix) {
		return fmt.Errorf("output line %d is not %q...: %q", line+1, prefix, s.Output)
	}
	return nil
}
