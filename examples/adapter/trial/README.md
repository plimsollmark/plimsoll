# The independent trial

Three fresh agents, each a different Claude model, wrote a fleet adapter from
[PROMPT.md](PROMPT.md): the platform's contract, its judging rules as they then stood, the
injected client's error shape and the description generated from the vendor's OpenAPI document.
This is the second, clean run, on 2026-10-14; [the first run](first-run/README.md) leaked part
of the hidden test plan into the agents' context and is kept as history.

| Agent | Model | Rounds | Final | Result here |
|---|---|---|---|---|
| [haiku](haiku/) | claude-haiku-5-5 | 1, then KEEP | [round1.js](haiku/round1.js) | 5 of 6 scenarios |
| [sonnet](sonnet/) | claude-sonnet-5-5 | 2, then KEEP | [round2.js](sonnet/round2.js) | 5 of 6 scenarios |
| [opus](opus/) | claude-opus-5-5 | 2, then KEEP | [round2.js](opus/round2.js) | 6 of 6 scenarios |

`final.js` in each folder is the adapter that ran; the notes each agent wrote beside its code
and its later replies are in the same folder.

## How each agent was run

Each agent was a one-shot Claude Code session (`claude -p`) started in its own empty directory
outside this repository, `/tmp/plimsoll-clean-trial/<model>`, with:

- `--safe-mode`: every customization off, so no CLAUDE.md, no agent instructions, no memory, no
  hooks, no MCP servers;
- `--tools ""`: no tools at all, so nothing could be read, searched, written or run;
- the prompt text of [PROMPT.md](PROMPT.md), byte for byte the text the first run used.

Each later round was the same session resumed (`--resume`) with the same flags. The
development scenario's result ([round1-message.txt](round1-message.txt), and for the two agents
that revised, [round2-message.txt](round2-message.txt)) was sent back verbatim; all three agents
received the same text each round, since all passed it.

## The audit

The three session transcripts were checked afterwards: no tool call of any kind; the models
were claude-haiku-5-5, claude-sonnet-5-5 and claude-opus-5-5; none of this repository's text
(its agent instructions, the simulator, the second adapter, the scenario names) appears in them.
The one thing besides the prompt that reached the models is the session's environment note,
which states the working directory, so they could see the folder name
`/tmp/plimsoll-clean-trial/<model>`. That names the project and nothing about the task.

## Results

Judged like every other adapter on [the page](../../../docs/examples/adapter/index.html), through
plimsolld over all six scenarios (a seventh, a refused order, and an eighth, a vendor that never answers, were added on 15 October 2026; the page runs these adapters on both too, unseen, and all three pass them), by the eight rules (the two added after the first run,
"kept the contract's shapes" and "the inventory is the vendor's", check obligations the contract
already stated):

- Claude Opus: all six.
- Claude Haiku: five; it fails the overloaded vendor. It tries a create 4 times over about
  1.2 s, then honestly reports `unresolved`, and the command never becomes an order.
- Claude Sonnet: five; the same scenario the same way, 5 tries over about 1.5 s.

The overloaded vendor in that scenario stays down longer than those budgets; nothing in the
prompt said how long it would last. The pattern matches the first run exactly, so the first
run's leak made no difference to the outcome.

## Fairness, as the trial was set up

The three agents had the same text, the same development scenario and the same number of
rounds, so their results are comparable with each other. They are not a model ranking: one
task, one sample each. They are not comparable with `adapter-v2.js` either, which was rewritten
with the harness and every scenario in view, and repaired after reviews.
