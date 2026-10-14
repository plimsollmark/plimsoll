# The independent trial, first run (superseded)

This run's context leaked (below), so it was run again cleanly the same day; [the clean run](../README.md) is the one the page shows. This record is kept as it was, with links adjusted.

Three fresh agents, each a different Claude model, wrote a fleet adapter from
[PROMPT.md](../PROMPT.md): the platform's contract, its six judging rules, the injected client's
error shape and the description generated from the vendor's OpenAPI document. The trial was run
on 2026-10-14 through Claude Code's Agent tool, one agent per model, in the background.

| Agent | Model | Rounds | Final |
|---|---|---|---|
| [haiku](haiku/final.js) | claude-haiku-5-5 | 1 (kept after seeing the development result) | `round1.js` |
| [sonnet](sonnet/final.js) | claude-sonnet-5-5 | 1 (kept) | `round1.js` |
| [opus](opus/final.js) | claude-opus-5-5 | 1 (kept) | `round1.js` |

## Results

Judged like every other adapter on the page, through plimsolld over all six scenarios, by the
rules as they stand now (eight: the two added after the trial, "kept the contract's shapes"
and "the inventory is the vendor's", check obligations the contract already stated):

| Agent | Passed | Failed |
|---|---|---|
| Claude Opus | 6 of 6 | none |
| Claude Haiku | 5 of 6 | the overloaded vendor: the create was retried 4 times over about 1.5 s, then reported `unresolved`; the command never became an order |
| Claude Sonnet | 5 of 6 | the overloaded vendor: the same, 6 tries over about 1 s, two commands left unplaced |

Both failures are honest (`unresolved` is the contract's word for "I could not tell"), and
both are failures all the same: the vendor in that scenario stays overloaded for longer than
their retry budget, and nothing in the prompt said how long it would last.
[The rendered page](../../../../docs/examples/adapter/index.html) has every run's verdict and the
signed evidence.

The exact message each agent received after its first answer is
[round1-message.txt](round1-message.txt); all three were identical, since all three passed.
The development runner in [devscenario](../devscenario/main.go) now prints the rules as they
stand; at the time it printed six.

## What each agent could do

- **No tools.** The instruction forbids reading, searching, writing or running anything. The
  agents' transcripts were audited afterwards: each made only its two hand-back calls (one per
  round) and no tool call of any other kind.
- **One disclosed development scenario per round, up to three rounds.** After each answer the
  adapter was run once through the platform's harness against the simulated vendor in the
  nominal scenario ([devscenario](../devscenario/main.go), with the real generated client and a
  stand-in for the broker socket), and the harness's report and the six rules' outcomes were sent
  back verbatim. All three passed it on the first try and kept their adapter.
- **No example adapter.** None was given; an adapter is a few dozen lines, and an example would
  have been the answer.
- **Hidden from them by design:** the other four scenarios, and the further cases the platform
  holds back.

## What leaked, and what did not

Claude Code gives every subagent the repository's agent instructions and a git status. The
agents' context therefore also held this repository's `AGENTS.md` as it stood at the start of
that session, whose entry for this example names three of the five scenarios (a robot fault, an
overloaded vendor answering 503, a lost acknowledgement) and says the first adapter's defect was
re-sending a create; and a git status whose recent commit titles mention command IDs. It held no
code, nothing of the second adapter, nothing of the dropped-connection scenario, and nothing of
the held-back cases. The prompt itself already warned of lost answers, missing answers, 503s,
faults and the vendor's duplicate suppression by command ID, so the leak added little; but the
adapters were not written from the prompt alone, and this file says so. The Haiku agent's note on
keeping its adapter names the leaked scenarios.

## Fairness, as the trial was set up

The three agents had the same text, the same development scenario and the same number of rounds,
so their results are comparable with each other. They are not a model ranking: one task, one
sample each. They are not comparable with `adapter-v2.js` either, which was rewritten with the
harness and every scenario in view.
