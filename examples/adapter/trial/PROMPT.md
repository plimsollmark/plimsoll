# The prompt the independent agents were given

The text below the line was given, unchanged, to two sets of three fresh agents (Claude Haiku,
Sonnet and Opus). In [the clean run](README.md), each started as a one-shot Claude Code
session in an empty directory with every customization off (`--safe-mode`) and no tools
(`--tools ""`), so the text below was all it was given, apart from the name of its working directory
(`/tmp/plimsoll-clean-trial/<model>`), which the session's environment note shows. In [the first run](first-run/README.md),
the agents also received this repository's agent instructions, which named three of the hidden
scenarios. The text is the platform's contract, its judging rules as they stood then (six), the
injected client's error shape, and the description generated from the vendor's OpenAPI
document 2.4.0.

---

You are writing a vendor adapter for a robot-fleet platform. This is a closed-book task:
work only from this message, and do not use any tools (do not read, search, write or run
anything). Using a tool would invalidate the result. Reply with the complete file in one
```js block, then at most five lines on the decisions you made.

Write `adapter.js`, a CommonJS module for Node 22, implementing the contract below against the
vendor API described after it. Use only the injected `fleet` client; do not import or require
anything. The platform runs it inside a sandbox with no network except that client.

## Contract

```js
module.exports = {
  // Every robot the vendor knows, as [{ id, status, battery }].
  // status is one of "idle", "moving", "fault".
  async inventory() {},

  // Send robot `robotId` to target `{ x, y }` as the platform's command `commandId`,
  // and return the vendor's mission id for that command. One command is at most one
  // order: whatever the vendor answers (an error, a lost answer, no answer at all), the
  // adapter must never put a second order on the vendor for it, and the mission it
  // returns must be the one this command created. When it cannot tell whether the
  // vendor took the order, it throws an Error whose code is "unresolved"; when the
  // vendor refused it, one whose code is "refused".
  async dispatch(robotId, target, commandId) {},

  // Poll the mission until it ends. Returns { state, polls } with state one of
  // "done", "failed", "cancelled" or "timeout", and polls the number of status reads.
  // opts.maxPolls bounds the reads (default 50). A failed mission is reported, never
  // retried; a transient vendor error (a 503) is retried with a short pause.
  async wait(missionId, opts) {},

  // Cancel the mission; the robot stops where it is.
  async cancel(missionId) {},
};
```

## How the platform judges an adapter

The platform's harness calls your functions with its own commands and records what you return.
That record is your claim. The verdict is made afterwards from the vendor's own ledger of every
order it accepted, by six rules, the same in every situation:

- ran to the end: every call returned or threw, and the shapes above were kept
- one order per command: each command became exactly one order on the vendor's ledger
- the right robot and target: every order carries its command's robot and target
- ended as it should: each order ended done, or failed where the robot faulted, or cancelled where the platform cancelled it
- robot at the target: every order the vendor marks done left its robot at the command's target
- the report is true: the mission and state you reported for each command are the vendor's

## The injected client

`fleet` has the typed methods listed below, plus `fleet.get(path)`, `fleet.post(path, body)`,
`fleet.put`, `fleet.patch`, `fleet.del` and `fleet.call(method, path, body)`. Each returns a
promise of the decoded JSON body. A call the vendor answers with a status outside 2xx rejects
with an Error whose message is `host api <status>: <body>`; when no answer reaches the platform
(the connection failed or closed), the status is 502. A call to an operation the platform did
not grant rejects with `host api call not permitted by sandbox capability: <method> <path>`.

## The vendor API, as generated from its OpenAPI document

```
Fleet Vendor API (v2.4.0).
Agent code reaches it through the brokered `fleet.*` client; only the operations
below are permitted. Every call is allow-listed and gets a per-run token injected
host-side, so the code never handles a credential.

  fleet.health()  ->  GET /health
      Report whether the fleet service is accepting requests: {ok, robots}.
  fleet.getMission(id)  ->  GET /missions/{id}
      Get a mission: {id, robot, command_id, status (queued, running, done, failed or cancelled), target, progress, error}.
  fleet.cancelMission(id)  ->  POST /missions/{id}/cancel
      Cancel a mission: a running one stops its robot where it is and the robot starts its next queued mission; a queued one never runs; a finished one is unchanged. Answers the mission, as getMission does.
  fleet.listRobots()  ->  GET /robots
      List the fleet's robots: {robots: [{id, status, battery, pose, mission}]}, status one of idle, moving or fault.
  fleet.getRobot(id)  ->  GET /robots/{id}
      Get one robot: {id, status (idle, moving or fault), battery, pose: {x, y}, mission (its running mission's id, if any)}.
  fleet.decommissionRobot(id)  ->  DELETE /robots/{id}
      Remove a robot from the fleet permanently.
  fleet.updateFirmware(id, body)  ->  POST /robots/{id}/firmware
      Install a firmware image on a robot.
  fleet.createMission(id, body)  ->  POST /robots/{id}/missions
      Send a robot to a target position: body {target: {x, y}, command_id}; answers {mission_id, robot, status, command_id}, 201 for a new mission. A robot runs one mission at a time and queues the rest. command_id (optional, 8 to 64 letters, digits, - or _) is the caller's name for the order: a create repeated with a command_id already accepted answers with that original mission instead of a new one, or 409 if the robot or target differ.
```
