# The fleet adapter contract

A vendor adapter is one JavaScript file, loaded with `require`, that exports four
functions. The platform's harness calls them; the adapter reaches the vendor's API only
through the `fleet` client the run injects (the typed methods listed in the generated
description, plus `fleet.get`, `fleet.post`, `fleet.put`, `fleet.patch`, `fleet.del` and
`fleet.call` on raw paths). There is no other network path, and the adapter never
handles a credential.

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
  // opts.maxPolls bounds the reads (default 50), failed reads included. A failed mission
  // is reported, never retried; a transient vendor error (a 503) is retried with a short
  // pause, within the same bound.
  async wait(missionId, opts) {},

  // Cancel the mission; the robot stops where it is.
  async cancel(missionId) {},
};
```

The harness (`harness.js`) runs the commands in `plan.json`, which the platform writes for
each run (each command has an ID, a robot and a target; one is marked to be cancelled):

```
node harness.js <scenario> <adapter file>
```

It prints one line, `ADAPTER-REPORT {...}`: every value the adapter returned, as it returned
it (both inventories; for each command, what dispatch returned or threw, and what wait returned
under the read budget it was given). The harness judges nothing. It runs in the same process as
the adapter, so its report is the adapter's claim, not evidence.

The verdict is made on the platform's host, after the run, from what the adapter cannot write:
the plan, the vendor's ledger (every order the vendor accepted, with its command ID, robot,
target, every state it entered and where the robot stood when it ended) and the vendor's own
record of its robots; the report is checked against them. Eight rules, the same for every
scenario:

| Rule | Holds when |
|---|---|
| ran to the end | the harness ran every step: the adapter loaded, exported the four functions, and no call hung |
| kept the contract's shapes | every value returned has the shape above: inventory entries with an id, a status of `idle`, `moving` or `fault` and a numeric battery; a mission id, or an Error coded `refused` or `unresolved`; from every dispatched command's wait, a state of `done`, `failed`, `cancelled` or `timeout` with a read count within `maxPolls`, and no more status reads of the mission reaching the vendor than `maxPolls` (the vendor counts them) |
| the inventory is the vendor's | each inventory lists exactly the vendor's robots, and the last, the run's final call, matches the vendor's record of each one's status and battery |
| one order per command | each command became exactly one order on the vendor's ledger |
| the right robot and target | every order on the ledger carries its command's robot and target |
| ended as it should | each order ended done, or failed where the scenario faults its robot, or cancelled where the platform cancelled it; an order the vendor answers nothing about is not judged |
| robot at the target | every order the vendor marks done left its robot at the command's target |
| the report is true | the mission and state the adapter reported for each command are the vendor's, its read count is no lower than the reads the vendor served, a command the vendor refused is reported as an Error coded `refused`, and a command the vendor holds is never reported as anything but its mission or an Error coded `unresolved` |

| Scenario | What the vendor does |
|---|---|
| `nominal` | three idle robots; every order can complete |
| `fault` | robot r2 faults two steps into its order |
| `overload` | the next four requests after the first order answer 503 |
| `lost_ack` | r2's first order is accepted and started, but its answer is a 503 |
| `dropped` | r2's first order is accepted and started, then the connection closes with no answer (the broker answers the adapter 502) |
| `server_error` | r2's first order is accepted and started, but its answer is a 500 |
| `refused` | r3 is in fault before the run starts, and the vendor refuses every order for it with a 409 |
| `silent` | r2's first order is accepted and started, then the vendor's gateway answers 504 to every request about r2 (an order for it, a repeat, a read of r2, a read or cancel of its orders) and does nothing; the fleet list is still answered |

A 409 from the vendor's create means one of two things, which its body tells apart: the robot
cannot take orders (`{"error": "robot is in fault"}`, as in `refused`: the contract's answer is
an Error coded `refused`), or the `command_id` already names an order for another robot or
target (`{"error": "command_id already names an order for another robot or target"}`).

The platform's broker stands between the adapter and the vendor. After the vendor answers 503 or
429, the broker's circuit breaker answers further calls 503 itself, without reaching the vendor,
for the vendor's Retry-After (at most 30 seconds); after a 503 it asks the vendor's health route
about once a second and lets calls through again as soon as that answers. A call the broker shed
never reached the vendor, so retrying a create with the same `command_id` is safe, and an adapter
that stops retrying a 503 sooner can leave a command with no order (in `overload`, it does).

In `silent` nothing the adapter can ask about r2's order is answered, so its outcome stays unknown
to the end: the contract's answer is an Error coded `unresolved`, within the run's time (the
harness stops a run that has not finished after 75 seconds). The order's mission is also an
honest answer, if the adapter can find it another way.
