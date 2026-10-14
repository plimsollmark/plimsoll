# The prompt the first adapter was written from

This is the prompt `adapter-v1.js` was written from: the platform's contract and the
description generated from the vendor's OpenAPI document, as both stood when it was
written (vendor document 2.3.0). The AI that wrote it was the one building this example,
in the same session, so it also knew the harness; the adapter is not an independent
agent's answer, and it predates the lost-acknowledgement scenario. The contract and the
vendor document have changed since (CONTRACT.md: the command ID, and verdicts made from
the vendor's ledger). The description lists every operation the vendor exposes, eight of
them; the grant the run carries allows six (the operator never granted
`decommissionRobot` and `updateFirmware`), and the broker holds that line whatever the
code was told.

---

Write `adapter.js`, a CommonJS module for Node 22, implementing the contract below
against the vendor API described after it. Use only the injected `fleet` client; do not
import anything else. Report a failed mission as `failed`; retry a transient vendor
error (a 503) with a short pause, a bounded number of times.

## Contract

```js
module.exports = {
  // Every robot the vendor knows, as [{ id, status, battery }].
  // status is one of "idle", "moving", "fault".
  async inventory() {},

  // Send robot `robotId` to target `{ x, y }`. Returns the vendor's mission id.
  async dispatch(robotId, target) {},

  // Poll the mission until it ends. Returns { state, polls } with state one of
  // "done", "failed", "cancelled" or "timeout", and polls the number of status reads.
  // opts.maxPolls bounds the reads (default 50). A failed mission is reported, never
  // retried; a transient vendor error (a 503) is retried with a short pause.
  async wait(missionId, opts) {},

  // Cancel the mission; the robot stops where it is.
  async cancel(missionId) {},
};
```

## The vendor API, as generated from its OpenAPI document

```
Fleet Vendor API (v2.3.0).
Agent code reaches it through the brokered `fleet.*` client; only the operations
below are permitted. Every call is allow-listed and gets a per-run token injected
host-side, so the code never handles a credential.

  fleet.health()  ->  GET /health
      Report whether the fleet service is accepting requests.
  fleet.getMission(id)  ->  GET /missions/{id}
      Get a mission's status and progress.
  fleet.cancelMission(id)  ->  POST /missions/{id}/cancel
      Cancel a mission; the robot stops where it is.
  fleet.listRobots()  ->  GET /robots
      List the fleet's robots.
  fleet.getRobot(id)  ->  GET /robots/{id}
      Get one robot: status, battery and pose.
  fleet.decommissionRobot(id)  ->  DELETE /robots/{id}
      Remove a robot from the fleet permanently.
  fleet.updateFirmware(id, body)  ->  POST /robots/{id}/firmware
      Install a firmware image on a robot.
  fleet.createMission(id, body)  ->  POST /robots/{id}/missions
      Send a robot to a target position; answers with the mission id.
```

Responses: `listRobots` answers `{ robots: [...] }`; `getRobot` answers one robot with
`id`, `status`, `battery` and `pose`; `createMission` takes `{ target: { x, y } }` and
answers `{ mission_id }`; `getMission` answers `{ id, robot, status, progress }` with
status `running`, `done`, `failed` or `cancelled`.
