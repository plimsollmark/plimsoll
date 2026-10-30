The artifact is one JavaScript file, `controller.js`, exporting:

```js
export default function makeController() {
  return {
    step(obs) {
      return { thrust: 0.45, roll: 0, pitch: 0, yawRate: 0 };
    },
  };
}
```

This example only illustrates the interface, it is not a flight controller. Start from
`baselines/stabilizer.js` in your work directory, a working plain waypoint follower. You can
fly it, read the results, change it, and repeat. Every trial creates a fresh controller.

Fly through three numbered square gate openings in order, then land on the landing pad,
within 15 seconds. The room spans x and z from -3 to 3 metres and y from 0 to 3 metres.
Gravity is 9.81 metres per second squared. Up is +y. Gate planes face +x, and only a
crossing from smaller x to larger x counts. Each opening is 0.42 metres wide and high;
the drone's horizontal collision half-width is 0.175 m and vertical half-height 0.07 m,
so its whole body must fit through. Gate frames are physical, the spaces outside them
are open. A missed gate is still the next gate until you return and cross it correctly.

The harness owns the inner attitude stabilizer and four motor mixer. You control navigation,
collective thrust, desired tilt, and yaw rate at 100 calls per simulated second. The simulation
integrates twice per call to resolve motor lag and gate crossings. It is a simplified benchmark,
not a validated model of a real aircraft.

`step(obs)` receives only these fields, all distances in metres, time in seconds, angles
in radians, speeds in metres per second, and angular rates in radians per second:

- `t`: elapsed simulated time, starting at 0, increasing by 0.01 seconds.
- `pos: {x, y, z}`: noisy drone centre position. A resting centre is at y = 0.07.
- `vel: {x, y, z}`: noisy velocity.
- `att: {roll, pitch, yaw}`: noisy attitude angles. At yaw zero, positive pitch tilts
  thrust toward +x, positive roll tilts it toward -z. Positive yaw rotates +x toward -z.
- `rates: {roll, pitch, yaw}`: noisy derivatives of the corresponding attitude angles.
- `gateIndex`: 0, 1, or 2 for the next gate; 3 after all three have been crossed.
- `nextGate: {centre: {x,y,z}, normal: {x,y,z}}`: the next gate, or `null` after the last.
  Gate centres are (-1.15, 1.05, -0.85), (0.15, 1.40, 0.25), (1.35, 1.05, 1.05).
  Normals are (1, 0, 0). Gate and pad coordinates are exact, not noisy.
- `pad: {centre: {x,y,z}}`: the landing-pad centre, (2.05, 0, 1.65).

Return a plain object with four finite numeric fields:

- `thrust`: collective motor demand, clamped to [0, 1]. Four motors can each produce
  up to 4 N. Demand is not altitude, and 0.5 is not guaranteed to hover.
- `roll` and `pitch`: desired attitude angles, each clamped to [-0.6, 0.6].
- `yawRate`: desired yaw rate, clamped to [-2, 2].

The mass is 0.6 kg plus a hidden 0 to 0.35 kg payload. Motors have a hidden 20 to 60 ms
first-order response lag, one has 0 to 35 percent less thrust, and air drag is linear.
Wind (this is the hard version of the course) has a hidden seeded base component of up to 2.2 m/s and two or three gusts. Every trial has an abrupt
0.2-second gust; other gusts last 0.2 to 2.0 seconds, with speeds of 4 to 9 m/s. The short
gust can move the drone before its tilted thrust catches up, so advance knowledge can help.
The starting pad position varies by a few centimetres and is visible with sensor noise in
the first observation. You never receive the seed, trial index, wind, mass, or motor parameters.

Success requires all three gates, then a centre within 0.15 m horizontally of the pad,
centre height at most 0.095 m, speed below 0.5 m/s, and roll/pitch each below 0.18 rad,
continuously for 0.25 s before the 15-second deadline. This short hold rejects a passing bounce.
Floor/wall contact faster than 0.85 m/s, a hard tilted floor landing, tilt beyond 1.2 rad,
or any gate-frame collision fails. Soft wall contact is constrained by the room boundary.

Rules: no imports, external access, or asynchronous actions. The source is rejected if it
contains any of `import`, `require`, `process`, `globalThis`, `constructor`, `prototype`,
`__proto__`, `eval`, `Function`, `Reflect`, `Proxy`, `fetch`, `Date`, `performance`, including
inside comments and strings. The child has an empty environment, permission to read only
its own source and host module, and no granted file writes, network, subprocesses, or workers.
The trusted simulator runs separately. Malformed output, a crash, a step that hangs
for 5 seconds, or more than 5 seconds of CPU time in one flight (counted from when the controller
starts to load) fails that trial. Keep source below 256 KiB, a source-size guard,
and the JavaScript old-generation heap below 48 MiB. This heap limit does not bound total
process memory or typed-array allocations. Do not write to stdout, which carries
the harness protocol. The supplied deterministic controller needs no randomness or clock.

You do not have the simulator. Write your controller to `controller.js` in your work
directory and fly it with the `fly` tool, which runs it in a separate sandbox and answers, for
each flight, whether it passed, why it ended, how many gates it passed, how far it ended from
the pad centre and how many seconds it flew. `fly` flies the four smoke flights, or a number of
new flights drawn at random for you; you may fly any seed it has given you again. You will not
see the flights you are graded on. Your sandbox has Node.js and Python if you want to test
pieces of your code, and `node --check controller.js` checks its syntax.
