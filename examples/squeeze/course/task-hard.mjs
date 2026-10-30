// The hard drone course, ported from the did-it-learn hackathon entry (github.com/carrollco/did-it-learn,
// tasks/drone-hard/task.mjs, 2026-10-25). Frozen: the numbers are the hackathon's, so a score here means
// what it meant there. Two changes, both from the entry's own list of mistakes: the 16 practice seeds
// are not in this file (they are a sealed set the harness sends to grading runs only), and the smoke
// seeds are random 32-bit numbers instead of 101 to 104, the first numbers anyone would try.
// This file reaches only practice and grading runs, never a rebuild's sandbox.
export const TASK = Object.freeze({
  version: 'drone-hard-1', dt: 0.01, substeps: 2, duration: 15, gravity: 9.81,
  room: Object.freeze({ minX: -3, maxX: 3, minZ: -3, maxZ: 3, height: 3 }),
  baseMass: 0.6, payloadMax: 0.35, maxMotorThrust: 4.0,
  motorLagMin: 0.02, motorLagMax: 0.06, motorWeaknessMax: 0.35,
  arm: 0.115, inertia: 0.006, yawCoefficient: 0.014, linearDrag: 0.42,
  bodyRadius: 0.175, bodyHeight: 0.07, gateOpening: 0.42, gateFrame: 0.07,
  baseWindMax: 2.2, gustMin: 4, gustMax: 9, gustDurationMin: 0.2,
  gustDurationMax: 2.0, gustStartMin: 2.0, gustStartMax: 12.0,
  positionNoise: 0.001, velocityNoise: 0.018, attitudeNoise: 0.003,
  rateNoise: 0.012, startOffset: 0.045,
  contactCrashSpeed: 0.85, flipAngle: 1.2, landingRadius: 0.15,
  landingSpeed: 0.5, landingTilt: 0.18, landingHold: 0.25,
});

const v = (x, y, z) => Object.freeze({ x, y, z });
export const TAKEOFF = v(-2.1, 0, -1.65);
export const PAD = Object.freeze({ centre: v(2.05, 0, 1.65) });
export const GATES = Object.freeze([
  Object.freeze({ centre: v(-1.15, 1.05, -0.85), normal: v(1, 0, 0) }),
  Object.freeze({ centre: v(0.15, 1.40, 0.25), normal: v(1, 0, 0) }),
  Object.freeze({ centre: v(1.35, 1.05, 1.05), normal: v(1, 0, 0) }),
]);

export const SMOKE = Object.freeze([249602000, 694222088, 3821313589, 972765592]);

export function random(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), a | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function trialParameters(seed) {
  const r = random(seed), between = (a, b) => a + (b - a) * r();
  const offset = { x: between(-TASK.startOffset, TASK.startOffset), z: between(-TASK.startOffset, TASK.startOffset) };
  const mass = TASK.baseMass + between(0, TASK.payloadMax);
  const lag = between(TASK.motorLagMin, TASK.motorLagMax);
  const weakMotor = Math.floor(r() * 4), weakness = between(0, TASK.motorWeaknessMax);
  const angle = between(0, 2 * Math.PI), strength = between(0, TASK.baseWindMax);
  const baseWind = { x: Math.cos(angle) * strength, y: 0, z: Math.sin(angle) * strength };
  const gusts = Array.from({ length: r() < 0.5 ? 2 : 3 }, (_, i) => {
    const start = between(TASK.gustStartMin, TASK.gustStartMax);
    // Every trial has one abrupt 200 ms gust, shorter than the navigation response.
    const duration = i === 0 ? TASK.gustDurationMin : between(TASK.gustDurationMin, TASK.gustDurationMax);
    const a = between(0, 2 * Math.PI), s = between(TASK.gustMin, TASK.gustMax);
    return { start, duration, x: Math.cos(a) * s, y: 0, z: Math.sin(a) * s };
  });
  return { offset, mass, lag, weakMotor, weakness, baseWind, gusts };
}
