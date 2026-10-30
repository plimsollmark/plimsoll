// Plain waypoint follower: position PD, slow altitude integral, no trial recognition.
export default function makeController() {
  let targetIndex = -1, phase = 'climb', integralY = 0, settle = 0;
  const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));
  return {
    step(obs) {
      const p = obs.pos, v = obs.vel;
      let target;
      if (obs.gateIndex < 3) {
        const gate = obs.nextGate.centre;
        if (targetIndex !== obs.gateIndex) { targetIndex = obs.gateIndex; phase = 'align'; settle = 0; }
        if (phase === 'align') {
          target = { x: gate.x - 0.45, y: gate.y, z: gate.z };
          if (Math.hypot(target.x - p.x, target.y - p.y, target.z - p.z) < 0.10 && Math.hypot(v.x, v.y, v.z) < 0.35) settle++;
          else settle = 0;
          if (settle > 15) phase = 'cross';
        }
        if (phase === 'cross') target = { x: gate.x + 0.35, y: gate.y, z: gate.z };
      } else {
        target = { x: obs.pad.centre.x, y: 0.95, z: obs.pad.centre.z };
        if (phase !== 'descend' && Math.hypot(target.x - p.x, target.z - p.z) < 0.09 && Math.hypot(v.x, v.z) < 0.20) phase = 'descend';
        if (phase === 'descend') target.y = 0.025;
      }
      const ax = clamp(3.8 * (target.x - p.x) - 3.2 * v.x, -2.8, 2.8);
      const az = clamp(3.8 * (target.z - p.z) - 3.2 * v.z, -2.8, 2.8);
      const ey = target.y - p.y;
      integralY = clamp(integralY + ey * 0.01, -0.5, 1.9);
      const ay = clamp(5.5 * ey - 3.5 * v.y + 2.4 * integralY, -3.5, 4.5);
      const cy = Math.cos(obs.att.yaw), sy = Math.sin(obs.att.yaw);
      const pitch = clamp((cy * ax - sy * az) / 9.81, -0.45, 0.45);
      const roll = clamp(-(sy * ax + cy * az) / 9.81, -0.45, 0.45);
      const thrust = (0.72 * (9.81 + ay)) / (16 * Math.max(0.7, Math.cos(obs.att.roll) * Math.cos(obs.att.pitch)));
      return { thrust, roll, pitch, yawRate: -2 * obs.att.yaw };
    },
  };
}
