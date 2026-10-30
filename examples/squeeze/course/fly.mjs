#!/usr/bin/env node
// Flies a controller on a list of seeded flights and prints one JSON object on stdout.
//
//   node fly.mjs <controller.js> <cases.json> [--cpu-budget SECONDS] [--record DIR [--fps N]]
//
// cases.json holds {"seeds": [...]}, unsigned 32-bit integers; any other field (a set's name,
// the nonce that seals it) is ignored. The output is {valid, error?, passed, total, results},
// each result {seed, success, reason, gatesPassed, landingError, simulatedSeconds, cpuSeconds,
// startCpuSeconds}: the controller's CPU time in the flight, and in starting before it.
// A controller that fails validation is {valid: false, error} and exit status 1; a flight that
// fails is a normal result. Ported from the hackathon's run.mjs, which took named splits.
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { runTrial, validateSource } from './sim.mjs';

const args = process.argv.slice(2);
const option = (name, fallback) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : fallback; };
let output;
try {
  const [file, casesFile] = args;
  if (!file || !casesFile || file.startsWith('--') || casesFile.startsWith('--')) throw new Error('usage: node fly.mjs <controller.js> <cases.json> [--cpu-budget SECONDS] [--record DIR]');
  const seeds = JSON.parse(readFileSync(casesFile, 'utf8')).seeds;
  if (!Array.isArray(seeds) || !seeds.length || seeds.length > 4096 || !seeds.every((s) => Number.isInteger(s) && s >= 0 && s <= 0xffffffff)) {
    throw new Error('cases.json needs "seeds": a nonempty array of unsigned 32-bit integers');
  }
  const cpuBudget = Number(option('--cpu-budget', '5'));
  if (!(cpuBudget > 0 && cpuBudget <= 60)) throw new Error('--cpu-budget must be above 0 and at most 60 seconds');
  const recordDir = option('--record'), fps = Number(option('--fps', '30'));
  if (!(Number.isInteger(fps) && fps >= 1 && fps <= 60)) throw new Error('--fps must be a whole number from 1 to 60');
  if (recordDir) mkdirSync(recordDir, { recursive: true });
  const artifact = validateSource(resolve(file)), results = [];
  for (const seed of seeds) {
    const { result, track } = await runTrial(artifact, seed, { record: Boolean(recordDir), cpuBudget, fps });
    results.push(result);
    if (recordDir) writeFileSync(join(recordDir, `seed-${seed}.json`), JSON.stringify(track));
  }
  output = { valid: true, passed: results.filter((r) => r.success).length, total: seeds.length, results };
} catch (error) {
  output = { valid: false, error: String(error.message).slice(0, 300), passed: 0, total: 0, results: [] };
  process.exitCode = 1;
}
process.stdout.write(JSON.stringify(output) + '\n');
