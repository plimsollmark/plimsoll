// The platform's conformance harness: loads a vendor adapter, runs the commands of
// plan.json through it against the vendor API the run's grant reaches, and prints one
// report line.
//
//   node harness.js <scenario> <adapter file>
//
// The harness is the platform's code; the adapter is the agent's. Both run inside the
// sandbox, in one process, and the only way out is the injected `fleet` client. So the
// report is the adapter's claim: the verdict is made on the host, from the plan and the
// vendor's ledger. The scenario argument is only recorded; the harness does not know
// what the vendor will do.
"use strict";

const fs = require("fs");

const scenario = process.argv[2];
const adapterFile = process.argv[3];

const report = { scenario, adapter: adapterFile, completed: false, commands: [], inventories: [], polls: 0, retries: 0, errors: [] };
const fail = (msg) => { report.errors.push(msg); };
const finish = (code) => { console.log("ADAPTER-REPORT " + JSON.stringify(report)); process.exit(code); };
const errorOf = (e) => ({ error: String((e && e.message) || e).slice(0, 200), code: (e && typeof e.code === "string") ? e.code : "" });
// What the adapter returned, as JSON, so the host can check its shape: never judged here.
const raw = (v) => {
  if (v === undefined) return null;
  try { const s = JSON.stringify(v); return s.length <= 4096 ? JSON.parse(s) : { truncated: s.length }; } catch (e) { return { unserializable: String(e && e.message) }; }
};

const guard = setTimeout(() => { fail("harness timeout after 75 s"); finish(2); }, 75000);
guard.unref();

async function main() {
  if (!scenario || !adapterFile) { fail("usage: node harness.js <scenario> <adapter file>"); return finish(2); }
  if (typeof globalThis.fleet !== "object") { fail("no fleet client in this run: the grant is missing"); return finish(2); }
  let plan;
  try { plan = JSON.parse(fs.readFileSync("plan.json", "utf8")); } catch (e) { fail("plan.json: " + e.message); return finish(2); }
  let adapter;
  try { adapter = require("./" + adapterFile); } catch (e) { fail("adapter failed to load: " + e.message); return finish(1); }
  for (const fn of ["inventory", "dispatch", "wait", "cancel"]) {
    if (typeof adapter[fn] !== "function") { fail("adapter does not export " + fn); }
  }
  if (report.errors.length) return finish(1);

  // 1. Inventory, recorded as returned.
  const takeInventory = async () => {
    try { report.inventories.push({ returned: raw(await adapter.inventory()), error: "" }); }
    catch (e) { report.inventories.push({ returned: null, error: errorOf(e).error }); }
  };
  await takeInventory();

  // 2. Dispatch every command, then wait for each mission. An error the adapter throws
  //    is recorded against its command, and the run goes on.
  const rows = plan.commands.map((c) => ({ id: c.id, robot: c.robot, mission: "", dispatched: null, state: "", polls: 0, max_polls: 0, waited: null, error: "", code: "" }));
  report.commands = rows;
  const send = async (c, row) => {
    try {
      const m = await adapter.dispatch(c.robot, c.target, c.id);
      row.dispatched = raw(m);
      if (typeof m === "string" && m !== "") row.mission = m;
    } catch (e) { Object.assign(row, errorOf(e)); }
  };
  const watch = async (row, maxPolls) => {
    if (!row.mission) return;
    row.max_polls = maxPolls;
    try {
      const w = await adapter.wait(row.mission, { maxPolls });
      row.waited = raw(w);
      row.state = (w && typeof w.state === "string") ? w.state : "";
      row.polls = (w && typeof w.polls === "number") ? w.polls : 0;
      report.polls += row.polls;
      if (w && typeof w.retries === "number") report.retries = Math.max(report.retries, w.retries);
    } catch (e) { Object.assign(row, errorOf(e)); }
  };
  for (let i = 0; i < plan.commands.length; i++) if (!plan.commands[i].cancel) await send(plan.commands[i], rows[i]);
  for (let i = 0; i < plan.commands.length; i++) if (!plan.commands[i].cancel) await watch(rows[i], 40);

  // 3. The commands the platform cancels: dispatch, cancel at once, then wait.
  for (let i = 0; i < plan.commands.length; i++) {
    if (!plan.commands[i].cancel) continue;
    await send(plan.commands[i], rows[i]);
    if (rows[i].mission) {
      try { await adapter.cancel(rows[i].mission); } catch (e) { Object.assign(rows[i], errorOf(e)); }
      await watch(rows[i], 5);
    }
  }

  // 4. Inventory again, as the last call of the run.
  await takeInventory();

  report.completed = report.errors.length === 0;
  finish(report.completed ? 0 : 1);
}

main().catch((e) => { fail("harness error: " + (e && e.message)); finish(1); });
