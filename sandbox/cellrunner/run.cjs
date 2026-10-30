const fs = require('node:fs'), util = require('node:util'), vm = require('node:vm');
globalThis.require = require('node:module').createRequire(process.cwd() + '/');
globalThis.module = { exports: {} }; globalThis.exports = globalThis.module.exports;
globalThis.__dirname = '.'; globalThis.__filename = '[eval]';
let tla = null;
try { tla = require('internal/repl/await').processTopLevelAwait; } catch {}
const src = fs.readFileSync('.plimsoll/cell.js', 'utf8');
let wrapped = null;
if (tla) { try { wrapped = tla(src); } catch {} }
(async () => {
  let v;
  if (wrapped) {
    const out = await vm.runInThisContext(wrapped, { filename: 'cell.js' });
    v = out === undefined ? undefined : out.value;
  } else {
    v = vm.runInThisContext(src, { filename: 'cell.js' });
    if (v instanceof Promise) v = await v;
  }
  if (v !== undefined) console.log(util.inspect(v, { depth: 4 }));
})().catch((e) => { console.error(e); process.exitCode = 1; });
