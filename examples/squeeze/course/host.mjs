// Untrusted controller host. The parent grants only this file and the artifact read access.
//
// Ported from the did-it-learn hackathon entry (tasks/drone/host.mjs). One change: the host says
// "booted" before it loads the controller and waits for "go", so the parent can read the CPU time
// the runtime took to start, before any controller code has run, and count the controller's own
// loading and every step against its budget.
import { readFileSync, readSync, writeSync } from 'node:fs';

const FORBIDDEN = /import|require|process|globalThis|constructor|prototype|__proto__|eval|Function|Reflect|Proxy|fetch|Date|performance/;
const source = readFileSync(process.argv[2], 'utf8');
if (FORBIDDEN.test(source)) throw new Error('forbidden source token');
// Raw stdio also works where creating Node net.Socket wrappers for child pipes is denied.
const send = (message) => writeSync(1, JSON.stringify(message) + '\n');
const chunk = Buffer.alloc(8192);
let buffer = '';
// nextLine is the parent's next message, or null when its pipe closes.
function nextLine() {
  for (;;) {
    const end = buffer.indexOf('\n');
    if (end >= 0) {
      const line = buffer.slice(0, end);
      buffer = buffer.slice(end + 1);
      return line;
    }
    const count = readSync(0, chunk, 0, chunk.length, null);
    if (!count) return null;
    buffer += chunk.toString('utf8', 0, count);
  }
}
send({ booted: true });
if (nextLine() === null) throw new Error('the parent closed the pipe before go');
const module = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
if (typeof module.default !== 'function') throw new Error('expected default controller factory');
const controller = module.default();
if (!controller || typeof controller.step !== 'function') throw new Error('expected step(obs)');
send({ ready: true });
for (;;) {
  const line = nextLine();
  if (line === null) break;
  try {
    const request = JSON.parse(line);
    const action = controller.step(request.obs);
    send({ action });
  } catch (error) {
    send({ error: String(error.message).slice(0, 180) });
    break;
  }
}
