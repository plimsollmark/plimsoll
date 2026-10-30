import assert from 'node:assert/strict';
import {readFileSync, readdirSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node 22 or later is required');
globalThis.crypto ??= webcrypto;
vm.runInThisContext(readFileSync(new URL('./check.js', import.meta.url), 'utf8'));
const dir = new URL('../../docs/examples/sbom/', import.meta.url);
// Every image label published beside the example, as the page hands them to the checker.
const imageFiles = Object.fromEntries(readdirSync(dir).filter(n => /^image-[a-f0-9]{12}\.cdx\.json$/.test(n))
  .map(n => [n, readFileSync(new URL(n, dir)).toString('base64')]));
assert.ok(Object.keys(imageFiles).length >= 2, 'the published image labels');
const {changeOneCharacter} = globalThis.PlimsollReceipt;
const check = bom => globalThis.PlimsollReceipt.check(bom, imageFiles);
const flip = h => (h[0] === '0' ? '1' : '0') + h.slice(1);
const names = readdirSync(dir).filter(n => /^run-[a-f0-9]{12}\.cdx\.json$/.test(n)).sort();
assert.ok(names.length >= 4, 'the published BOMs');
let verdicts = 0;
for (const name of names) {
  const bom = JSON.parse(readFileSync(new URL(name, dir)));
  const qualified = bom.declarations.evidence.length === 2;
  if (qualified) verdicts++;
  const good = await check(bom);
  const labelled = Boolean(bom.components[0].externalReferences); // the image's own label, when the example has one
  assert.equal(good.length, 10 + (qualified ? 2 : 0) + (labelled ? 1 : 0), name + ' ' + JSON.stringify(good));
  assert.ok(good.every(c => c.ok), name + ' ' + JSON.stringify(good));
  // One byte of the sealed subject: the seal, the record and the line's copy of the envelope fail, nothing else.
  const changed = changeOneCharacter(bom);
  assert.equal(changed.before.length, 1);
  assert.equal(changed.after.length, 1);
  const refused = await check(changed.bom);
  const broken = ['seal', 'record', 'line'];
  for (const id of broken) assert.equal(refused.find(c => c.id === id)?.ok, false, JSON.stringify(refused));
  assert.ok(refused.filter(c => !broken.includes(c.id)).every(c => c.ok), JSON.stringify(refused));
  const file = structuredClone(bom);
  const f = file.metadata.component.components[0].hashes[0];
  f.content = flip(f.content);
  assert.equal((await check(file)).find(c => c.id === 'files')?.ok, false);
  const claim = structuredClone(bom), c = claim.declarations.claims[0];
  c.predicate = c.predicate.replace(/file-set digest ([a-f0-9])/, (_, h) => 'file-set digest ' + flip(h));
  assert.equal((await check(claim)).find(c => c.id === 'claims')?.ok, false);
  // Cross-language agreement must cover actual raw bytes and request order.
  for (const field of ['request_sha256', 'result_sha256', 'record_sha256']) {
    const prop = structuredClone(bom);
    prop.metadata.component.properties.find(p => p.name === 'plimsoll:' + field).value = '0'.repeat(64);
    assert.equal((await check(prop)).find(c => c.id === 'properties')?.ok, false);
  }
  const exchange = structuredClone(bom);
  const a = exchange.declarations.evidence[0].data.find(d => d.name === 'exchange.json').contents.attachment;
  const x = JSON.parse(Buffer.from(a.content, 'base64'));
  x.response.project.steps[0].stdout = Buffer.from([0, 255, 254]).toString('base64');
  a.content = Buffer.from(JSON.stringify(x)).toString('base64');
  assert.equal((await check(exchange)).find(c => c.id === 'result')?.ok, false);
  // The line's stated place, and the line's own bytes under its link.
  const moved = structuredClone(bom);
  moved.properties.find(p => p.name === 'plimsoll:bundle_line').value = '99';
  assert.equal((await check(moved)).find(c => c.id === 'line')?.ok, false);
  const cut = structuredClone(bom);
  const line = cut.declarations.evidence[0].data.find(d => d.name === 'entry.json').contents.attachment;
  const bytes = Buffer.from(line.content, 'base64');
  bytes[bytes.indexOf('"request":"') + 11] ^= 1;
  line.content = bytes.toString('base64');
  assert.equal((await check(cut)).find(c => c.id === 'line')?.ok, false);
  if (qualified) {
    const word = structuredClone(bom), c4 = word.declarations.claims[3];
    c4.predicate = c4.predicate.includes('Verdict: pass.') ? c4.predicate.replace('Verdict: pass.', 'Verdict: fail.') : c4.predicate.replace('Verdict: fail.', 'Verdict: pass.');
    assert.equal((await check(word)).find(c => c.id === 'verdict')?.ok, false, 'the verdict word');
    const scored = structuredClone(bom), m = scored.declarations.attestations[0].map[3].conformance;
    m.score = m.score === 1 ? 0 : 1;
    assert.equal((await check(scored)).find(c => c.id === 'verdict')?.ok, false, 'the score');
    const st = structuredClone(bom), sa = st.declarations.evidence[1].data[0].contents.attachment;
    const env = JSON.parse(Buffer.from(sa.content, 'base64')), body = JSON.parse(Buffer.from(env.payload, 'base64'));
    body.subject[0].digest.sha256 = flip(body.subject[0].digest.sha256);
    env.payload = Buffer.from(JSON.stringify(body)).toString('base64');
    sa.content = Buffer.from(JSON.stringify(env)).toString('base64');
    assert.equal((await check(st)).find(c => c.id === 'statement')?.ok, false, 'the statement subject');
    // The requirements pin and the verdicts per requirement: a flipped REQ-004, or a pin
    // that is not the stored requirements file, fails the verdict line as well as the seal.
    for (const [what, edit] of [['a flipped requirement verdict', q => { const v = q.requirement_verdicts.find(r => r.id === 'REQ-004'); v.status = v.status === 'held' ? 'not_held' : 'held'; }],
      ['a pin that is not the stored file', q => { q.requirements.sha256 = flip(q.requirements.sha256); }],
      ['no pin', q => { delete q.requirements; }]]) {
      const t = structuredClone(bom), ta = t.declarations.evidence[1].data[0].contents.attachment;
      const e = JSON.parse(Buffer.from(ta.content, 'base64')), b = JSON.parse(Buffer.from(e.payload, 'base64'));
      edit(b.predicate);
      e.payload = Buffer.from(JSON.stringify(b)).toString('base64');
      ta.content = Buffer.from(JSON.stringify(e)).toString('base64');
      assert.equal((await check(t)).find(c => c.id === 'verdict')?.ok, false, what);
    }
    const other = names.find(n => n !== name && JSON.parse(readFileSync(new URL(n, dir))).declarations.evidence.length === 2);
    const swapped = structuredClone(bom);
    swapped.declarations.evidence[1] = JSON.parse(readFileSync(new URL(other, dir))).declarations.evidence[1];
    const swappedResult = await check(swapped);
    assert.equal(swappedResult.find(c => c.id === 'statement')?.ok, false, "the other run's statement");
  }
  assert.ok((await check(bom)).every(c => c.ok), 'tamper operation modified original');
}
assert.equal(verdicts, 2, 'two verdict BOMs');
console.log(`PASS: ${names.length} receipts (${verdicts} with a verdict), seal, record, line, statement and verdict tampering, file hash, claim digest, properties and raw-byte outputs`);
if (process.argv[2]) {
  for (const v of JSON.parse(readFileSync(process.argv[2]))) {
    assert.equal(await PlimsollReceipt.requestDigest(v.exchange.request), v.request, 'Go request vector');
    assert.equal(await PlimsollReceipt.resultDigest(v.exchange.response), v.result, 'Go raw-byte result vector');
    assert.equal(await PlimsollReceipt.recordDigest(v.exchange.response.record), v.record, 'Go record vector');
    assert.equal(await PlimsollReceipt.fileSetDigest(v.files), v.fileSet, 'Go UTF-8 path-order vector');
  }
  console.log('PASS: Go vectors for protocols 1/2/3/4, Unicode paths, raw outputs, truncation and software rules');
}
