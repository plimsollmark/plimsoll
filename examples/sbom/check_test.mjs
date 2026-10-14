import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {webcrypto} from 'node:crypto';
import vm from 'node:vm';
if (Number(process.versions.node.split('.')[0]) < 22) throw new Error('Node 22 or later is required');
globalThis.crypto ??= webcrypto;
vm.runInThisContext(readFileSync(new URL('./check.js', import.meta.url), 'utf8'));
const imageName = 'image-1c6cbab4a47d.cdx.json';
const imageFiles = {[imageName]: readFileSync(new URL('../../docs/examples/sbom/' + imageName, import.meta.url)).toString('base64')};
const {changeOneCharacter} = globalThis.PlimsollReceipt;
const check = bom => globalThis.PlimsollReceipt.check(bom, imageFiles);
const names = ['run-c7e245a369dd.cdx.json', 'run-af0fa2597b81.cdx.json'];
for (const name of names) {
  const bom = JSON.parse(readFileSync(new URL('../../docs/examples/sbom/' + name, import.meta.url)));
  const good = await check(bom);
  assert.equal(good.length, 11, JSON.stringify(good));
  assert.ok(good.every(c => c.ok), JSON.stringify(good));
  const changed = changeOneCharacter(bom);
  assert.equal(changed.before.length, 1);
  assert.equal(changed.after.length, 1);
  const refused = await check(changed.bom);
  for (const id of ['seal', 'record']) assert.equal(refused.find(c => c.id === id)?.ok, false, JSON.stringify(refused));
  assert.ok(refused.filter(c => !['seal', 'record'].includes(c.id)).every(c => c.ok), JSON.stringify(refused));
  const file = structuredClone(bom);
  const f = file.metadata.component.components[0].hashes[0];
  f.content = (f.content[0] === '0' ? '1' : '0') + f.content.slice(1);
  assert.equal((await check(file)).find(c => c.id === 'files')?.ok, false);
  const claim = structuredClone(bom), c = claim.declarations.claims[0];
  c.predicate = c.predicate.replace(/file-set digest ([a-f0-9])/, (_, h) => 'file-set digest ' + (h === '0' ? '1' : '0'));
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
  assert.ok((await check(bom)).every(c => c.ok), 'tamper operation modified original');
}
console.log('PASS: both receipts, seal and record tampering, file hash, claim digest, properties and raw-byte outputs');
if (process.argv[2]) {
  for (const v of JSON.parse(readFileSync(process.argv[2]))) {
    assert.equal(await PlimsollReceipt.requestDigest(v.exchange.request), v.request, 'Go request vector');
    assert.equal(await PlimsollReceipt.resultDigest(v.exchange.response), v.result, 'Go raw-byte result vector');
    assert.equal(await PlimsollReceipt.recordDigest(v.exchange.response.record), v.record, 'Go record vector');
    assert.equal(await PlimsollReceipt.fileSetDigest(v.files), v.fileSet, 'Go UTF-8 path-order vector');
  }
  console.log('PASS: Go vectors for protocols 1/2/3, Unicode paths, raw outputs, truncation and software rules');
}
