// Local browser check of the architecture explorer. Uses a Playwright you installed
// (setup in docs/trainers/README.md); the script itself never downloads anything or calls AI.
// From the repository root, with docs/ served on 127.0.0.1:8766:
//   PLAYWRIGHT_MODULE=$PWD/tmp/playwright/node_modules/playwright node docs/trainers/check-architecture.mjs [URL]
// Screenshots go to tmp/ under the current directory.
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
import {mkdirSync,writeFileSync} from 'node:fs';
import {paths,providers,nodes,pathSteps,connections} from './architecture-model.mjs';

const require = createRequire(import.meta.url);
const {chromium} = require(process.env.PLAYWRIGHT_MODULE || 'playwright');
const base = process.argv[2] || 'http://127.0.0.1:8766/trainers/architecture.html';
const origin = new URL(base).origin;
assert.ok(['127.0.0.1','localhost','[::1]'].includes(new URL(base).hostname),'Use a local static preview.');
mkdirSync('tmp',{recursive:true});
const browser = await chromium.launch({headless:true});
const page = await browser.newPage({viewport:{width:1512,height:1050},reducedMotion:'reduce'});
async function assertConnectionVisible() {
  const framing = await page.evaluate(() => {
    const scroller = document.querySelector('#mapScroll');
    const viewport = scroller.getBoundingClientRect();
    const step = document.querySelector('#activeConnection').dataset;
    const cards = [step.from, step.to].map(id => {
      const rect = document.querySelector(`[data-node="${id}"] .node-card`).getBoundingClientRect();
      return {left:rect.left,right:rect.right};
    });
    return {left:viewport.left,right:viewport.right,width:scroller.clientWidth,cards};
  });
  const span = Math.max(...framing.cards.map(c => c.right)) - Math.min(...framing.cards.map(c => c.left));
  // Reserve room for strokes: if both cards fit, neither may be clipped.
  const visible = span <= framing.width - 16 ? framing.cards : framing.cards.slice(1);
  for (const card of visible) {
    assert.ok(card.left >= framing.left && card.right <= framing.right,`clipped endpoint: ${JSON.stringify(framing)}`);
  }
}
const errors = [], external = [], missing = [];
page.on('pageerror', error => errors.push(error.message));
page.on('response', response => {if (response.status() >= 400) missing.push(`${response.status()} ${response.url()}`);});
await page.route('**/*',route => {
  if (new URL(route.request().url()).origin !== origin) {external.push(route.request().url());return route.abort();}
  return route.continue();
});
let rendered = 0, jumps = 0, variants = 0;
const failures = [];
try {
  await page.goto(base);
  await page.locator('#stepInspector h2').waitFor();
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
  await page.screenshot({path:'tmp/architecture-desktop.png',fullPage:true});
  await page.locator('#next').click();
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 2 of/);
  await page.keyboard.press('ArrowRight');
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 3 of/);
  await page.keyboard.press('ArrowLeft');
  await page.locator('#previous').click();
  await page.locator('[data-category="api"]').click();
  assert.equal(await page.locator('#pathSelect').inputValue(),'granted');
  for (const provider of ['runsc','docker','wasm','e2b']) {
    await page.locator('#providerSelect').selectOption(provider);
    assert.match(await page.locator('#providerName').innerText(),new RegExp(providers[provider].tier));
  }
  // Exercise every rendered step, including provider-specific variants and repeated hops.
  for (const path of paths) {
    for (const provider of path.fixedProvider ? ['runsc'] : ['runsc','docker','wasm','e2b']) {
      await page.goto(`${base}#path=${path.id}&provider=${provider}&step=1`);
      await page.waitForFunction(id => document.querySelector('#pathSelect').value === id,path.id);
      const list = pathSteps(path,path.fixedProvider || provider);
      for (let index=0;index<list.length;index++) {
        const step = list[index];
        if (index) await page.locator('#next').click();
        assert.equal(await page.locator('#activeConnection').getAttribute('data-step'),step.id,`${path.id}/${provider}/${index}`);
        assert.equal(await page.locator('#activeConnection').getAttribute('data-from'),step.from);
        assert.equal(await page.locator('#activeConnection').getAttribute('data-to'),step.to);
        assert.equal(await page.locator('#stepInspector h2').innerText(),step.title);
        assert.ok((await page.locator('#stepInspector .payload').innerText()).trim());
        assert.ok(!(await page.locator('#stepInspector').innerText()).includes('{{'));
        rendered++;
      }
      assert.equal(await page.locator('#next').isDisabled(),true);
      await page.locator('#restart').click();
      assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
      variants++;
    }
    console.log(`Path verified: ${path.id}`);
  }
  // Follow every component connection through the public controls. Start on WASM
  // so a jump into a default project path must also select a compatible provider.
  for (const id of Object.keys(nodes)) {
    for (const port of connections(id)) {
      await page.goto(`${base}#path=run&provider=wasm&step=1&node=${id}`);
      await page.waitForFunction(() => !document.querySelector('#nodeInspector').hidden);
      const selector = `[data-jump="${port.path.id}"][data-index="${port.index}"][data-variant="${port.variant}"]`;
      await page.locator(selector).click();
      assert.equal(await page.locator('#activeConnection').getAttribute('data-step'),port.step.id);
      assert.equal(await page.locator('#nodeInspector').isHidden(),true);
      jumps++;
    }
  }
  await page.goto(`${base}#path=granted&provider=runsc&step=13`);
  await page.locator('[data-node="broker"]').click();
  await page.locator('[data-filter="in"]').click();
  const incoming = await page.locator('.port-direction').allInnerTexts();
  assert.ok(incoming.length,'incoming connection direction labels are missing');
  for (const text of incoming) assert.match(text,/^IN FROM/);
  await page.locator('[data-filter="out"]').click();
  const outgoing = await page.locator('.port-direction').allInnerTexts();
  assert.ok(outgoing.length,'outgoing connection direction labels are missing');
  for (const text of outgoing) assert.match(text,/^OUT TO/);
  const saved = page.url();
  await page.locator('.skip-link').focus();
  await page.keyboard.press('Enter');
  assert.equal(page.url(),saved,'skip link preserves the selected path');
  await page.reload();
  await page.locator('#nodeInspector h2').waitFor();
  assert.equal(page.url(),saved);
  assert.equal(await page.locator('#nodeInspector h2').innerText(),'Shared API broker');
  await page.locator('#showStep').click();
  await page.locator('#next').click();
  await page.goBack();
  await page.waitForFunction(() => document.querySelector('#stepCounter').textContent.startsWith('Connection 13 '));
  await page.goForward();
  await page.waitForFunction(() => document.querySelector('#stepCounter').textContent.startsWith('Connection 14 '));
  await page.evaluate(() => document.activeElement.blur());
  await page.keyboard.press('Home');
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
  await page.keyboard.press('ArrowRight');
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 2 of/);
  await page.keyboard.press('End');
  assert.equal(await page.locator('#next').isDisabled(),true);
  await page.locator('[data-node="adapter"]').focus();
  await page.keyboard.press('Enter');
  assert.equal(await page.locator('#nodeInspector h2').innerText(),'Guest-call adapter');
  // Playback advances, pauses, and stops when selecting another path.
  await page.goto(`${base}#path=run&provider=runsc&step=1`);
  await page.clock.install();
  await page.locator('#play').click();
  await page.clock.runFor(5001);
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 2 of/);
  await page.locator('#play').click();
  await page.clock.runFor(6000);
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 2 of/);
  await page.locator('#play').click();
  await page.locator('[data-category="refuse"]').click();
  await page.clock.runFor(6000);
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
  assert.equal(await page.locator('#play').getAttribute('aria-pressed'),'false');
  // Links actually resolve under the shipped docs tree. A link into the public
  // repository is checked against the working tree instead of fetched: the file is
  // published by the same export as this page, and GitHub rate-limits headless
  // fetches (429) so a network check would flake on a valid link. Any other
  // off-site link is a failure, so the page cannot quietly grow external links.
  const repoLink = /^https:\/\/github\.com\/plimsollmark\/plimsoll\/blob\/main\/(.+)$/;
  const {existsSync} = await import('node:fs');
  for (const href of await page.locator('a[href]:not([href^="#"])').evaluateAll(elements => elements.map(a => a.href))) {
    const match = href.match(repoLink);
    if (match) {
      assert.ok(existsSync(new URL(`../../${match[1]}`, import.meta.url)), `${href} names a file that is not in the working tree`);
      continue;
    }
    assert.ok(href.startsWith(new URL(base).origin), `unexpected off-site link ${href}`);
    const response = await page.request.get(href);
    assert.equal(response.status(),200,href);
  }
  // Malformed bookmarks are bounded and do not execute markup or break the view.
  await page.goto(`${base}#path=__proto__&provider=constructor&step=Infinity&node=toString`);
  await page.waitForFunction(() => document.querySelector('#pathSelect').value === 'run');
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
  await page.goto(`${base}#path=granted&provider=runsc&step=13`);
  await page.locator('#walkthrough').scrollIntoViewIfNeeded();
  await page.screenshot({path:'tmp/architecture-api.png',fullPage:true});
  await page.locator('#mapExpand').click();
  assert.equal(await page.locator('#mapExpand').getAttribute('aria-pressed'),'true');
  await page.locator('#mapExpand').click();
  // Narrow viewports scroll the map, not the entire page. The toolbar stays usable.
  for (const width of [390,768,1280,1512]) {
    await page.setViewportSize({width,height:900});
    await page.goto(base);
    await page.waitForFunction(() => document.querySelector('#stepCounter').textContent.startsWith('Connection 1 '));
    assert.equal(await page.locator('#mapScroll').evaluate(el => el.scrollLeft),0,'initial view starts at the left edge');
    await assertConnectionVisible();
    if (width === 390) await page.screenshot({path:'tmp/architecture-mobile-initial.png',fullPage:true});
    // Admission checks the limiter; the handler owns the following dispatch.
    for (let step = 2; step <= 4; step++) {
      await page.locator('#next').click();
      await assertConnectionVisible();
    }
    assert.equal(await page.locator('#activeConnection').getAttribute('data-from'),'service');
    assert.equal(await page.locator('#activeConnection').getAttribute('data-to'),'provider');
    if (width === 390) await page.screenshot({path:'tmp/architecture-mobile-dispatch.png',fullPage:true});
    // Selecting a new provider starts over and reveals the initial connection.
    await page.locator('#providerSelect').selectOption('wasm');
    await assertConnectionVisible();
    await page.goto(`${base}#path=granted&provider=wasm&step=11`);
    await page.waitForFunction(() => document.querySelector('#stepCounter').textContent.startsWith('Connection 11 '));
    await assertConnectionVisible();
    assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth),false,`overflow at ${width}`);
    assert.equal(await page.evaluate(() => getComputedStyle(document.documentElement).colorScheme),'light');
    if (width === 390) {
      await page.screenshot({path:'tmp/architecture-mobile.png',fullPage:true});
      await page.locator('#stepInspector').scrollIntoViewIfNeeded();
      assert.ok((await page.locator('#next').boundingBox()).y >= 0);
      await page.locator('#next').click();
      assert.match(await page.locator('#stepCounter').innerText(),/Connection 12 of/);
    }
  }
  // A fast restart must cancel a pending native smooth pan as well as playback.
  await page.emulateMedia({reducedMotion:'no-preference'});
  await page.setViewportSize({width:390,height:900});
  await page.goto(base);
  await page.locator('#stepInspector h2').waitFor();
  await page.evaluate(() => {
    for (let i=0;i<3;i++) document.querySelector('#next').click();
    document.querySelector('#restart').click();
  });
  await page.waitForTimeout(600); // Outlast Chromium's smooth pan before checking its final position.
  assert.match(await page.locator('#stepCounter').innerText(),/Connection 1 of/);
  await assertConnectionVisible();
  // These floors are the existing traversal counts; a lower count means paths were lost.
  assert.ok(variants >= 74,`lost path variants: ${variants} < 74`);
  assert.ok(rendered >= 792,`lost rendered connections: ${rendered} < 792`);
  assert.ok(jumps >= 148,`lost component jumps: ${jumps} < 148`);
} catch (error) {
  failures.push(error);
} finally {
  await browser.close();
  // Check diagnostics even after an earlier assertion fails, preserving both failures.
  for (const [name, events] of [['browser errors',errors],['external requests',external],['missing assets',missing]]) {
    try { assert.deepEqual(events,[],name); } catch (error) { failures.push(error); }
  }
}
if (failures.length) throw new AggregateError(failures,'architecture browser check failed');
const result = {variants,renderedConnections:rendered,componentJumps:jumps,viewports:[390,768,1280,1512],browserErrors:errors,externalRequests:external,missingAssets:missing};
writeFileSync('tmp/architecture-browser-results.json',JSON.stringify(result,null,2)+'\n');
console.log(JSON.stringify(result,null,2));
