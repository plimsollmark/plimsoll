import test from 'node:test';
import assert from 'node:assert/strict';
import {existsSync} from 'node:fs';
import {nodes,providers,steps,paths,categories,pathSteps,connections} from './architecture-model.mjs';

test('each path resolves complete teaching steps, valid components, and implementation evidence', () => {
  assert.equal(new Set(paths.map(path => path.id)).size,paths.length);
  const used = new Set();
  for (const path of paths) {
    assert.ok(categories.some(category => category.id === path.category),path.id);
    for (const provider of Object.keys(providers)) {
      for (const step of pathSteps(path,provider)) {
        used.add(step.id);
        assert.ok(nodes[step.from] && nodes[step.to],`${path.id}: ${step.id}`);
        for (const field of ['title','moves','why','payload']) assert.ok(step[field]?.trim(),`${step.id}: ${field}`);
        assert.ok(existsSync(new URL(`../../${step.source}`,import.meta.url)),step.source);
        for (const [,key] of JSON.stringify(step).matchAll(/\{\{(\w+)\}\}/g)) assert.ok(key in providers[provider],key);
      }
    }
  }
  assert.deepEqual([...used].sort(),Object.keys(steps).sort(),'unreachable connection');
});

test('every component connection jump resolves to its exact directed connection', () => {
  for (const id of Object.keys(nodes)) {
    const ports = connections(id);
    assert.ok(ports.some(({step}) => step.to === id),`${id}: incoming`);
    assert.ok(ports.some(({step}) => step.from === id),`${id}: outgoing`);
    for (const {step,path,index,variant} of ports) {
      const target = pathSteps(path,variant === 'default' ? 'runsc' : variant)[index];
      assert.equal(target.id,step.id);
      assert.equal(target.from,step.from);
      assert.equal(target.to,step.to);
    }
  }
});

const ids = (id,provider='runsc') => pathSteps(paths.find(path => path.id === id),provider).map(step => step.id);
test('early refusals never reach execution or credential minting', () => {
  for (const path of ['auth-denied','profile-denied','floor-denied','capacity-denied']) {
    const route = ids(path);
    assert.ok(!route.includes('dispatch'),path);
    assert.ok(!route.includes('prepare-token'),path);
    assert.ok(!route.some(id => id.startsWith('launch')),path);
    assert.ok(route.at(-1) === 'error-caller' || route.at(-1) === 'bad-auth',path);
  }
});

test('project support and startup checks follow the actual provider contracts', () => {
  assert.ok(ids('project','wasm').includes('unsupported'));
  assert.ok(!ids('project','wasm').includes('prepare-token'));
  for (const provider of ['docker','runsc','e2b']) assert.ok(ids('project',provider).includes('launch-project'));
  assert.deepEqual(ids('startup','wasm'),['configure','wasm-ready','startup-profile','serve']);
});

test('host-call denials, quota cooldown, and availability recovery take distinct paths', () => {
  assert.ok(!ids('route-denied').includes('upstream'));
  assert.ok(ids('route-denied').includes('launch-grant'),'guest already runs when call is denied');
  assert.ok(ids('backpressure-503').includes('health-probe'));
  assert.ok(!ids('backpressure-429').includes('health-probe'));
  assert.ok(ids('backpressure-429').includes('shed'));
  const full = ids('granted');
  for (const pair of [['prepare-token','launch-grant'],['upstream','api-reply'],['api-reply','guest-reply'],['finish','result'],['result','caller-result']]) assert.ok(full.indexOf(pair[0]) < full.indexOf(pair[1]),pair.join(' → '));
  assert.ok(ids('evidence-mismatch').indexOf('launch') < ids('evidence-mismatch').indexOf('mismatch'));
});

test('contextual examples do not substitute successful evidence for refusal cases', () => {
  const floor = pathSteps(paths.find(p => p.id === 'floor-denied'),'runsc')[0];
  assert.match(floor.payload,/weaker or unknown/);
  const denied = pathSteps(paths.find(p => p.id === 'route-denied'),'runsc').find(s => s.id === 'guest-call');
  assert.match(denied.payload,/DELETE/);
  assert.doesNotMatch(denied.payload,/"GET"/);
});
