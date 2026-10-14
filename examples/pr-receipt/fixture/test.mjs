import assert from 'node:assert/strict';
import {sum} from './sum.mjs';
assert.equal(sum([10, 20, -5]), 25);
assert.equal(sum([]), 0);
console.log('two sum checks passed');
