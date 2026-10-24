// Runs inside the sandbox: an offline npm install of one fixture package from its tarball,
// then an import of it. node /driver.mjs NAME
import { execFileSync } from 'node:child_process';
import fs from 'node:fs';

const name = process.argv[2];
fs.mkdirSync('/work', { recursive: true });
fs.writeFileSync('/work/package.json', '{"name":"w","version":"1.0.0"}');
execFileSync('npm', ['install', '--offline', '--cache', '/cache', '--no-audit', '--no-fund',
  '/fixtures/plimsoll-fixture-' + name + '-1.0.0.tgz'], { cwd: '/work', stdio: ['ignore', 'ignore', 'inherit'] });
execFileSync('node', ['-e', 'require("plimsoll-fixture-' + name + '")'], { cwd: '/work', stdio: 'inherit' });
console.log(JSON.stringify({ fixture: name }));
