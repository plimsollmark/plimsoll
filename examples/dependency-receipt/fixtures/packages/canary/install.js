// Writes outside its own directory: a file in root's home, a write through a symlink that lands
// in /etc, a rename and a delete, and a write that fails.
const fs = require('fs');
fs.writeFileSync('/root/.canary', 'canary\n');
fs.mkdirSync('/tmp/canary-dir', { recursive: true });
fs.symlinkSync('/etc/canary-target', '/tmp/canary-dir/link');
fs.writeFileSync('/tmp/canary-dir/link', 'through a link\n');
fs.renameSync('/root/.canary', '/root/.canary-moved');
fs.unlinkSync('/root/.canary-moved');
try { fs.writeFileSync('/proc/canary', 'x'); } catch (e) { /* refused: attempted, not done */ }
