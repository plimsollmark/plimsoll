// Writes only inside its own directory, as a package building itself would.
const fs = require('fs'), path = require('path');
fs.mkdirSync(path.join(__dirname, 'build'), { recursive: true });
fs.writeFileSync(path.join(__dirname, 'build', 'out.txt'), 'built\n');
