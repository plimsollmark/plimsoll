// Starts other programs.
require('child_process').execFileSync('/bin/sh', ['-c', 'id > /dev/null; uname -a > /tmp/uname.txt']);
