"""Copy tracked text files into a project request, without running project code."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

project = Path(sys.argv[1]).resolve()
out = Path(sys.argv[2]).resolve()
if project == out or project in out.parents:
    raise SystemExit('Output must be outside the target project')
command = os.environ.get('TEST_COMMAND', 'npm test')
number = os.environ.get('PR_NUMBER', '0')
if not re.fullmatch(r'[0-9]{1,12}', number) or not command.strip():
    raise SystemExit('PR_NUMBER must be digits and TEST_COMMAND must be nonempty')
paths = subprocess.check_output(['git', '-C', str(project), 'ls-files', '-z']).split(b'\0')
files = []
# These match plimsoll's project-file budgets, not a guessed unlimited upload.
size = 0
for raw in filter(None, paths):
    name = raw.decode('utf-8', errors='strict')
    path = project / name
    if not path.is_file() or path.is_symlink() or path.resolve().is_relative_to(project) is False:
        raise SystemExit('Tracked file must be a regular file inside the project: ' + name)
    if any(parent.is_symlink() for parent in path.parents if parent != project and parent.is_relative_to(project)):
        raise SystemExit('Symlink parent refused: ' + name)
    if path.stat().st_size > 4 * 1024 * 1024 - size:
        raise SystemExit('Project file budget exceeded; narrow the tracked project')
    with path.open('rb') as stream:
        content = stream.read(4 * 1024 * 1024 - size + 1)
    size += len(content)
    if size > 4 * 1024 * 1024:
        raise SystemExit('Project file budget exceeded; narrow the tracked project')
    if len(raw) > 1024 or b'\0' in content:
        raise SystemExit('Only bounded paths and UTF-8 text files are supported: ' + name)
    files.append({'path': name, 'content': content.decode('utf-8', errors='strict')})
if not files or len(files) > 200:
    raise SystemExit('Use a project with 1 to 200 tracked text files')
base = os.environ.get('PR_BASE_SHA', '')
head = subprocess.run(['git', '-C', str(project), 'rev-parse', 'HEAD'], capture_output=True, text=True)
if base:
    if not re.fullmatch(r'[a-f0-9]{40}', base):
        raise SystemExit('PR_BASE_SHA must be a full commit SHA')
    changed = subprocess.check_output(['git', '-C', str(project), 'diff', '--name-only', '--diff-filter=ACMR', '-z', base, 'HEAD'])
else:
    changed = subprocess.check_output(['git', '-C', str(project), 'diff', '--cached', '--name-only', '--diff-filter=ACMR', '-z'])
changes = [p.decode('utf-8') for p in changed.split(b'\0') if p]
request = {'protocol': 3, 'minimumIsolation': 'kernel', 'traceId': 'pr-receipt-' + number,
           'timeoutMs': 30000, 'project': {'files': files, 'steps': [command]}}
out.mkdir(parents=True, exist_ok=True)
(out / 'request.json').write_text(json.dumps(request, indent=2) + '\n')
(out / 'context.json').write_text(json.dumps({'pull_request': number, 'tested_head': head.stdout.strip() if head.returncode == 0 else None,
                                           'changed_files': changes, 'command': command,
                                           'context_is_unsigned': True}, indent=2) + '\n')
