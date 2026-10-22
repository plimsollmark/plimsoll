"""Copy tracked text files into a project request, without running project code.

The request also carries .pr-receipt/subject.json, which names the repository, the commit
and the pull request, so the signed request says what was tested and a receipt for one
commit or repository does not pass for another with the same files."""
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
# No default: a number left unset would name pull request 0 for every pull request. No
# leading zero: one pull request has one subject, so one digest.
number = os.environ.get('PR_NUMBER', '')
repository = os.environ.get('PR_REPOSITORY', '')
if not re.fullmatch(r'0|[1-9][0-9]{0,11}', number) or not command.strip():
    raise SystemExit('PR_NUMBER must be set, in digits with no leading zero (0 for a run outside a pull request), and TEST_COMMAND must be nonempty')
if not re.fullmatch(r'[!-~]{1,256}', repository):
    raise SystemExit("PR_REPOSITORY must be the CI platform's name for the repository, such as owner/name")
head = subprocess.run(['git', '-C', str(project), 'rev-parse', '--verify', '--quiet', 'HEAD^{commit}'],
                      capture_output=True, text=True)
if head.returncode != 0:
    raise SystemExit('The project has no commit; the receipt names the commit it tested')
commit = head.stdout.strip()
if subprocess.check_output(['git', '-C', str(project), 'status', '--porcelain', '--untracked-files=no']):
    raise SystemExit('Tracked files differ from the commit; the receipt would name a commit it did not test')
SUBJECT = '.pr-receipt/subject.json'
subject = json.dumps({'commit': commit, 'pull_request': number, 'repository': repository}, indent=2) + '\n'
paths = subprocess.check_output(['git', '-C', str(project), 'ls-files', '-z']).split(b'\0')
files = []
# These match plimsoll's project-file budgets, not a guessed unlimited upload. The
# subject is one of the files and counts against both.
size = len(subject.encode())
for raw in filter(None, paths):
    name = raw.decode('utf-8', errors='strict')
    if name.startswith('.pr-receipt/'):
        raise SystemExit('A tracked file would collide with the receipt subject: ' + name)
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
if not files or len(files) > 199:
    raise SystemExit('Use a project with 1 to 199 tracked text files; the receipt subject is the 200th')
files.append({'path': SUBJECT, 'content': subject})
base = os.environ.get('PR_BASE_SHA', '')
if base:
    if not re.fullmatch(r'[a-f0-9]{40}', base):
        raise SystemExit('PR_BASE_SHA must be a full commit SHA')
    changed = subprocess.check_output(['git', '-C', str(project), 'diff', '--name-only', '--diff-filter=ACMR', '-z', base, 'HEAD'])
else:  # the commit's own changes; every file of a first commit
    changed = subprocess.check_output(['git', '-C', str(project), 'diff-tree', '--root', '--no-commit-id', '-r',
                                       '--name-only', '--diff-filter=ACMR', '-z', 'HEAD'])
changes = [p.decode('utf-8') for p in changed.split(b'\0') if p]
request = {'protocol': 3, 'minimumIsolation': 'kernel', 'traceId': 'pr-receipt-' + number,
           'timeoutMs': 30000, 'project': {'files': files, 'steps': [command]}}
out.mkdir(parents=True, exist_ok=True)
(out / 'request.json').write_text(json.dumps(request, indent=2) + '\n')
(out / 'context.json').write_text(json.dumps({'pull_request': number, 'tested_head': commit,
                                           'changed_files': changes, 'command': command,
                                           'context_is_unsigned': True}, indent=2) + '\n')
