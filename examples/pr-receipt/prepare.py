"""Copy tracked text files into a project request, without running project code.

The request also carries .pr-receipt/subject.json, which names the repository, the commit
and the pull request, so the signed request says what was tested and a receipt for one
commit or repository does not pass for another with the same files. With PR_BASE_SHA it
also names the base, and with SESSION_TRAILER the coding-agent sessions recorded on the pull
request's commits."""
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
base = os.environ.get('PR_BASE_SHA', '')
if base and not re.fullmatch(r'[a-f0-9]{40}', base):
    raise SystemExit('PR_BASE_SHA must be a full commit SHA')
# A coding agent's sessions, where a session recorder writes a trailer on each commit made
# in a session naming its session IDs: SESSION_TRAILER is that trailer's key, and unset means
# none are read. The commit message is fixed by the commit ID the subject already names;
# listing the IDs puts them where a policy reading the receipt finds them. The commits are
# the pull request's own (base..head), or the head alone with no base, and the base is named
# too, so a verifier rebuilds the same list.
TRAILER = os.environ.get('SESSION_TRAILER', '')
if TRAILER and not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9-]{0,63}', TRAILER):
    raise SystemExit('SESSION_TRAILER must be a commit trailer key: letters, digits and hyphens')
log = subprocess.run(['git', '-C', str(project), '-c', 'trailer.separators=:', '-c', 'log.showSignature=false',
                      '-c', 'i18n.logOutputEncoding=UTF-8', 'log', '--no-color',
                      f'--format=%(trailers:key={TRAILER},valueonly,separator=%x00)%x00',
                      *([base + '..' + commit] if base else ['-1', commit])], capture_output=True)
if log.returncode != 0:
    raise SystemExit("PR_BASE_SHA must be a commit in the project's history (fetch the full history)")
sessions = set()
for value in log.stdout.decode('utf-8', errors='replace').split('\0') if TRAILER else []:
    for token in re.split(r'[\s,]+', value.strip()):
        if not token:
            continue
        if not re.fullmatch(r'[A-Za-z0-9._:-]{1,64}', token):
            raise SystemExit(f'A {TRAILER} trailer holds something other than session IDs: {token[:80]!r}')
        sessions.add(token)
if len(sessions) > 64:
    raise SystemExit(f'The commits name {len(sessions)} agent sessions; a receipt lists at most 64')
SUBJECT = '.pr-receipt/subject.json'
fields = {'commit': commit, 'pull_request': number, 'repository': repository}
if base:
    fields['base'] = base
if sessions:
    fields['agent_sessions'] = sorted(sessions)
subject = json.dumps(fields, indent=2, sort_keys=True) + '\n'
# The files come from the commit's own objects, never the working tree: what the subject
# names is exactly what runs, whatever the working tree holds now or a moment from now
# (reading the tree after a clean-tree check left a window between the two).
tree = subprocess.check_output(['git', '-C', str(project), 'ls-tree', '-r', '-z', '-l', '--full-tree', commit])
files = []
# These match plimsoll's project-file budgets, not a guessed unlimited upload. The
# subject is one of the files and counts against both.
size = len(subject.encode())
for entry in filter(None, tree.split(b'\0')):
    meta, _, raw = entry.partition(b'\t')
    mode, kind, oid, length = meta.split()
    try:
        name = raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError:
        raise SystemExit('Only UTF-8 paths are supported: ' + raw.decode('utf-8', errors='replace'))
    if name.startswith('.pr-receipt/'):
        raise SystemExit('A tracked file would collide with the receipt subject: ' + name)
    if kind != b'blob' or mode not in (b'100644', b'100755'):
        raise SystemExit('Tracked file must be a regular file, not a link or a submodule: ' + name)
    size += int(length)
    if size > 4 * 1024 * 1024:
        raise SystemExit('Project file budget exceeded; narrow the tracked project')
    content = subprocess.check_output(['git', '-C', str(project), 'cat-file', 'blob', oid.decode()])
    if len(content) != int(length) or len(raw) > 1024 or b'\0' in content:
        raise SystemExit('Only bounded paths and UTF-8 text files are supported: ' + name)
    try:
        files.append({'path': name, 'content': content.decode('utf-8', errors='strict')})
    except UnicodeDecodeError:
        raise SystemExit('Only bounded paths and UTF-8 text files are supported: ' + name)
if not files or len(files) > 199:
    raise SystemExit('Use a project with 1 to 199 tracked text files; the receipt subject is the 200th')
files.append({'path': SUBJECT, 'content': subject})
if base:
    changed = subprocess.check_output(['git', '-C', str(project), 'diff', '--name-only', '--diff-filter=ACMR', '-z', base, commit])
else:  # the commit's own changes; every file of a first commit
    changed = subprocess.check_output(['git', '-C', str(project), 'diff-tree', '--root', '--no-commit-id', '-r',
                                       '--name-only', '--diff-filter=ACMR', '-z', commit])
changes = [p.decode('utf-8') for p in changed.split(b'\0') if p]
# JUNIT_PATH names the JUnit file the test command writes; the sandbox returns it inside
# the signed result (junit.py). Its rule is plain relative names, stricter than plimsoll's.
# COVERAGE_PATH names the lcov file it writes, returned the same way (formats.py turns it
# into Cobertura); it comes second, after the JUnit file, so it needs JUNIT_PATH too.
junit = os.environ.get('JUNIT_PATH', '')
coverage = os.environ.get('COVERAGE_PATH', '')
for name, value, example in (('JUNIT_PATH', junit, 'reports/junit.xml'), ('COVERAGE_PATH', coverage, 'coverage/lcov.info')):
    if value and (not re.fullmatch(r'[A-Za-z0-9_-][A-Za-z0-9._-]*(/[A-Za-z0-9_-][A-Za-z0-9._-]*)*', value)
                  or len(value) > 256 or value.startswith('.pr-receipt/')):
        raise SystemExit(f'{name} must be a relative path of plain names inside the project, such as {example}')
    if value in {f['path'] for f in files}:
        raise SystemExit(f'{name} names a tracked file; the report must be one the test command writes')
if coverage and (not junit or coverage == junit):
    raise SystemExit('COVERAGE_PATH needs JUNIT_PATH set too, naming a different file')
project_request = {'files': files, 'steps': [command]}
if junit:
    project_request['artifacts'] = [junit] + ([coverage] if coverage else [])
request = {'protocol': 4, 'minimumIsolation': 'kernel', 'traceId': 'pr-receipt-' + number,
           'timeoutMs': 30000, 'project': project_request}
out.mkdir(parents=True, exist_ok=True)
(out / 'request.json').write_text(json.dumps(request, indent=2) + '\n')
(out / 'context.json').write_text(json.dumps({'pull_request': number, 'tested_head': commit,
                                           'changed_files': changes, 'command': command,
                                           'context_is_unsigned': True}, indent=2) + '\n')
