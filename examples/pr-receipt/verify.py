"""Check a pull request's receipt that someone else made, before trusting what it says.

A receipt (the CycloneDX file receipt.sh writes) is unsigned; the run record inside it is
signed. Anything that reads the receipt's fields alone, a policy engine or a merge check,
believes whatever is written there. This runs first, on the machine that decides, with
the public key of the operator you trust (whoever ran plimsoll and signed the run), and
says whether the receipt counts for this pull request and whether its tests passed.

When the same CI job runs receipt.sh and gates on it, receipt.sh already decides from the
signed result. This is for the other case: the receipt comes from an operator outside the
pull request's control, and the repository's required check verifies it.

The checks, in order:
1. signature: `sbom -check` against the operator's key, given here and never taken from
   the receipt. It checks the signature, the run record, and that every field of the
   receipt equals the signed request and result. The checker's success alone is not taken
   as the operator's signature: without a key it checks against the receipt's own, which
   passes for any signer, so this requires its line saying it compared the operator's key.
2. head: the signed request equals the request prepare.py builds for the repository, the
   pull request's head commit, its number, its base, the test command, the JUnit path and
   the session trailer, all from the CI configuration; so the agent sessions the subject
   lists are the ones on the pull request's commits. prepare.py puts the repository, commit and number in a file of the
   request, .pr-receipt/subject.json, so a receipt for another commit with the same
   files, or for another repository, is refused. git runs with its defaults, never the
   machine's settings (core.autocrlf=true once rewrote every file at checkout).
3. junit (with --junit): the file equals the JUnit report junit.py derives from the signed
   result, byte for byte.
   test-result (with --test-result and --attest): the in-toto test-result statement is
   signed with the operator's key (`plimsoll-attest open-statement`) and its subject and
   predicate equal the ones formats.py derives from the signed result.
   coverage (with --coverage): the Cobertura file equals the one formats.py converts from
   the lcov file inside the signed result, byte for byte.
4. result: the run completed behind the kernel tier or stronger and every step exited 0
   without timing out. Decided from the signed result, never from printed text or JUnit.

Prints a JSON report naming the SHA-256 of the receipt bytes it checked; exits 0 when every
check passes, 1 when the receipt is refused or its tests failed, 2 on a usage error and 3
when the check could not be run:

  python3 -I examples/pr-receipt/verify.py --sbom SBOM_BINARY \\
    --receipt RECEIPT.cdx.json --trusted-pub OPERATOR.pub \\
    --repo PROJECT_CLONE --repository OWNER/NAME --head HEAD_SHA --pr NUMBER \\
    --command 'npm test' [--base BASE_SHA] [--session-trailer KEY] [--junit-path reports/junit.xml] [--junit junit.xml] \\
    [--coverage-path coverage/lcov.info] [--coverage coverage.cobertura.xml] \\
    [--attest PLIMSOLL_ATTEST_BINARY --test-result test-result.intoto.json]
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PREPARE = HERE / 'prepare.py'
OPERATOR_COMPARED = 'PASS: attached key matches independently trusted key.'
SUBJECT = '.pr-receipt/subject.json'
RECIPE_ENV = ('TEST_COMMAND', 'PR_NUMBER', 'PR_BASE_SHA', 'PR_REPOSITORY', 'JUNIT_PATH', 'COVERAGE_PATH', 'SESSION_TRAILER')
TIERS = {'kernel': 1, 'vm': 2}  # the recipe's floor and what is stronger


def load_junit():
    """junit.py beside this file, by path: under python3 -I this directory is not on the
    import path, and a module of that name elsewhere must never stand in for it."""
    spec = importlib.util.spec_from_file_location('pr_receipt_junit', HERE / 'junit.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


junit = load_junit()


def load_formats():
    spec = importlib.util.spec_from_file_location('pr_receipt_formats', HERE / 'formats.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


formats = load_formats()


def clean_env(**extra):
    """The caller's environment without git's overrides, the machine's git settings or the
    recipe's own settings."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k not in RECIPE_ENV}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', **extra)
    return env


def check_signature(sbom, receipt, trusted_pub):
    p = subprocess.run([sbom, '-check', receipt, '-trusted-pub', trusted_pub],
                       capture_output=True, text=True, env=clean_env())
    lines = [line for line in (p.stdout + p.stderr).splitlines() if line.strip()]
    if p.returncode != 0:
        tool = next((line for line in reversed(lines) if line.startswith('sbom: ')), lines[-1] if lines else 'no output')
        if tool.startswith('sbom: -trusted-pub'):
            raise RuntimeError(f"the operator's key could not be used: {tool}")
        for marker, plain in (('differs from independently trusted key', "signed with a key other than the operator's"),
                              ('BOM differs from the verified exchange', 'a field of the receipt no longer matches the signed run record'),
                              ('does not match the request and result it came with',
                               "the request and result attached inside the receipt no longer match the signed run record's fingerprints")):
            if marker in tool:
                return False, plain, tool
        return False, 'the signature or the run record does not check', tool
    if OPERATOR_COMPARED not in lines:
        raise RuntimeError("the checker passed without comparing the signer with the operator's key")
    return True, "signed with the operator's key; every field matches the signed run record", None


def no_duplicates(pairs):
    """A repeated key could be read one way by the Go checker and another way here."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError('a JSON object repeats a key')
    return dict(pairs)


def signed_exchange(raw):
    """The request and response inside the receipt, trusted only after check_signature
    passed on these same bytes."""
    bom = json.loads(raw, object_pairs_hook=no_duplicates)
    data = bom['declarations']['evidence'][0]['data']
    attachment = next(d for d in data if d['name'] == 'exchange.json')['contents']['attachment']
    content = base64.b64decode(attachment['content'], validate=True)
    return json.loads(content, object_pairs_hook=no_duplicates)


def recipe_request(a, scratch):
    """The request prepare.py builds for the head commit, in the exchange's field names."""
    checkout = scratch / 'head'
    for args in (['clone', '--quiet', '--no-checkout', '--shared', str(a.repo), str(checkout)],
                 ['-C', str(checkout), 'checkout', '--quiet', '--detach', a.head]):
        subprocess.run(['git', '-c', 'advice.detachedHead=false', *args], check=True,
                       capture_output=True, env=clean_env())
    out = scratch / 'request'
    env = clean_env(TEST_COMMAND=a.command, PR_NUMBER=a.pr, PR_REPOSITORY=a.repository)
    if a.junit_path:
        env['JUNIT_PATH'] = a.junit_path
    if a.coverage_path:
        env['COVERAGE_PATH'] = a.coverage_path
    if a.base:
        env['PR_BASE_SHA'] = a.base
    if a.session_trailer:
        env['SESSION_TRAILER'] = a.session_trailer
    subprocess.run([sys.executable, '-I', str(PREPARE), str(checkout), str(out)], check=True,
                   capture_output=True, env=env)
    r = json.loads((out / 'request.json').read_text())
    return {
        'protocol': r['protocol'],
        'minimum_isolation': r['minimumIsolation'],
        'trace_id': r['traceId'],
        'timeout_ms': r['timeoutMs'],
        'software_rule': None,
        'project': {'files': r['project']['files'], 'steps': r['project']['steps'],
                    'artifacts': r['project'].get('artifacts', []), 'grant_profile': ''},
    }


def a_command(request):
    return ' && '.join(request['project']['steps'])


def differences(got, want):
    """Plain sentences for each way the signed request differs from the recipe's."""
    out = []
    gf = {f['path']: f['content'] for f in got.get('project', {}).get('files', [])}
    wf = {f['path']: f['content'] for f in want['project']['files']}
    if SUBJECT not in gf:
        out.append('the run does not say which repository, commit or pull request it tested')
    elif gf[SUBJECT] != wf[SUBJECT]:
        try:
            gs = json.loads(gf[SUBJECT], object_pairs_hook=no_duplicates)
        except ValueError:
            gs = None
        gs = gs if isinstance(gs, dict) else {}
        ws = json.loads(wf[SUBJECT])
        for key, says in (('repository', 'was for repository'), ('commit', 'tested commit'), ('pull_request', 'was for pull request'),
                          ('base', 'names base'), ('agent_sessions', 'lists agent sessions')):
            if gs.get(key) != ws.get(key):
                out.append(f'the run {says} {gs.get(key)!r}; this is {ws.get(key)!r}')
        if not out:
            out.append(f'{SUBJECT} as tested differs from the one the recipe writes')
    gf.pop(SUBJECT, None)
    wf.pop(SUBJECT, None)
    for path in sorted(wf.keys() - gf.keys()):
        out.append(f'{path} is in the head commit but was not tested')
    for path in sorted(gf.keys() - wf.keys()):
        out.append(f'{path} was tested but is not in the head commit')
    for path in sorted(gf.keys() & wf.keys()):
        if gf[path] != wf[path]:
            out.append(f'{path} as tested differs from the head commit')
    if got.get('project', {}).get('steps') != want['project']['steps']:
        ran = ', '.join(f'"{s}"' for s in got.get('project', {}).get('steps', [])) or 'nothing'
        out.append(f"the run executed {ran}; the configured test command is \"{a_command(want)}\"")
    if got.get('project', {}).get('artifacts') != want['project']['artifacts']:
        out.append(f"the run returned {got.get('project', {}).get('artifacts')!r}; the configured JUnit path gives {want['project']['artifacts']!r}")
    if got.get('trace_id') != want['trace_id']:
        out.append(f"the run is labelled {got.get('trace_id')!r}; this pull request's label is {want['trace_id']!r}")
    for key in sorted((got.keys() | want.keys()) - {'project', 'trace_id'}):
        if got.get(key) != want.get(key):
            out.append(f'{key} is {got.get(key)!r}; the recipe sets {want.get(key)!r}')
    for key in sorted((got.get('project', {}).keys() | want['project'].keys()) - {'files', 'steps', 'artifacts'}):
        if got.get('project', {}).get(key) != want['project'].get(key):
            out.append(f"project {key} is {got['project'].get(key)!r}; the recipe sets {want['project'].get(key)!r}")
    if not out and got != want:
        out.append('the signed request differs from the recipe in a field this verifier does not name')
    return out


def check_junit(x, path):
    want, source = junit.junit(x)
    given = Path(path).read_bytes()
    if want is None:
        return False, f'a JUnit file was given, but {source}'
    if given != want:
        return False, f'the file differs from {source}, as the signed result holds it'
    return True, f'byte for byte {source}, as the signed result holds it'


def check_test_result(a, x):
    """The statement is the operator's, and says what the signed result says."""
    p = subprocess.run([a.attest, 'open-statement', '-pub', a.trusted_pub, '-type', formats.TEST_RESULT, a.test_result],
                       capture_output=True, text=True, env=clean_env())
    if p.returncode != 0:
        reason = (p.stderr.strip().splitlines() or ['no output'])[-1]
        return False, f"the statement is not an in-toto test-result statement signed with the operator's key: {reason}"
    got = json.loads(p.stdout, object_pairs_hook=no_duplicates)
    want, source = formats.test_result(x)
    canon = lambda v: json.dumps(v, sort_keys=True)
    if canon(got['subject']) != canon(want['subject']):
        return False, 'the statement names another repository or commit than the signed request'
    if canon(got['predicate']) != canon(want['predicate']):
        return False, 'the statement differs from the one the signed result gives'
    return True, f"signed with the operator's key and equal to the statement the signed result gives ({want['predicate']['result']}; {source})"


def check_coverage(x, path):
    derived = formats.coverage(x)
    given = Path(path).read_bytes()
    if derived is None:
        return False, 'a coverage file was given, but the receipt was made without COVERAGE_PATH'
    want, source = derived
    if want is None:
        return False, f'a coverage file was given, but {source}'
    if given != want:
        return False, f'the file differs from the Cobertura {source}'
    return True, f'byte for byte the Cobertura {source}'


def check_result(x):
    """Pass or fail from the signed result alone."""
    r = x['response']
    p = r['project']
    tier = r.get('isolation', '')
    if TIERS.get(tier, 0) < TIERS['kernel']:
        return False, f'the run reports the {tier or "unknown"} tier; the recipe requires kernel or stronger'
    if p.get('outcome') != 'PROJECT_OUTCOME_COMPLETED':
        return False, f"the run did not complete: {p.get('outcome')}"
    requested = x['request']['project']['steps']
    steps = p.get('steps') or []
    if len(steps) != len(requested):
        return False, f'{len(steps)} of {len(requested)} steps ran'
    for i, s in enumerate(steps):
        if s.get('timed_out'):
            return False, f'step {i + 1} timed out'
        if s.get('exit_code', 0) != 0:
            return False, f"step {i + 1} exited {s['exit_code']}"
    return True, f'every step exited 0 behind the {tier} tier'


def requested(a):
    """The optional checks this run was asked for, in the order they are made."""
    return [name for name, given in (('junit', a.junit), ('test-result', a.test_result), ('coverage', a.coverage)) if given]


def verify(a, raw):
    """The checks on raw, the receipt read once: the checker and the later checks see the
    same bytes, so a file swapped between two reads cannot pass one and feed the other."""
    checks = []
    (ROOT / 'tmp').mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='verify-', dir=ROOT / 'tmp'))
    try:
        (scratch / 'receipt.cdx.json').write_bytes(raw)
        ok, detail, tool = check_signature(a.sbom, str(scratch / 'receipt.cdx.json'), a.trusted_pub)
        if ok:
            try:
                x = signed_exchange(raw)
            except ValueError as e:
                ok, detail, tool = False, 'the receipt could not be read unambiguously', str(e)
        checks.append({'check': 'signature', 'passed': ok, 'detail': detail} | ({'tool': tool} if tool else {}))
        if not ok:
            for name in ['head'] + requested(a) + ['result']:
                checks.append({'check': name, 'passed': None,
                               'detail': 'not checked: an unverified receipt proves nothing'})
            return checks
        try:
            want = recipe_request(a, scratch)
            diff = differences(x['request'], want)
            checks.append({'check': 'head', 'passed': not diff,
                           'detail': '; '.join(diff) if diff else f'tested exactly commit {a.head[:12]} of {a.repository}, pull request {a.pr}, with {a.command!r}'})
        except subprocess.CalledProcessError as e:
            reason = (e.stderr or b'').decode(errors='replace').strip().splitlines()
            checks.append({'check': 'head', 'passed': False,
                           'detail': f"the recipe's request for commit {a.head[:12]} could not be rebuilt: {reason[-1] if reason else e}"})
    finally:
        shutil.rmtree(scratch)
    if a.junit:
        ok, detail = check_junit(x, a.junit)
        checks.append({'check': 'junit', 'passed': ok, 'detail': detail})
    if a.test_result:
        ok, detail = check_test_result(a, x)
        checks.append({'check': 'test-result', 'passed': ok, 'detail': detail})
    if a.coverage:
        ok, detail = check_coverage(x, a.coverage)
        checks.append({'check': 'coverage', 'passed': ok, 'detail': detail})
    ok, detail = check_result(x)
    checks.append({'check': 'result', 'passed': ok, 'detail': detail})
    return checks


def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--sbom', required=True, help='the examples/sbom checker, built')
    p.add_argument('--receipt', required=True)
    p.add_argument('--trusted-pub', required=True, help="the operator's public key, never the receipt's own")
    p.add_argument('--repo', required=True, help='a clone of the project holding the head commit')
    p.add_argument('--repository', required=True, help="the CI platform's name for the repository, such as owner/name")
    p.add_argument('--head', required=True, help="the pull request's head commit, from the CI platform")
    p.add_argument('--pr', required=True)
    p.add_argument('--command', required=True, help='the configured test command')
    p.add_argument('--junit-path', default='', help='the JUNIT_PATH the receipt was made with, if any')
    p.add_argument('--base', default='', help="the pull request's base commit, as the receipt was made with PR_BASE_SHA")
    p.add_argument('--session-trailer', default='', help='the SESSION_TRAILER the receipt was made with, if any')
    p.add_argument('--junit', default='', help='a junit.xml to check against the signed result')
    p.add_argument('--coverage-path', default='', help='the COVERAGE_PATH the receipt was made with, if any')
    p.add_argument('--coverage', default='', help='a coverage.cobertura.xml to check against the signed result')
    p.add_argument('--attest', default='', help='the plimsoll-attest binary, built; needed for --test-result')
    p.add_argument('--test-result', default='', help='a test-result.intoto.json to check against the signed result')
    a = p.parse_args()
    if a.test_result and not a.attest:
        p.error('--test-result needs --attest, the plimsoll-attest binary that checks its signature')
    if (not re.fullmatch(r'[a-f0-9]{40}', a.head) or not re.fullmatch(r'0|[1-9][0-9]{0,11}', a.pr) or not a.command.strip()
            or not re.fullmatch(r'[!-~]{1,256}', a.repository) or (a.base and not re.fullmatch(r'[a-f0-9]{40}', a.base))):
        p.error('--head and --base must be full commit SHAs, --pr digits with no leading zero, --command nonempty, --repository printable with no spaces')
    try:
        raw = Path(a.receipt).read_bytes()
        checks = verify(a, raw)
    except Exception as e:  # a crash is not a refusal: the receipt was never judged
        print(json.dumps({'verified': False, 'error': f'{type(e).__name__}: {e}'}, indent=2))
        sys.exit(3)
    verified = all(c['passed'] for c in checks)
    print(json.dumps({'verified': verified, 'receipt_sha256': hashlib.sha256(raw).hexdigest(), 'checks': checks}, indent=2))
    sys.exit(0 if verified else 1)


if __name__ == '__main__':
    main()
