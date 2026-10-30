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
   the session trailer, all from the CI configuration, at the protocol number the receipt
   was made with when that is this release's or an earlier one; so the agent sessions the subject
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
5. tests (whenever the signed request asks for a test report, or with --min-tests): the
   report the run returned inside the signed result is JUnit this reads, lists no failure or
   error, and lists at least --min-tests tests that ran (default 1, so a report of zero
   tests, or of skipped tests only, fails). A failure the report lists fails this though every
   step exited 0: the signed test-result statement says FAILED for it too. The report is
   the project's own, so this shows what its framework wrote, not that the tests are good.
6. policy (with --policy and --opa): the repository's own Rego policy, evaluated by the
   `opa` command (Open Policy Agent) over facts from the signed run, only after the
   signature and head checks passed. It evaluates data.plimsoll.receipt.deny, a set of
   strings, each a refusal; an empty set adds none. A policy can only refuse: the checks
   above still decide. policy/input.schema.json lists what a policy reads, and OPA checks
   the policy against it, so a misspelled field is an error rather than a rule that never
   fires. The policy runs with no built-in that reaches the network, reads the
   environment or reads the clock or a random source, so a decision repeats offline.
   Read the policy from the base branch or another repository, never from the pull
   request's own checkout, whose author could rewrite it. --policy-input FILE writes the
   input the policy reads, for writing and testing a policy.

With --self-consistent instead of --trusted-pub, the signature is checked only against the
key the receipt carries (receipt.sh's default key is made for the run and deleted): every
check still runs, the report says signer self_consistent, and it is never verified, since
anyone can make a key and sign a receipt.

Prints a JSON report naming the SHA-256 of the receipt bytes it checked, with the receipt's
states (states.py: which commit it covers, whether that is the head given here, whether the
run completed, what came back, how many tests ran, the verdict) and what stays unverified;
exits 0 when every check passes against the operator's key, 1 when the receipt is refused,
its tests failed or it was checked as self-consistent only, 2 on a usage error and 3 when
the check could not be run (its states then all unknown; a policy that does not compile,
calls a built-in it may not, or defines no deny set included):

  python3 -I examples/pr-receipt/verify.py --sbom SBOM_BINARY \\
    --receipt RECEIPT.cdx.json (--trusted-pub OPERATOR.pub | --self-consistent) \\
    --repo PROJECT_CLONE --repository OWNER/NAME --head HEAD_SHA --pr NUMBER \\
    --command 'npm test' [--base BASE_SHA] [--session-trailer KEY] [--junit-path reports/junit.xml] [--junit junit.xml] [--min-tests N] \\
    [--coverage-path coverage/lcov.info] [--coverage coverage.cobertura.xml] \\
    [--attest PLIMSOLL_ATTEST_BINARY --test-result test-result.intoto.json] \\
    [--opa OPA_BINARY --policy POLICY.rego ...] [--policy-input INPUT.json]
"""
import argparse
import atexit
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
ATTACHED_ONLY = 'LIMIT: attached key only; signer identity is not established.'
SUBJECT = '.pr-receipt/subject.json'
RECIPE_ENV = ('TEST_COMMAND', 'PR_NUMBER', 'PR_BASE_SHA', 'PR_REPOSITORY', 'JUNIT_PATH', 'COVERAGE_PATH', 'SESSION_TRAILER')
TIERS = {'kernel': 1, 'vm': 2}  # the recipe's floor and what is stronger
POLICY_QUERY = 'data.plimsoll.receipt.deny'
POLICY_INPUT_VERSION = 1
POLICY_SCHEMA = HERE / 'policy' / 'input.schema.json'
OPA_PIN = HERE / 'policy' / 'opa.version'
OPA_MAX_BYTES = 512 << 20  # the pinned static build is under 100 MB
# Every tier, weakest first, as a policy compares them; anything else ranks -1, below none.
RANKS = {'none': 0, 'process': 1, 'container': 2, 'kernel': 3, 'vm': 4}
# Built-ins a policy may not call: they reach the network, read the environment (where a CI
# job keeps its secrets), or read the clock or a random source, so the same receipt and
# policy could decide differently later. Every built-in OPA marks nondeterministic is
# removed (eleven in v1.21.4, the JSON schema matchers among them, which fetch remote
# references); the first six names are listed too, in case a release drops a mark. The two
# certificate verifiers check against the current time and carry no mark.
DENIED_BUILTINS = {'http.send', 'net.lookup_ip_addr', 'opa.runtime', 'time.now_ns', 'rand.intn', 'uuid.rfc4122',
                   'crypto.x509.parse_and_verify_certificates', 'crypto.x509.parse_and_verify_certificates_with_options'}
OPA_TIMEOUT_S = 120  # a policy over one receipt takes milliseconds; this bounds a runaway one


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


def load_states():
    spec = importlib.util.spec_from_file_location('pr_receipt_states', HERE / 'states.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


states = load_states()


def clean_env(**extra):
    """The caller's environment without git's overrides, the machine's git settings or the
    recipe's own settings."""
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_') and k not in RECIPE_ENV}
    env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1', **extra)
    return env


def check_signature(sbom, receipt, trusted_pub):
    """Against the operator's key, or with no key (--self-consistent) against the key the
    receipt carries."""
    p = subprocess.run([sbom, '-check', receipt] + (['-trusted-pub', trusted_pub] if trusted_pub else []),
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
    if not trusted_pub:
        if ATTACHED_ONLY not in lines:
            raise RuntimeError('the checker passed without saying which key it checked against')
        return True, 'consistent with the key the receipt carries, not with a key given separately; every field matches the signed run record', None
    if OPERATOR_COMPARED not in lines:
        raise RuntimeError("the checker passed without comparing the signer with the operator's key")
    return True, "signed with the operator's key; every field matches the signed run record", None


def no_duplicates(pairs):
    """A repeated key could be read one way by the Go checker and another way here."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError('a JSON object repeats a key')
    return dict(pairs)


def attachment(raw, name):
    bom = json.loads(raw, object_pairs_hook=no_duplicates)
    data = bom['declarations']['evidence'][0]['data']
    found = next(d for d in data if d['name'] == name)['contents']['attachment']
    return base64.b64decode(found['content'], validate=True)


def signed_exchange(raw):
    """The request and response inside the receipt, trusted only after check_signature
    passed on these same bytes."""
    return json.loads(attachment(raw, 'exchange.json'), object_pairs_hook=no_duplicates)


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


def check_test_result(a, x, pub):
    """The statement is signed with the run's key (the operator's, or with --self-consistent
    the one the receipt carries), and says what the signed result says."""
    p = subprocess.run([a.attest, 'open-statement', '-pub', pub, '-type', formats.TEST_RESULT, a.test_result],
                       capture_output=True, text=True, env=clean_env())
    if p.returncode != 0:
        reason = (p.stderr.strip().splitlines() or ['no output'])[-1]
        return False, f"the statement is not an in-toto test-result statement signed with the run's key: {reason}"
    got = json.loads(p.stdout, object_pairs_hook=no_duplicates)
    want, source = formats.test_result(x)
    canon = lambda v: json.dumps(v, sort_keys=True)
    if canon(got['subject']) != canon(want['subject']):
        return False, 'the statement names another repository or commit than the signed request'
    if canon(got['predicate']) != canon(want['predicate']):
        return False, 'the statement differs from the one the signed result gives'
    return True, f"signed with the run's key and equal to the statement the signed result gives ({want['predicate']['result']}; {source})"


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


def number(v):
    """An integer from the exchange, where 64-bit fields arrive as decimal strings."""
    return int(v) if v not in (None, '') else 0


def policy_input(x, raw, checks, signer):
    """What a policy reads: facts from the signed exchange and the verifier's own checks,
    never the receipt's unsigned fields and never a step's output, which the tested code
    writes. Called only after the signature and head checks passed; signer says against
    which key the signature passed (trusted_key, or self_consistent: the receipt's own)."""
    request, response = x['request'], x['response']
    files = {f['path']: f['content'] for f in request['project']['files']}
    subject = json.loads(files[SUBJECT], object_pairs_hook=no_duplicates)
    project, record = response['project'], response['record']
    artifacts = []
    for f in project.get('artifacts') or []:
        content = base64.b64decode(f.get('content', ''), validate=True)
        artifacts.append({'path': f['path'], 'sha256': hashlib.sha256(content).hexdigest(), 'bytes': len(content)})
    return {
        'plimsoll_policy_input': POLICY_INPUT_VERSION,
        'receipt_sha256': hashlib.sha256(raw).hexdigest(),
        'signer': signer,
        'checks': {c['check'].replace('-', '_'): c['passed'] for c in checks},
        'subject': {'repository': subject['repository'], 'commit': subject['commit'],
                    'pull_request': subject['pull_request'], 'base': subject.get('base', ''),
                    'agent_sessions': subject.get('agent_sessions', [])},
        'request': {'protocol': request['protocol'], 'minimum_isolation': request['minimum_isolation'],
                    'minimum_isolation_rank': RANKS.get(request['minimum_isolation'], -1),
                    'timeout_ms': number(request['timeout_ms']), 'steps': request['project']['steps'],
                    'artifacts': request['project'].get('artifacts', []), 'trace_id': request['trace_id']},
        'result': {'provider': response.get('sandbox', ''), 'isolation': response.get('isolation', ''),
                   'isolation_rank': RANKS.get(response.get('isolation', ''), -1),
                   'outcome': project.get('outcome', '').removeprefix('PROJECT_OUTCOME_').lower(),
                   'environment': response.get('environment', ''), 'software_identity': response.get('software_identity', ''),
                   'duration_ms': number(response.get('duration_ms')),
                   'steps': [{'command': step.get('command', ''), 'exit_code': step.get('exit_code', 0),
                              'timed_out': bool(step.get('timed_out', False)), 'duration_ms': number(step.get('duration_ms'))}
                             for step in project.get('steps') or []],
                   'artifacts': artifacts, 'artifacts_truncated': bool(project.get('artifacts_truncated', False))},
        'record': {'version': record['version'], 'record_sha256': record['record_sha256'],
                   'request_sha256': record['request_sha256'], 'result_sha256': record['result_sha256'],
                   'started_unix_ms': number(record.get('started_unix_ms')), 'ended_unix_ms': number(record.get('ended_unix_ms')),
                   'session': record.get('session', ''), 'instance': record.get('instance', '')},
    }


def pinned_opa_sha256():
    """The SHA-256 policy/opa.version pins the opa binary to."""
    for line in OPA_PIN.read_text().splitlines():
        if line.startswith('sha256_linux_amd64_static='):
            want = line.split('=', 1)[1].strip()
            if re.fullmatch(r'[a-f0-9]{64}', want):
                return want
    raise RuntimeError(f'{OPA_PIN} pins no SHA-256')


def checked_opa(path, want):
    """A private copy of the opa binary at path, made only when its SHA-256 is want: the
    bytes hashed are the bytes run, so nothing can swap the binary between the check and
    the run, however the harness found it (a PATH lookup, a tool cache, a path the pull
    request's own workflow chose). Returns the copy's path; its directory is removed at
    exit."""
    with open(path, 'rb') as f:
        data = f.read(OPA_MAX_BYTES + 1)
    if len(data) > OPA_MAX_BYTES:
        raise RuntimeError(f'the opa binary {path} is larger than {OPA_MAX_BYTES} bytes')
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        raise RuntimeError(f'the opa binary {path} has SHA-256 {got}; the gate runs only {want} '
                           f'(policy/opa.version, or --opa-sha256), so it was not run')
    d = tempfile.mkdtemp(prefix='pr-receipt-opa-')
    atexit.register(shutil.rmtree, d, True)
    copy = os.path.join(d, 'opa')
    fd = os.open(copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    return copy


def opa(a, *args):
    """The opa command with the caller's environment minus every OPA_ variable, which
    would otherwise set any flag of its own (OPA_EVAL_DATA adds policy files)."""
    env = {k: v for k, v in clean_env().items() if not k.startswith('OPA_')}
    try:
        return subprocess.run([a.opa, *args], capture_output=True, text=True, env=env, timeout=OPA_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'opa {args[0]} took over {OPA_TIMEOUT_S} s') from None


def opa_error(p):
    """OPA's own words for a failed evaluation: its JSON errors, or its last line."""
    try:
        errors = json.loads(p.stdout).get('errors') or []
        said = '; '.join(f"{e.get('code', 'error')}: {e.get('message', '')}" for e in errors)
    except (ValueError, AttributeError):
        said = ''
    lines = [line for line in (p.stdout + p.stderr).splitlines() if line.strip()]
    return said or (lines[-1] if lines else f'exit {p.returncode}, no output')


def offline_capabilities(a):
    """This OPA's capabilities with every built-in a policy may not call removed, and no
    host it may reach."""
    p = opa(a, 'capabilities', '--current')
    if p.returncode != 0:
        raise RuntimeError(f'opa capabilities --current failed: {opa_error(p)}')
    caps = json.loads(p.stdout, object_pairs_hook=no_duplicates)
    builtins = caps.get('builtins')
    if not isinstance(builtins, list) or not builtins:
        raise RuntimeError('opa capabilities --current listed no built-in functions')
    caps['builtins'] = [b for b in builtins if not b.get('nondeterministic') and b.get('name') not in DENIED_BUILTINS]
    caps['allow_net'] = []
    return caps


def check_policy(a, inp):
    """(passed, detail, refusals): the policy's deny set over inp. Raises when it cannot be
    evaluated, so a policy that is wrong never passes for one that found nothing."""
    (ROOT / 'tmp').mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='policy-', dir=ROOT / 'tmp'))
    try:
        (scratch / 'capabilities.json').write_text(json.dumps(offline_capabilities(a)))
        (scratch / 'input.json').write_text(json.dumps(inp))
        args = ['eval', '--format', 'json', '--strict-builtin-errors', '--capabilities', str(scratch / 'capabilities.json'),
                '--schema', str(POLICY_SCHEMA), '--input', str(scratch / 'input.json')]
        for path in a.policy:
            args += ['--data', path]
        p = opa(a, *args, POLICY_QUERY)
    finally:
        shutil.rmtree(scratch)
    if p.returncode != 0:
        raise RuntimeError(f'the policy could not be evaluated: {opa_error(p)}')
    result = json.loads(p.stdout, object_pairs_hook=no_duplicates).get('result') or []
    if not result:
        raise RuntimeError(f'the policy defines no {POLICY_QUERY}: its package must be plimsoll.receipt, with deny rules')
    denied = result[0]['expressions'][0]['value']
    if not isinstance(denied, list) or not all(isinstance(m, str) for m in denied):
        raise RuntimeError(f'{POLICY_QUERY} must be a set of strings')
    if denied:
        return False, '; '.join(denied), denied
    return True, f"{len(a.policy)} {'policy' if len(a.policy) == 1 else 'policies'} over the signed run refused nothing", []


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


def check_tests(x, min_tests):
    """The tests check (states.tests_gate on the signed result), or None when the signed
    request asks for no test report and no minimum was given."""
    return states.tests_gate(states.tests(x, min_tests))


def last(a):
    """The checks made after result, which read the others."""
    return ['policy'] if a.policy else []


def verify(a, raw):
    """The checks on raw, the receipt read once: the checker and the later checks see the
    same bytes, so a file swapped between two reads cannot pass one and feed the other.
    Returns the checks and what the states are read from: the signed exchange (None unless
    the signature checked), the signer, and how the head check came out."""
    checks = []
    facts = {'x': None, 'signer': 'refused', 'signer_detail': '', 'head_result': None}
    (ROOT / 'tmp').mkdir(exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix='verify-', dir=ROOT / 'tmp'))
    try:
        (scratch / 'receipt.cdx.json').write_bytes(raw)
        ok, detail, tool = check_signature(a.sbom, str(scratch / 'receipt.cdx.json'), a.trusted_pub)
        if ok:
            try:
                x = signed_exchange(raw)
                key = None if a.trusted_pub else attachment(raw, 'harness.pub')
            except ValueError as e:
                ok, detail, tool = False, 'the receipt could not be read unambiguously', str(e)
        checks.append({'check': 'signature', 'passed': ok, 'detail': detail} | ({'tool': tool} if tool else {}))
        if not ok:
            facts['signer_detail'] = detail
            # tests is named when the configuration asks for a report: the unread receipt cannot say.
            for name in ['head'] + requested(a) + ['result'] + (['tests'] if a.junit_path or a.min_tests else []) + last(a):
                checks.append({'check': name, 'passed': None,
                               'detail': 'not checked: an unverified receipt proves nothing'})
            return checks, facts
        facts.update(x=x, signer='trusted_key' if a.trusted_pub else 'self_consistent')
        try:
            want = recipe_request(a, scratch)
            # The protocol is the plimsoll release the receipt was made with, not a fact about
            # the commit: a receipt an earlier release made (a lower number) is evidence for the
            # same request, and stays checkable after the protocol moves on.
            signed = x['request'].get('protocol')
            if isinstance(signed, int) and not isinstance(signed, bool) and 1 <= signed <= want['protocol']:
                want['protocol'] = signed
            diff = differences(x['request'], want)
            facts['head_result'] = 'differs' if diff else 'match'
            checks.append({'check': 'head', 'passed': not diff,
                           'detail': '; '.join(diff) if diff else f'tested exactly commit {a.head[:12]} of {a.repository}, pull request {a.pr}, with {a.command!r}'})
        except subprocess.CalledProcessError as e:
            facts['head_result'] = 'unbuilt'
            reason = (e.stderr or b'').decode(errors='replace').strip().splitlines()
            checks.append({'check': 'head', 'passed': False,
                           'detail': f"the recipe's request for commit {a.head[:12]} could not be rebuilt: {reason[-1] if reason else e}"})
        if a.junit:
            ok, detail = check_junit(x, a.junit)
            checks.append({'check': 'junit', 'passed': ok, 'detail': detail})
        if a.test_result:
            pub = a.trusted_pub
            if not pub:  # the key the receipt carries, the one the signature check used
                pub = str(scratch / 'attached.pub')
                Path(pub).write_bytes(key)
            ok, detail = check_test_result(a, x, pub)
            checks.append({'check': 'test-result', 'passed': ok, 'detail': detail})
    finally:
        shutil.rmtree(scratch)
    if a.coverage:
        ok, detail = check_coverage(x, a.coverage)
        checks.append({'check': 'coverage', 'passed': ok, 'detail': detail})
    ok, detail = check_result(x)
    checks.append({'check': 'result', 'passed': ok, 'detail': detail})
    gate = check_tests(x, a.min_tests)
    if gate is not None:
        checks.append({'check': 'tests', 'passed': gate[0], 'detail': gate[1]})
    if next(c['passed'] for c in checks if c['check'] == 'head'):
        inp = policy_input(x, raw, checks, facts['signer'])
        if a.policy_input:
            Path(a.policy_input).write_text(json.dumps(inp, indent=2, sort_keys=True) + '\n')
        if a.policy:
            ok, detail, refusals = check_policy(a, inp)
            checks.append({'check': 'policy', 'passed': ok, 'detail': detail, 'refusals': refusals})
    elif a.policy:
        checks.append({'check': 'policy', 'passed': None,
                       'detail': "not checked: the run is not this pull request's, so its facts are not this pull request's"})
    return checks, facts


def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    p.add_argument('--sbom', required=True, help='the examples/sbom checker, built')
    p.add_argument('--receipt', required=True)
    p.add_argument('--trusted-pub', default='', help="the operator's public key, never the receipt's own")
    p.add_argument('--self-consistent', action='store_true',
                   help='check only against the key the receipt carries (a key made for the run): never verified')
    p.add_argument('--repo', required=True, help='a clone of the project holding the head commit')
    p.add_argument('--repository', required=True, help="the CI platform's name for the repository, such as owner/name")
    p.add_argument('--head', required=True, help="the pull request's head commit, from the CI platform")
    p.add_argument('--pr', required=True)
    p.add_argument('--command', required=True, help='the configured test command')
    p.add_argument('--junit-path', default='', help='the JUNIT_PATH the receipt was made with, if any')
    p.add_argument('--base', default='', help="the pull request's base commit, as the receipt was made with PR_BASE_SHA")
    p.add_argument('--session-trailer', default='', help='the SESSION_TRAILER the receipt was made with, if any')
    p.add_argument('--junit', default='', help='a junit.xml to check against the signed result')
    p.add_argument('--min-tests', default=None, metavar='N',
                   help='the fewest tests that ran the returned test report must list (default 1 when the receipt asks for a report)')
    p.add_argument('--coverage-path', default='', help='the COVERAGE_PATH the receipt was made with, if any')
    p.add_argument('--coverage', default='', help='a coverage.cobertura.xml to check against the signed result')
    p.add_argument('--attest', default='', help='the plimsoll-attest binary, built; needed for --test-result')
    p.add_argument('--test-result', default='', help='a test-result.intoto.json to check against the signed result')
    p.add_argument('--policy', action='append', default=[],
                   help='a Rego policy (package plimsoll.receipt, deny rules) from outside the pull request; repeatable')
    p.add_argument('--opa', default='', help='the opa binary (Open Policy Agent); needed for --policy')
    p.add_argument('--opa-sha256', default='', help='the SHA-256 the opa binary must have (default: the one policy/opa.version pins)')
    p.add_argument('--policy-input', default='', help='write the input a policy reads to this file, once the signature and head checks pass')
    a = p.parse_args()
    if bool(a.trusted_pub) == a.self_consistent:
        p.error("give exactly one of --trusted-pub (the operator's key) and --self-consistent")
    if a.test_result and not a.attest:
        p.error('--test-result needs --attest, the plimsoll-attest binary that checks its signature')
    if a.policy and not a.opa:
        p.error('--policy needs --opa, the Open Policy Agent binary that evaluates it')
    if a.opa_sha256 and not re.fullmatch(r'[a-f0-9]{64}', a.opa_sha256):
        p.error('--opa-sha256 must be 64 lowercase hex digits')
    if (not re.fullmatch(r'[a-f0-9]{40}', a.head) or not re.fullmatch(r'0|[1-9][0-9]{0,11}', a.pr) or not a.command.strip()
            or not re.fullmatch(r'[!-~]{1,256}', a.repository) or (a.base and not re.fullmatch(r'[a-f0-9]{40}', a.base))):
        p.error('--head and --base must be full commit SHAs, --pr digits with no leading zero, --command nonempty, --repository printable with no spaces')
    if a.min_tests is not None:
        if not re.fullmatch(r'[1-9][0-9]{0,5}', a.min_tests):
            p.error('--min-tests must be a whole number from 1 to 999999')
        a.min_tests = int(a.min_tests)
    given = {'repository': a.repository, 'pr': a.pr, 'head': a.head}
    try:
        if a.opa:
            a.opa = checked_opa(a.opa, a.opa_sha256 or pinned_opa_sha256())
        raw = Path(a.receipt).read_bytes()
        checks, facts = verify(a, raw)
    except Exception as e:  # a crash is not a refusal: the receipt was never judged
        st, unverified = states.derive(None, signer='unknown', given=given)
        print(json.dumps({'verified': False, 'error': f'{type(e).__name__}: {e}', 'states': st, 'unverified': unverified}, indent=2))
        sys.exit(3)
    companions = {c['check']: c['passed'] for c in checks if c['check'] in ('junit', 'test-result', 'coverage')}
    policy = next((len(c['refusals']) for c in checks if c['check'] == 'policy' and c['passed'] is not None), None)
    st, unverified = states.derive(facts['x'], signer=facts['signer'], signer_detail=facts['signer_detail'],
                                   given=given, head_result=facts['head_result'], companions=companions, min_tests=a.min_tests,
                                   policy_refusals=policy)
    verified = all(c['passed'] for c in checks) and facts['signer'] == 'trusted_key'
    print(json.dumps({'verified': verified, 'receipt_sha256': hashlib.sha256(raw).hexdigest(),
                      'states': st, 'unverified': unverified, 'checks': checks}, indent=2))
    sys.exit(0 if verified else 1)


if __name__ == '__main__':
    main()
