"""Receipt states: what a pull-request receipt covers, said plainly.

A receipt that checks is not a pull request whose tests passed. verify.py checks a receipt;
this module reads the checked receipt into a few states, each one word from a small closed
set (VALUES), with one plain sentence beside it:

- signer: trusted_key (the signature checks against a key given to the checker
  separately), self_consistent (only against the key the receipt carries, which anyone can
  make), refused (it does not check), unknown (the check could not run).
- covers: known or unknown, with the repository, commit, pull request and base that
  .pr-receipt/subject.json, a file of the signed request, names.
- candidate: current (the commit is the head the checker was given, and the signed request
  is exactly what the recipe builds there), stale (another commit of the same repository
  and pull request), mismatch (the head's commit, but other files, command or settings),
  other (another repository or pull request, or no subject), unknown.
- run: completed, setup_failed, timed_out, protocol_error, runner_failed (the signed
  outcome), or unknown.
- steps: passed (every requested step ran and exited 0 without timing out), failed,
  not_run, unknown.
- tests: discovered (the test report the run returned inside the signed result lists at
  least one test that ran), zero (none ran), unknown (no report requested, none returned,
  or unreadable). Its field minimum is the fewest tests that ran the gate requires (1
  whenever a report was requested, unless the checker was given more); tests_gate() is that
  rule, which verify.py checks and the verdict follows.
- evidence: complete (every file the run was asked to return came back and no output was
  cut), partial, unknown.
- verdict: passed, incomplete, failed, refused, unknown, from the states above and, when
  verify.py ran a policy (--policy), its refusals (verdict()).

Unknown stays unknown: nothing here rounds a missing fact up. Every state comes from the
signed exchange, read only after the signature check passed, and from what the checker is
given (the repository, pull request and head, from the CI platform); never from a file
beside the receipt or from text the run printed. Details are this file's own words and
those values, never guest-written text such as test names.

  python3 -I states.py summary STATES_JSON [--uploaded OUTCOME] [--artifact NAME]

prints a job summary (markdown, one line per state) from verify.py's report. A missing
report prints a summary saying no states were written. --uploaded is the CI platform's
outcome of the step that kept the receipt (GitHub's steps.<id>.outcome), which adds the
one state a verifier cannot know: stored.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import sys
from xml.etree import ElementTree as ET

HERE = Path(__file__).resolve().parent
SUBJECT = '.pr-receipt/subject.json'
VALUES = {
    'verdict': ('passed', 'incomplete', 'failed', 'refused', 'unknown'),
    'signer': ('trusted_key', 'self_consistent', 'refused', 'unknown'),
    'covers': ('known', 'unknown'),
    'candidate': ('current', 'stale', 'mismatch', 'other', 'unknown'),
    'run': ('completed', 'setup_failed', 'timed_out', 'protocol_error', 'runner_failed', 'unknown'),
    'steps': ('passed', 'failed', 'not_run', 'unknown'),
    'tests': ('discovered', 'zero', 'unknown'),
    'evidence': ('complete', 'partial', 'unknown'),
    'stored': ('uploaded', 'not_uploaded', 'unknown'),  # the job summary only
}
ORDER = ('verdict', 'signer', 'covers', 'candidate', 'run', 'steps', 'tests', 'evidence')
LABELS = {'verdict': 'Verdict', 'signer': 'Signer', 'covers': 'Covers', 'candidate': 'Candidate', 'run': 'Run',
          'steps': 'Steps', 'tests': 'Tests', 'evidence': 'Evidence', 'stored': 'Stored'}
OUTCOMES = {
    'PROJECT_OUTCOME_COMPLETED': ('completed', 'ran to its end'),
    'PROJECT_OUTCOME_SETUP_FAILED': ('setup_failed', 'did not complete: setup failed before any step began, so none of the code ran'),
    'PROJECT_OUTCOME_TIMED_OUT': ('timed_out', 'did not complete: the time limit ended it'),
    'PROJECT_OUTCOME_PROTOCOL_ERROR': ('protocol_error', 'did not complete: the sandbox gave no result that could be read, so what ran is unknown'),
    'PROJECT_OUTCOME_RUNNER_FAILED': ('runner_failed', 'did not complete: the runner failed after a step began'),
}
RUN_SAID = dict(OUTCOMES.values())
TIERS = {'kernel': 1, 'vm': 2}  # the recipe's floor and what is stronger
NOT_READ = 'not read: an unverified receipt proves nothing'
ALWAYS = (
    ('merge_result', 'the merge: the receipt covers the head commit, not the commit a merge would make'),
    ('authorship', 'who wrote the files: the receipt names commits, and any agent sessions the commits name, not their authors'),
    ('test_quality', 'whether the tests check the change: the pull request supplies its own tests, and its code writes any test report'),
)
FILES = {'junit': 'junit.xml', 'test-result': 'test-result.intoto.json', 'coverage': 'coverage.cobertura.xml'}
COMPANIONS = (
    ('junit', 'junit_file', 'junit.xml beside the receipt: not given to the checker, so not compared with the signed result'),
    ('test-result', 'test_result_statement', 'test-result.intoto.json beside the receipt: not given to the checker, so not compared with the signed result'),
    ('coverage', 'coverage_file', 'coverage.cobertura.xml beside the receipt: not given to the checker, so not compared with the signed result'),
)


def _load(name, file):
    """A module beside this file, by path: under python3 -I this directory is not on the
    import path, and a module of that name elsewhere must never stand in for it."""
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


junit = _load('pr_receipt_junit', 'junit.py')
formats = _load('pr_receipt_formats', 'formats.py')


def code(value):
    """A value as a markdown code span on one line; a backtick inside cannot end it."""
    return '`' + re.sub(r'[\x00-\x1f\x7f]', ' ', str(value)).replace('`', "'") + '`'


def no_duplicates(pairs):
    """A repeated key could be read one way here and another way by the recipe."""
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError('a JSON object repeats a key')
    return dict(pairs)


def state(value, detail, **fields):
    return {'value': value, 'detail': detail, **fields}


def subject(x):
    """The signed request's subject file as a dict, or None when it has none, or one that
    does not name a repository, commit and pull request."""
    files = [f for f in x['request']['project'].get('files') or [] if f.get('path') == SUBJECT]
    if len(files) != 1:
        return None
    try:
        s = json.loads(files[0]['content'], object_pairs_hook=no_duplicates)
    except (ValueError, TypeError):
        return None
    if not isinstance(s, dict) or not all(isinstance(s.get(k), str) for k in ('repository', 'commit', 'pull_request')):
        return None
    return s


def covers(s):
    if s is None:
        return state('unknown', 'the signed request names no repository, commit or pull request')
    base = s.get('base') if isinstance(s.get('base'), str) else None
    detail = f"commit {code(s['commit'])} of {code(s['repository'])}, pull request {code(s['pull_request'])}"
    return state('known', detail + (f', base {code(base)}' if base else ''),
                 repository=s['repository'], commit=s['commit'], pull_request=s['pull_request'], base=base)


def candidate(s, given, head_result):
    """given: the repository, pull request and head from the CI platform. head_result:
    verify.py's head check, 'match', 'differs' (the signed request is not what the recipe
    builds for the head), 'unbuilt' (the recipe's request could not be rebuilt) or None."""
    if not given or not given.get('head'):
        return state('unknown', 'no head was given to compare with', head=None)
    head = given['head']
    if s is None:
        return state('other', 'the signed request does not say which commit it tested, so it is not evidence for this head', head=head)
    if s['repository'] != given.get('repository'):
        return state('other', f"the receipt is for repository {code(s['repository'])}; this is {code(given.get('repository'))}", head=head)
    if s['pull_request'] != given.get('pr'):
        return state('other', f"the receipt is for pull request {code(s['pull_request'])}; this is {code(given.get('pr'))}", head=head)
    if s['commit'] != head:
        return state('stale', f"it covers commit {code(s['commit'])}, not the head {code(head)}: evidence for another commit of this pull request", head=head)
    if head_result == 'match':
        return state('current', 'the commit is the head the checker was given, and the signed request is exactly what the recipe builds there; a later push makes it stale', head=head)
    if head_result == 'differs':
        return state('mismatch', 'it names the head commit, but the signed request is not what the recipe builds there with this configuration (the head check says how)', head=head)
    if head_result == 'unbuilt':
        return state('unknown', "the recipe's request for the head could not be rebuilt, so what the head holds was not compared (the head check says why)", head=head)
    return state('unknown', 'the signed request was not compared with what the head holds', head=head)


def run(x):
    r = x['response']
    p = r.get('project') or {}
    record = r.get('record') or {}
    tier = r.get('isolation') if re.fullmatch(r'[a-z_]{1,20}', str(r.get('isolation'))) else ''
    requested = len(x['request']['project'].get('steps') or [])
    ran = len(p.get('steps') or [])
    fields = {'isolation': tier or None, 'steps_ran': ran, 'steps_requested': requested}
    unanswered = record.get('unanswered')
    if unanswered:
        word = unanswered if re.fullmatch(r'[a-z_]{1,40}', str(unanswered)) else 'an error'
        return state('unknown', f'the call may have run but got no answer (it ended with {word})', **fields)
    value, said = OUTCOMES.get(p.get('outcome'), (None, None))
    if value is None:
        named = p.get('outcome') if re.fullmatch(r'[A-Z_]{1,64}', str(p.get('outcome'))) else 'none'
        return state('unknown', f'the signed result names an outcome this reader does not know ({named})', **fields)
    if TIERS.get(tier, 0) < TIERS['kernel']:
        where = f"behind the {tier or 'unstated'} tier, below the kernel floor the recipe requires"
    else:
        where = f'behind the {tier} tier'
    if value == 'timed_out':
        limit = x['request'].get('timeout_ms')
        if isinstance(limit, int) and limit > 0:
            said = f'did not complete: its {limit / 1000:g}-second limit ended it'
    return state(value, f'{said} {where}; {ran} of {requested} steps ran', **fields)


def steps(x, run_state):
    requested = x['request']['project'].get('steps') or []
    ran = (x['response'].get('project') or {}).get('steps') or []
    for i, s in enumerate(ran):
        exit_code = s.get('exit_code')
        if not isinstance(exit_code, int) or isinstance(exit_code, bool) or not isinstance(s.get('timed_out'), bool):
            return state('unknown', f'step {i + 1} has no exit code or timeout flag in the signed result')
        if s['timed_out']:
            return state('failed', f'step {i + 1} of {len(requested)} timed out')
        if s['exit_code'] != 0:
            return state('failed', f"step {i + 1} of {len(requested)} exited {s['exit_code']}")
    if requested and len(ran) == len(requested):
        return state('passed', f'every step ran and exited 0 without timing out ({len(ran)} of {len(requested)})')
    if run_state['value'] in ('protocol_error', 'unknown'):
        return state('unknown', 'which steps ran is unknown')
    if not ran:
        return state('not_run', 'no step ran')
    return state('not_run', f'{len(ran)} of {len(requested)} steps ran; the rest did not')


def report_counts(content):
    """(cases, passed, failed, skipped) from JUnit XML, or None when it is not JUnit this
    reads. A case with a failure or error is failed; one with only skipped, skipped."""
    try:
        root = junit.parse_report(content)
    except (ET.ParseError, ValueError, LookupError):
        return None
    tag = lambda node: node.tag.rsplit('}', 1)[-1] if isinstance(node.tag, str) else ''
    if tag(root) not in ('testsuite', 'testsuites'):
        return None
    passed = failed = skipped = 0
    for case in root.iter():
        if tag(case) != 'testcase':
            continue
        children = {tag(child) for child in case}
        if children & {'failure', 'error'}:
            failed += 1
        elif 'skipped' in children:
            skipped += 1
        else:
            passed += 1
    return passed + failed + skipped, passed, failed, skipped


def minimum(x, min_tests=None):
    """The fewest tests that ran the returned report must list for the gate to pass:
    min_tests when the checker was given one (PLIMSOLL_MIN_TESTS), else 1 when the signed
    request asks for any file back (the recipe asks for the test report first), else None:
    no report was asked for, so there is nothing to count and no minimum."""
    if min_tests is not None:
        return min_tests
    return 1 if x['request']['project'].get('artifacts') else None


def tests(x, min_tests=None):
    least = minimum(x, min_tests)
    none = {'cases': None, 'passed': None, 'failed': None, 'skipped': None, 'report_passed': None, 'minimum': least}
    try:
        report = junit.framework_report(x)
    except (ValueError, KeyError, TypeError):
        return state('unknown', 'the signed request asks for files this reader does not recognize as a test report', **none)
    if report is None:
        return state('unknown', 'no test report was requested (JUNIT_PATH unset): the receipt knows the exit codes, not how many tests ran', **none)
    path, content = report
    if content is None:
        why = 'it was over the artifact budget' if x['response']['project'].get('artifacts_truncated') else 'the test command did not write it'
        return state('unknown', f'the run returned no {code(path)} ({why}), so how many tests ran is unknown', **none)
    counts = report_counts(content)
    if counts is None:
        return state('unknown', f'the {code(path)} the run returned is not a JUnit report this reads, so how many tests ran is unknown', **none)
    cases, passed, failed, skipped = counts
    report_passed = formats.test_report(content)[2]
    fields = {'cases': cases, 'passed': passed, 'failed': failed, 'skipped': skipped, 'report_passed': report_passed, 'minimum': least}
    whose = "the test framework's own count, written by the project's code and returned inside the signed result"
    plural = lambda n: f"{n} test case{'' if n == 1 else 's'}"
    if passed + failed == 0:
        listed = 'lists no test case' if not cases else f'lists {plural(cases)}, all skipped'
        return state('zero', f'the {code(path)} the run returned {listed}: no test ran ({whose})', **fields)
    note = '' if report_passed or failed else '; its failure counters are not zero'
    return state('discovered', f'the {code(path)} the run returned lists {plural(cases)}: {passed} passed, {failed} failed, {skipped} skipped{note} ({whose})', **fields)


def tests_gate(t):
    """The gate's rule on the tests state (the plan's D1 and D2): (passed, detail), or None
    when no report was asked for and no minimum given, so there is nothing to judge. It fails
    when the returned report is missing or unreadable, lists a failure or error (even though
    every step exited 0), or lists fewer tests that ran than the minimum."""
    least = t.get('minimum')
    if least is None:
        return None
    need = f"the gate requires at least {least} test{'' if least == 1 else 's'} that ran"
    if t['value'] == 'unknown':
        return False, f"{t['detail']}; {need}"
    if t['failed'] or not t['report_passed']:
        return False, f"the returned test report lists failures or errors: {t['detail']}"
    ran = t['passed']
    if ran < least:
        return False, f"the returned test report lists {ran} test{'' if ran == 1 else 's'} that ran; {need}"
    return True, f"the returned test report lists {ran} test{'' if ran == 1 else 's'} that ran and no failure; {need}"


def evidence(x, run_state):
    if run_state['value'] in ('protocol_error', 'unknown'):
        return state('unknown', 'the run gave no readable result, so what came back is unknown', missing=None, cut=None)
    p = x['response']['project']
    wanted = x['request']['project'].get('artifacts') or []
    returned = {a.get('path') for a in p.get('artifacts') or []}
    missing = [w for w in wanted if w not in returned]
    cut = []
    if p.get('artifacts_truncated'):
        cut.append('the returned files, over the artifact budget')
    for i, s in enumerate(p.get('steps') or []):
        for stream in ('stdout', 'stderr'):
            if s.get(stream + '_truncated'):
                cut.append(f'step {i + 1} {stream}')
    if missing or cut:
        said = []
        if missing:
            said.append('the run did not return ' + ', '.join(code(m) for m in missing))
        if cut:
            said.append('cut: ' + ', '.join(cut))
        return state('partial', '; '.join(said), missing=missing, cut=cut)
    asked = 'every file the run was asked to return came back inside the signed result' if wanted else 'the run was asked to return no file'
    return state('complete', asked + ', and no output was cut', missing=[], cut=[])


def verdict(s, companions, policy_refusals=None):
    """The one-word reading, first match wins; the order is the README's. policy_refusals
    is how many refusals the repository's policy made (verify.py --policy), None when no
    policy ran."""
    refused = [name for name, ok in (companions or {}).items() if ok is False]
    if s['signer']['value'] == 'unknown':
        return state('unknown', 'the receipt could not be checked, so nothing in it is established')
    if s['signer']['value'] == 'refused':
        return state('refused', 'its signature does not check against the given key, so nothing in it is believed')
    if s['candidate']['value'] in ('stale', 'mismatch', 'other'):
        return state('refused', "it is not evidence for this pull request's head: " + s['candidate']['detail'])
    if refused:
        names = ' and '.join(f'the {FILES.get(name, name)}' for name in refused)
        return state('refused', f"{names} given with the receipt {'does' if len(refused) == 1 else 'do'} not match its signed result")
    failures = []
    if s['run']['value'] not in ('completed', 'unknown'):
        failures.append('the run ' + RUN_SAID[s['run']['value']])
    if s['run']['value'] != 'unknown' and TIERS.get(s['run']['isolation'] or '', 0) < TIERS['kernel']:
        failures.append('it ran below the kernel floor')
    if s['steps']['value'] in ('failed', 'not_run'):
        failures.append(s['steps']['detail'])
    gate = tests_gate(s['tests'])
    if s['tests']['value'] != 'unknown' and (s['tests']['failed'] or not s['tests']['report_passed']):
        failures.append('the test report the run returned lists failures')
    elif s['run']['value'] == 'completed' and gate is not None and not gate[0]:
        # A run that did not complete has failed above already; one whose result is unknown
        # stays unknown below, since a report it may not have finished counts for nothing.
        failures.append(gate[1])
    if policy_refusals:
        # The count, not the text: the refusals are the policy author's words, in the policy check.
        failures.append(f"the repository's policy refused it ({policy_refusals} {'refusal' if policy_refusals == 1 else 'refusals'}, listed in the policy check)")
    if failures:
        return state('failed', '; '.join(failures))
    unknown = [name for name in ('candidate', 'run', 'steps') if s[name]['value'] == 'unknown']
    if unknown:
        return state('unknown', 'not established: ' + ', '.join(unknown))
    gaps = []
    if s['signer']['value'] == 'self_consistent':
        gaps.append('it is signed only with the key it carries, so who made it is not shown')
    if s['tests']['value'] == 'unknown':  # no report was asked for; a requested one failed above
        gaps.append('how many tests ran is unknown')
    if s['evidence']['value'] != 'complete':
        gaps.append('part of the evidence did not come back')
    if gaps:
        return state('incomplete', 'every check that ran passed, but ' + '; '.join(gaps) + '. Do not read it as passed')
    return state('passed', f"the tests ran on the current head behind the {s['run']['isolation']} tier and passed, checked against the operator's key")


def unverified(s, x, companions):
    if x is None or s['signer']['value'] not in ('trusted_key', 'self_consistent'):
        return [{'code': 'everything', 'detail': 'everything in the receipt: its signature was not established'}]
    items = [{'code': c, 'detail': d} for c, d in ALWAYS]
    if s['signer']['value'] == 'self_consistent':
        items.append({'code': 'signer_identity', 'detail': 'who signed it: the only key it checks against is the one it carries'})
    if s['tests']['value'] == 'unknown':
        items.append({'code': 'test_count', 'detail': 'how many tests ran'})
    lcov = len(x['request']['project'].get('artifacts') or []) > 1
    for name, c, d in COMPANIONS:
        if (companions or {}).get(name) is None and (name != 'coverage' or lcov):
            items.append({'code': c, 'detail': d})
    return items


def derive(x, *, signer, signer_detail='', given=None, head_result=None, companions=None, min_tests=None, policy_refusals=None):
    """(states, unverified) for exchange x, the receipt's signed request and response, which
    the caller read only after its signature check passed; x is None when it did not.
    signer is that check's result (VALUES['signer']); given holds the repository, pr and head
    the checker was given; head_result is verify.py's head check; companions maps each
    companion file check ('junit', 'test-result', 'coverage') to True, False, or None when
    the file was not given; min_tests is the minimum test count the checker was given, if
    any (minimum() says what stands in for it); policy_refusals is how many refusals the
    repository's policy made, None when no policy ran."""
    if signer not in ('trusted_key', 'self_consistent'):
        x = None
    signer_text = {
        'trusted_key': 'the signature and run record check against a key given to the checker separately, not the one the receipt carries',
        'self_consistent': 'the signature checks only against the key the receipt carries; anyone can make a key and sign a receipt, so this shows the receipt agrees with itself, not who made it',
        'refused': signer_detail or 'the signature or the run record does not check against the given key',
        'unknown': signer_detail or 'the signature check could not run',
    }[signer]
    s = {'signer': state(signer, signer_text)}
    if x is None:
        s['covers'] = state('unknown', NOT_READ)
        s['candidate'] = state('unknown', NOT_READ, head=(given or {}).get('head'))
        s['run'] = state('unknown', NOT_READ, isolation=None, steps_ran=None, steps_requested=None)
        s['steps'] = state('unknown', NOT_READ)
        s['tests'] = state('unknown', NOT_READ, cases=None, passed=None, failed=None, skipped=None, report_passed=None, minimum=None)
        s['evidence'] = state('unknown', NOT_READ, missing=None, cut=None)
    else:
        subj = subject(x)
        s['covers'] = covers(subj)
        s['candidate'] = candidate(subj, given, head_result)
        s['run'] = run(x)
        s['steps'] = steps(x, s['run'])
        s['tests'] = tests(x, min_tests)
        s['evidence'] = evidence(x, s['run'])
    v = verdict(s, companions, policy_refusals)
    ordered = {'verdict': v, **{name: s[name] for name in ORDER[1:]}}
    return ordered, unverified(s, x, companions)


def stored(outcome, artifact):
    if outcome == 'success':
        return state('uploaded', f'kept as the workflow artifact {code(artifact)}' if artifact else 'kept as a workflow artifact')
    if outcome in ('failure', 'cancelled'):
        return state('not_uploaded', f'the upload step ended {outcome}: the receipt was not kept, and the runner holding it is discarded with the job')
    if outcome == 'skipped':
        return state('not_uploaded', 'the upload step did not run')
    return state('unknown', "the upload step's outcome is not known")


def summary(report, uploaded=None, artifact=''):
    """Markdown lines: a heading with the verdict, one line per state, what stays unverified."""
    if not isinstance(report, dict) or not isinstance(report.get('states'), dict) or any(
            not isinstance(report['states'].get(name), dict) for name in ORDER):
        why = ('no states: receipt.sh did not write states.json (the job stopped before it, or the check could not run)'
               if report is None else 'no states: states.json is not a report of them')
        states, gaps = derive(None, signer='unknown', signer_detail=why)
        sha = None
    else:
        states, gaps, sha = report['states'], report.get('unverified') or [], report.get('receipt_sha256')
    lines = [f"### plimsoll receipt: {states['verdict']['value']}", '']
    for name in ORDER:
        lines.append(f"- **{LABELS[name]}:** {code(states[name]['value'])}. {states[name]['detail'][:1].upper()}{states[name]['detail'][1:]}.")
    if uploaded is not None:
        st = stored(uploaded, artifact)
        lines.append(f"- **{LABELS['stored']}:** {code(st['value'])}. {st['detail'][:1].upper()}{st['detail'][1:]}.")
    if gaps:
        lines.append('- **Unverified:** ' + '; '.join(g['detail'] for g in gaps) + '.')
    if sha:
        lines += ['', f"Receipt SHA-256 {code(sha)}. The full report, with each check, is `states.json` beside the receipt."]
    return lines


def main():
    p = argparse.ArgumentParser(description=__doc__.split('\n\n')[0])
    sub = p.add_subparsers(dest='command', required=True)
    s = sub.add_parser('summary', help="print the job summary from verify.py's report")
    s.add_argument('report', help='states.json: the JSON report verify.py printed')
    s.add_argument('--uploaded', default=None, help="the CI platform's outcome of the step that kept the receipt")
    s.add_argument('--artifact', default='', help='the name the receipt was kept under')
    a = p.parse_args()
    path = Path(a.report)
    report = None
    if path.exists():
        try:
            report = json.loads(path.read_text())
        except (ValueError, UnicodeDecodeError):
            report = 'unreadable'  # summary() says states.json is not a report
    print('\n'.join(summary(report, a.uploaded, a.artifact)))


if __name__ == '__main__':
    main()
