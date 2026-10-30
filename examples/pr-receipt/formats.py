"""The receipt in standard formats: an in-toto test-result statement and Cobertura coverage.

Evidence stores and policy engines read a handful of standard formats. Both files here
are derived from the checked receipt alone, so any reader rebuilds them from the signed
result and compares (verify.py does), and neither adds anything the run record does not
already hold:

- test-result.statement.json: the subject and predicate of an in-toto test-result
  statement (https://in-toto.io/attestation/test-result/v0.1). receipt.sh signs it with
  the operator's key as test-result.intoto.json (`plimsoll-attest sign-statement`). The
  subject is the repository and commit the signed request names; the result is PASSED
  only when the run completed, every step exited 0 without timing out, and the returned
  JUnit report lists no failures and at least one test that ran and passed (zero tests, or
  skipped ones only, is FAILED); the test names come from junit.xml. The
  predicate has no field for where the tests ran, so the run record's entry under
  `configuration` carries the isolation tier, provider and environment as annotations,
  the standard's own extension point.
- coverage.cobertura.xml: the Cobertura form of the lcov file the run returned, when the
  receipt was made with COVERAGE_PATH. Like the framework's JUnit report, the project's
  own code writes it, so it is only as honest as the tests; what it cannot do is differ
  from what the run returned.

  python3 -I formats.py OUTPUT_DIRECTORY   # reads run-*.cdx.json and junit.xml
"""
import base64
import glob
import importlib.util
import json
from pathlib import Path
import posixpath
import sys
from xml.etree import ElementTree as ET

HERE = Path(__file__).resolve().parent
TEST_RESULT = 'https://in-toto.io/attestation/test-result/v0.1'


def load_junit():
    """junit.py beside this file, by path: -I keeps this directory off the import path."""
    spec = importlib.util.spec_from_file_location('pr_receipt_junit', HERE / 'junit.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


junit = load_junit()


def passed(x):
    """The receipt's pass rule, from the signed result: the run completed, it had steps,
    and every one exited 0 without timing out."""
    p = x['response']['project']
    steps = p.get('steps') or []
    return (p.get('outcome') == 'PROJECT_OUTCOME_COMPLETED' and bool(steps)
            and all(s.get('exit_code', 0) == 0 and not s.get('timed_out') for s in steps))


def subject_file(x):
    """The repository and commit from .pr-receipt/subject.json, a file of the signed request."""
    files = [f for f in x['request']['project']['files'] if f['path'] == '.pr-receipt/subject.json']
    if len(files) != 1:
        raise ValueError('the signed request has no single .pr-receipt/subject.json')
    s = json.loads(files[0]['content'])
    return s['repository'], s['commit']


def test_report(report):
    """(passed names, failed names, report passed) from JUnit. Skipped cases are neither.
    Unreadable reports still permit a receipt, but cannot support PASSED."""
    ok, bad = [], []
    try:
        root = junit.parse_report(report)
    except (ET.ParseError, ValueError, LookupError):
        return [], [], False
    tag = lambda node: node.tag.rsplit('}', 1)[-1]
    if tag(root) not in ('testsuite', 'testsuites'):
        return [], [], False
    report_passed = True
    for node in root.iter():
        if tag(node) in ('failure', 'error'):
            report_passed = False
        if tag(node) in ('testsuite', 'testsuites'):
            for key in ('failures', 'errors'):
                value = node.get(key)
                if value is not None and (not value.isascii() or not value.isdigit() or value.strip('0')):
                    report_passed = False
    cases = [node for node in root.iter() if tag(node) == 'testcase']
    for case in cases:
        name = case.get('name', '')
        children = {tag(child) for child in case}
        if children & {'failure', 'error'}:
            bad.append(name)
        elif 'skipped' not in children:
            ok.append(name)
    return ok, bad, report_passed


def test_result(x):
    """The statement's subject and predicate, and where its test names came from. A run
    asked for a JUnit file that did not return one still gets a FAILED statement,
    with no test names: it cannot establish a passing report. So does one whose report lists
    no test that ran. A higher minimum (PLIMSOLL_MIN_TESTS) is the gate's setting, not the
    signed result's, so the statement does not carry it; it lists the passed tests, which a
    policy can count."""
    report, source = junit.junit(x)
    record = x['response']['record']
    repository, commit = subject_file(x)
    ok, bad, report_passed = test_report(report) if report is not None else ([], [], False)
    predicate = {
        # ok: at least one test ran and passed. A report of zero tests, or of skipped ones
        # only, shows no test ran, which is never a pass (the gate's default minimum of one).
        'result': 'PASSED' if passed(x) and report_passed and ok else 'FAILED',
        'configuration': [
            {'name': 'plimsoll run record', 'digest': {'sha256': record['record_sha256']},
             'annotations': {'isolation': record['isolation'], 'provider': record['provider'],
                             'environment': record['environment']}},
            {'name': 'plimsoll run request', 'digest': {'sha256': record['request_sha256']}},
        ],
    }
    if ok:
        predicate['passedTests'] = ok
    if bad:
        predicate['failedTests'] = bad
    statement = {'subject': [{'name': repository, 'digest': {'gitCommit': commit}}], 'predicate': predicate}
    return statement, (f'test names from {source}' if report is not None else f'no test names: {source}')


def lcov_report(x):
    """(path, bytes) of the requested lcov file as the run returned it, (path, None) when
    the run did not return it, or None when the receipt was made without COVERAGE_PATH.
    prepare.py requests the JUnit file first and the coverage file second."""
    wanted = x['request']['project'].get('artifacts') or []
    if len(wanted) < 2:
        return None
    for a in x['response']['project'].get('artifacts') or []:
        if a['path'] == wanted[1]:
            return wanted[1], base64.b64decode(a['content'], validate=True)
    return wanted[1], None


def rate(hit, total):
    return f'{hit / total:.4f}' if total else '1'


class LcovError(ValueError):
    """The returned file is not an lcov report this converter can state coverage from."""


def count(text):
    """A non-negative whole number from an lcov field."""
    if not text.isascii() or not text.isdigit():
        raise LcovError('a count is not a non-negative whole number')
    return int(text)


def cobertura_from_lcov(lcov, timestamp_ms):
    """Cobertura XML from lcov text: one class per source file, grouped into packages by
    directory. The same input always gives the same bytes. Text with no source file record,
    no line record, a record left open, or a count that is not a whole number is refused
    (LcovError), so that no malformed or empty report becomes a coverage rate."""
    files = {}
    current = None
    for line in lcov.decode().splitlines():
        tag, _, value = line.partition(':')
        if tag == 'SF':
            if current is not None:
                raise LcovError('a source file record starts before the last one ended')
            current = files.setdefault(value, {'lines': {}, 'branches': {}})
        elif tag == 'end_of_record':
            current = None
        elif current is None:
            continue
        elif tag == 'DA':
            fields = value.split(',')
            if len(fields) not in (2, 3):
                raise LcovError('a DA record does not have a line and a count')
            n = count(fields[0])
            current['lines'][n] = current['lines'].get(n, 0) + count(fields[1])
        elif tag == 'BRDA':
            fields = value.split(',')
            if len(fields) != 4:
                raise LcovError('a BRDA record does not have four fields')
            number, block, branch, taken = fields
            key = (block, branch)
            b = current['branches'].setdefault(count(number), {})
            b[key] = b.get(key, False) or (taken != '-' and count(taken) > 0)
    if current is not None:
        raise LcovError('the last source file record has no end_of_record')
    if not files:
        raise LcovError('no source file record (SF:)')
    if not any(f['lines'] for f in files.values()):
        raise LcovError('no line record (DA:)')
    all_lines = sum(len(f['lines']) for f in files.values())
    hit_lines = sum(1 for f in files.values() for h in f['lines'].values() if h > 0)
    all_branches = sum(len(b) for f in files.values() for b in f['branches'].values())
    hit_branches = sum(1 for f in files.values() for b in f['branches'].values() for t in b.values() if t)
    root = ET.Element('coverage', {
        'line-rate': rate(hit_lines, all_lines), 'branch-rate': rate(hit_branches, all_branches),
        'lines-covered': str(hit_lines), 'lines-valid': str(all_lines),
        'branches-covered': str(hit_branches), 'branches-valid': str(all_branches),
        'complexity': '0', 'version': 'plimsoll pr-receipt', 'timestamp': str(timestamp_ms)})
    ET.SubElement(ET.SubElement(root, 'sources'), 'source').text = '.'
    packages = ET.SubElement(root, 'packages')
    by_dir = {}
    for path in sorted(files):
        by_dir.setdefault(posixpath.dirname(path) or '.', []).append(path)
    for directory, paths in by_dir.items():
        pl = [h for p in paths for h in files[p]['lines'].values()]
        pb = [t for p in paths for b in files[p]['branches'].values() for t in b.values()]
        package = ET.SubElement(packages, 'package', {
            'name': directory, 'line-rate': rate(sum(1 for h in pl if h), len(pl)),
            'branch-rate': rate(sum(1 for t in pb if t), len(pb)), 'complexity': '0'})
        classes = ET.SubElement(package, 'classes')
        for path in paths:
            f = files[path]
            fb = [t for b in f['branches'].values() for t in b.values()]
            cls = ET.SubElement(classes, 'class', {
                'name': posixpath.basename(path), 'filename': path,
                'line-rate': rate(sum(1 for h in f['lines'].values() if h), len(f['lines'])),
                'branch-rate': rate(sum(1 for t in fb if t), len(fb)), 'complexity': '0'})
            ET.SubElement(cls, 'methods')
            lines = ET.SubElement(cls, 'lines')
            for n in sorted(set(f['lines']) | set(f['branches'])):
                attrs = {'number': str(n), 'hits': str(f['lines'].get(n, 0))}
                if n in f['branches']:
                    b = f['branches'][n]
                    taken = sum(1 for t in b.values() if t)
                    attrs |= {'branch': 'true', 'condition-coverage': f'{round(100 * taken / len(b))}% ({taken}/{len(b)})'}
                else:
                    attrs['branch'] = 'false'
                ET.SubElement(lines, 'line', attrs)
    ET.indent(root)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding='unicode').encode() + b'\n'


def coverage(x):
    """(bytes, source) for coverage.cobertura.xml, (None, reason) when the run was asked
    for an lcov file and did not return one, or None without COVERAGE_PATH."""
    report = lcov_report(x)
    if report is None:
        return None
    path, content = report
    if content is None:
        truncated = x['response']['project'].get('artifacts_truncated')
        return None, (f'the run returned no {path}: ' +
                      ('it was over the artifact budget' if truncated else 'the test command did not write it'))
    try:
        converted = cobertura_from_lcov(content, int(x['response']['record']['started_unix_ms']))
    except LcovError as e:
        # The project's code writes the lcov file; one this cannot read gives no coverage
        # file rather than stopping the receipt. The reasons are this file's own words, never
        # the file's text.
        return None, f'the run\'s {path} is not lcov this converter reads: {e}'
    except (ValueError, UnicodeDecodeError) as e:
        return None, f'the run\'s {path} is not lcov this converter reads ({type(e).__name__})'
    return converted, f'converted from the run\'s own {path}'


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: formats.py OUTPUT_DIRECTORY')
    out = Path(sys.argv[1])
    boms = glob.glob(str(out / 'run-*.cdx.json'))
    if len(boms) != 1:
        raise SystemExit(f'expected one run-*.cdx.json in {out}, found {len(boms)}')
    x = junit.exchange(Path(boms[0]).read_bytes())
    statement, source = test_result(x)
    (out / 'test-result.statement.json').write_text(json.dumps(statement, indent=2, sort_keys=True) + '\n')
    print('test-result.statement.json: ' + source)
    cov = coverage(x)
    if cov is not None:
        content, source = cov
        if content is None:
            print('No coverage.cobertura.xml: ' + source)
        else:
            (out / 'coverage.cobertura.xml').write_bytes(content)
            print('coverage.cobertura.xml: ' + source)


if __name__ == '__main__':
    main()
