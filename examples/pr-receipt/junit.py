"""The receipt's JUnit file: the test framework's own report, or one built from the steps.

JUnit XML is the test-report format CI systems and evidence stores read. A receipt run
with JUNIT_PATH set asks the sandbox to return that file after the run; it comes back
inside the signed result, so junit.xml here is those exact bytes and cannot be edited
without failing the run record. Without JUNIT_PATH, junit.xml is built from the signed
result alone: one test case per requested step (passed, failed by its exit code, timed
out, or never run because an earlier step failed), so any reader can rebuild it.

Either way the file is only as honest as the tests: the project's own code writes the
framework's report, so it can claim anything. What it cannot do is differ from what the
run returned. Pass or fail is decided from the signed exit codes, never from this file.

  python3 -I junit.py OUTPUT_DIRECTORY   # reads its run-*.cdx.json, writes junit.xml
"""
import base64
import glob
import json
from pathlib import Path
import sys
from xml.etree import ElementTree as ET


def exchange(bom_bytes):
    """The signed request and response attached inside a receipt."""
    bom = json.loads(bom_bytes)
    data = bom['declarations']['evidence'][0]['data']
    a = next(d for d in data if d['name'] == 'exchange.json')['contents']['attachment']
    return json.loads(base64.b64decode(a['content'], validate=True))


def framework_report(x):
    """(path, bytes) of the requested JUnit file as the run returned it, (path, None) when
    the run did not return it, or None when the request asked for no file. prepare.py
    requests the JUnit file first."""
    wanted = x['request']['project'].get('artifacts') or []
    if not wanted:
        return None
    if len(wanted) > 2:
        raise ValueError('the receipt recipe requests at most two artifacts, the JUnit file and then the lcov file')
    for a in x['response']['project'].get('artifacts') or []:
        if a['path'] == wanted[0]:
            return wanted[0], base64.b64decode(a['content'], validate=True)
    return wanted[0], None


def from_steps(x):
    """JUnit XML built from the signed result alone; the same receipt always gives the
    same bytes."""
    r = x['response']
    p = r['project']
    record = r['record']
    requested = x['request']['project'].get('steps') or []
    ran = p.get('steps') or []
    cases = []
    failures = errors = skipped = 0
    for i, command in enumerate(requested):
        case = ET.Element('testcase', {'classname': 'plimsoll.step', 'name': f'step {i + 1}: {command}'})
        if i < len(ran):
            s = ran[i]
            case.set('time', f"{int(s.get('duration_ms', '0')) / 1000:.3f}")
            if s.get('timed_out'):
                errors += 1
                ET.SubElement(case, 'error', {'type': 'timeout', 'message': 'the step timed out'})
            elif s.get('exit_code', 0) != 0:
                failures += 1
                ET.SubElement(case, 'failure', {'type': 'exit', 'message': f"exit code {s['exit_code']}"})
        else:
            skipped += 1
            ET.SubElement(case, 'skipped', {'message': 'not run: an earlier step failed or the run stopped'})
        cases.append(case)
    if p.get('outcome') != 'PROJECT_OUTCOME_COMPLETED' and not failures and not errors:
        # The run stopped with no step to blame (the runner failed around a step): one case
        # names the outcome, never the detail text, which the guest may have shaped.
        errors += 1
        case = ET.Element('testcase', {'classname': 'plimsoll.run', 'name': 'run outcome'})
        ET.SubElement(case, 'error', {'type': 'outcome', 'message': p.get('outcome') or 'no outcome'})
        cases.append(case)
    counts = {'tests': str(len(cases)), 'failures': str(failures), 'errors': str(errors), 'skipped': str(skipped)}
    root = ET.Element('testsuites', {'name': 'plimsoll receipt', **counts})
    suite = ET.SubElement(root, 'testsuite', {'name': 'plimsoll run ' + record['record_sha256'][:12], **counts})
    props = ET.SubElement(suite, 'properties')
    for name in ('record_sha256', 'request_sha256', 'result_sha256', 'isolation', 'provider'):
        ET.SubElement(props, 'property', {'name': 'plimsoll.' + name, 'value': record[name]})
    ET.SubElement(props, 'property', {'name': 'plimsoll.junit_source', 'value': 'steps'})
    suite.extend(cases)
    ET.indent(root)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding='unicode').encode() + b'\n'


def junit(x):
    """(bytes, source) for the receipt's junit.xml, or (None, reason) when the run was
    asked for a JUnit file and did not return one."""
    report = framework_report(x)
    if report is None:
        return from_steps(x), 'built from the steps'
    path, content = report
    if content is None:
        truncated = x['response']['project'].get('artifacts_truncated')
        return None, (f'the run returned no {path}: ' +
                      ('it was over the artifact budget' if truncated else 'the test command did not write it'))
    return content, f"the test framework's own {path}"


def main():
    if len(sys.argv) != 2:
        raise SystemExit('usage: junit.py OUTPUT_DIRECTORY')
    out = Path(sys.argv[1])
    boms = glob.glob(str(out / 'run-*.cdx.json'))
    if len(boms) != 1:
        raise SystemExit(f'expected one run-*.cdx.json in {out}, found {len(boms)}')
    content, source = junit(exchange(Path(boms[0]).read_bytes()))
    if content is None:
        print('No junit.xml: ' + source)
        return
    (out / 'junit.xml').write_bytes(content)
    print('junit.xml: ' + source)


if __name__ == '__main__':
    main()
