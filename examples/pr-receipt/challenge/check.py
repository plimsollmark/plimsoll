#!/usr/bin/env python3
"""Run every case of the receipt challenge through verify.py and print what it decided.

    python3 -I examples/pr-receipt/challenge/check.py --sbom PATH_TO_BUILT_SBOM_CHECKER

Build the checker first: go -C examples/sbom build -o /tmp/sbom . (any path). Each case names
a receipt, the commit a gate would be checking it for, and what a correct gate decides: accept,
or refuse at a named check. A gate of your own can run the same cases from cases.json; this
script is the reference answer. Exit 0 when every case comes out as cases.json says.
"""
import argparse, json, pathlib, subprocess, sys, tempfile

here = pathlib.Path(__file__).resolve().parent
verify = here.parent / 'verify.py'


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--sbom', required=True, help='the examples/sbom checker, built')
    args = ap.parse_args()
    spec = json.loads((here / 'cases.json').read_text())
    commits = json.loads((here / 'commits.json').read_text())
    wrong = 0
    with tempfile.TemporaryDirectory() as scratch:
        repo = pathlib.Path(scratch) / 'project'
        subprocess.run(['git', '-c', 'advice.detachedHead=false', 'clone', '-q', str(here / 'project.bundle'), str(repo)], check=True)
        subprocess.run(['git', '-C', str(repo), 'fetch', '-q', str(here / 'project.bundle'), '+refs/heads/*:refs/remotes/bundle/*'], check=True)
        print(f'{"case":<38}{"decided":<26}expected')
        for c in spec['cases']:
            d = here / 'receipts' / c['receipt']
            cmd = [sys.executable, '-I', str(verify), '--sbom', args.sbom, '--receipt', str(d / 'receipt.cdx.json'),
                   '--trusted-pub', str(here / 'operator.pub'), '--repo', str(repo),
                   '--repository', c.get('repository', spec['repository']), '--head', commits[c['head']],
                   '--pr', spec['pull_request'], '--command', spec['command'], '--junit-path', spec['junit_path'],
                   '--junit', str(d / 'junit.xml')]
            out = subprocess.run(cmd, capture_output=True, text=True)
            report = json.loads(out.stdout)
            failed = [k['check'] for k in report['checks'] if k.get('passed') is False]
            decided = 'accept' if report['verified'] else 'refuse at ' + (failed[0] if failed else '?')
            expected = 'accept' if c.get('accept') else 'refuse at ' + c['refused_at']
            ok = report['verified'] if c.get('accept') else (not report['verified'] and c['refused_at'] in failed)
            wrong += not ok
            print(f'{c["name"]:<38}{decided:<26}{expected}{"" if ok else "   <- differs"}')
    print('every case as expected' if not wrong else f'{wrong} case(s) differ')
    return 1 if wrong else 0


if __name__ == '__main__':
    sys.exit(main())
