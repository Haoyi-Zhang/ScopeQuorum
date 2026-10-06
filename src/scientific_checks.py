"""Run the finite owned-fixture campaign into a new output directory.

No paper compilation, network targets, installs, or retained-result overwrites.
Windows excludes directory-fsync durability; Go is used only if already present.
The suite has a 30-minute wall-time budget and preserves raw command output.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import signal
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import cryptography

ROOT = Path(__file__).resolve().parents[1]
DURABLE_MODULES = {'test_durable_witness', 'test_durable_witness_network'}


def run_owned(command, *, cwd, env, log, timeout):
    """Bound one owned command and its children; retain a true failure outcome."""
    started = time.monotonic()
    with log.open('w', encoding='utf-8') as handle:
        process = subprocess.Popen(command, cwd=cwd, env=env, stdout=handle,
                                   stderr=subprocess.STDOUT, start_new_session=os.name != 'nt')
        try:
            code = process.wait(timeout=timeout)
            outcome = 'EXIT'
        except subprocess.TimeoutExpired:
            outcome = 'TIMEOUT'
            if os.name == 'nt':
                taskkill = Path(os.environ['SystemRoot']) / 'System32/taskkill.exe'
                subprocess.run([str(taskkill), '/PID', str(process.pid), '/T', '/F'],
                               stdout=handle, stderr=subprocess.STDOUT, timeout=15, check=False)
            else:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            code = process.wait(timeout=15)
    return {'command': command, 'exit_code': code, 'outcome': outcome,
            'elapsed_seconds_host_diagnostic': time.monotonic() - started}


def quorum_complete(result):
    return (result['parameter_rows'] == 385 and result['quorum_pair_checks'] == 250942
            and result['existence_checks'] == 55 and result['failures'] == 0)


def write(path: Path, value) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n', encoding='utf-8')


def flatten(suite):
    for case in suite:
        if isinstance(case, unittest.TestSuite):
            yield from flatten(case)
        else:
            yield case


def units(output: Path) -> int:
    cases = list(flatten(unittest.defaultTestLoader.discover(str(ROOT / 'tests'))))
    if os.name == 'nt':
        for case in cases:
            if case.__class__.__module__ in DURABLE_MODULES:
                case.__class__.__unittest_skip__ = True
                case.__class__.__unittest_skip_why__ = 'POSIX directory-fsync durability not validated on Windows'
    result = unittest.TextTestRunner(verbosity=2).run(unittest.TestSuite(cases))
    write(output / 'unit.json', {
        'discovered': len(cases), 'run': result.testsRun,
        'passed': result.testsRun - len(result.skipped) - len(result.failures) - len(result.errors),
        'skipped': [{'test': case.id(), 'reason': reason} for case, reason in result.skipped],
        'failures': [case.id() for case, _ in result.failures],
        'errors': [case.id() for case, _ in result.errors],
        'successful': result.wasSuccessful(),
    })
    return 0 if result.wasSuccessful() else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--units', action='store_true', help=argparse.SUPPRESS)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'; temporary.mkdir()
    os.environ.update(PYTHONUTF8='1', PYTHONDONTWRITEBYTECODE='1',
                      TEMP=str(temporary), TMP=str(temporary), TMPDIR=str(temporary))
    tempfile.tempdir = str(temporary)
    if args.units:
        return units(output)
    started = time.monotonic(); deadline = started + 1800
    report = {
        'started_utc': datetime.now(timezone.utc).isoformat(),
        'platform': platform.platform(), 'machine': platform.machine(),
        'python': sys.version, 'cryptography': cryptography.__version__,
        'scope': 'finite formal models and synthetic/projection loopback fixtures only',
        'rss_scope': 'Linux getrusage only; null elsewhere',
        'posix_resource_limits_applied_to_main_campaign': os.name != 'nt',
        'commands': [], 'not_executed': [], 'passed': False,
    }
    env = dict(os.environ)
    env.update(GOMAXPROCS='2', GOCACHE=str(temporary / 'go-cache'),
               GOPATH=str(temporary / 'go-path'), GOTOOLCHAIN='local', GOPROXY='off')
    python = [sys.executable, '-B']
    generated = output / 'generated'
    jobs = [
        ('unit', python + ['src/scientific_checks.py', '--units', '--output', str(output / 'unit')]),
        ('finite', python + ['tests/finite.py', '--output', str(output / 'finite.json')]),
        ('differential', python + ['tests/differential.py', '--iterations', '500', '--seed', '20261006', '--output', str(output / 'differential.json')]),
        ('witness-finite', python + ['tests/witness_finite.py', '--output', str(output / 'witness-finite.json')]),
        ('boundary', python + ['src/boundary_study.py', '--output', str(output / 'boundary.json')]),
        ('renewal', python + ['src/renewal_study.py', '--output', str(output / 'renewal'), '--generated', str(generated)]),
        ('selector', python + ['src/selector_study.py', '--renewal-traces', str(output / 'renewal/traces.json.gz'), '--output-dir', str(output / 'selector'), '--paper-generated', str(generated)]),
        ('witness', python + ['src/witness_study.py', '--output', str(output / 'witness'), '--generated', str(generated)]),
        ('witness-network', python + ['src/witness_network_study.py', '--output', str(output / 'witness-network')]),
    ]
    if os.name == 'nt':
        report['not_executed'].append({'study': 'durable-witness', 'reason': 'POSIX directory fsync unavailable; no Windows durability claim'})
    else:
        jobs.append(('durable-witness', python + ['src/durable_witness_study.py', '--output', str(output / 'durable-witness'), '--generated', str(generated)]))
    if shutil.which('go'):
        jobs.append(('quorum', ['go', 'run', 'checks/quorum.go']))
    else:
        report['not_executed'].append({'study': 'quorum-go', 'reason': 'no installed Go toolchain; no independent Go rerun claimed'})
    jobs += [
        ('main-campaign', python + ['src/reproduce.py', '--all', '--portable', '--output', str(output / 'main')]),
        ('main-analysis', python + ['src/analyze.py', '--results', str(output / 'main'), '--output', str(output / 'main-analysis'), '--compare-semantic', str(ROOT / 'results/semantic-reference.json.gz')]),
    ]
    try:
        for name, command in jobs:
            print(name + ' started', flush=True)
            log = output / (name + '.log')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('30-minute suite budget exhausted')
            record = run_owned(command, cwd=ROOT, env=env, log=log, timeout=min(900, remaining))
            report['commands'].append({'name': name, **record})
            write(output / 'run.json', report)
            print(name + ' ' + record['outcome'] + ' ' + str(record['exit_code']), flush=True)
            if record['exit_code'] or record['outcome'] != 'EXIT':
                raise ValueError(name + ' failed; see raw log')
            if name == 'quorum':
                write(output / 'quorum.json', json.loads(log.read_text(encoding='utf-8')))
        def read(relative):
            return json.loads((output / relative).read_text(encoding='utf-8'))
        renewal = read('renewal/summary.json')
        witness = read('witness/summary.json')
        network = read('witness-network/summary.json')
        actual = renewal['actual_protocol_checks']
        checks = {
            'unit_tests_passed': read('unit/unit.json')['successful'],
            'renewal_96_traces': renewal['study']['traces'] == 96,
            'renewal_actual_30_passed': actual['count'] == actual['passed'] == 30,
            'renewal_encoding_parity': renewal['fixed_length_parity']['all_equal'],
            'selector_96_traces': read('selector/selector-summary.json')['study']['traces'] == 96,
            'witness_96_traces': witness['study']['traces'] == 96,
            'witness_adversarial': witness['adversarial_checks']['count'] == witness['adversarial_checks']['passed'],
            'witness_encoding_parity': witness['fixed_length_parity']['all_equal'],
            'witness_state_accounting': witness['state']['actual_model_checks']['all_model_bytes_equal'],
            'network_45_passed': network['cases'] == network['passed'] == 45,
            'network_24_client_states': network['client_state_checks'] == network['client_state_checks_passed'] == 24,
            'full_main_semantic_equal': read('main-analysis/semantic-reproduction.json')['semantic_equal'],
        }
        if os.name != 'nt':
            checks['no_unexpected_posix_unit_skips'] = not read('unit/unit.json')['skipped']
            durable = read('durable-witness/summary.json')
            checks['durable_33_passed'] = durable['cases'] == durable['passed'] == 33
        if shutil.which('go'):
            checks['complete_independent_go_census'] = quorum_complete(read('quorum.json'))
        report['result_checks'] = checks
        if not all(checks.values()):
            raise ValueError('result checks failed')
        report['passed'] = True
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        report['error'] = str(error)
        print(str(error), file=sys.stderr)
    finally:
        report['elapsed_seconds_host_diagnostic'] = time.monotonic() - started
        report['finished_utc'] = datetime.now(timezone.utc).isoformat()
        write(output / 'run.json', report)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
