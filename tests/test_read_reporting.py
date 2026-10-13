"""Owned raw-report identity and typed-parity controls; no network execution."""
from copy import deepcopy
import json
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from witness_read_study import compare
from witness_read_report import report

ROOT = Path(__file__).resolve().parents[1]


def pair():
    source = ROOT / 'results/tcp-read-20261014'
    return [json.loads((source / ('public-lock-1-0-' + mode + '.json')).read_text(encoding='utf-8'))
            for mode in ('prefix', 'scope')]


class ReadReportingTests(unittest.TestCase):
    def test_paired_queries_and_workload_are_identical(self):
        prefix, scope = pair()
        self.assertEqual(compare(prefix, scope)['read_pairs'], 10)
        for field, value in (('family', 'another-owned-family'), ('span', 2),
                             ('churn', 1), ('fault', 'other-owned-condition')):
            changed = deepcopy(scope)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                compare(prefix, changed)
        for field, value in (('step', 10), ('root', 'n0/another-owned-root'),
                             ('now', 100), ('expected_serve', False)):
            changed = deepcopy(scope)
            changed['rows'][0][field] = value
            with self.subTest(field=field), self.assertRaises(AssertionError):
                compare(prefix, changed)

    def test_boolean_and_integer_results_remain_distinct(self):
        prefix, scope = pair()
        changed = deepcopy(scope)
        changed['rows'][0]['verdict']['serve'] = 1
        with self.assertRaises(AssertionError):
            compare(prefix, changed)
        changed = deepcopy(scope)
        changed['rows'][0]['now'] = float(changed['rows'][0]['now'])
        with self.assertRaises(AssertionError):
            compare(prefix, changed)

    def test_duplicate_trace_is_rejected_before_tabulation(self):
        prefix, scope = pair()
        summary = dict(comparisons=[compare(prefix, scope)], traces=1, modes=2, read_pairs=10)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'source'
            source.mkdir()
            for name, value in (('summary.json', summary), ('prefix.json', prefix),
                                ('scope.json', scope), ('duplicate.json', prefix)):
                (source / name).write_text(json.dumps(value), encoding='utf-8')
            with self.assertRaisesRegex(AssertionError, 'duplicate raw read trace'):
                report(source, base / 'output', base / 'generated')
            self.assertFalse((base / 'generated').exists())

    def test_omitted_comparator_cannot_leave_an_unaudited_raw_pair(self):
        prefix, scope = pair()
        summary = dict(comparisons=[], traces=0, modes=2, read_pairs=0)
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / 'source'
            source.mkdir()
            for name, value in (('summary.json', summary), ('prefix.json', prefix), ('scope.json', scope)):
                (source / name).write_text(json.dumps(value), encoding='utf-8')
            with self.assertRaisesRegex(AssertionError, 'inventory mismatch'):
                report(source, base / 'output', base / 'generated')
            self.assertFalse((base / 'generated').exists())
