"""Owned execution-report controls; never hide failed or skipped tests."""
from copy import deepcopy
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from verify_artifact import unit_receipt
from verify_artifact import main


def receipt(count):
    ids = ['owned.tests.Case.test_' + str(i) for i in range(count)]
    return ids, dict(discovered=count, run=count, passed=count, test_ids=ids,
                     skipped=[], failures=[], errors=[], successful=True)


class UnitReceiptTests(unittest.TestCase):
    def test_existing_output_is_preserved_before_reading_or_running(self):
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'owned-marker.txt'
            marker.write_text('retained observation', encoding='utf-8')
            with patch.object(sys, 'argv', ['verify_artifact', '--output', folder, '--retained-only']), \
                 patch('verify_artifact.retained_comparison', side_effect=AssertionError('must not read first')):
                with self.assertRaises(FileExistsError):
                    main()
            self.assertEqual(marker.read_text(encoding='utf-8'), 'retained observation')

    def test_current_inventory_can_grow_without_a_frozen_count(self):
        for count in (149, 158, 165):
            ids, value = receipt(count)
            self.assertEqual(unit_receipt(value, ids, posix=True)['passed_tests'], count)

    def test_omitted_or_replaced_test_is_rejected(self):
        ids, value = receipt(3)
        for replacement in (ids[:-1], ids[:-1] + ['other.test']):
            with self.subTest(replacement=replacement), self.assertRaises(ValueError):
                unit_receipt(value, replacement, posix=True)

    def test_failure_or_error_is_never_reported_as_pass(self):
        ids, value = receipt(3)
        for field in ('failures', 'errors'):
            bad = deepcopy(value)
            bad[field] = [ids[0]]
            with self.subTest(field=field), self.assertRaises(ValueError):
                unit_receipt(bad, ids, posix=True)

    def test_platform_skip_remains_explicit_and_posix_requires_none(self):
        ids, value = receipt(3)
        value.update(passed=2, skipped=[dict(test=ids[0], reason='POSIX directory fsync unavailable')])
        checked = unit_receipt(value, ids, posix=False)
        self.assertEqual(checked['passed_tests'], 2)
        self.assertFalse(checked['complete_without_skips'])
        self.assertEqual(len(checked['skipped_tests']), 1)
        with self.assertRaises(ValueError):
            unit_receipt(value, ids, posix=True)

    def test_boolean_counts_do_not_equal_integer_counts(self):
        ids, value = receipt(1)
        for field in ('discovered', 'run', 'passed'):
            bad = deepcopy(value)
            bad[field] = True
            with self.subTest(field=field), self.assertRaises(ValueError):
                unit_receipt(bad, ids, posix=True)

    def test_empty_inventory_and_false_success_are_rejected(self):
        ids, value = receipt(0)
        with self.assertRaises(ValueError):
            unit_receipt(value, ids, posix=True)
        ids, value = receipt(1)
        value['successful'] = False
        with self.assertRaises(ValueError):
            unit_receipt(value, ids, posix=True)

    def test_inconsistent_or_duplicate_skip_accounting_is_rejected(self):
        ids, value = receipt(3)
        bad = deepcopy(value)
        bad['passed'] = 2
        with self.assertRaises(ValueError):
            unit_receipt(bad, ids, posix=False)
        bad['skipped'] = [dict(test=ids[0], reason='unsupported')] * 2
        bad['passed'] = 1
        with self.assertRaises(ValueError):
            unit_receipt(bad, ids, posix=False)
