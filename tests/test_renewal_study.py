"""Regression checks for the deterministic cache-renewal size study."""
from __future__ import annotations

from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))

from renewal_study import (actual_protocol_checks, fixed_length_parity, run_fault,
                           run_trace)


class RenewalStudyTests(unittest.TestCase):
    def test_actual_signature_check_breakdown_is_24_plus_6(self):
        result = actual_protocol_checks()
        self.assertEqual(result['count'], 30)
        self.assertEqual(result['passed'], 30)
        self.assertEqual(result['update_count'], 24)
        self.assertEqual(result['extension_count'], 6)

    def test_fixed_token_model_matches_real_object_lengths(self):
        result = fixed_length_parity()
        self.assertTrue(result['all_equal'])
        self.assertGreaterEqual(result['count'], 8)

    def test_scope_delta_beats_prefix_on_repeated_churn(self):
        result = run_trace('generated', 1, 'hot', 4)
        self.assertLess(result['totals']['scope-delta']['wire_bytes'],
                        result['totals']['prefix']['wire_bytes'])

    def test_static_trace_does_not_hide_status_advantage(self):
        result = run_trace('public-lock', 1, 'increasing', 0)
        self.assertLess(result['totals']['cached-status']['wire_bytes'],
                        result['totals']['scope-delta']['wire_bytes'])

    def test_each_fault_projects_at_most_one_kind_of_cause(self):
        expected = {
            'unrelated-publication': (0, 0, 0),
            'artifact-revocation': (0, 1, 0),
            'capability-revocation': (0, 0, 1),
            'conflicting-publication': (1, 0, 0),
        }
        for update, counts in expected.items():
            with self.subTest(update=update):
                result = run_fault('generated', 3, update)
                projection = result['scope_projection']
                actual = (len(projection['conflicts']),
                          len(projection['revoked_keys']),
                          len(projection['revoked_caps']))
                self.assertEqual(actual, counts)


if __name__ == '__main__':
    unittest.main(verbosity=2)
