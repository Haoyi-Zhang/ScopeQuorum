"""Quorum cardinality must not be reported as unconditional liveness."""
import unittest

from witness_finite import run


class WitnessFiniteTests(unittest.TestCase):
    def test_reachability_report_is_threshold_only(self):
        result = run()
        self.assertNotIn('guaranteed_liveness_rows_by_reachable_count', result)
        self.assertEqual(result['honest_signer_threshold_rows_by_reachable_count'],
                         {'0': 0, '1': 0, '2': 0, '3': 8, '4': 5})
        self.assertIn('split branches do not guarantee progress', result['threshold_scope'])
        self.assertEqual(result['ordered_quorum_fault_checks'], 80)
        self.assertEqual(result['reachability_fault_cases'], 80)
        self.assertFalse(result['safety_failures'])
