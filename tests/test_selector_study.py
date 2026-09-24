import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))

from selector_study import ThresholdSelector, quote_registration, run_selector_trace
from renewal_study import ScopeClient, StatusClient, add_cost, build_model


class SelectorStudyTests(unittest.TestCase):
    def test_quote_is_charged_and_registration_positive(self):
        graph_map, root, _, authorities = build_model('generated', 1)
        ns = root.split('/', 1)[0]
        authority = authorities[ns]
        needed = {root}

        quote, register = quote_registration(authority, needed, 1)
        self.assertGreater(quote['wire_bytes'], 0)
        self.assertGreater(register, 0)

        # A status-mode refresh must charge both the signed quote and the
        # ordinary status transaction, and the charged amount becomes the
        # threshold state for the next causal decision.
        expected_status, _ = StatusClient().refresh(authority, needed, 1)
        expected_first = dict(quote)
        add_cost(expected_first, expected_status)
        selector = ThresholdSelector()
        observed_first, action = selector.refresh(authority, needed, 1, 0)
        self.assertEqual(observed_first, expected_first)
        self.assertEqual(selector.status_mode_bytes[ns], expected_first['wire_bytes'])
        self.assertNotIn(ns, selector.scope_mode)
        self.assertIn('+status:', action)

        # Force only the already-observed threshold state above the current
        # registration quote.  The switch must charge a fresh quote plus the
        # actual registration, and subsequent refreshes must not quote again.
        selector.status_mode_bytes[ns] = 10**9
        next_quote, _ = quote_registration(authority, needed, 11)
        expected_scope, _ = ScopeClient().refresh(authority, needed, 11)
        expected_switch = dict(next_quote)
        add_cost(expected_switch, expected_scope)
        observed_switch, action = selector.refresh(authority, needed, 11, 1)
        self.assertEqual(observed_switch, expected_switch)
        self.assertIn(ns, selector.scope_mode)
        self.assertEqual(selector.switches[ns], 1)
        self.assertIn('+switch:', action)

        expected_renew, _ = selector.scope.refresh(authority, needed, 21)
        # Rebuild the same post-switch state to avoid mutating the selector a
        # second time before the assertion.
        replica = ThresholdSelector()
        replica.status_mode_bytes[ns] = 10**9
        replica.refresh(authority, needed, 11, 1)
        observed_renew, action = replica.refresh(authority, needed, 21, 2)
        self.assertEqual(observed_renew, expected_renew)
        self.assertTrue(action.startswith('scope:'))

    def test_trace_is_deterministic_and_causal_shape(self):
        first = run_selector_trace('generated', 1, 'hot', 4)
        second = run_selector_trace('generated', 1, 'hot', 4)
        self.assertEqual(first, second)
        self.assertEqual(first['queries'], 32)
        self.assertEqual(len(first['rows']), 32)
        self.assertGreater(first['totals']['wire_bytes'], 0)
        for ns, step in first['switches'].items():
            self.assertIsInstance(ns, str)
            self.assertGreaterEqual(step, 1)


if __name__ == '__main__':
    unittest.main()
