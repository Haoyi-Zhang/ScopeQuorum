"""Regression tests distinguish quorum safety from branch agreement."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from boundary_study import split_case, run
class BoundaryTests(unittest.TestCase):
    def test_split_two_one_blocks_without_byzantine_cooperation(self):
        r=split_case(2,False);self.assertEqual((r['later_left_signatures'],r['later_right_signatures']),(2,1));self.assertFalse(r['any_quorum'])
    def test_split_one_two_blocks_without_byzantine_cooperation(self):
        self.assertFalse(split_case(1,False)['any_quorum'])
    def test_aligned_honest_witnesses_can_certify(self):
        self.assertTrue(split_case(3,False)['any_quorum'])
    def test_byzantine_cooperation_cannot_create_two_quorums(self):
        for n in (0,1,2,3):
            self.assertFalse(split_case(n,True)['both_quorums'])
    def test_matrix_contains_counterexamples(self):
        self.assertEqual(run()['honest_reachability_counterexamples'],2)
