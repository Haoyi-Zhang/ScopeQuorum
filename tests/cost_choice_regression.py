"""Explicit regressions; no extra sockets or external input."""
from fractions import Fraction
import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from cost_choice import analyze,weighted_saving

class Choice(unittest.TestCase):
    def test_all_retained_raw_traces(self):
        report=analyze()
        self.assertEqual((report['traces'],report['paired_reads']), (12,120))
        self.assertEqual(report['scope_cheaper_at_equal_prices'],1)
        self.assertEqual(report['aggregate_break_even_client_price'],'543988/303485')
    def test_exact_threshold_and_tie(self):
        self.assertEqual(weighted_saving(10,20,2),0)
        self.assertLess(weighted_saving(10,20,Fraction(19,10)),0)
        self.assertGreater(weighted_saving(10,20,Fraction(21,10)),0)
    def test_witness_saving_and_zero_price(self):
        self.assertGreater(weighted_saving(10,-5,0),0)
        self.assertEqual(weighted_saving(10,0,0),0)
    def test_bad_price_or_premise(self):
        for args in [(0,1,1),(True,1,1),(10,True,1),(10,1,-1)]:
            with self.assertRaises(ValueError):weighted_saving(*args)

if __name__=='__main__':unittest.main()
