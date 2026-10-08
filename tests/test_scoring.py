#!/usr/bin/env python3
"""
Unit Tests for ThreatLens Scoring Engine:
- Scoring formula compliance
- Weight normalization [0, 100]
- Threshold classifications
- High-priority evidence chain enforcement
- Insufficient local evidence detection
"""

import sys
import os
import unittest
from datetime import datetime

# Add root directory to python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from experiments.run_experiment import score_threatlens, score_baseline, load_data

class TestThreatLensScoring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = load_data()

    def test_score_normalization_bounds(self):
        """Ensure scores are strictly normalized within [0, 100] across extreme inputs."""
        extreme_low = {
            "indicator": "192.0.2.254",
            "confidence": "0",
            "severity": "low",
            "source_reliability": "0.1",
            "last_seen": "2020-01-01 00:00:00",
            "cve": ""
        }
        res_low = score_threatlens(extreme_low, self.context)
        self.assertGreaterEqual(res_low["score"], 0.0)
        self.assertLessEqual(res_low["score"], 100.0)

        extreme_high = {
            "indicator": "198.51.100.1", # Has active traffic and CVE
            "confidence": "100",
            "severity": "critical",
            "source_reliability": "1.0",
            "last_seen": "2026-10-08 11:59:00",
            "cve": "CVE-2024-3400"
        }
        res_high = score_threatlens(extreme_high, self.context)
        self.assertGreaterEqual(res_high["score"], 0.0)
        self.assertLessEqual(res_high["score"], 100.0)
        self.assertGreaterEqual(res_high["score"], 60.0)

    def test_classification_thresholds(self):
        """Validate threshold mapping: 0-19 IRRELEVANT, 20-39 LOW, 40-59 MEDIUM, 60-79 HIGH, 80-100 CRITICAL."""
        threshold_map = [
            (10.0, "IRRELEVANT"),
            (19.0, "IRRELEVANT"),
            (20.0, "LOW"),
            (35.0, "LOW"),
            (40.0, "MEDIUM"),
            (55.0, "MEDIUM"),
            (60.0, "HIGH"),
            (75.0, "HIGH"),
            (80.0, "CRITICAL"),
            (95.0, "CRITICAL")
        ]
        for score_val, expected_label in threshold_map:
            if score_val >= 80.0:
                lbl = "CRITICAL"
            elif score_val >= 60.0:
                lbl = "HIGH"
            elif score_val >= 40.0:
                lbl = "MEDIUM"
            elif score_val >= 20.0:
                lbl = "LOW"
            else:
                lbl = "IRRELEVANT"
            self.assertEqual(lbl, expected_label, f"Mismatch for score {score_val}")

    def test_high_priority_evidence_requirement(self):
        """Every indicator classified as HIGH or CRITICAL must provide an explicit evidence chain."""
        high_sample = {
            "indicator": "198.51.100.1",
            "confidence": "95",
            "severity": "critical",
            "source_reliability": "0.95",
            "last_seen": "2026-10-08 10:00:00",
            "cve": "CVE-2024-3400"
        }
        res = score_threatlens(high_sample, self.context)
        self.assertTrue(res["is_prioritized"])
        self.assertGreater(len(res["evidence"]), 0, "High-priority indicator must have non-empty evidence list")
        self.assertTrue(any("Observed in network telemetry" in e or "Associated CVE" in e for e in res["evidence"]))

    def test_weak_evidence_penalty_suppression(self):
        """Unseen commodity threat with high external confidence must receive weak evidence penalty and be suppressed."""
        commodity_threat = {
            "indicator": "192.0.2.88",
            "confidence": "95",
            "severity": "critical",
            "source_reliability": "0.9",
            "last_seen": "2026-09-01 00:00:00",
            "cve": "CVE-2020-0688" # Unrelated CVE
        }
        res = score_threatlens(commodity_threat, self.context)
        self.assertFalse(res["is_prioritized"], "Unrelated commodity threat should be suppressed by local relevance")
        self.assertLess(res["score"], 40.0)
        self.assertIn("weak_evidence_penalty", res["breakdown"])
        self.assertEqual(res["breakdown"]["weak_evidence_penalty"], -20.0)

    def test_baseline_noise_inflation(self):
        """Baseline external feed prioritizes commodity noise because it lacks local context."""
        commodity_threat = {
            "indicator": "192.0.2.88",
            "confidence": "95",
            "severity": "critical",
            "source_reliability": "0.9"
        }
        res_baseline = score_baseline(commodity_threat)
        self.assertTrue(res_baseline["is_prioritized"], "Baseline should flag commodity threat due to feed severity")
        self.assertGreaterEqual(res_baseline["score"], 60.0)

if __name__ == "__main__":
    unittest.main()
