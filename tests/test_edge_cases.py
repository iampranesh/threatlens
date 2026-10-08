#!/usr/bin/env python3
"""
Edge Case Tests for ThreatLens:
Validates resilience against 6 core edge cases:
1. Stale indicator (>180 days old, no local observation)
2. Shared cloud/CDN infrastructure dampener (Cloudflare, AWS CloudFront, Public DNS)
3. Missing asset inventory (Unmapped internal IP/asset handled gracefully)
4. Conflicting threat feeds (Disagreement in severity/confidence)
5. Duplicate indicators across multiple feed imports
6. Malformed indicator syntax and schema violations
"""

import sys
import os
import unittest
import copy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from experiments.run_experiment import score_threatlens, load_data

class TestThreatLensEdgeCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = load_data()

    def test_edge_case_1_stale_indicator(self):
        """Edge Case 1: Stale indicator from 250 days ago should receive staleness penalty and be suppressed."""
        stale_record = {
            "indicator": "203.0.113.60",
            "confidence": "90",
            "severity": "high",
            "source_reliability": "0.85",
            "last_seen": "2025-12-01 00:00:00", # >300 days old
            "cve": "CVE-2017-0144"
        }
        res = score_threatlens(stale_record, self.context)
        self.assertLess(res["score"], 40.0)
        self.assertEqual(res["breakdown"]["staleness_penalty"], -15.0)
        self.assertTrue(any("Staleness Penalty applied" in e for e in res["evidence"]))

    def test_edge_case_2_shared_cloud_cdn_ip(self):
        """Edge Case 2: Multi-tenant CDN IP (Cloudflare 104.16.124.96) must trigger CDN dampener to avoid blocking critical infrastructure."""
        cdn_record = {
            "indicator": "104.16.124.96",
            "confidence": "85",
            "severity": "high",
            "source_reliability": "0.9",
            "last_seen": "2026-10-07 12:00:00",
            "cve": ""
        }
        res = score_threatlens(cdn_record, self.context)
        self.assertLess(res["score"], 50.0)
        self.assertEqual(res["breakdown"]["cdn_penalty"], -25.0)
        self.assertTrue(any("Shared Cloud / CDN Infrastructure dampener applied" in e for e in res["evidence"]))

    def test_edge_case_3_missing_asset_inventory(self):
        """Edge Case 3: Network telemetry references an uninventoried asset ID. System must degrade gracefully without crashing."""
        context_copy = copy.deepcopy(self.context)
        # Inject traffic with unknown asset
        fake_ioc = "198.51.100.222"
        context_copy["traffic_by_indicator"][fake_ioc] = [{
            "traffic_id": "TRF-999999",
            "timestamp": "2026-10-08 08:00:00",
            "indicator": fake_ioc,
            "asset_id": "UNKNOWN-SHADOW-IT-99", # Missing from software inventory
            "frequency": 2,
            "action": "allowed"
        }]

        unmapped_record = {
            "indicator": fake_ioc,
            "confidence": "70",
            "severity": "medium",
            "source_reliability": "0.8",
            "last_seen": "2026-10-08 08:00:00",
            "cve": ""
        }
        # Scorer must not throw KeyError or AttributeError
        res = score_threatlens(unmapped_record, context_copy)
        self.assertIn("score", res)
        self.assertEqual(res["matched_asset"], "NONE")
        self.assertGreater(res["breakdown"]["traffic"], 0.0)

    def test_edge_case_4_conflicting_threat_feeds(self):
        """Edge Case 4: Multiple feeds report contradictory severity/confidence for same IOC."""
        feed_low_rel = {
            "indicator": "198.51.100.1",
            "confidence": "95",
            "severity": "critical",
            "source_reliability": "0.20", # Untrusted community scraper
            "last_seen": "2026-10-08 10:00:00",
            "cve": "CVE-2024-3400"
        }
        res_low_rel = score_threatlens(feed_low_rel, self.context)

        feed_high_rel = {
            "indicator": "198.51.100.1",
            "confidence": "95",
            "severity": "critical",
            "source_reliability": "0.98", # Mandiant / CISA high trust
            "last_seen": "2026-10-08 10:00:00",
            "cve": "CVE-2024-3400"
        }
        res_high_rel = score_threatlens(feed_high_rel, self.context)

        # High reliability source yields greater source contribution
        self.assertGreater(res_high_rel["breakdown"]["source_reliability"], res_low_rel["breakdown"]["source_reliability"])
        self.assertGreaterEqual(res_high_rel["score"], res_low_rel["score"])

    def test_edge_case_5_duplicate_indicators(self):
        """Edge Case 5: Duplicate ingestion of identical indicator should produce deterministic, consistent scores."""
        dup_record = {
            "indicator": "198.51.100.2",
            "confidence": "92",
            "severity": "high",
            "source_reliability": "0.9",
            "last_seen": "2026-10-07 10:00:00",
            "cve": "CVE-2021-41773"
        }
        res1 = score_threatlens(dup_record, self.context)
        res2 = score_threatlens(dup_record, self.context)
        self.assertEqual(res1["score"], res2["score"])
        self.assertEqual(res1["label"], res2["label"])

    def test_edge_case_6_malformed_input_graceful_handling(self):
        """Edge Case 6: Handles missing dates, null confidence, or empty strings gracefully."""
        malformed = {
            "indicator": "unknown-or-empty",
            "confidence": None,
            "severity": "",
            "source_reliability": None,
            "last_seen": "INVALID_DATE_FORMAT",
            "cve": None
        }
        res = score_threatlens(malformed, self.context)
        self.assertIsInstance(res["score"], float)
        self.assertIn(res["label"], ["IRRELEVANT", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

if __name__ == "__main__":
    unittest.main()
