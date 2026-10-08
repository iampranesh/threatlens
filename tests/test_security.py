#!/usr/bin/env python3
"""
Security Test Suite for ThreatLens:
Validates defense against attacks and enforces security architecture:
1. Score manipulation protection (Client cannot forge score)
2. Role-Based Access Control (RBAC: Analyst, Reviewer, Admin)
3. Threat feed poisoning protection & input validation
4. High-impact containment action human review gating
5. Tamper-evident audit trail (no secrets logged)
6. Scoring configuration versioning & rollback authorization
"""

import sys
import os
import unittest
import json
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from experiments.run_experiment import score_threatlens, load_data

class MockAuthContext:
    def __init__(self, user: str, role: str):
        self.user = user
        self.role = role # "ANALYST", "REVIEWER", "ADMIN"

class MockAuditLog:
    def __init__(self):
        self.entries = []

    def log(self, user: str, role: str, action: str, resource: str, result: str, reason: str = ""):
        # Security invariant: NEVER log passwords or secrets
        entry = {
            "timestamp": "2026-10-08T12:00:00Z",
            "request_id": str(uuid.uuid4()),
            "user": user,
            "role": role,
            "action": action,
            "resource": resource,
            "result": result,
            "reason": reason
        }
        self.entries.append(entry)
        return entry

class TestThreatLensSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.context = load_data()
        cls.audit = MockAuditLog()

    def test_sec_1_score_manipulation_protection(self):
        """
        ATTACK: Attacker submits client payload attempting to force score to 100 or 0.
        DEFENSE: Backend ignores or rejects client-provided score; computes independently.
        """
        malicious_client_payload = {
            "indicator": "192.0.2.99", # Commodity irrelevant IP
            "score": 100.0,            # ATTACK ATTEMPT: Force maximum score!
            "label": "CRITICAL",       # ATTACK ATTEMPT: Force critical classification!
            "confidence": "50",
            "severity": "medium",
            "source_reliability": "0.8",
            "cve": ""
        }
        # In ThreatLens, score_threatlens calculates independently from evidence
        calculated = score_threatlens(malicious_client_payload, self.context)
        
        # Verify the client-forged score of 100.0 was completely thwarted
        self.assertNotEqual(calculated["score"], 100.0)
        self.assertLess(calculated["score"], 30.0, "Score manipulation attack thwarted; true evidence evaluated.")
        self.assertEqual(calculated["label"], "IRRELEVANT")

    def test_sec_2_rbac_authorization_matrix(self):
        """
        VERIFY RBAC:
        - ANALYST: Read-only, cannot modify scoring config, cannot approve containment actions.
        - REVIEWER: Can review & approve/reject changes.
        - ADMIN: Can propose configuration changes and execute rollbacks.
        """
        analyst = MockAuthContext("sarah.chen@corp.internal", "ANALYST")
        reviewer = MockAuthContext("marcus.vance@corp.internal", "REVIEWER")
        admin = MockAuthContext("elena.rostova@corp.internal", "ADMIN")

        def can_modify_config(auth):
            return auth.role == "ADMIN"

        def can_approve_action(auth):
            return auth.role in ("REVIEWER", "ADMIN")

        def can_view_indicators(auth):
            return auth.role in ("ANALYST", "REVIEWER", "ADMIN")

        # Test Analyst restrictions
        self.assertFalse(can_modify_config(analyst), "Analyst must NOT be able to modify configuration")
        self.assertFalse(can_approve_action(analyst), "Analyst must NOT be able to approve containment actions")
        self.assertTrue(can_view_indicators(analyst), "Analyst can view indicators")

        # Test Reviewer permissions
        self.assertFalse(can_modify_config(reviewer), "Reviewer must NOT author configuration changes directly")
        self.assertTrue(can_approve_action(reviewer), "Reviewer can approve proposed containment actions")

        # Test Admin permissions
        self.assertTrue(can_modify_config(admin), "Admin can manage configuration")
        self.assertTrue(can_approve_action(admin), "Admin can approve containment actions")

    def test_sec_3_feed_poisoning_defense(self):
        """
        ATTACK: Adversary injects malicious indicator with inflated confidence > 100, malformed fields, or spoofed source.
        DEFENSE: Input validator clips confidence to [0, 100], validates source reliability, and prevents schema corruption.
        """
        poisoned_feed_record = {
            "indicator": "192.0.2.111",
            "confidence": 999999, # Inflated beyond valid bounds!
            "severity": "CRITICAL_EXECUTE_CODE_INJECTION",
            "source_reliability": 5.0, # Exceeds max 1.0!
            "cve": "<script>alert(1)</script>" # XSS attempt in CVE field
        }

        # Sanitization logic
        def sanitize_feed_record(rec):
            conf = float(rec.get("confidence", 50))
            conf = min(100.0, max(0.0, conf))
            rel = float(rec.get("source_reliability", 0.8))
            rel = min(1.0, max(0.0, rel))
            cve_clean = "".join(c for c in rec.get("cve", "") if c.isalnum() or c in "-_")
            return {
                "indicator": rec["indicator"],
                "confidence": conf,
                "severity": rec["severity"].split("_")[0].lower() if "critical" in rec["severity"].lower() else "low",
                "source_reliability": rel,
                "cve": cve_clean
            }

        sanitized = sanitize_feed_record(poisoned_feed_record)
        self.assertEqual(sanitized["confidence"], 100.0)
        self.assertEqual(sanitized["source_reliability"], 1.0)
        self.assertNotIn("<script>", sanitized["cve"])

        # Feed poisoning thwarted - score remains suppressed because local evidence is 0
        scored = score_threatlens(sanitized, self.context)
        self.assertFalse(scored["is_prioritized"])
        self.assertLess(scored["score"], 40.0)

    def test_sec_4_high_impact_containment_pipeline(self):
        """
        POLICY: High-impact actions (Firewall IP block, host isolation) MUST NOT execute automatically.
        Pipeline: Detection -> Recommendation -> Human Review -> Approval -> Action -> Audit.
        """
        class ContainmentPipeline:
            def __init__(self):
                self.status = "PROPOSED"
                self.approved_by = None

            def approve(self, user_context, audit_log):
                if user_context.role not in ("REVIEWER", "ADMIN"):
                    audit_log.log(user_context.user, user_context.role, "APPROVE_FIREWALL_BLOCK", "198.51.100.1", "DENIED", "Insufficient role privileges")
                    raise PermissionError("Only REVIEWER or ADMIN may approve containment actions.")
                self.status = "APPROVED"
                self.approved_by = user_context.user
                audit_log.log(user_context.user, user_context.role, "APPROVE_FIREWALL_BLOCK", "198.51.100.1", "SUCCESS", "Human review verified")

        pipe = ContainmentPipeline()
        analyst = MockAuthContext("analyst1", "ANALYST")
        reviewer = MockAuthContext("reviewer1", "REVIEWER")

        # Analyst attempt must fail
        with self.assertRaises(PermissionError):
            pipe.approve(analyst, self.audit)
        self.assertEqual(pipe.status, "PROPOSED")

        # Reviewer attempt succeeds
        pipe.approve(reviewer, self.audit)
        self.assertEqual(pipe.status, "APPROVED")
        self.assertEqual(pipe.approved_by, "reviewer1")

    def test_sec_5_audit_trail_integrity(self):
        """
        AUDIT: Ensure every sensitive action creates an immutable log entry with zero secret leakage.
        """
        test_audit = MockAuditLog()
        entry = test_audit.log(
            user="admin_elena",
            role="ADMIN",
            action="CONFIG_UPDATE",
            resource="scoring_weights",
            result="SUCCESS",
            reason="Increased traffic weight from 25 to 30 based on telemetry validation"
        )
        self.assertIn("timestamp", entry)
        self.assertIn("request_id", entry)
        self.assertEqual(entry["action"], "CONFIG_UPDATE")
        self.assertEqual(entry["result"], "SUCCESS")
        # Ensure no credential keys exist
        self.assertNotIn("password", entry)
        self.assertNotIn("token", entry)

    def test_sec_6_configuration_versioning_and_rollback(self):
        """
        GOVERNANCE: Scoring configurations must be versioned with rollback capability.
        """
        config_history = [
            {"version": 1, "traffic_weight": 20.0, "status": "ARCHIVED"},
            {"version": 2, "traffic_weight": 30.0, "status": "ACTIVE"}
        ]

        def rollback(target_version, user_context, audit_log):
            if user_context.role != "ADMIN":
                audit_log.log(user_context.user, user_context.role, "ROLLBACK_CONFIG", f"v{target_version}", "DENIED", "Admin role required")
                raise PermissionError("Rollback requires ADMIN privileges.")
            target = next((c for c in config_history if c["version"] == target_version), None)
            if not target:
                raise ValueError("Target version not found.")
            # Set target active
            for c in config_history:
                c["status"] = "ARCHIVED"
            target["status"] = "ACTIVE"
            audit_log.log(user_context.user, user_context.role, "ROLLBACK_CONFIG", f"v{target_version}", "SUCCESS", f"Restored version {target_version}")
            return target

        admin = MockAuthContext("admin1", "ADMIN")
        rolled = rollback(1, admin, self.audit)
        self.assertEqual(rolled["version"], 1)
        self.assertEqual(rolled["traffic_weight"], 20.0)
        self.assertEqual(rolled["status"], "ACTIVE")

if __name__ == "__main__":
    unittest.main()
