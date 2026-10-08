# ThreatLens: System Requirements Specification & Traceability Matrix

## 1. Functional Requirements (FR)

| Req ID | Title | Description | Implementation Component | Test / Verification |
|:---|:---|:---|:---|:---|
| **FR-01** | Multi-Feed Ingestion & Normalization | Ingest external IOCs (IPv4, IPv6, Domain, URL, SHA256) with source metadata, confidence, and CVE mappings. Standardize schema into canonical format. | `server/services/feedService.ts` / `scripts/generate_dataset.py` | `tests/test_scoring.py` / Ingestion API Test |
| **FR-02** | Organizational Context Integration | Maintain authoritative records of organizational software inventory, internet-facing assets, criticality tiers, and known CVE exposures. | `server/services/inventoryService.ts` / `data/raw/software_inventory.csv` | `tests/test_scoring.py` |
| **FR-03** | Network Telemetry Correlation | Correlate inbound/outbound connection events, port, protocol, byte volumes, and pass/block actions against incoming threat indicators. | `server/services/trafficService.ts` / `data/raw/observed_traffic.csv` | `tests/test_scoring.py` |
| **FR-04** | Historical Incident Cross-Referencing | Cross-reference indicators against historical internal security incident records, confirmed malicious tags, and business impact. | `server/services/incidentService.ts` / `data/raw/historical_incidents.csv` | `tests/test_scoring.py` |
| **FR-05** | Explainable Local-Relevance Scoring | Compute normalized local-relevance score (0–100) combining exposure, telemetry, software/CVE, recency, and dampening penalties. | `server/scoring/engine.ts` / `experiments/run_experiment.py` | `tests/test_scoring.py` |
| **FR-06** | Tiered Classification & Thresholding | Categorize indicators into IRRELEVANT (0-19), LOW (20-39), MEDIUM (40-59), HIGH (60-79), CRITICAL (80-100). | `server/scoring/engine.ts` | `tests/test_scoring.py::test_classification_thresholds` |
| **FR-07** | High-Priority Evidence Chain | Generate human-readable evidence chains for all HIGH and CRITICAL indicators explaining specific telemetry and asset links. | `server/scoring/engine.ts` | `tests/test_scoring.py::test_high_priority_evidence_requirement` |
| **FR-08** | Noise Suppression Workflow | Suppress external commodity noise from primary SOC alert queue without manual triage. | `server/scoring/engine.ts` / Dashboard filter | `experiments/run_experiment.py` |
| **FR-09** | Versioned Scoring Configuration | Support versioned scoring weights (v1, v2...) with change rationale and author attribution. | `server/services/configService.ts` | `tests/test_security.py::test_sec_6_configuration_versioning_and_rollback` |
| **FR-10** | Configuration Rollback Engine | Revert active scoring parameters to any previous version with complete audit preservation. | `server/services/configService.ts` | `tests/test_security.py::test_sec_6_configuration_versioning_and_rollback` |

---

## 2. Non-Functional Requirements (NFR)

| Req ID | Title | Metric / Target | Implementation | Verification |
|:---|:---|:---|:---|:---|
| **NFR-01** | Scoring Latency | Average scoring time < 5 ms per indicator | In-memory indexing and hash-map lookups | Measured: 0.041 ms per indicator (`results/metrics.json`) |
| **NFR-02** | Determinism & Reproducibility | 100% identical outputs on identical inputs (Seed = 42) | Fixed random seed and stateless mathematical scoring | Verified in `tests/test_edge_cases.py::test_edge_case_5_duplicate_indicators` |
| **NFR-03** | Resilience & Safe Degradation | Zero unhandled exceptions on missing telemetry or unmapped assets | Safe dictionary lookups and fallback defaults | Verified in `tests/test_edge_cases.py::test_edge_case_3_missing_asset_inventory` |
| **NFR-04** | Containerized Portability | Zero-dependency launch via Docker and docker-compose | Dockerfile and docker-compose.yml | Build & run validated |
| **NFR-05** | UI Responsiveness | Sub-100ms client-side filter and navigation response | Reactive state architecture with Tailwind 4 & Lucide | Verified in browser UI |
| **NFR-06** | Clean Architectural Boundaries | Strict separation of Ingestion, Correlation, Scoring, Governance, and Presentation layers | Modular TypeScript/Python packages | Codebase review |

---

## 3. Security Requirements (SEC)

| Req ID | Title | Description | Implementation | Verification |
|:---|:---|:---|:---|:---|
| **SEC-01** | Role-Based Access Control (RBAC) | Enforce three tiers: ANALYST (read & investigate), REVIEWER (approve changes & actions), ADMIN (manage config & rollback). | `server/security/auth.ts` | `tests/test_security.py::test_sec_2_rbac_authorization_matrix` |
| **SEC-02** | Score Manipulation Protection | Client-supplied scores or labels must be rejected or ignored; backend computes all scores independently. | `server/api/scoreRouter.ts` | `tests/test_security.py::test_sec_1_score_manipulation_protection` |
| **SEC-03** | Threat Feed Poisoning Defense | Schema validation, confidence bounds [0-100], source trust weighting, and duplicate rejection. | `server/services/feedService.ts` | `tests/test_security.py::test_sec_3_feed_poisoning_defense` |
| **SEC-04** | High-Impact Action Gating | Automated blocking prohibited. High-impact actions require Detection → Recommendation → Review → Approval → Action. | `server/services/actionService.ts` | `tests/test_security.py::test_sec_4_high_impact_containment_pipeline` |
| **SEC-05** | Tamper-Evident Audit Trail | Immutable logging of login, score calculation, config update, review, rollback, and containment. Zero secret leakage. | `server/services/auditService.ts` | `tests/test_security.py::test_sec_5_audit_trail_integrity` |
| **SEC-06** | Safe Input Sanitation | Strict regex validation for IPv4, IPv6, domains, URLs, CVE identifiers, and SHA256 hashes. | `server/security/validator.ts` | `tests/test_edge_cases.py::test_edge_case_6_malformed_input_graceful_handling` |
| **SEC-07** | Shared Infrastructure Dampening | Multi-tenant CDN and public DNS addresses (e.g. Cloudflare, Fastly, CloudFront, 8.8.8.8) dampened to prevent outage. | `server/scoring/engine.ts` | `tests/test_edge_cases.py::test_edge_case_2_shared_cloud_cdn_ip` |

---

## 4. Evaluation & Benchmark Requirements (EVAL)

| Req ID | Metric | Predefined Target | Baseline Measured | ThreatLens Measured | Status |
|:---|:---|:---:|:---:|:---:|:---:|
| **EVAL-01** | Irrelevant Suppression Rate | ≥ 60.0% | 33.06% | **100.00%** | **PASS** |
| **EVAL-02** | Local Threat Recall | ≥ 95.0% | 100.00% | **96.67%** | **PASS** |
| **EVAL-03** | False Negative Rate (FNR) | ≤ 5.0% | 0.00% | **3.33%** | **PASS** |
| **EVAL-04** | Analyst Workload Reduction | ≥ 50.0% | 0.00% | **79.83%** | **PASS** |
| **EVAL-05** | Alert Queue Precision | Target: High | 20.86% | **100.00%** | **INFO / SUPERIOR** |

---

## 5. Traceability Matrix

```text
Requirement (FR/SEC/EVAL) ────────► Implementation File ────────► Automated Test ────────► Ground Truth Artifact
FR-01 (Feed Ingestion)            server/services/feedService.ts   tests/test_scoring.py    data/raw/threat_feeds.csv
FR-02 (Software Inventory)        server/services/inventoryService tests/test_scoring.py    data/raw/software_inventory.csv
FR-03 (Observed Traffic)          server/services/trafficService   tests/test_scoring.py    data/raw/observed_traffic.csv
FR-04 (Historical Incidents)      server/services/incidentService  tests/test_scoring.py    data/raw/historical_incidents.csv
FR-05 (Local Relevance Scorer)    server/scoring/engine.ts         tests/test_scoring.py    results/metrics.json
FR-06 (Thresholds 0-100)          server/scoring/engine.ts         tests/test_scoring.py    results/experiment_summary.md
FR-07 (Evidence Chain)            server/scoring/engine.ts         tests/test_scoring.py    results/error_analysis.csv
SEC-01 (RBAC Authorization)       server/security/auth.ts          tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
SEC-02 (Anti-Manipulation)        server/api/scoreRouter.ts        tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
SEC-03 (Feed Poisoning Guard)     server/services/feedService.ts   tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
SEC-04 (Human-in-the-Loop)        server/services/actionService.ts tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
SEC-05 (Audit Trail)              server/services/auditService.ts  tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
SEC-06 (Config Rollback)          server/services/configService.ts tests/test_security.py   docs/SECURITY_TEST_RESULTS.md
EVAL-01 to EVAL-05 (Benchmarks)   experiments/run_experiment.py    test discovery (17 tests)results/metrics.json
```
