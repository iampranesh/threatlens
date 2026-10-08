# ThreatLens: Challenge Requirement Evidence Matrix

| Challenge Requirement | Implementation Component | Test / Verification File | Measured Evidence / Proof |
|:---|:---|:---|:---|
| **Local-Relevance Scoring** | `server/scoring/engine.ts` & `experiments/run_experiment.py` | `tests/test_scoring.py` | Transparent linear formula producing score in $[0, 100]$ with factor breakdown (`results/metrics.json`) |
| **External Threat Feed Ingestion** | `server/services/feedService.ts` | `tests/test_scoring.py` | 1,000 multi-source indicators ingested (`data/raw/threat_feeds.csv`) |
| **Software Inventory Correlation** | `server/services/inventoryService.ts` | `tests/test_scoring.py` | 10 assets mapped against CVEs and perimeter exposure (`data/raw/software_inventory.csv`) |
| **Observed Traffic Correlation** | `server/services/trafficService.ts` | `tests/test_scoring.py` | 1,851 session telemetry records matched by IOC & port (`data/raw/observed_traffic.csv`) |
| **Historical Incidents Linkage** | `server/services/incidentService.ts` | `tests/test_scoring.py` | 59 historical incidents correlated by IOC (`data/raw/historical_incidents.csv`) |
| **Baseline Model Comparison** | `experiments/run_experiment.py` (baseline engine) | `experiments/run_experiment.py` | External-feed-only baseline generates 719 alerts vs ThreatLens 145 alerts (`results/experiment_summary.md`) |
| **Noise Suppression Benchmark** | Scoring suppression logic & classification | `experiments/run_experiment.py` | **100.00%** of irrelevant indicators suppressed (Target $\ge 60\%$, PASS) |
| **Local Threat Recall Benchmark** | Evidence correlation & priority thresholds | `experiments/run_experiment.py` | **96.67%** local threats retained (Target $\ge 95\%$, PASS) |
| **Analyst Workload Reduction** | Triage filtering & noise elimination | `experiments/run_experiment.py` | **79.83%** workload reduction (Target $\ge 50\%$, PASS) |
| **False Negative Rate (FNR)** | Sensitivity tuning | `experiments/run_experiment.py` | **3.33%** FNR (Target $\le 5.0\%$, PASS) |
| **False Negative Error Analysis** | `results/error_analysis.csv` | `experiments/run_experiment.py` | Root causes & remediations documented for all 5 FN samples |
| **High-Priority Evidence Chain** | `server/scoring/engine.ts` | `tests/test_scoring.py::test_high_priority_evidence_requirement` | Every HIGH/CRITICAL IOC has multi-point evidence chain; verified in code |
| **Edge Case 1: Stale Indicators** | `server/scoring/engine.ts` | `tests/test_edge_cases.py::test_edge_case_1_stale_indicator` | Inactive $>250$ days penalized $-15$ pts; suppressed |
| **Edge Case 2: Shared CDN / Cloud IP** | `server/scoring/engine.ts` | `tests/test_edge_cases.py::test_edge_case_2_shared_cloud_cdn_ip` | Cloudflare / AWS IPs dampened $-25$ pts to prevent outage |
| **Edge Case 3: Missing Inventory** | Fallback mapping logic | `tests/test_edge_cases.py::test_edge_case_3_missing_asset_inventory` | Graceful default without unhandled exceptions |
| **Edge Case 4: Conflicting Feeds** | Source reliability weighting | `tests/test_edge_cases.py::test_edge_case_4_conflicting_threat_feeds` | Trusted sources out-weight community scrapers |
| **Edge Case 5: Duplicate Ingestion** | Deterministic deduplication | `tests/test_edge_cases.py::test_edge_case_5_duplicate_indicators` | Idempotent scoring verified |
| **Score Manipulation Defense** | `server/api/scoreRouter.ts` | `tests/test_security.py::test_sec_1_score_manipulation_protection` | Client-provided scores rejected; backend computes independently |
| **Role-Based Authorization (RBAC)** | `server/security/auth.ts` | `tests/test_security.py::test_sec_2_rbac_authorization_matrix` | ANALYST, REVIEWER, ADMIN role restrictions verified |
| **Feed Poisoning Defense** | Schema sanitation & bounds checking | `tests/test_security.py::test_sec_3_feed_poisoning_defense` | Out-of-bounds confidence and XSS payloads neutralized |
| **Human-in-the-Loop Containment** | `server/services/actionService.ts` | `tests/test_security.py::test_sec_4_high_impact_containment_pipeline` | Containment held in PROPOSED until Reviewer/Admin approves |
| **Tamper-Evident Audit Logging** | `server/services/auditService.ts` | `tests/test_security.py::test_sec_5_audit_trail_integrity` | Append-only audit events with request ID; zero secret leakage |
| **Configuration Version & Rollback** | `server/services/configService.ts` | `tests/test_security.py::test_sec_6_configuration_versioning_and_rollback` | Active config restored to v1; audit trail emitted |
| **Interactive SOC Dashboard** | React + TypeScript + Tailwind 4 UI | Vite build / compiler verification | Fully operational 8-view SOC application on port 3000 |
| **Docker Containerization** | `Dockerfile` & `docker-compose.yml` | Container build configuration | Production-ready zero-dependency container deployment |
| **CI/CD Automation** | `.github/workflows/ci.yml` | Workflow verification | Automated linting, test discovery, and build checks |
