# ThreatLens: Explainable Local-Relevance Threat Intelligence Prioritization Platform

[![CI Pipeline](https://github.com/organization/threatlens/actions/workflows/ci.yml/badge.svg)](https://github.com/organization/threatlens/actions)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Node.js 20+](https://img.shields.io/badge/node-20+-green.svg)](https://nodejs.org/)
[![Status](https://img.shields.io/badge/Benchmark-PASS-emerald.svg)](results/metrics.json)

> **Industry Challenge Formulation:** Security teams receive large volumes of external threat indicators, many of which require contextualisation against local organisational evidence. **ThreatLens** evaluates external threat indicators against **organisational exposure evidence** to answer: *"How relevant is this external threat indicator to OUR organisation?"*

---

## 1. Key Results Summary (Experimental Proof)

Evaluated against a reproducible pilot benchmark of **1,000 indicators** (150 true local threats, 850 irrelevant commodity noise) using RFC 5737 safe IP spaces and fixed random seed `42`. *These results represent a controlled synthetic pilot benchmark and should not be interpreted as production performance claims.*

| Metric | Baseline (Feed Only) | Predefined Target | ThreatLens Measured | Status |
|:---|:---:|:---:|:---:|:---:|
| **Irrelevant Suppression Rate** | 33.06% | **≥ 60.0%** | **100.00%** | **PASS** |
| **Local Threat Recall** | 100.00% | **≥ 95.0%** | **96.67%** | **PASS** |
| **Alert Queue Precision** | 20.86% | Target: High | **100.00%** | **SUPERIOR** |
| **False Positive Rate (FPR)** | 66.94% | Target: Low | **0.00%** | **SUPERIOR** |
| **False Negative Rate (FNR)** | 0.00% | **≤ 5.0%** | **3.33%** | **PASS** |
| **Analyst Workload Reduction** | 0.00% | **≥ 50.0%** | **79.83%** | **PASS** |
| **Prioritized Alert Inflow** | 719 alerts | Target: Low Fatigue | **145 alerts** | **79.83% reduction in prioritised alert volume in the synthetic pilot benchmark.** |
| **Average Scoring Latency** | 0.041 ms | < 5.0 ms | **0.041 ms** | **PASS** |

*All results verified via `python3 experiments/run_experiment.py` and saved in `results/metrics.json`.*

---

## 2. Architecture & Pipeline

```text
External Threat Feeds
        ↓
Indicator Ingestion (Schema validation, confidence bounding)
        ↓
Indicator Normalization (Canonical RFC 5737 representation)
        ↓
Organisational Evidence (Software inventory, traffic telemetry, historical incidents)
        ↓
Correlation Engine (In-memory indexed asset and telemetry matching)
        ↓
Local-Relevance Scoring (Multi-factor transparent linear formulation)
        ↓
Classification (IRRELEVANT: 0-19, LOW: 20-39, MEDIUM: 40-59, HIGH: 60-79, CRITICAL: 80-100)
        ↓
Evidence / Explainability (Verifiable evidence chain for all High/Critical IOCs)
        ↓
Analyst Dashboard (High-density SOC workstation UI)
        ↓
Human Review / Approval (Two-person containment action authorization)
        ↓
Audit Trail (Immutable append-only event stream, zero secret leakage)
        ↓
Rollback (One-click scoring configuration restoration)
```

---

## 3. Mathematical Scoring Formulation

The ThreatLens local-relevance score $S \in [0, 100]$ is computed as:

$$S = \text{clamp}_{[0, 100]} \left( F_{\text{traffic}} + F_{\text{incident}} + F_{\text{cve}} + F_{\text{exposure}} + F_{\text{crit}} + F_{\text{feed}} + F_{\text{recency}} + F_{\text{source}} - P_{\text{stale}} - P_{\text{weak}} - P_{\text{cdn}} \right)$$

### Factor Weights:
- **Observed Traffic ($F_{\text{traffic}} \in [0, 30]$):** $12 + 5 \cdot \ln(N_{\text{events}} + 1) + 6 \cdot \mathbb{I}_{\text{allowed}}$.
- **Historical Incidents ($F_{\text{incident}} \in [0, 25]$):** $15 + 5 \cdot N_{\text{malicious\_incidents}}$.
- **Software / CVE Inventory Match ($F_{\text{cve}} \in [0, 20]$):** Matches active organizational inventory; full weight on perimeter assets, $0.65\times$ on internal.
- **Perimeter Exposure ($F_{\text{exposure}} \in [0, 15]$):** Asset is internet-facing.
- **Asset Criticality ($F_{\text{crit}} \in [0, 10]$):** Critical = 10, High = 7.5, Medium = 4.5, Low = 2.
- **Feed Reputation ($F_{\text{feed}} \in [0, 10]$):** Normalized feed confidence and severity.
- **Temporal Recency ($F_{\text{recency}} \in [0, 10]$):** Seen $<24\text{h} \rightarrow 10$, $<7\text{d} \rightarrow 7.5$, $<30\text{d} \rightarrow 4$.
- **Source Reliability ($F_{\text{source}} \in [0, 5]$):** Provenance weighting.

### Safeguard Penalties:
- **Staleness Penalty ($P_{\text{stale}} = 15$):** Applied if last seen $>90$ days ago with zero local observations.
- **Weak Local Evidence Penalty ($P_{\text{weak}} = 20$):** Applied if external severity is High/Critical but the indicator has zero matching traffic, zero CVE matches, and zero incidents.
- **Shared Cloud/CDN Dampener ($P_{\text{cdn}} = 25$):** Applied to multi-tenant Cloudflare, Fastly, AWS CloudFront, or Google DNS IPs to prevent operational outages.

---

## 4. Security Architecture & RBAC

| Security Role | Indicator Triage | Evidence Inspection | Containment Actions | Config Management | Config Rollback |
|:---|:---:|:---:|:---:|:---:|:---:|
| **ANALYST** | Full Read | Full Read | Propose Only | Prohibited | Prohibited |
| **REVIEWER** | Full Read | Full Read | **Approve / Reject** | Review Proposals | Prohibited |
| **ADMIN** | Full Read | Full Read | **Approve / Reject** | **Author Changes** | **Execute Rollback** |

### Core Security Controls:
1. **Score Manipulation Defense:** The server completely ignores client-supplied scores. Scores are computed exclusively by the backend scoring engine using authoritative server-side evidence contexts.
2. **Threat Feed Poisoning Defense:** Strict input sanitation, confidence bounds clipping $[0, 100]$, and source reliability multipliers.
3. **High-Impact Containment Gating:** Automated blocking is architecturally forbidden. Containment actions require Detection → Recommendation → Review → Approval → Execution.
4. **Tamper-Evident Audit Logging:** Tamper-evident application-level log entries with unique UUID request identifiers. Zero passwords or credentials captured.

---

## 5. Quickstart & Installation

### Option A: Local Run (Fastest)
```bash
# 1. Clone repository
git clone https://github.com/organization/threatlens.git
cd threatlens

# 2. Install dependencies
npm install

# 3. Generate synthetic datasets (Seed: 42)
python3 scripts/generate_dataset.py

# 4. Run automated test suites (17 tests)
python3 -m unittest discover tests

# 5. Run benchmark experiment
python3 experiments/run_experiment.py

# 6. Start full-stack platform
npm run dev
# Open http://localhost:3000 in your browser
```

### Option B: Docker Compose
```bash
cp .env.example .env
docker compose up --build
# Access UI at http://localhost:3000
```

---

## 6. Project Repository Layout

```text
threatlens/
├── backend/ & src/server/
│   ├── types.ts               # Core TypeScript domain types
│   ├── scoringEngine.ts       # Explainable local-relevance scoring engine
│   ├── dataStore.ts           # In-memory indexed datastore
│   ├── security.ts            # RBAC authorization & input validation
│   ├── apiRouter.ts           # REST API endpoints
│   └── app.ts                 # Express application entry
├── src/                       # Frontend SOC Dashboard (React 19, Tailwind 4)
│   ├── components/
│   │   ├── Header.tsx         # Role switcher & live telemetry ticker
│   │   ├── DashboardView.tsx  # Executive KPIs & suppression funnel
│   │   ├── ExplorerView.tsx   # Searchable, filterable indicator grid
│   │   ├── ExplainModal.tsx   # Detailed evidence workbench
│   │   ├── BenchmarkView.tsx  # Confusion matrix & target validation
│   │   ├── GovernanceView.tsx # Weight management & 1-click rollback
│   │   ├── AuditView.tsx      # Immutable audit trail
│   │   └── SecuritySuiteView.tsx # Live adversarial attack suite
│   ├── App.tsx
│   └── main.tsx
├── data/
│   ├── raw/                   # Threat feeds, traffic, inventory, incidents CSVs
│   ├── processed/             # Unified pilot dataset bundle
│   └── validation/            # Ground truth validation labels
├── experiments/
│   └── run_experiment.py      # Benchmark runner (Baseline vs ThreatLens)
├── scripts/
│   ├── generate_dataset.py    # Synthetic dataset generator (Seed 42)
│   ├── generate_charts.py     # SVG visualization generator
│   └── run_security_tests.py  # Security test verification script
├── tests/
│   ├── test_scoring.py        # Scoring logic & threshold tests
│   ├── test_edge_cases.py     # 6 edge cases tests
│   └── test_security.py       # 6 security attack scenario tests
├── results/
│   ├── metrics.json           # Measured evaluation metrics
│   ├── baseline_metrics.json  # Raw feed baseline metrics
│   ├── error_analysis.csv     # Root cause analysis on False Negatives
│   ├── confusion_matrix.svg   # Visual confusion matrix
│   ├── baseline_vs_scorer.svg # Comparative bar charts
│   ├── suppression_analysis.svg # Noise suppression funnel chart
│   └── experiment_summary.md  # Formal benchmark report
├── docs/
│   ├── REQUIREMENTS.md        # FR/NFR/SEC specifications & traceability matrix
│   ├── ARCHITECTURE.md        # System architecture & mathematical formulation
│   ├── VALIDATION.md          # Comprehensive experimental report
│   ├── THREAT_MODEL.md        # STRIDE threat model & mitigations
│   ├── SECURITY_TEST_RESULTS.md # Security test matrix
│   ├── LIMITATIONS.md         # System limitations & engineering boundaries
│   ├── EVIDENCE_MATRIX.md     # Requirement-to-proof cross-reference
│   └── FINAL_REPORT.md        # 35-section competition master report
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
└── package.json
```

---

## 7. REST API Reference

| Method | Endpoint | Description | Auth / Role |
|:---|:---|:---|:---|
| `GET` | `/api/health` | System health & indicators loaded | Public |
| `GET` | `/api/version` | Engine version & RFC compliance | Public |
| `GET` | `/api/auth/me` | Current authenticated session | Public |
| `POST` | `/api/auth/switch-role` | Switch session role (Analyst, Reviewer, Admin) | Public (Simulation) |
| `GET` | `/api/indicators` | Paginated IOCs with multi-filter query | All Roles |
| `GET` | `/api/indicators/:id` | Single indicator detail | All Roles |
| `POST` | `/api/indicators` | Ingest new indicator with schema validation | All Roles |
| `POST` | `/api/score` | Compute local relevance score independently | All Roles |
| `GET` | `/api/high-priority` | Fetch all actionable prioritized alerts (Score ≥ 60) | All Roles |
| `GET` | `/api/evidence/:id` | Fetch full factor breakdown & packet logs | All Roles |
| `GET` | `/api/metrics` | Fetch real-time evaluation benchmark stats | All Roles |
| `GET` | `/api/audit` | Query immutable audit log | All Roles |
| `GET` | `/api/config` | Query active config and version history | All Roles |
| `POST` | `/api/config/change` | Propose scoring weight modification | **ADMIN** |
| `POST` | `/api/config/review` | Approve or reject pending proposal | **REVIEWER / ADMIN** |
| `POST` | `/api/config/rollback` | Rollback active scoring to previous version | **ADMIN** |
| `POST` | `/api/actions/propose` | Propose containment action (Block / Isolate) | All Roles |
| `POST` | `/api/actions/review` | Approve/reject containment action | **REVIEWER / ADMIN** |

---

## 8. Demo Flow for Evaluators (5–7 Minute Walkthrough)

1. **Open Dashboard (`/`):** Observe executive KPIs showing **100.00% suppression rate**, **96.67% recall**, and **79.8% analyst workload reduction**.
2. **Review Comparative Alert Fatigue:** Notice that the Baseline external feed alerted on **719 indicators** (569 false alarms), whereas ThreatLens prioritized only **145 indicators**.
3. **Open Indicator Explorer:** Filter by "Prioritized Queue". Inspect any CRITICAL or HIGH indicator.
4. **Inspect Evidence Workbench:** Review the **Factor Contribution Breakdown** (Traffic, Incident, CVE, Exposure, Penalties) and the **Verifiable Evidence Chain**.
5. **Inspect Network Telemetry:** View correlated packet logs showing allowed/blocked packets, ports, and affected asset hostname.
6. **Simulate Containment Action:** Click "Containment Action" on an indicator. Propose a firewall block. Notice it is held in `PROPOSED` status.
7. **Role Escalation & Approval:** Switch active user from *Sarah Chen (Analyst)* to *Marcus Vance (Reviewer)*. Navigate to Audit or Containment queue and approve the action.
8. **Test Security Attack Suite:** Switch to the **Security & Edge Tests** tab. Click "Execute Entire Test Suite". Observe live defense verification against score tampering, privilege escalation, feed poisoning, and CDN IP dampening.
9. **Configuration Rollback:** Switch to *Elena Rostova (Admin)*. Navigate to Governance. Propose a change, approve it, and execute a **1-click Rollback**.

---

## 9. License

This project is licensed under the Apache 2.0 License - see the [LICENSE](LICENSE) file for details.
