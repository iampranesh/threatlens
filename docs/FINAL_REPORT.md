# ThreatLens: Explainable Local-Relevance Threat Intelligence Prioritization Platform
## Comprehensive Technical & Experimental Evaluation Report

---

## 1. Executive Summary
Security operations teams receive large volumes of external threat indicators, many of which require contextualisation against local organisational evidence. **ThreatLens** addresses this operational challenge by establishing an explainable, evidence-based prioritization platform that evaluates external IOCs through organizational exposure, internal network telemetry, software inventory, and historical incidents. On a controlled synthetic validation set of 1,000 indicators, ThreatLens reduced prioritised alert volume from 719 to 145, a 79.83% reduction, while achieving 96.67% local-threat recall and 100% precision. These results are from a reproducible synthetic pilot benchmark and are not production performance claims.

---

## 2. Problem Statement
The central security problem is:
> *"How relevant is this external threat indicator to OUR organisation?"*

Standard Threat Intelligence Platforms (TIPs) prioritize indicators based solely on external feed metrics (e.g., feed reputation, global severity). This triggers hundreds of low-relevance alerts for threats targeting technologies the enterprise does not own, while subtle threats targeting vulnerable internal assets get lost in the noise.

---

## 3. Industry Context
Enterprises consume feeds from commercial vendors, open-source aggregators, and governmental bodies. Security analysts frequently spend substantial effort manually querying firewall logs and SIEMs to check whether an external IP or domain has ever touched company assets.

---

## 4. Objectives
1. Automatically correlate external threat intelligence with internal evidence.
2. Provide transparent, explainable scoring normalized to $[0, 100]$.
3. Suppress $\ge 60\%$ of irrelevant indicators while preserving $\ge 95\%$ of local threats.
4. Enforce enterprise security governance (RBAC, human-in-the-loop containment, tamper-evident auditing, and configuration rollback).

---

## 5. Requirements
Defined across 10 Functional Requirements (FR-01 to FR-10), 6 Non-Functional Requirements (NFR-01 to NFR-06), 7 Security Requirements (SEC-01 to SEC-07), and 5 Evaluation Targets (EVAL-01 to EVAL-05). Full specifications and traceability matrix are documented in `docs/REQUIREMENTS.md`.

---

## 6. Proposed Solution
ThreatLens establishes an ingestion-to-action pipeline:
```text
External Feed Ingestion ──► Normalization ──► Evidence Correlation ──► Explainable Scoring
   ──► Tiered Classification ──► Evidence Generation ──► Analyst Review ──► Human-Approved Action ──► Audit
```

---

## 7. Architecture
Layered modular architecture with clear separation of concerns (detailed in `docs/ARCHITECTURE.md`):
- **Ingestion & Normalization (`src/server/security.ts`):** Schema sanitization, bounds checking, and deduplication.
- **Organizational Context Engine (`src/server/dataStore.ts`):** In-memory indexed software inventory, network telemetry, and historical incidents.
- **Explainable Scoring Engine (`src/server/scoringEngine.ts`):** Multi-factor transparent scoring with positive factors and negative penalty dampeners.
- **Governance & RBAC (`src/server/security.ts`):** Three distinct security roles (`ANALYST`, `REVIEWER`, `ADMIN`).
- **Presentation Layer (`src/`):** High-density SOC workstation dashboard built with React 19, TypeScript, and Tailwind CSS 4.

---

## 8. Data Sources
Synthetically generated via `scripts/generate_dataset.py` using RFC 5737 and RFC 3849 safe IP spaces with fixed seed `42`:
1. **Threat Intelligence Feeds (`data/raw/threat_feeds.csv`):** 1,000 indicators across IPv4, IPv6, Domain, URL, SHA256.
2. **Software Inventory (`data/raw/software_inventory.csv`):** 10 core organizational assets with 8 specific CVE mappings.
3. **Observed Traffic (`data/raw/observed_traffic.csv`):** 1,851 session telemetry records.
4. **Historical Incidents (`data/raw/historical_incidents.csv`):** 59 verified incident logs.
5. **Ground Truth Labels (`data/validation/validation_labels.csv`):** 1,000 labels (150 local threats vs 850 irrelevant noise).

---

## 9. Scoring Methodology
A deterministic, explainable linear formulation implemented in `src/server/scoringEngine.ts`:
$$S = \text{clamp}_{[0, 100]} \left( F_{\text{traffic}} + F_{\text{incident}} + F_{\text{cve}} + F_{\text{exposure}} + F_{\text{crit}} + F_{\text{feed}} + F_{\text{recency}} + F_{\text{source}} - P_{\text{stale}} - P_{\text{weak}} - P_{\text{cdn}} \right)$$
- **Observed Traffic ($F_{\text{traffic}} \in [0, 30]$):** $12 + 5 \cdot \ln(N_{\text{events}} + 1) + 6 \cdot \mathbb{I}_{\text{allowed}}$.
- **Historical Incidents ($F_{\text{incident}} \in [0, 25]$):** $15 + 5 \cdot N_{\text{malicious\_incidents}}$.
- **Software / CVE Inventory Match ($F_{\text{cve}} \in [0, 20]$):** Matches active organizational inventory; full weight on perimeter assets, $0.65\times$ on internal.
- **Perimeter Exposure ($F_{\text{exposure}} \in [0, 15]$):** $15\text{ pts}$ if internet-exposed, $6.75\text{ pts}$ if internal.
- **Asset Criticality ($F_{\text{crit}} \in [0, 10]$):** Critical = $10$, High = $7.5$, Medium = $4.5$, Low = $2.0$.
- **Feed Reputation ($F_{\text{feed}} \in [0, 10]$):** Normalized feed confidence and severity.
- **Temporal Recency ($F_{\text{recency}} \in [0, 10]$):** Seen $<24\text{h} \rightarrow 10$, $<7\text{d} \rightarrow 7.5$, $<30\text{d} \rightarrow 4$.
- **Source Reliability ($F_{\text{source}} \in [0, 5]$):** Provenance weighting.
- **Staleness Penalty ($P_{\text{stale}} = 15$):** Applied if last seen $>90$ days ago with zero local observations.
- **Weak Local Evidence Penalty ($P_{\text{weak}} = 20$):** Applied if external severity is High/Critical but the indicator has zero matching traffic, zero CVE matches, and zero incidents.
- **Shared Cloud/CDN Dampener ($P_{\text{cdn}} = 25$):** Applied to multi-tenant Cloudflare, Fastly, AWS CloudFront, or Google DNS IPs to prevent operational outages.

---

## 10. Labels and Thresholds
- **0–19: IRRELEVANT** (Suppressed from default SOC alert stream)
- **20–39: LOW** (Monitored passively; non-actionable)
- **40–59: MEDIUM** (Under surveillance; secondary triage)
- **60–79: HIGH** (Actionable alert queue; requires analyst review)
- **80–100: CRITICAL** (Immediate containment candidate)

---

## 11. Explainability
Every HIGH and CRITICAL indicator is guaranteed to possess an explainable evidence chain answering:
> *"WHY did the system give this score?"*
Each evidence point references concrete telemetry counts, specific asset hostnames, application versions, or incident ticket IDs. If evidence is insufficient, it explicitly displays: `INSUFFICIENT LOCAL EVIDENCE`.

---

## 12. Security Architecture
ThreatLens enforces defense-in-depth:
- Server-authoritative computation (no client trust).
- Role-Based Access Control on all routes (`src/server/security.ts`).
- Strict input sanitation against injection attacks.
- Tamper-evident application-level audit logging with unique UUID request identifiers (`src/server/dataStore.ts`).

---

## 13. Threat Model
Evaluated against STRIDE taxonomy in `docs/THREAT_MODEL.md`. All major threat categories (Score manipulation, Feed poisoning, Privilege escalation, Denial-of-Service through CDN blocking) mapped to active security controls.

---

## 14. Secure Defaults
- Least-privilege role assignment by default (`ANALYST`).
- Automated blocking disabled by default.
- Default suppression of unverified external noise.

---

## 15. Misuse Resistance
- Client attempts to submit forced scores (`{"score": 100}`) are rejected or stripped.
- Attempted feed poisoning with out-of-bounds confidence values is clipped to $[0, 100]$.

---

## 16. Audit Trail
Comprehensive tamper-evident event stream capturing login, score calculation, config proposals, reviewer sign-offs, rollbacks, and containment actions. Invariant: Zero secrets or passwords logged.

---

## 17. Change Review
Scoring configuration changes must be proposed with a mandatory rationale. Changes are staged in `PENDING_REVIEW` until an independent REVIEWER or ADMIN approves or rejects the modification.

---

## 18. Rollback
Admins can instantly roll back active scoring configurations to any previous version (e.g. v2 $\rightarrow$ v1). Rollbacks emit dedicated audit events and update active scoring weights immediately.

---

## 19. Implementation
Fullstack application using Node.js, Express, TypeScript, React 19, Tailwind CSS 4, and Lucide Icons, accompanied by reproducible Python experiment pipelines.

---

## 20. API
RESTful endpoints implemented in `src/server/apiRouter.ts`:
- `GET /api/health`, `GET /api/version`
- `GET /api/indicators`, `GET /api/indicators/:id`
- `POST /api/score`, `GET /api/high-priority`, `GET /api/evidence/:id`
- `POST /api/indicators`, `GET /api/metrics`
- `GET /api/audit`, `GET /api/config`, `POST /api/config/change`, `POST /api/config/review`, `POST /api/config/rollback`
- `POST /api/actions/propose`, `POST /api/actions/review`

---

## 21. UI
High-density SOC interface (`src/components/`) featuring:
1. Executive KPIs and Comparative Suppression Funnel (`DashboardView.tsx`).
2. Indicator Explorer with multi-attribute filtering (`ExplorerView.tsx`).
3. Explainability Workbench with factor breakdown and packet inspection (`ExplainModal.tsx`).
4. Baseline vs. Scorer Benchmarks with Confusion Matrix heatmaps (`BenchmarkView.tsx`).
5. Governance, Review Queue, and Configuration Rollback (`GovernanceView.tsx`).
6. Tamper-evident Audit Trail viewer (`AuditView.tsx`).
7. Interactive Security Attack & Edge Case test suite (`SecuritySuiteView.tsx`).

---

## 22. Validation Dataset
1,000 synthetic indicators with explicit ground truth:
- **150 Local Threats (15%):** Associated with organizational software, network telemetry, or incident records.
- **850 Irrelevant Commodity Noise (85%):** External internet noise, untargeted botnets, third-party exploits.

---

## 23. Experimental Methodology
Both the Baseline model and ThreatLens were evaluated across identical validation sets using `experiments/run_experiment.py`. All outputs are preserved in `results/metrics.json` and `results/baseline_metrics.json`.

---

## 24. Baseline
External-feed-only model scoring:
$$\text{Baseline} = \text{Feed Confidence} \times \text{Severity Multiplier}$$
Flags 719 indicators as actionable alerts (569 false alarms; 79.1% false-alarm rate).

---

## 25. Target
Predefined targets established prior to experimental execution:
- Irrelevant Suppression Rate: $\ge 60.0\%$
- Local Threat Recall: $\ge 95.0\%$
- False Negative Rate: $\le 5.0\%$
- Analyst Workload Reduction: $\ge 50.0\%$

---

## 26. Measured Results

The following values are the **ACTUAL** measured experiment results extracted directly from `results/metrics.json`:

| Metric | Baseline (Feed Only) | Predefined Target | ThreatLens Measured | Status |
|:---|:---:|:---:|:---:|:---:|
| **Irrelevant Suppression Rate** | 33.06% | $\ge 60.0\%$ | **100.00%** | **PASS** |
| **Local Threat Recall** | 100.00% | $\ge 95.0\%$ | **96.67%** | **PASS** |
| **Alert Queue Precision** | 20.86% | Target: High | **100.00%** | **SUPERIOR** |
| **False Positive Rate (FPR)** | 66.94% | Target: Low | **0.00%** | **SUPERIOR** |
| **False Negative Rate (FNR)** | 0.00% | $\le 5.0\%$ | **3.33%** | **PASS** |
| **Analyst Workload Reduction** | 0.00% | $\ge 50.0\%$ | **79.83%** | **PASS** |
| **Prioritized Alert Inflow** | 719 alerts | Target: Low Fatigue | **145 alerts** | **79.83% reduction in prioritised alert volume in the synthetic pilot benchmark.** |
| **Average Scoring Latency** | 0.041 ms | $< 5.0\text{ ms}$ | **0.041 ms** | **PASS** |

### Confusion Matrix Comparison:
- **Baseline Model:** `TP = 150`, `FP = 569`, `TN = 281`, `FN = 0` (Total Prioritized = 719).
- **ThreatLens Model:** `TP = 145`, `FP = 0`, `TN = 850`, `FN = 5` (Total Prioritized = 145).

---

## 27. False Positives
**Zero False Positives (0.00%).** No irrelevant commodity threat received a score $\ge 60$. All 850 irrelevant indicators were successfully suppressed into the `IRRELEVANT` or `LOW` tiers, eliminating false positives in this synthetic validation dataset.

---

## 28. False Negatives (Explicit Inspection of All 5 Samples)
**Exactly 5 False Negatives (3.33% FNR).** As recorded in `results/error_analysis.csv`, these 5 local threats were classified as `MEDIUM` ($40 - 59$) rather than `HIGH` ($\ge 60$):

| Indicator | Ground Truth | ThreatLens Score | Prediction | Root Cause Analysis | Recommended Fix |
|:---|:---:|:---:|:---:|:---|:---|
| `449937d78e2d25c953bbda26ef3337b590926777097e04992c90770701660baa` | local | **43.9** | MEDIUM | Targeted asset was internal-only with sparse telemetry and lower external feed confidence. | Lower threshold for critical internal crown-jewel assets even with single telemetry log. |
| `apt-telemetry-c2-044.synthetic-threat.org` | local | **42.8** | MEDIUM | Reconnaissance probe against internal endpoint; lower traffic frequency dampened score below 60. | Provide crown-jewel asset sensitivity multiplier. |
| `dc8d5ec863164d1980f0b2c6b8088d83e24cb3972ef57cec378e3fd91f3cf1e7` | local | **46.4** | MEDIUM | Targeted database host; zero outbound traffic prevented high-priority elevation. | Add policy rule boosting database tier assets into HIGH triage. |
| `198.51.100.71` | local | **57.5** | MEDIUM | Borderline score (57.5 vs 60.0 cutoff); untrusted community feed dampened source weight. | Provide analysts with an adjustable "Borderline Triage" view in Medium queue. |
| `198.51.100.92` | local | **43.6** | MEDIUM | Internal workstation asset; lower criticality tier prevented score from crossing 60. | Lower threshold for crown-jewel internal workstations. |

---

## 29. Edge Cases
Six edge cases implemented and verified in `tests/test_edge_cases.py`:
1. **Stale Threat Feeds:** Indicator inactive for $>250$ days was automatically penalized by $-15$ points and suppressed.
2. **Shared Cloud / CDN Addresses:** Multi-tenant Cloudflare IP `104.16.124.96` received a $-25$ point dampener to prevent blocking essential infrastructure.
3. **Missing Asset Inventory Records:** Network telemetry referencing an unmapped asset handled gracefully without exceptions.
4. **Conflicting Threat Feeds:** High-reputation intelligence was prioritized over low-reliability community scrapers.
5. **Duplicate Ingestion:** Deterministic deduplication produced identical, idempotent scores.
6. **Malformed Inputs:** Sanitized null values, non-numeric confidence inputs, and invalid date formats safely.

---

## 30. Performance
Average scoring latency is **0.041 ms per indicator**, enabling real-time stream ingestion of $>20,000$ IOCs per second on standard hardware.

---

## 31. Stakeholder Validation (SIMULATED)
> **SIMULATED STAKEHOLDER VALIDATION:** Stakeholder validation was simulated using synthetic expert personas; no external SOC users participated in the evaluation.
- **Persona 1 (Tier-1 SOC Analyst):** Rated workload reduction **5.0 / 5.0**; commended clear evidence explanations.
- **Persona 2 (Incident Response Lead):** Rated explainability **4.8 / 5.0**; highlighted immediate visibility into affected assets.
- **Persona 3 (SOC Manager):** Rated governance **4.7 / 5.0**; praised human-in-the-loop containment approvals.
- **Persona 4 (Security Architect):** Rated architecture **4.8 / 5.0**; validated defense against client score tampering.
- **Overall Simulated Usability Score:** **4.8 / 5.0**.

---

## 32. Limitations (Honest Engineering Boundary Conditions)
Documented fully in `docs/LIMITATIONS.md`:
1. **Synthetic Pilot Data:** While RFC 5737 compliant and architected to mirror real-world threat actors and CVEs, synthetic telemetry lacks the packet fragmentation, NAT ambiguities, and encrypted SNI issues found in large-scale production.
2. **Telemetry Visibility Blindspots:** If internal telemetry has blindspots on unmonitored segments or shadow IT, ThreatLens may penalize indicators targeting those segments under the *Weak Local Evidence* rule.
3. **Ephemeral Cloud IP Churn:** Attack infrastructure hosted on cloud providers (e.g. AWS EC2, Azure) frequently rotates IPs within hours.
4. **Static Linear Weights:** While transparent and explainable, fixed linear factor weights require periodic governance reviews to adapt to organizational infrastructure changes.
5. **Low-and-Slow Reconnaissance Probes:** 5 true local threats were scored as MEDIUM (40–59) due to sparse single-packet telemetry.

---

## 33. Future Work
- **Streaming Telemetry Ingestion:** Connectors for Zeek, Suricata, and AWS/GCP VPC Flow Logs via Apache Kafka.
- **Passive DNS (pDNS) Graph Correlation:** Historical domain-to-IP mapping to handle ephemeral cloud infrastructure churn.
- **Weight Sensitivity Backtesting Engine:** Automated simulation tools allowing security architects to model proposed weight changes against historical SOC incident queues before deployment.
- **Bi-Directional SIEM/SOAR Integrations:** Webhooks for Splunk, Microsoft Sentinel, and Cortex XSOAR for automated containment ticket dispatch.

---

## 34. Conclusion
ThreatLens demonstrates in the synthetic pilot benchmark that correlating external threat intelligence with internal organizational exposure suppresses external noise (100% suppression of irrelevant indicators, 79.83% analyst workload reduction in this benchmark) without losing locally applicable threats (96.67% recall). Explainable, transparent scoring provides the evidence required for high-confidence SOC operations.

---

## 35. Reproducibility
The entire evaluation is 100% reproducible via:
```bash
python3 scripts/generate_dataset.py
python3 experiments/run_experiment.py
python3 -m unittest discover tests
```
All outputs are saved in `results/metrics.json`, `results/error_analysis.csv`, and `results/experiment_summary.md`.
