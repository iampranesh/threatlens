# ThreatLens: System Architecture & Technical Design

## 1. System Overview

**ThreatLens** is an explainable local-relevance threat intelligence prioritization platform. It bridges the critical operational gap between raw external threat intelligence feeds and organizational reality. Instead of treating every external IOC as an immediate alert, ThreatLens evaluates each indicator through the lens of organizational exposure, internal network telemetry, software inventory, and historical incidents.

---

## 2. End-to-End Pipeline Architecture

```text
                                 EXTERNAL WORLD
                        ┌──────────────────────────────┐
                        │   External Threat Feeds      │
                        │ (AlienVault, AbuseIPDB,      │
                        │  CrowdStrike, Mandiant, etc.)│
                        └──────────────┬───────────────┘
                                       │ Raw IOCs (IPv4, Domain, URL, Hash)
                                       ▼
                     ┌───────────────────────────────────┐
                     │ 1. INGESTION & NORMALIZATION      │
                     │  - Strict schema validation       │
                     │  - Confidence bounding [0-100]    │
                     │  - De-duplication & Provenance    │
                     └─────────────────┬─────────────────┘
                                       │ Canonical IOC Records
                                       ▼
        ORGANIZATIONAL CONTEXT         │
   ┌──────────────────────────────┐    │
   │ Software Inventory & CVEs    ├────┤
   ├──────────────────────────────┤    │
   │ Network Telemetry & Traffic  ├────┼────────────────────────────────┐
   ├──────────────────────────────┤    │                                │
   │ Historical Incident Records  ├────┘                                │
   └──────────────────────────────┘                                     │
                                       │ Correlated Context             │
                                       ▼                                │
                     ┌───────────────────────────────────┐              │
                     │ 2. LOCAL-RELEVANCE SCORING ENGINE │              │
                     │  - Exposure Factor (+15)          │              │
                     │  - Telemetry Traffic Factor (+30) │              │
                     │  - Incident Factor (+25)          │              │
                     │  - Software/CVE Factor (+20)      │              │
                     │  - Feed Reputation (+10)          │              │
                     │  - Asset Criticality (+10)        │              │
                     │  - Recency Factor (+10)           │              │
                     │  - Source Reliability (+5)        │              │
                     │  - Staleness Penalty (-15)        │              │
                     │  - Weak Evidence Penalty (-20)    │              │
                     │  - CDN / Shared Infra Dampener(-25│              │
                     └─────────────────┬─────────────────┘              │
                                       │ Normalized Score [0, 100]      │
                                       ▼                                │
                     ┌───────────────────────────────────┐              │
                     │ 3. CLASSIFICATION & EXPLAINABILITY│              │
                     │  - 0-19:   IRRELEVANT (Suppressed)│              │
                     │  - 20-39:  LOW                    │              │
                     │  - 40-59:  MEDIUM                 │              │
                     │  - 60-79:  HIGH     (Actionable)  │              │
                     │  - 80-100: CRITICAL (Actionable)  │              │
                     │  - Generates verifiable Evidence  │              │
                     └─────────────────┬─────────────────┘              │
                                       │                                │
            ┌──────────────────────────┴──────────────────────────┐     │
            │                                                     │     │
            ▼                                                     ▼     │
  ┌───────────────────┐                                 ┌───────────────────┐
  │ SUPPRESSED QUEUE  │                                 │ ACTIONABLE SOC    │
  │ (Noise Filtered)  │                                 │ ALERT QUEUE       │
  │ 855 Indicators    │                                 │ 145 Verified IOCs │
  └───────────────────┘                                 └─────────┬─────────┘
                                                                  │
                                                                  ▼
                                                ┌───────────────────────────────────┐
                                                │ 4. HUMAN-IN-THE-LOOP CONTAINMENT  │
                                                │  - Analyst recommends block       │
                                                │  - Reviewer/Admin approves        │
                                                │  - Firewall / EDR action executed │
                                                │  - Immutable Audit Event logged   │
                                                └─────────────────┬─────────────────┘
                                                                  │
                                                                  ▼
                                                ┌───────────────────────────────────┐
                                                │ 5. GOVERNANCE & CONFIG ROLLBACK   │
                                                │  - Versioned scoring configurations│
                                                │  - Instant rollback with audit log│
                                                └───────────────────────────────────┘
```

---

## 3. Mathematical Formulation of Local Relevance

The local-relevance score $S \in [0, 100]$ is computed as:

$$S = \text{clamp}_{[0, 100]} \left( \sum_{i} W_i \cdot F_i - \sum_{j} P_j \right)$$

### Positive Weight Factors ($F_i$):
1. **Traffic Telemetry Factor ($F_{\text{traffic}} \in [0, 30]$):**
   $$F_{\text{traffic}} = \min(30, 12 + 5 \cdot \ln(N_{\text{events}} + 1) + 6 \cdot \mathbb{I}_{\text{allowed}})$$
2. **Historical Incident Factor ($F_{\text{incident}} \in [0, 25]$):**
   $$F_{\text{incident}} = \min(25, 15 + 5 \cdot N_{\text{malicious\_incidents}})$$
3. **Software & CVE Inventory Factor ($F_{\text{cve}} \in [0, 20]$):**
   Full 20 pts if CVE matches an internet-facing asset; $13\text{ pts}$ ($0.65\times$) if internal asset.
4. **Perimeter Exposure Factor ($F_{\text{exposure}} \in [0, 15]$):**
   $15\text{ pts}$ if target asset is perimeter internet-exposed; $6.75\text{ pts}$ if internal.
5. **Asset Criticality Factor ($F_{\text{crit}} \in [0, 10]$):**
   Critical = $10$, High = $7.5$, Medium = $4.5$, Low = $2.0$.
6. **External Threat Feed Factor ($F_{\text{feed}} \in [0, 10]$):**
   $$\frac{\text{Confidence}}{100} \times 10 \times \text{SeverityWeight}$$
7. **Temporal Recency Factor ($F_{\text{recency}} \in [0, 10]$):**
   Observed $<24\text{h} \rightarrow 10\text{ pts}$; $<7\text{d} \rightarrow 7.5\text{ pts}$; $<30\text{d} \rightarrow 4\text{ pts}$.
8. **Source Reliability Factor ($F_{\text{source}} \in [0, 5]$):**
   $5 \times \text{SourceReliabilityMultiplier} \in [0, 1]$.

### Negative Penalties ($P_j$):
- **Staleness Penalty ($P_{\text{stale}} = 15$):** Applied if last seen $>90$ days ago with zero local telemetry.
- **Weak Local Evidence Penalty ($P_{\text{weak}} = 20$):** Applied if external severity is High/Critical but the indicator has zero matching traffic, zero CVE matches, and zero incidents.
- **Shared Cloud/CDN Dampener ($P_{\text{cdn}} = 25$):** Applied if the indicator belongs to known multi-tenant CDN/public resolver IP space (Cloudflare, Fastly, AWS CloudFront, Google DNS).

---

## 4. Role-Based Access Control (RBAC) Architecture

| Role | Indicator Triage | Evidence Inspection | High-Impact Containment | Config Management | Config Rollback |
|:---|:---:|:---:|:---:|:---:|:---:|
| **ANALYST** | Read / Filter | Full Read | Recommend Only | Prohibited | Prohibited |
| **REVIEWER** | Read / Filter | Full Read | **Approve / Reject** | Review Proposals | Prohibited |
| **ADMIN** | Read / Filter | Full Read | **Approve / Reject** | **Author Changes** | **Execute Rollback** |

---

## 5. High-Impact Action Safety Flow

Automated blocking of IP addresses or domain names based solely on external threat feeds causes catastrophic operational downtime when benign CDN or cloud infrastructure is involved. ThreatLens enforces a strict human-in-the-loop workflow:

```text
[Threat Detected & Prioritized]
               │
               ▼
   [Analyst Reviews Evidence]
               │
               ▼
[Analyst Recommends Containment] (e.g. Block IP 198.51.100.1 at Border Firewall)
               │
               ▼
     [Held in PROPOSED state]
               │
               ▼
[Reviewer / Admin Evaluates Rationale]
       ├── Approved ──► [Containment Action Dispatched & Logged]
       └── Rejected ──► [Action Cancelled with Stated Reason]
```

---

## 6. Audit Logging & Governance

All state transitions are recorded into an append-only, tamper-evident audit store. Each record contains:
- `timestamp`: UTC ISO-8601 string
- `request_id`: UUIDv4
- `user`: Authenticated operator
- `role`: Operating security role
- `action`: Domain action (e.g. `CONFIG_CHANGE`, `ACTION_APPROVE`, `FEED_IMPORT`, `SCORE_CALCULATE`)
- `resource`: Target entity
- `result`: `SUCCESS` or `DENIED`
- `reason`: Operator or security rationale
- **Strict Invariant:** Credentials, private keys, passwords, and tokens are stripped before writing.
