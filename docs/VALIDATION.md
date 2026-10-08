# ThreatLens: Experimental Validation & Benchmark Report

## 1. Experimental Methodology & Dataset Setup

The experimental validation of **ThreatLens** evaluates whether correlating external threat intelligence with internal organizational exposure effectively suppresses noise without discarding true local threats.

### Pilot Dataset Composition:
- **Seed:** Fixed at `42` for strict mathematical reproducibility.
- **Total Ingested Indicators:** 1,000 (across IPv4, IPv6, Domain, URL, SHA256).
- **Ground Truth Distribution:**
  - **150 Locally Applicable Threats (15.0%):** Tied to active organizational assets (`WEB-PROD-01`, `VPN-GW-01`, `K8S-INGRESS-01`, etc.), confirmed internal network traffic, or historical incident records.
  - **850 Irrelevant Commodity Threats (85.0%):** External internet noise, untargeted botnets, third-party software exploits not present in our environment, and multi-tenant CDN infrastructure.
- **Network Telemetry Logs:** 1,851 observed connection events.
- **Historical Incidents:** 59 confirmed security incident records.
- **Software Inventory:** 10 core organizational assets with 8 CVE vulnerability assignments.

---

## 2. Benchmark Comparison: Baseline vs. ThreatLens

### Baseline Definition:
External threat-feed-only prioritization:
$$\text{Baseline Score} = \text{Feed Confidence} \times \text{Severity Weight} \times \text{Source Reliability}$$
An indicator is prioritized for SOC analyst triage if $\text{Baseline Score} \ge 60.0$.

### ThreatLens Definition:
Explainable local-relevance scorer integrating organizational exposure, network telemetry, CVE inventory, temporal recency, and noise suppression penalties. Prioritized if $\text{Local Score} \ge 60.0$.

---

## 3. Measured Experimental Results

| Metric | Predefined Target | Baseline (Feed Only) | ThreatLens (Local Relevance) | Experimental Status |
|:---|:---:|:---:|:---:|:---:|
| **Irrelevant Suppression Rate** | $\ge 60.0\%$ | 33.06% | **100.00%** | **PASS** |
| **Local Threat Recall** | $\ge 95.0\%$ | 100.00% | **96.67%** | **PASS** |
| **Precision** | Info / High | 20.86% | **100.00%** | **SUPERIOR** |
| **False Positive Rate (FPR)** | Info / Low | 66.94% | **0.00%** | **SUPERIOR** |
| **False Negative Rate (FNR)** | $\le 5.0\%$ | 0.00% | **3.33%** | **PASS** |
| **Analyst Workload Reduction** | $\ge 50.0\%$ | 0.00% | **79.83%** | **PASS** |
| **Prioritized Alert Volume** | Target: Low Fatigue | 719 alerts | **145 alerts** | **79.83% reduction in prioritised alert volume in the synthetic pilot benchmark.** |
| **Scoring Latency** | $< 5.0\text{ ms}$ | 0.041 ms | **0.041 ms** | **PASS** |

---

## 4. Confusion Matrix Analysis

```text
                     BASELINE MODEL                      THREATLENS LOCAL SCORER
               ┌────────────────────────┐              ┌────────────────────────┐
               │ Predicted  │ Predicted │              │ Predicted  │ Predicted │
               │ Prioritize │ Suppress  │              │ Prioritize │ Suppress  │
┌──────────────┼────────────┼───────────┤┌─────────────┼────────────┼───────────┤
│ Actual Local │  150 (TP)  │   0 (FN)  ││Actual Local │  145 (TP)  │   5 (FN)  │
├──────────────┼────────────┼───────────┤├─────────────┼────────────┼───────────┤
│ Actual Noise │  569 (FP)  │ 281 (TN)  ││Actual Noise │    0 (FP)  │ 850 (TN)  │
└──────────────┴────────────┴───────────┘└─────────────┴────────────┴───────────┘
```

### Key Statistical Takeaway:
- Under the **Baseline model**, SOC analysts must investigate **719 alerts**, of which **569 (79.1%) are completely irrelevant false alarms**, inducing massive alert fatigue.
- Under **ThreatLens**, alert volume drops to **145 prioritized alerts**, with **zero irrelevant false alarms** escaping into the high-priority queue, while capturing **96.67% of all real organizational threats**.
- **Net Workload Reduction: 79.83%.**

---

## 5. False Negative Deep Dive & Error Analysis

The 5 False Negatives in the experiment were extracted and analyzed in `results/error_analysis.csv`:

| Indicator | Ground Truth | ThreatLens Score | Classification | Root Cause Analysis | Remediation Recommendation |
|:---|:---:|:---:|:---:|:---|:---|
| `449937d78e2d25c953bbda26ef3337b590926777097e04992c90770701660baa` | local | 43.9 | MEDIUM | Targeted asset was internal-only with sparse telemetry and lower external feed confidence. | Lower threshold for critical internal crown-jewel assets even with single telemetry log. |
| `apt-telemetry-c2-044.synthetic-threat.org` | local | 42.8 | MEDIUM | Reconnaissance probe against internal endpoint; lower traffic frequency dampened score below 60. | Provide crown-jewel asset sensitivity multiplier. |
| `dc8d5ec863164d1980f0b2c6b8088d83e24cb3972ef57cec378e3fd91f3cf1e7` | local | 46.4 | MEDIUM | Targeted database host; zero outbound traffic prevented high-priority elevation. | Add policy rule boosting database tier assets into HIGH triage. |
| `198.51.100.71` | local | 57.5 | MEDIUM | Borderline score (57.5 vs 60.0 cutoff); untrusted community feed dampened source weight. | Provide analysts with an adjustable "Borderline Triage" view in Medium queue. |
| `198.51.100.92` | local | 43.6 | MEDIUM | Internal workstation asset; lower criticality tier prevented score from crossing 60. | Lower threshold for crown-jewel internal workstations. |

---

## 6. Edge Cases Tested & Verified

1. **Stale Threat Feeds:** Threat inactive for $>250$ days was automatically penalized by $-15$ points and suppressed.
2. **Shared Cloud / CDN Addresses:** Cloudflare and AWS CloudFront IPs received $-25$ dampening, preventing operational disruptions.
3. **Missing Software Asset Records:** Gracefully fell back to generic exposure weighting without unhandled exceptions.
4. **Conflicting Threat Feeds:** High-reputation intelligence was prioritized over low-reliability community scrapers.
5. **Duplicate Ingestion:** Deterministic deduplication preserved single authoritative records.
6. **Malformed Inputs:** Sanitized null values and malformed timestamps safely.
