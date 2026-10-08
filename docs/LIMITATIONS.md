# ThreatLens: System Limitations & Honest Engineering Evaluation

In accordance with transparent engineering principles, this document outlines the boundary conditions, constraints, and limitations of the current ThreatLens prototype.

---

## 1. Synthetic Data Realism vs. Enterprise Telemetry
- **Limitation:** The experimental evaluation was conducted on a reproducible synthetic dataset of 1,000 indicators, 1,851 traffic logs, and 10 representative enterprise assets generated with fixed seed `42`.
- **Impact:** While RFC 5737 compliant and architected to mirror real-world threat actors and CVEs, synthetic telemetry lacks the unpredictable anomalies, packet fragmentation, duplicate NAT mappings, and encrypted SNI complications encountered in high-volume enterprise production.
- **Production Path:** Integrate real Zeek, Suricata, or VPC Flow Log ingestion pipelines with streaming window deduplication.

---

## 2. Incomplete Telemetry Coverage & Blindspots
- **Limitation:** If internal network telemetry has blindspots (e.g., unmonitored air-gapped subnets, shadow IT infrastructure, or uninstrumented SaaS applications), ThreatLens will penalize indicators targeting those segments under the "Weak Local Evidence" rule.
- **Impact:** Attackers executing silent lateral movement across unmonitored systems may receive a lower score than warranted.
- **Production Path:** Introduce an explicit `UNCERTAINTY_FLAG` when assets reside in low-visibility network segments rather than applying full weak-evidence penalties.

---

## 3. Ephemeral Cloud & Multi-Tenant Infrastructure
- **Limitation:** Cloud-hosted attack infrastructure frequently rotates IP addresses in minutes (Fast Flux, ephemeral AWS EC2, or Azure containers).
- **Impact:** An indicator reported in external threat feeds may point to an IP address that hosted malicious C2 yesterday, but now serves benign legitimate traffic for an enterprise customer.
- **Production Path:** Dynamic DNS resolution tracking and passive DNS (pDNS) historical mapping to measure temporal validity windows.

---

## 4. Concept Drift & Fixed Weighting Limitations
- **Limitation:** The current scoring formula utilizes transparent, deterministic linear factor weights. While completely explainable, static weights do not automatically adapt to changing threat landscapes (e.g. an organization undergoing rapid cloud migration where perimeter IP exposure matters less than identity tokens).
- **Impact:** Periodic manual governance reviews are necessary to adjust weights.
- **Production Path:** Provide simulated weight sensitivity backtesting so analysts can model the impact of weight changes on historical queues before deploying new versions.

---

## 5. False Negatives on Low-and-Slow Zero-Day Reconnaissance
- **Limitation:** In the benchmark evaluation, 5 true local threats were scored as MEDIUM ($48.8 - 58.1$) instead of HIGH ($\ge 60$). These were threats exhibiting minimal telemetry (e.g., 1 blocked connection attempt or unexploited zero-day reconnaissance).
- **Impact:** If analysts only review HIGH and CRITICAL queues, low-and-slow probes may take longer to surface.
- **Production Path:** Implement secondary threshold triage allowing SOC analysts to filter for "Emerging High-Velocity Probes" in the MEDIUM queue.

---

## 6. Lack of Multi-Month SOC Field Trials
- **Limitation:** ThreatLens was evaluated in a 30-hour benchmark cycle rather than a longitudinal multi-month human study with live SOC shift rotations.
- **Impact:** Stakeholder feedback is simulated rather than based on long-term SOC fatigue telemetry.
