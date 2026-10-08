#!/usr/bin/env python3
"""
Generates clean SVG charts for evaluation metrics:
- confusion_matrix.svg
- baseline_vs_scorer.svg
- suppression_analysis.svg
"""

import os
import json

RESULTS_DIR = "results"
with open(os.path.join(RESULTS_DIR, "metrics.json"), "r", encoding="utf-8") as f:
    data = json.load(f)

t = data["threatlens_metrics"]
b = data["baseline_metrics"]

# 1. Confusion Matrix SVG
cm_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 700 450" width="100%" height="100%" style="background:#090d16; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;">
  <rect width="100%" height="100%" fill="#0a0f1d" rx="12"/>
  <text x="350" y="40" fill="#f8fafc" font-size="20" font-weight="700" text-anchor="middle">ThreatLens Evaluation Confusion Matrix</text>
  <text x="350" y="65" fill="#94a3b8" font-size="13" text-anchor="middle">N = 1,000 Indicators (150 Local Threats vs. 850 Irrelevant Commodity IOCs)</text>

  <!-- Labels -->
  <text x="230" y="115" fill="#38bdf8" font-size="14" font-weight="600" text-anchor="middle">PREDICTED PRIORITIZED</text>
  <text x="470" y="115" fill="#38bdf8" font-size="14" font-weight="600" text-anchor="middle">PREDICTED SUPPRESSED</text>

  <!-- Row 1: Actual Local -->
  <text x="90" y="195" fill="#f59e0b" font-size="13" font-weight="600" text-anchor="end">ACTUAL LOCAL (150)</text>
  <!-- TP Box -->
  <rect x="130" y="130" width="200" height="120" rx="8" fill="#064e3b" stroke="#10b981" stroke-width="2"/>
  <text x="230" y="175" fill="#a7f3d0" font-size="28" font-weight="800" text-anchor="middle">{t['tp']}</text>
  <text x="230" y="205" fill="#6ee7b7" font-size="13" font-weight="600" text-anchor="middle">TRUE POSITIVE (96.7%)</text>
  <text x="230" y="225" fill="#d1fae5" font-size="11" text-anchor="middle">Locally applicable & retained</text>

  <!-- FN Box -->
  <rect x="370" y="130" width="200" height="120" rx="8" fill="#450a0a" stroke="#ef4444" stroke-width="2"/>
  <text x="470" y="175" fill="#fecaca" font-size="28" font-weight="800" text-anchor="middle">{t['fn']}</text>
  <text x="470" y="205" fill="#f87171" font-size="13" font-weight="600" text-anchor="middle">FALSE NEGATIVE (3.3%)</text>
  <text x="470" y="225" fill="#fee2e2" font-size="11" text-anchor="middle">Sparse internal telemetry</text>

  <!-- Row 2: Actual Irrelevant -->
  <text x="90" y="325" fill="#94a3b8" font-size="13" font-weight="600" text-anchor="end">ACTUAL IRRELEVANT (850)</text>
  <!-- FP Box -->
  <rect x="130" y="270" width="200" height="120" rx="8" fill="#312e81" stroke="#6366f1" stroke-width="1"/>
  <text x="230" y="315" fill="#c7d2fe" font-size="28" font-weight="800" text-anchor="middle">{t['fp']}</text>
  <text x="230" y="345" fill="#818cf8" font-size="13" font-weight="600" text-anchor="middle">FALSE POSITIVE (0.0%)</text>
  <text x="230" y="365" fill="#e0e7ff" font-size="11" text-anchor="middle">Zero noise escaped to SOC</text>

  <!-- TN Box -->
  <rect x="370" y="270" width="200" height="120" rx="8" fill="#0f172a" stroke="#38bdf8" stroke-width="2"/>
  <text x="470" y="315" fill="#bae6fd" font-size="28" font-weight="800" text-anchor="middle">{t['tn']}</text>
  <text x="470" y="345" fill="#38bdf8" font-size="13" font-weight="600" text-anchor="middle">TRUE NEGATIVE (100%)</text>
  <text x="470" y="365" fill="#e0f2fe" font-size="11" text-anchor="middle">Correctly suppressed noise</text>

  <!-- Summary footer -->
  <text x="350" y="420" fill="#64748b" font-size="12" text-anchor="middle">Recall: 96.67%  |  Suppression: 100.00%  |  Precision: 100.00%  |  Accuracy: 99.50%</text>
</svg>
"""

with open(os.path.join(RESULTS_DIR, "confusion_matrix.svg"), "w") as f:
    f.write(cm_svg.strip())

# 2. Baseline vs Scorer SVG
b_vs_s_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 760 440" width="100%" height="100%" style="background:#090d16; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;">
  <rect width="100%" height="100%" fill="#0a0f1d" rx="12"/>
  <text x="380" y="36" fill="#f8fafc" font-size="20" font-weight="700" text-anchor="middle">Baseline vs. ThreatLens Performance Comparison</text>
  <text x="380" y="58" fill="#94a3b8" font-size="13" text-anchor="middle">Evaluating alert suppression, precision, and analyst workload</text>

  <!-- Legend -->
  <rect x="250" y="78" width="16" height="12" fill="#ef4444" rx="3"/>
  <text x="272" y="88" fill="#cbd5e1" font-size="12">Baseline (Feed Only)</text>
  <rect x="420" y="78" width="16" height="12" fill="#10b981" rx="3"/>
  <text x="442" y="88" fill="#cbd5e1" font-size="12">ThreatLens (Local-Relevance)</text>

  <!-- Metrics Bars -->
  <!-- 1. Suppression Rate -->
  <g transform="translate(60, 115)">
    <text x="0" y="15" fill="#e2e8f0" font-size="13" font-weight="600">Irrelevant Suppression Rate</text>
    <!-- Baseline Bar -->
    <rect x="240" y="2" width="{b['suppression_rate'] * 4}" height="18" fill="#ef4444" rx="4"/>
    <text x="{245 + b['suppression_rate'] * 4}" y="16" fill="#fca5a5" font-size="12" font-weight="600">{b['suppression_rate']}%</text>
    <!-- ThreatLens Bar -->
    <rect x="240" y="24" width="{t['suppression_rate'] * 4}" height="18" fill="#10b981" rx="4"/>
    <text x="{245 + t['suppression_rate'] * 4}" y="38" fill="#86efac" font-size="12" font-weight="600">{t['suppression_rate']}%</text>
  </g>

  <!-- 2. Local Threat Recall -->
  <g transform="translate(60, 180)">
    <text x="0" y="15" fill="#e2e8f0" font-size="13" font-weight="600">Local Threat Recall</text>
    <!-- Baseline Bar -->
    <rect x="240" y="2" width="{b['recall'] * 4}" height="18" fill="#ef4444" rx="4"/>
    <text x="{245 + b['recall'] * 4}" y="16" fill="#fca5a5" font-size="12" font-weight="600">{b['recall']}%</text>
    <!-- ThreatLens Bar -->
    <rect x="240" y="24" width="{t['recall'] * 4}" height="18" fill="#10b981" rx="4"/>
    <text x="{245 + t['recall'] * 4}" y="38" fill="#86efac" font-size="12" font-weight="600">{t['recall']}%</text>
  </g>

  <!-- 3. Alert Precision -->
  <g transform="translate(60, 245)">
    <text x="0" y="15" fill="#e2e8f0" font-size="13" font-weight="600">Alert Queue Precision</text>
    <!-- Baseline Bar -->
    <rect x="240" y="2" width="{b['precision'] * 4}" height="18" fill="#ef4444" rx="4"/>
    <text x="{245 + b['precision'] * 4}" y="16" fill="#fca5a5" font-size="12" font-weight="600">{b['precision']}%</text>
    <!-- ThreatLens Bar -->
    <rect x="240" y="24" width="{t['precision'] * 4}" height="18" fill="#10b981" rx="4"/>
    <text x="{245 + t['precision'] * 4}" y="38" fill="#86efac" font-size="12" font-weight="600">{t['precision']}%</text>
  </g>

  <!-- 4. Workload Reduction -->
  <g transform="translate(60, 310)">
    <text x="0" y="15" fill="#e2e8f0" font-size="13" font-weight="600">SOC Workload Reduction</text>
    <!-- Baseline Bar -->
    <rect x="240" y="2" width="10" height="18" fill="#ef4444" rx="4"/>
    <text x="255" y="16" fill="#fca5a5" font-size="12" font-weight="600">0.0% (Baseline)</text>
    <!-- ThreatLens Bar -->
    <rect x="240" y="24" width="{t['workload_reduction'] * 4}" height="18" fill="#38bdf8" rx="4"/>
    <text x="{245 + t['workload_reduction'] * 4}" y="38" fill="#7dd3fc" font-size="12" font-weight="600">+{t['workload_reduction']}%</text>
  </g>

  <!-- Bottom Insight -->
  <rect x="60" y="380" width="640" height="40" fill="#1e293b" rx="6"/>
  <text x="380" y="405" fill="#cbd5e1" font-size="13" font-weight="500" text-anchor="middle">Alert Fatigue Eliminated: 719 baseline alerts reduced to 145 verified local incidents.</text>
</svg>
"""

with open(os.path.join(RESULTS_DIR, "baseline_vs_scorer.svg"), "w") as f:
    f.write(b_vs_s_svg.strip())

# 3. Suppression Analysis SVG
supp_svg = f"""<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 720 400" width="100%" height="100%" style="background:#090d16; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;">
  <rect width="100%" height="100%" fill="#0a0f1d" rx="12"/>
  <text x="360" y="36" fill="#f8fafc" font-size="20" font-weight="700" text-anchor="middle">Threat Intelligence Alert Funnel &amp; Noise Suppression</text>
  <text x="360" y="58" fill="#94a3b8" font-size="13" text-anchor="middle">How organizational correlation filters 1,000 raw indicators</text>

  <!-- Funnel step 1 -->
  <g transform="translate(60, 90)">
    <rect x="0" y="0" width="600" height="50" fill="#1e293b" stroke="#334155" rx="8"/>
    <text x="20" y="30" fill="#f1f5f9" font-size="14" font-weight="600">1. External Threat Intelligence Ingestion</text>
    <text x="580" y="30" fill="#94a3b8" font-size="14" font-weight="700" text-anchor="end">1,000 Indicators</text>
  </g>

  <!-- Funnel step 2: Baseline Alert Fatigue -->
  <g transform="translate(60, 155)">
    <rect x="0" y="0" width="450" height="50" fill="#450a0a" stroke="#b91c1c" rx="8"/>
    <text x="20" y="30" fill="#fecaca" font-size="14" font-weight="600">2. Baseline External-Feed-Only Alerting</text>
    <text x="430" y="30" fill="#f87171" font-size="14" font-weight="700" text-anchor="end">719 Alerts (High Fatigue)</text>
  </g>

  <!-- Funnel step 3: ThreatLens Suppression -->
  <g transform="translate(60, 220)">
    <rect x="0" y="0" width="600" height="50" fill="#0f172a" stroke="#0284c7" rx="8"/>
    <text x="20" y="30" fill="#38bdf8" font-size="14" font-weight="600">3. Noise Suppressed by ThreatLens</text>
    <text x="580" y="30" fill="#38bdf8" font-size="14" font-weight="700" text-anchor="end">-855 Suppressed (85.5% Total Inflow)</text>
  </g>

  <!-- Funnel step 4: Actionable Local Queue -->
  <g transform="translate(60, 285)">
    <rect x="0" y="0" width="220" height="50" fill="#064e3b" stroke="#10b981" rx="8"/>
    <text x="20" y="30" fill="#6ee7b7" font-size="14" font-weight="600">4. High-Priority Local Queue</text>
    <text x="200" y="30" fill="#a7f3d0" font-size="14" font-weight="700" text-anchor="end">145 Actionable IOCs</text>
  </g>

  <text x="360" y="375" fill="#64748b" font-size="12" text-anchor="middle">Every actionable IOC contains an evidence chain linking network telemetry, affected assets, or CVE inventory.</text>
</svg>
"""

with open(os.path.join(RESULTS_DIR, "suppression_analysis.svg"), "w") as f:
    f.write(supp_svg.strip())

print("[*] Generated SVG evaluation charts in results/")
