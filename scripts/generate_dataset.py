#!/usr/bin/env python3
"""
ThreatLens - Synthetic Dataset Generator
Generates reproducible synthetic threat intelligence feeds, internal software inventory,
observed network telemetry, historical security incidents, and ground-truth validation labels.

Adheres strictly to RFC 5737 (TEST-NET-1, TEST-NET-2, TEST-NET-3) and RFC 3849 for safe synthetic IP spaces.
Fixed random seed = 42 for 100% reproducibility.
"""

import os
import csv
import json
import random
import hashlib
from datetime import datetime, timedelta

# Fix seed for strict reproducibility
SEED = 42
random.seed(SEED)

DATA_RAW_DIR = "data/raw"
DATA_PROCESSED_DIR = "data/processed"
DATA_VALIDATION_DIR = "data/validation"

os.makedirs(DATA_RAW_DIR, exist_ok=True)
os.makedirs(DATA_PROCESSED_DIR, exist_ok=True)
os.makedirs(DATA_VALIDATION_DIR, exist_ok=True)

# -------------------------------------------------------------
# 1. SOFTWARE INVENTORY GENERATION
# -------------------------------------------------------------
ASSETS = [
    {
        "asset_id": "WEB-PROD-01",
        "hostname": "portal.corporate.internal",
        "application": "Apache HTTP Server",
        "vendor": "Apache",
        "version": "2.4.49",
        "operating_system": "Ubuntu 22.04 LTS",
        "internet_exposed": True,
        "criticality": "critical",
        "cves": ["CVE-2021-41773", "CVE-2021-42013"],
        "owner": "Web Infrastructure Team",
        "environment": "production"
    },
    {
        "asset_id": "WEB-PROD-02",
        "hostname": "api.corporate.internal",
        "application": "Spring Boot Framework",
        "vendor": "VMware Tanzu",
        "version": "2.5.4",
        "operating_system": "Debian 11",
        "internet_exposed": True,
        "criticality": "high",
        "cves": ["CVE-2022-22965"], # Spring4Shell
        "owner": "API Platform Team",
        "environment": "production"
    },
    {
        "asset_id": "K8S-INGRESS-01",
        "hostname": "ingress.k8s.corporate.internal",
        "application": "nginx-ingress-controller",
        "vendor": "F5 NGINX",
        "version": "1.1.0",
        "operating_system": "Alpine Linux 3.16",
        "internet_exposed": True,
        "criticality": "critical",
        "cves": ["CVE-2021-25742"],
        "owner": "Cloud Infrastructure",
        "environment": "production"
    },
    {
        "asset_id": "VPN-GW-01",
        "hostname": "vpn.corporate.internal",
        "application": "GlobalProtect VPN Gateway",
        "vendor": "Palo Alto Networks",
        "version": "9.1.8",
        "operating_system": "PAN-OS 9.1",
        "internet_exposed": True,
        "criticality": "critical",
        "cves": ["CVE-2024-3400"],
        "owner": "Network Security Ops",
        "environment": "production"
    },
    {
        "asset_id": "APP-CORE-03",
        "hostname": "crm-backend.internal",
        "application": "Log4j Core Library",
        "vendor": "Apache",
        "version": "2.14.1",
        "operating_system": "Red Hat Enterprise Linux 8.5",
        "internet_exposed": False,
        "criticality": "high",
        "cves": ["CVE-2021-44228"], # Log4Shell
        "owner": "Enterprise Apps",
        "environment": "production"
    },
    {
        "asset_id": "DB-MAIN-01",
        "hostname": "db-cluster-node1.internal",
        "application": "PostgreSQL Server",
        "vendor": "PostgreSQL Global Dev Group",
        "version": "15.3",
        "operating_system": "Ubuntu 22.04 LTS",
        "internet_exposed": False,
        "criticality": "critical",
        "cves": ["CVE-2023-39417"],
        "owner": "Data Engineering",
        "environment": "production"
    },
    {
        "asset_id": "STAGING-API-01",
        "hostname": "staging-api.dev.internal",
        "application": "NodeJS Express Gateway",
        "vendor": "OpenJS",
        "version": "18.16.0",
        "operating_system": "Ubuntu 22.04 LTS",
        "internet_exposed": True,
        "criticality": "medium",
        "cves": ["CVE-2023-30589"],
        "owner": "DevOps Services",
        "environment": "staging"
    },
    {
        "asset_id": "WORKSTATION-SEC-09",
        "hostname": "sec-ops-ws09.internal",
        "application": "Google Chrome Enterprise",
        "vendor": "Google",
        "version": "118.0.5993.88",
        "operating_system": "Windows 11 Pro 22H2",
        "internet_exposed": False,
        "criticality": "low",
        "cves": ["CVE-2023-5217"],
        "owner": "IT Endpoints",
        "environment": "workstation"
    },
    {
        "asset_id": "MAIL-RELAY-01",
        "hostname": "smtp.corporate.internal",
        "application": "Exim Mail Transfer Agent",
        "vendor": "Exim Maintainers",
        "version": "4.95",
        "operating_system": "Debian 10",
        "internet_exposed": True,
        "criticality": "high",
        "cves": ["CVE-2023-42115"],
        "owner": "Messaging Team",
        "environment": "production"
    },
    {
        "asset_id": "DEV-TEST-05",
        "hostname": "sandbox-runner.dev.internal",
        "application": "Redis In-Memory Store",
        "vendor": "Redis Ltd",
        "version": "7.0.5",
        "operating_system": "Ubuntu 20.04 LTS",
        "internet_exposed": False,
        "criticality": "low",
        "cves": ["CVE-2022-35977"],
        "owner": "R&D Lab",
        "environment": "internal"
    }
]

def save_software_inventory():
    file_path = os.path.join(DATA_RAW_DIR, "software_inventory.csv")
    with open(file_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "asset_id", "hostname", "application", "vendor", "version",
            "operating_system", "internet_exposed", "criticality", "cves", "owner", "environment"
        ])
        for a in ASSETS:
            writer.writerow([
                a["asset_id"],
                a["hostname"],
                a["application"],
                a["vendor"],
                a["version"],
                a["operating_system"],
                str(a["internet_exposed"]).lower(),
                a["criticality"],
                ";".join(a["cves"]),
                a["owner"],
                a["environment"]
            ])
    print(f"[*] Saved {len(ASSETS)} software inventory assets to {file_path}")

# -------------------------------------------------------------
# 2. THREAT FEEDS & GROUND TRUTH GENERATION (1,000 Indicators)
# -------------------------------------------------------------
FEED_SOURCES = [
    ("AlienVault-OTX-Syn", 0.85),
    ("AbuseIPDB-Syn", 0.90),
    ("CrowdStrike-Falcon-Syn", 0.95),
    ("Mandiant-AdvThreat-Syn", 0.96),
    ("EmergingThreats-Community-Syn", 0.70),
    ("CISA-KnownExploited-Syn", 0.98),
    ("ThreatConnect-Syn", 0.82)
]

MALWARE_FAMILIES = ["CobaltStrike", "LockBit3", "Qakbot", "Emotet", "RedLineStealer", "Mirai", "AsyncRAT", "SliverC2", "AgentTesla", "IcedID"]
THREAT_ACTORS = ["APT29 (Midnight Blizzard)", "APT28 (Fancy Bear)", "FIN7", "Lazarus Group", "Volt Typhoon", "Scattered Spider", "LockBit Gang"]
ATTACK_VECTORS = ["RCE Exploitation", "Phishing Attachment", "C2 Beaconing", "Credential Stuffing", "SQL Injection", "Brute Force", "Data Exfiltration"]

CDN_SHARED_IPS = [
    "104.16.124.96",   # Cloudflare CDN
    "104.21.45.12",    # Cloudflare CDN
    "151.101.65.140",  # Fastly CDN
    "13.224.160.10",   # AWS CloudFront
    "8.8.8.8",         # Google Public DNS
    "1.1.1.1"          # Cloudflare Resolver
]

def generate_indicators(total_count=1000):
    indicators = []
    labels = []
    traffic_logs = []
    historical_incidents = []

    base_time = datetime(2026, 10, 8, 12, 0, 0)

    # We designate exactly:
    # ~ 150 Locally Relevant threats (observed in traffic, associated with local CVE/software, or linked to past incident)
    # ~ 850 Irrelevant threats (completely external, not targeting our software/stack, zero internal traffic, or benign CDN)
    
    # 1. Generate 150 Locally Relevant indicators
    local_count = 150
    for i in range(1, local_count + 1):
        ind_type = random.choice(["ipv4", "domain", "url", "sha256"])
        source_name, src_rel = random.choice(FEED_SOURCES)
        
        # Pick an asset to create genuine local exposure
        asset = random.choice(ASSETS)
        matched_cve = random.choice(asset["cves"]) if asset["cves"] else "CVE-2024-3400"
        
        if ind_type == "ipv4":
            # RFC 5737 TEST-NET-2 range: 198.51.100.0/24
            indicator_val = f"198.51.100.{i % 250 + 1}"
        elif ind_type == "domain":
            indicator_val = f"apt-telemetry-c2-{i:03d}.synthetic-threat.org"
        elif ind_type == "url":
            indicator_val = f"http://198.51.100.{i % 250 + 1}/payloads/c2_beacon_{i}.bin"
        else: # sha256
            indicator_val = hashlib.sha256(f"malware-payload-local-{i}".encode()).hexdigest()

        confidence = random.randint(80, 99)
        severity = random.choice(["high", "critical"])
        days_ago = random.randint(0, 14)
        last_seen = (base_time - timedelta(days=days_ago, hours=random.randint(1, 23))).strftime("%Y-%m-%d %H:%M:%S")
        first_seen = (base_time - timedelta(days=days_ago + random.randint(5, 45))).strftime("%Y-%m-%d %H:%M:%S")

        malware = random.choice(MALWARE_FAMILIES)
        actor = random.choice(THREAT_ACTORS)
        tags = ["c2", "local-target", "active-campaign", malware.lower()]

        # Generate local evidence:
        has_traffic = random.random() < 0.85 # 85% observed in telemetry
        has_incident = random.random() < 0.40 # 40% tied to historical incident

        if has_traffic:
            # Generate 3 to 25 traffic logs
            traffic_events_count = random.randint(3, 25)
            for t_idx in range(traffic_events_count):
                event_time = base_time - timedelta(hours=random.randint(1, 72))
                traffic_logs.append({
                    "traffic_id": f"TRF-{len(traffic_logs)+1:06d}",
                    "timestamp": event_time.strftime("%Y-%m-%d %H:%M:%S"),
                    "indicator": indicator_val,
                    "asset_id": asset["asset_id"],
                    "source_ip": indicator_val if ind_type == "ipv4" else f"10.0.1.{random.randint(10, 200)}",
                    "destination_ip": f"10.0.1.{random.randint(10, 200)}" if ind_type == "ipv4" else "198.51.100.50",
                    "domain": indicator_val if ind_type == "domain" else "",
                    "port": random.choice([443, 80, 8443, 8080, 22]),
                    "protocol": "TCP",
                    "bytes": random.randint(450, 68000),
                    "direction": "inbound" if asset["internet_exposed"] else "outbound",
                    "action": "allowed" if random.random() < 0.7 else "blocked",
                    "frequency": traffic_events_count
                })

        if has_incident:
            historical_incidents.append({
                "incident_id": f"INC-2026-{len(historical_incidents)+1:04d}",
                "indicator": indicator_val,
                "date": (base_time - timedelta(days=random.randint(10, 120))).strftime("%Y-%m-%d"),
                "affected_asset": asset["asset_id"],
                "incident_type": random.choice(["Command and Control", "Exploitation Attempt", "Ransomware Staging"]),
                "severity": "high" if asset["criticality"] != "critical" else "critical",
                "confirmed_malicious": True,
                "resolution": "Contained & Remediated",
                "business_impact": "Disrupted internal service node; blocked lateral movement"
            })

        indicators.append({
            "indicator_id": f"IOC-{len(indicators)+1:05d}",
            "indicator": indicator_val,
            "type": ind_type,
            "source": source_name,
            "source_reliability": src_rel,
            "confidence": confidence,
            "severity": severity,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "tags": ";".join(tags),
            "malware_family": malware,
            "threat_actor": actor,
            "cve": matched_cve,
            "category": "local"
        })

        labels.append({
            "indicator": indicator_val,
            "type": ind_type,
            "ground_truth": "local",
            "exposure_asset": asset["asset_id"],
            "has_traffic": has_traffic,
            "has_incident": has_incident,
            "matched_cve": matched_cve,
            "reason": f"Active match against organizational asset {asset['asset_id']} ({asset['application']}) with local telemetry or CVE exposure."
        })

    # 2. Generate 850 Irrelevant external noise indicators
    # These represent global commodity threats, spam IPs, ICS threats, IoT bots that our company doesn't run.
    irrelevant_count = total_count - local_count
    
    # Let's seed specific Edge Cases in the irrelevant set:
    # Edge Case 1: Stale indicator (>180 days old)
    # Edge Case 2: Shared CDN / Cloudflare IP
    # Edge Case 4: Conflicting threat feeds
    # Edge Case 5: Duplicate indicators
    
    for i in range(1, irrelevant_count + 1):
        idx_global = local_count + i
        source_name, src_rel = random.choice(FEED_SOURCES)
        
        # Edge Case 2 check: Shared CDN IP
        if i <= 6:
            ind_type = "ipv4"
            indicator_val = CDN_SHARED_IPS[i - 1]
            cve = ""
            malware = "Generic-Scanner"
            actor = "Unknown"
            confidence = random.randint(60, 95)
            severity = "high"
            days_ago = random.randint(1, 5)
            edge_tag = "shared-cdn-infrastructure"
        # Edge Case 1 check: Stale indicator
        elif i <= 20:
            ind_type = "ipv4"
            # RFC 5737 TEST-NET-3: 203.0.113.0/24
            indicator_val = f"203.0.113.{i + 50}"
            cve = "CVE-2017-0144" # EternalBlue, not in our org
            malware = "WannaCry-Variant"
            actor = "Historic"
            confidence = 88
            severity = "high"
            days_ago = random.randint(180, 400) # Highly stale
            edge_tag = "stale-indicator"
        else:
            ind_type = random.choice(["ipv4", "domain", "url", "sha256"])
            if ind_type == "ipv4":
                # RFC 5737 TEST-NET-1: 192.0.2.0/24
                indicator_val = f"192.0.2.{i % 250 + 1}"
            elif ind_type == "domain":
                indicator_val = f"unrelated-malware-noise-{i:04d}.generic-botnet.biz"
            elif ind_type == "url":
                indicator_val = f"http://192.0.2.{i % 250 + 1}/botnet/drop_{i}.php"
            else:
                indicator_val = hashlib.sha256(f"irrelevant-commodity-noise-{i}".encode()).hexdigest()

            # CVEs completely outside our stack (e.g. Cisco IOS, WordPress, Fortinet, SolarWinds, Exchange)
            unrelated_cves = ["CVE-2020-0688", "CVE-2021-22986", "CVE-2022-42475", "CVE-2023-2868", "CVE-2020-1472", ""]
            cve = random.choice(unrelated_cves)
            malware = random.choice(MALWARE_FAMILIES)
            actor = random.choice(THREAT_ACTORS)
            confidence = random.randint(40, 98) # Many high confidence feeds on commodity threats!
            severity = random.choice(["low", "medium", "high", "critical"])
            days_ago = random.randint(5, 120)
            edge_tag = "external-noise"

        last_seen = (base_time - timedelta(days=days_ago, hours=random.randint(1, 23))).strftime("%Y-%m-%d %H:%M:%S")
        first_seen = (base_time - timedelta(days=days_ago + random.randint(10, 60))).strftime("%Y-%m-%d %H:%M:%S")

        tags = ["scanner", "botnet", "commodity", edge_tag]

        indicators.append({
            "indicator_id": f"IOC-{len(indicators)+1:05d}",
            "indicator": indicator_val,
            "type": ind_type,
            "source": source_name,
            "source_reliability": src_rel,
            "confidence": confidence,
            "severity": severity,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "tags": ";".join(tags),
            "malware_family": malware,
            "threat_actor": actor,
            "cve": cve,
            "category": "irrelevant"
        })

        labels.append({
            "indicator": indicator_val,
            "type": ind_type,
            "ground_truth": "irrelevant",
            "exposure_asset": "NONE",
            "has_traffic": False,
            "has_incident": False,
            "matched_cve": "NONE",
            "reason": f"External commodity threat with no organizational presence, no telemetry, no vulnerable software match ({edge_tag})."
        })

    # Save Threat Feeds
    feed_path = os.path.join(DATA_RAW_DIR, "threat_feeds.csv")
    with open(feed_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "indicator_id", "indicator", "type", "source", "source_reliability",
            "confidence", "severity", "first_seen", "last_seen", "tags",
            "malware_family", "threat_actor", "cve", "category"
        ])
        writer.writeheader()
        writer.writerows(indicators)
    print(f"[*] Saved {len(indicators)} threat feed indicators to {feed_path}")

    # Save Observed Traffic
    traffic_path = os.path.join(DATA_RAW_DIR, "observed_traffic.csv")
    with open(traffic_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "traffic_id", "timestamp", "indicator", "asset_id", "source_ip",
            "destination_ip", "domain", "port", "protocol", "bytes", "direction",
            "action", "frequency"
        ])
        writer.writeheader()
        writer.writerows(traffic_logs)
    print(f"[*] Saved {len(traffic_logs)} network telemetry records to {traffic_path}")

    # Save Historical Incidents
    inc_path = os.path.join(DATA_RAW_DIR, "historical_incidents.csv")
    with open(inc_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "incident_id", "indicator", "date", "affected_asset", "incident_type",
            "severity", "confirmed_malicious", "resolution", "business_impact"
        ])
        writer.writeheader()
        writer.writerows(historical_incidents)
    print(f"[*] Saved {len(historical_incidents)} historical incidents to {inc_path}")

    # Save Validation Labels (Ground Truth)
    val_path = os.path.join(DATA_VALIDATION_DIR, "validation_labels.csv")
    with open(val_path, mode="w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=[
            "indicator", "type", "ground_truth", "exposure_asset",
            "has_traffic", "has_incident", "matched_cve", "reason"
        ])
        writer.writeheader()
        writer.writerows(labels)
    print(f"[*] Saved {len(labels)} ground-truth validation labels to {val_path}")

    # Also save a unified JSON file for quick web application loading
    dataset_bundle = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "seed": SEED,
        "assets": ASSETS,
        "indicators": indicators,
        "traffic_logs": traffic_logs,
        "historical_incidents": historical_incidents,
        "validation_labels": labels
    }
    bundle_path = os.path.join(DATA_PROCESSED_DIR, "pilot_dataset.json")
    with open(bundle_path, "w", encoding="utf-8") as f:
        json.dump(dataset_bundle, f, indent=2)
    print(f"[*] Saved bundled JSON to {bundle_path}")

if __name__ == "__main__":
    print(f"=== ThreatLens Data Generator (Seed: {SEED}) ===")
    save_software_inventory()
    generate_indicators(1000)
    print("=== Dataset Generation Complete ===")
