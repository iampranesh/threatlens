# ThreatLens: Threat Model & Security Assurance

## 1. System Assets Under Protection

1. **Scoring Engine Integrity:** Algorithmic calculation of threat scores must remain tamper-proof.
2. **Scoring Configuration:** Weights, thresholds, and penalty values that determine alert prioritization.
3. **Internal Organizational Context:** Software inventory, network telemetry, and historical incidents (must not leak to external parties).
4. **Audit Trail:** Immutable record of security actions, reviews, approvals, and configuration changes.
5. **Containment Controls:** Firewall blocking and endpoint isolation APIs.

---

## 2. Threat Actors & Adversary Profiles

| Threat Actor | Motivation | Capabilities | Attack Vector |
|:---|:---|:---|:---|
| **Malicious External Threat Actor** | Evade detection; cause denial-of-service via false blocking | Injects fake/poisoned threat feed indicators; spoofs benign infrastructure | Public threat feed poisoning; CDN IP spoofing |
| **Compromised Analyst Account** | Cover tracks or suppress alerts for ongoing breach | Valid analyst login credentials; read/triage permissions | Attempted score tampering; unauthorized configuration edit |
| **Malicious Insider / Rogue Operator** | Sabotage production systems | Standard corporate network access; knowledge of internal asset IDs | Proposing abusive blocking rules; attempting privilege escalation |
| **Unauthorized API Client** | Data scraping or system manipulation | Unauthenticated or low-privilege network client | Forged HTTP requests; parameter tampering |

---

## 3. Threat Analysis (STRIDE) & Implemented Mitigations

### 1. Spoofing (Identity & Origin)
- **Threat:** Client spoofs authenticated user context or impersonates an administrator.
- **Implemented Mitigation:** Server-enforced role verification on every privileged endpoint. Session tokens with explicit role claims checked on backend.

### 2. Tampering (Data & Calculation Integrity)
- **Threat 1: Client-Side Score Manipulation.** An adversary submits a request containing `{"indicator": "192.0.2.1", "score": 100, "label": "CRITICAL"}` to trigger erroneous alert fatigue or evasion.
  - **Mitigation:** The server completely ignores client-supplied scores. Scores are computed exclusively by the backend scoring engine using authoritative server-side evidence contexts. Verified in test `SEC-01`.
- **Threat 2: Threat Feed Poisoning.** An external adversary feeds an indicator with `confidence: 999999` and XSS payloads in metadata.
  - **Mitigation:** Strict schema sanitation, bounds clipping to $[0, 100]$, and reliability weight dampeners. Verified in test `SEC-04`.
- **Threat 3: Unauthorized Scoring Weight Tampering.** An analyst lowers traffic weight to hide malicious activity.
  - **Mitigation:** Strict RBAC. Analysts are blocked with HTTP 403; only ADMIN can author configuration updates. Verified in test `SEC-02`.

### 4. Repudiation (Audit Integrity)
- **Threat:** An operator executes an unauthorized containment action or alters configuration and denies having performed it.
- **Implemented Mitigation:** Every state change, approval, rejection, and login event is written to an append-only audit trail with `timestamp`, `user`, `role`, `action`, `resource`, `result`, and unique `request_id`. Sensitive credentials are mathematically excluded. Verified in test `SEC-05`.

### 5. Information Disclosure (Privacy & Reconnaissance)
- **Threat:** External feeds or unauthorized users discover internal network topology or unpatched software versions.
- **Implemented Mitigation:** Synthetic RFC 5737 and RFC 3849 address spaces; RBAC restrictions on raw asset inventory endpoints.

### 6. Denial of Service (Containment Weaponization)
- **Threat:** Adversary flags major public CDNs or DNS providers (Cloudflare, Fastly, 8.8.8.8) in an external threat feed to trick the SOC into severing company internet access.
- **Implemented Mitigation:**
  1. Automated blocking is architecturally forbidden. High-impact containment requires human-in-the-loop approval.
  2. Built-in CDN & Shared Infrastructure Dampener penalizes known multi-tenant IPs by 25 points, preventing automated priority elevation. Verified in tests `SEC-03` and `SEC-04`.

### 7. Elevation of Privilege
- **Threat:** Analyst attempts to promote themselves or execute administrative rollback.
- **Implemented Mitigation:** Server-side role checks at the controller boundary. Privilege boundaries cannot be bypassed via UI manipulation. Verified in test `SEC-02`.
