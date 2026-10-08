# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |

## Reporting a Vulnerability

The ThreatLens team takes the security of our threat prioritization platform seriously.

If you believe you have found a security vulnerability in ThreatLens, please **do not open a public issue**. Instead, report it responsibly:

1. Email your findings to: `security-advisory@threatlens.internal`
2. Include:
   - Type of vulnerability (e.g. score manipulation, authentication bypass, injection)
   - Step-by-step reproduction instructions or proof-of-concept
   - Impact assessment
3. You will receive an acknowledgment within 24 hours.

## Security Controls Implemented

- Strict Role-Based Access Control (RBAC: ANALYST, REVIEWER, ADMIN)
- Independent server-side scoring computation (defense against client score tampering)
- Threat feed poisoning safeguards (bounds checking, source trust weighting)
- Human-in-the-loop gating on high-impact containment actions
- Non-repudiable audit logging without credential leakage
