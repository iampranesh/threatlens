import { Role, User } from './types.ts';
import { dataStore } from './dataStore.ts';

export const USERS: Record<string, User> = {
  analyst: {
    id: 'USR-ANALYST-01',
    name: 'Sarah Chen',
    email: 'sarah.chen@threatlens.corp',
    role: 'ANALYST',
    avatar: 'SC'
  },
  reviewer: {
    id: 'USR-REVIEWER-02',
    name: 'Marcus Vance',
    email: 'marcus.vance@threatlens.corp',
    role: 'REVIEWER',
    avatar: 'MV'
  },
  admin: {
    id: 'USR-ADMIN-03',
    name: 'Elena Rostova',
    email: 'elena.rostova@threatlens.corp',
    role: 'ADMIN',
    avatar: 'ER'
  }
};

export function requireRole(userRole: Role, allowedRoles: Role[], actionName: string): boolean {
  if (!allowedRoles.includes(userRole)) {
    dataStore.logAudit({
      user: dataStore.currentUser.name,
      role: userRole,
      action: actionName,
      resource: 'RBAC_SECURITY_BOUNDARY',
      result: 'DENIED',
      reason: `Role '${userRole}' is not permitted to perform '${actionName}'. Required: ${allowedRoles.join(' or ')}.`
    });
    return false;
  }
  return true;
}

export function sanitizeIndicator(indicator: string): string {
  if (!indicator || typeof indicator !== 'string') return '';
  return indicator.trim().replace(/[<>'"`;]/g, '');
}

export function validateIndicatorSyntax(indicator: string, type: string): { valid: boolean; reason?: string } {
  const clean = sanitizeIndicator(indicator);
  if (!clean) return { valid: false, reason: 'Empty indicator string' };

  if (type === 'ipv4') {
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Regex.test(clean)) return { valid: false, reason: 'Invalid IPv4 address format' };
  } else if (type === 'sha256') {
    const sha256Regex = /^[a-fA-F0-9]{64}$/;
    if (!sha256Regex.test(clean)) return { valid: false, reason: 'Invalid SHA256 hex string (must be 64 characters)' };
  } else if (type === 'domain') {
    const domainRegex = /^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$/;
    if (!domainRegex.test(clean)) return { valid: false, reason: 'Invalid domain syntax' };
  }

  return { valid: true };
}

export function sanitizeFeedInput(raw: any): {
  sanitized: any;
  warnings: string[];
} {
  const warnings: string[] = [];

  // Check confidence bounds
  let confidence = Number(raw.confidence ?? 50);
  if (isNaN(confidence)) {
    confidence = 50;
    warnings.push('Invalid numeric confidence; defaulted to 50');
  } else if (confidence > 100 || confidence < 0) {
    warnings.push(`Confidence ${confidence} out of range [0, 100]; clamped`);
    confidence = Math.min(100, Math.max(0, confidence));
  }

  // Check source reliability
  let reliability = Number(raw.source_reliability ?? 0.8);
  if (isNaN(reliability) || reliability > 1.0 || reliability < 0.0) {
    reliability = Math.min(1.0, Math.max(0.0, reliability || 0.8));
    warnings.push('Source reliability normalized to [0.0, 1.0]');
  }

  // Sanitize CVE
  const cve = raw.cve ? String(raw.cve).replace(/[^a-zA-Z0-9-_]/g, '').trim() : '';

  return {
    sanitized: {
      ...raw,
      indicator: sanitizeIndicator(raw.indicator),
      confidence,
      source_reliability: reliability,
      cve
    },
    warnings
  };
}
