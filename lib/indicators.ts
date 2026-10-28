import type { IndicatorType } from './types';

export const indicatorTypes: { value: IndicatorType; label: string }[] = [
  { value: 'ip', label: 'IP address' },
  { value: 'domain', label: 'Domain' },
  { value: 'url', label: 'URL' },
  { value: 'hash', label: 'File hash' },
  { value: 'email', label: 'Email address' },
  { value: 'username', label: 'Username / Handle' },
];

export const indicatorPlaceholders: Record<IndicatorType, string> = {
  ip: 'e.g. 198.51.100.23 or 2001:db8::1',
  domain: 'e.g. suspicious-c2.net or dark-rat.org',
  url: 'e.g. https://phishing-portal.live/login',
  hash: 'MD5, SHA-1, SHA-256, or SHA-512',
  email: 'e.g. campaign-operator@covert-spear.org',
  username: 'e.g. apt_shadow_operator',
};

export const sampleDemonstrationIndicators: { type: IndicatorType; value: string; label: string }[] = [
  { type: 'ip', value: '198.51.100.23', label: 'C2 Gateway IP' },
  { type: 'domain', value: 'dark-stealer-c2.net', label: 'Phishing Domain' },
  { type: 'url', value: 'https://login-verify-account.test/session', label: 'Credential Harvest URL' },
  { type: 'hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', label: 'Dropper SHA-256' },
  { type: 'email', value: 'phisher@covert-campaign.test', label: 'Spear-Phishing Sender' },
  { type: 'username', value: 'apt_ghost_operator', label: 'Forum Alias / Handle' },
];

export function isIndicatorType(value: string): value is IndicatorType {
  return indicatorTypes.some((item) => item.value === value);
}

export function indicatorTypeLabel(type: IndicatorType): string {
  return indicatorTypes.find((item) => item.value === type)?.label ?? type;
}

export function isValidIndicator(value: string, type: IndicatorType): boolean {
  if (type === 'ip') {
    const ipv4Parts = value.split('.');
    const isIpv4 =
      ipv4Parts.length === 4 &&
      ipv4Parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
    if (isIpv4) return true;

    try {
      return new URL(`http://[${value}]/`).hostname.length > 0;
    } catch {
      return false;
    }
  }

  if (type === 'domain') {
    const domain = value.endsWith('.') ? value.slice(0, -1) : value;
    const labels = domain.split('.');
    return (
      labels.length >= 2 &&
      labels.every(
        (label) =>
          label.length <= 63 &&
          /^[a-z\d](?:[a-z\d-]*[a-z\d])?$/i.test(label),
      )
    );
  }

  if (type === 'url') {
    try {
      const parsed = new URL(value);
      return parsed.protocol === 'http:' || parsed.protocol === 'https:';
    } catch {
      return false;
    }
  }

  if (type === 'email') {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
  }

  if (type === 'username') {
    return /^[a-zA-Z0-9_\-\.]{3,32}$/.test(value);
  }

  return /^(?:[a-f\d]{32}|[a-f\d]{40}|[a-f\d]{64}|[a-f\d]{128})$/i.test(value);
}

export function detectIndicatorType(value: string): IndicatorType | null {
  const trimmed = value.trim();
  if (!trimmed) return null;

  // 1. URL
  if (/^https?:\/\//i.test(trimmed)) {
    if (isValidIndicator(trimmed, 'url')) return 'url';
  }

  // 2. Email
  if (trimmed.includes('@')) {
    if (isValidIndicator(trimmed, 'email')) return 'email';
  }

  // 3. IPv4
  const parts = trimmed.split('.');
  if (
    parts.length === 4 &&
    parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) <= 255)
  ) {
    return 'ip';
  }

  // 4. File Hash
  if (
    /^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(
      trimmed,
    )
  ) {
    return 'hash';
  }

  // 5. Domain
  if (trimmed.includes('.') && !trimmed.includes('/') && isValidIndicator(trimmed, 'domain')) {
    return 'domain';
  }

  // 6. Username / Handle
  if (
    !trimmed.includes('.') &&
    !trimmed.includes('/') &&
    !trimmed.includes('@') &&
    isValidIndicator(trimmed, 'username')
  ) {
    return 'username';
  }

  // Fallback checks against any remaining valid type
  for (const t of ['ip', 'domain', 'url', 'email', 'hash', 'username'] as IndicatorType[]) {
    if (isValidIndicator(trimmed, t)) return t;
  }

  return null;
}

