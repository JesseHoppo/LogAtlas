// Pattern-driven IOC extraction from merged system-info entries + raw text.

import { normaliseTimeZone } from '../core/shared.js';
import { IOC_KEY_MAP, CONTENT_IOC_PATTERNS, STEALER_INFRA_PATTERNS, LIMITS } from '../core/definitions/patterns.js';

function isLoaderSampleValue(value) {
  const s = String(value || '').trim();
  if (!s) return false;
  if (s.length > 400) return false;
  if (s.includes(';')) return false;
  if (!/[\\/]/.test(s)) return false;
  if (/\.(?:exe|bat|ps1|dll|cmd|vbs|hta|scr|jar)$/i.test(s)) return true;
  if (/AppData[\\/]+(?:Local|Roaming)[\\/]+Temp[\\/]/i.test(s)) return true;
  return false;
}

function extractIOCs(sysinfoEntries, sysinfoText) {
  if (!sysinfoEntries) return null;
  const iocs = [];
  const seen = new Set();
  const claimedStrings = new Set();

  function pushIoc(ioc) {
    const k = `${ioc.label}:${ioc.value}`;
    if (seen.has(k)) return false;
    seen.add(k);
    iocs.push(ioc);
    return true;
  }

  for (const { label, kind, patterns } of IOC_KEY_MAP) {
    for (const [key, value] of Object.entries(sysinfoEntries)) {
      if (!patterns.some(rx => rx.test(key))) continue;
      let displayValue = value;
      let rawValue;
      if (label === 'Timezone') {
        const tz = normaliseTimeZone(value, sysinfoEntries.Country || sysinfoEntries.country);
        if (tz.offset != null || tz.source === 'unknown') {
          displayValue = tz.label;
          if (tz.label !== String(value).trim()) rawValue = String(value);
        }
      }
      if (label === 'Loader Sample' && !isLoaderSampleValue(displayValue)) continue;
      const ioc = { label, value: displayValue };
      if (kind) ioc.kind = kind;
      if (rawValue) ioc.rawValue = rawValue;
      if (pushIoc(ioc)) claimedStrings.add(String(displayValue));
      break;
    }
  }

  const infraCount = () => iocs.filter(i => i.kind === 'stealer-infra').length;

  function scanWith(patterns, text) {
    for (const { label, family, pattern } of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        if (infraCount() >= LIMITS.stealerInfraMaxItems) return;
        let value = match[0].replace(/^["']|["']$/g, '');
        if (family === 'Lumma') value = value.replace(/^@/, '');
        const ioc = { label, value, kind: 'stealer-infra' };
        if (family) ioc.family = family;
        if (pushIoc(ioc)) { claimedStrings.add(value); claimedStrings.add('@' + value); }
      }
    }
  }

  if (sysinfoText) scanWith(STEALER_INFRA_PATTERNS, sysinfoText);

  for (const value of Object.values(sysinfoEntries)) {
    if (infraCount() >= LIMITS.stealerInfraMaxItems) break;
    const s = String(value || '');
    if (!s || s.length > LIMITS.stealerInfraValueScanBytes) continue;
    scanWith(STEALER_INFRA_PATTERNS, s);
  }

  if (sysinfoText) {
    outer: for (const { label, kind, pattern } of CONTENT_IOC_PATTERNS) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(sysinfoText)) !== null) {
        const value = match[0];
        if (claimedStrings.has(value)) continue;
        if (label === 'C2/Panel URL') {
          let claimedAsInfra = false;
          for (const claimed of claimedStrings) {
            if (claimed.length > 8 && value.includes(claimed)) { claimedAsInfra = true; break; }
          }
          if (claimedAsInfra) continue;
        }
        if (label === 'Telegram Contact' || label === 'Telegram Channel') {
          const norm = value.replace(/^@/, '').toLowerCase();
          if ([...claimedStrings].some(c => c.replace(/^@/, '').toLowerCase().includes(norm))) continue;
        }
        const ioc = { label, value };
        if (kind) ioc.kind = kind;
        pushIoc(ioc);
        if (iocs.length >= LIMITS.iocMaxItems) break outer;
      }
    }
  }

  return iocs.length > 0 ? iocs : null;
}

export { extractIOCs };
