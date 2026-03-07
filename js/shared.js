// Shared helpers used across modules.

const MAX_SEARCH_MATCHES_PER_FILE = 5;
const BAR_CHART_MAX_ITEMS = 10;
const SEARCH_BATCH_SIZE = 20;
const CHROME_EPOCH_OFFSET = 11644473600000000n;

// Tree walking

function collectHintedNodes(node, hint, path, results) {
  if (!node) return;
  if (node[hint]) results.push({ node, path });
  if (node.children) {
    for (const child of Object.values(node.children)) {
      collectHintedNodes(child, hint, path + '/' + child.name, results);
    }
  }
}

function collectFileNodes(node, path, results) {
  if (!node) return;
  if (node.type === 'file') results.push({ node, path });
  if (node.children) {
    for (const child of Object.values(node.children)) {
      collectFileNodes(child, path + '/' + child.name, results);
    }
  }
}

// Domain extraction

function extractDomain(url) {
  if (!url) return null;
  try {
    let u = url.trim();
    if (!/^https?:\/\//i.test(u)) u = 'https://' + u;
    const hostname = new URL(u).hostname;
    if (!hostname || hostname === 'localhost') return null;
    return hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    const match = url.match(/(?:https?:\/\/)?(?:www\.)?([^\/\s:]+)/i);
    return match ? match[1] : null;
  }
}

function extractBaseDomain(domain) {
  if (!domain) return domain;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return domain;
  const parts = domain.split('.');
  if (parts.length <= 2) return domain;
  const commonSLDs = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && commonSLDs.includes(parts[parts.length - 2])) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

// Timestamp parsing

function parseTimestampValue(value) {
  if (value instanceof Date) {
    return !isNaN(value.getTime()) ? value : null;
  }
  if (value == null) return null;

  const str = String(value).trim();
  if (!str || str === '0' || /^(?:session|null|undefined|nan)$/i.test(str)) return null;

  if (/^\d+$/.test(str)) {
    try {
      const num = BigInt(str);
      let ms;
      if (num > 13000000000000000n) {
        // Chrome/WebKit epoch microseconds since 1601-01-01.
        ms = Number((num - CHROME_EPOCH_OFFSET) / 1000n);
      } else if (num > 1000000000000n) {
        ms = Number(num); // already ms
      } else {
        ms = Number(num * 1000n); // seconds
      }
      const date = new Date(ms);
      if (!isNaN(date.getTime()) && date.getFullYear() > 1970 && date.getFullYear() < 3000) {
        return date;
      }
    } catch {
      // fall through to string parsing
    }
  }

  const normalized = str.includes('T') ? str : str.replace(' ', 'T');
  const native = new Date(normalized);
  if (!isNaN(native.getTime()) && native.getFullYear() > 1970 && native.getFullYear() < 3000) {
    return native;
  }

  const dmyTime = str.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dmyTime) {
    let year = Number(dmyTime[3]);
    if (year < 100) year += 2000;
    const date = new Date(year, Number(dmyTime[2]) - 1, Number(dmyTime[1]), Number(dmyTime[4]), Number(dmyTime[5]), Number(dmyTime[6] || 0));
    if (!isNaN(date.getTime())) return date;
  }

  const dmy = str.match(/^(\d{1,2})[\/\-.](\d{1,2})[\/\-.](\d{2,4})$/);
  if (dmy) {
    let year = Number(dmy[3]);
    if (year < 100) year += 2000;
    const date = new Date(year, Number(dmy[2]) - 1, Number(dmy[1]));
    if (!isNaN(date.getTime())) return date;
  }

  const ymd = str.match(/^(\d{4})[\/\-.](\d{1,2})[\/\-.](\d{1,2})(?:\s+(\d{1,2}):(\d{2})(?::(\d{2}))?)?/);
  if (ymd) {
    const date = new Date(Number(ymd[1]), Number(ymd[2]) - 1, Number(ymd[3]), Number(ymd[4] || 0), Number(ymd[5] || 0), Number(ymd[6] || 0));
    if (!isNaN(date.getTime())) return date;
  }

  const dMonY = str.match(/^(\d{1,2})\s+(\w{3})\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?/);
  if (dMonY) {
    let year = dMonY[3];
    if (year.length === 2) year = '20' + year;
    const date = new Date(`${dMonY[2]} ${dMonY[1]} ${year} ${dMonY[4]}:${dMonY[5]}:${dMonY[6] || '00'}`);
    if (!isNaN(date.getTime())) return date;
  }

  return null;
}

// Cookie validity

function checkCookieValidity(expiresValue) {
  if (!expiresValue || expiresValue === '0' || String(expiresValue).toLowerCase() === 'session') {
    return { status: 'session', label: 'Session' };
  }

  const expiryDate = parseTimestampValue(expiresValue);
  if (!expiryDate) {
    return { status: 'unknown', label: 'Unknown expiry' };
  }

  const now = new Date();
  if (expiryDate < now) {
    return { status: 'expired', label: `Expired ${formatRelativeTime(expiryDate)}` };
  }
  return { status: 'valid', label: `Valid until ${formatRelativeTime(expiryDate)}` };
}

function formatRelativeTime(date) {
  const now = new Date();
  const diff = date - now;
  const absDiff = Math.abs(diff);

  if (absDiff < 60000) return 'just now';
  if (absDiff < 3600000) return `${Math.round(absDiff / 60000)}m ${diff > 0 ? 'from now' : 'ago'}`;
  if (absDiff < 86400000) return `${Math.round(absDiff / 3600000)}h ${diff > 0 ? 'from now' : 'ago'}`;
  if (absDiff < 2592000000) return `${Math.round(absDiff / 86400000)}d ${diff > 0 ? 'from now' : 'ago'}`;

  return date.toLocaleDateString();
}

// Download helper

function downloadBlob(content, filename, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

// Count items and return sorted top-N list

function topN(arr, n) {
  const counts = {};
  for (const item of arr) {
    if (!item) continue;
    counts[item] = (counts[item] || 0) + 1;
  }
  return Object.entries(counts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([value, count]) => ({ value, count }));
}

// Toast notification

function showNotification(message, type = 'info') {
  const existing = document.getElementById('notification');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.id = 'notification';
  el.className = `notification notification-${type}`;
  el.textContent = message;
  document.body.appendChild(el);

  setTimeout(() => {
    el.classList.add('fade-out');
    el.addEventListener('transitionend', () => el.remove());
  }, 4000);
}

// Clipboard

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = text;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    try {
      document.execCommand('copy');
      return true;
    } catch {
      return false;
    } finally {
      textarea.remove();
    }
  }
}

export {
  MAX_SEARCH_MATCHES_PER_FILE,
  BAR_CHART_MAX_ITEMS,
  SEARCH_BATCH_SIZE,
  collectHintedNodes,
  collectFileNodes,
  extractDomain,
  extractBaseDomain,
  parseTimestampValue,
  checkCookieValidity,
  formatRelativeTime,
  downloadBlob,
  topN,
  showNotification,
  copyToClipboard,
};
