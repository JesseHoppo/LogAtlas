// Shared helpers used across modules.

const MAX_SEARCH_MATCHES_PER_FILE = 5;
const BAR_CHART_MAX_ITEMS = 10;
const SEARCH_BATCH_SIZE = 20;

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

// Cookie validity

function checkCookieValidity(expiresValue) {
  if (!expiresValue || expiresValue === '0' || String(expiresValue).toLowerCase() === 'session') {
    return { status: 'session', label: 'Session' };
  }

  let expiryDate;
  const strVal = String(expiresValue);

  if (strVal.includes('-') || strVal.includes('/') || strVal.includes('Z')) {
    const date = new Date(strVal.replace(' ', 'T'));
    if (!isNaN(date.getTime())) {
      expiryDate = date;
    } else {
      return { status: 'session', label: 'Session' };
    }
  } else {
    let timestamp = parseInt(strVal, 10);
    if (isNaN(timestamp) || timestamp <= 0) return { status: 'session', label: 'Session' };
    if (timestamp > 9999999999) timestamp = Math.floor(timestamp / 1000);
    expiryDate = new Date(timestamp * 1000);
    if (isNaN(expiryDate.getTime())) return { status: 'session', label: 'Session' };
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
  checkCookieValidity,
  formatRelativeTime,
  downloadBlob,
  topN,
  showNotification,
  copyToClipboard,
};
