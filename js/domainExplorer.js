// Domain explorer page.

import { on, emit } from './state.js';
import { escapeHtml } from './utils.js';
import { getPasswordsData, getCookiesData, getHistoryData, escapeCSV } from './dataPages.js';
import { extractDomain, extractBaseDomain, downloadBlob } from './shared.js';
import { FIELD_PATTERNS } from './definitions.js';

const PAGE_SIZE = 100;

let domainIndex = null;
let domainList = [];
let domainFiltered = [];
let domainShown = 0;
let expandedDomain = null;

function buildDomainIndex() {
  const index = new Map();

  function getEntry(baseDomain) {
    if (!index.has(baseDomain)) {
      index.set(baseDomain, { credentials: [], cookies: [], history: [], subdomains: new Set() });
    }
    return index.get(baseDomain);
  }

  const pw = getPasswordsData();
  if (pw && pw.rows.length > 0) {
    const urlIdx = pw.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
    const userIdx = pw.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
    const passIdx = pw.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

    for (const { row } of pw.rows) {
      const url = urlIdx >= 0 ? row[urlIdx] : '';
      if (!url) continue;
      const domain = extractDomain(url);
      if (!domain) continue;
      const base = extractBaseDomain(domain);
      const entry = getEntry(base);
      entry.credentials.push({
        url,
        username: userIdx >= 0 ? row[userIdx] : '',
        password: passIdx >= 0 ? row[passIdx] : '',
      });
      if (domain !== base) entry.subdomains.add(domain);
    }
  }

  const ck = getCookiesData();
  if (ck && ck.rows.length > 0) {
    const hostIdx = ck.headers.findIndex(h => /^(host|domain)/i.test(h));
    const nameIdx = ck.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));

    for (const { row, validity, sessionType } of ck.rows) {
      const host = hostIdx >= 0 ? row[hostIdx] : '';
      if (!host) continue;
      const cleanHost = host.replace(/^\./, '');
      const base = extractBaseDomain(cleanHost);
      const entry = getEntry(base);
      entry.cookies.push({
        host: cleanHost,
        name: nameIdx >= 0 ? row[nameIdx] : '',
        validity,
        sessionType,
      });
      if (cleanHost !== base) entry.subdomains.add(cleanHost);
    }
  }

  const hist = getHistoryData();
  if (hist && hist.entries.length > 0) {
    for (const { url, title, visitCount } of hist.entries) {
      const domain = extractDomain(url);
      if (!domain) continue;
      const base = extractBaseDomain(domain);
      const entry = getEntry(base);
      entry.history.push({ url, title, visitCount });
      if (domain !== base) entry.subdomains.add(domain);
    }
  }

  domainIndex = index;

  domainList = [];
  for (const [domain, data] of index) {
    const total = data.credentials.length + data.cookies.length + data.history.length;
    domainList.push({
      domain,
      credentials: data.credentials.length,
      cookies: data.cookies.length,
      history: data.history.length,
      subdomains: data.subdomains.size,
      total,
      _data: data,
    });
  }
  domainList.sort((a, b) => b.total - a.total);
}

function domainRowBuilder(item) {
  return `<tr class="domain-row" data-domain="${escapeHtml(item.domain)}">
    <td class="domain-name-cell"><span class="domain-expand-icon">&#9656;</span> ${escapeHtml(item.domain)}</td>
    <td>${item.credentials}</td>
    <td>${item.cookies}</td>
    <td>${item.history}</td>
    <td>${item.subdomains}</td>
  </tr>`;
}

function renderDomainDetail(data, baseDomain) {
  let html = '<div class="domain-detail">';

  if (data.subdomains.size > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Subdomains</div>';
    html += '<div class="domain-subdomain-list">';
    for (const sub of [...data.subdomains].sort()) {
      html += `<span class="domain-subdomain-tag">${escapeHtml(sub)}</span>`;
    }
    html += '</div></div>';
  }

  if (data.credentials.length > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Credentials (' + data.credentials.length + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>URL</th><th>Username</th><th>Password</th></tr></thead><tbody>';
    const showCreds = data.credentials.slice(0, 20);
    for (const c of showCreds) {
      const masked = c.password ? c.password[0] + '\u2022'.repeat(Math.min(c.password.length - 1, 6)) : '';
      html += `<tr><td title="${escapeHtml(c.url)}">${escapeHtml(c.url)}</td><td>${escapeHtml(c.username)}</td><td class="password-cell masked">${escapeHtml(masked)}</td></tr>`;
    }
    html += '</tbody></table>';
    if (data.credentials.length > 20) {
      html += `<div class="domain-detail-more">${data.credentials.length - 20} more credentials...</div>`;
    }
    html += '</div>';
  }

  if (data.cookies.length > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Cookies (' + data.cookies.length + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>Host</th><th>Name</th><th>Status</th><th>Type</th></tr></thead><tbody>';
    const showCookies = data.cookies.slice(0, 20);
    for (const c of showCookies) {
      const typeLabel = c.sessionType === 'auth' ? 'Auth' : c.sessionType === 'session' ? 'Session' : '';
      html += `<tr><td>${escapeHtml(c.host)}</td><td>${escapeHtml(c.name)}</td>`;
      html += `<td><span class="validity-badge validity-badge-${c.validity.status}">${escapeHtml(c.validity.label)}</span></td>`;
      html += `<td>${typeLabel ? `<span class="session-badge session-badge-${c.sessionType}">${typeLabel}</span>` : ''}</td></tr>`;
    }
    html += '</tbody></table>';
    if (data.cookies.length > 20) {
      html += `<div class="domain-detail-more">${data.cookies.length - 20} more cookies...</div>`;
    }
    html += '</div>';
  }

  if (data.history.length > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">History (' + data.history.length + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>URL</th><th>Title</th><th>Visits</th></tr></thead><tbody>';
    const showHistory = data.history.slice(0, 20);
    for (const h of showHistory) {
      html += `<tr><td title="${escapeHtml(h.url)}">${escapeHtml(h.url)}</td><td>${escapeHtml(h.title)}</td><td>${h.visitCount}</td></tr>`;
    }
    html += '</tbody></table>';
    if (data.history.length > 20) {
      html += `<div class="domain-detail-more">${data.history.length - 20} more entries...</div>`;
    }
    html += '</div>';
  }

  html += '</div>';
  return html;
}

function renderDomainsPage(searchQuery = '') {
  const summary = document.getElementById('domainsSummary');
  const stats = document.getElementById('domainsStats');
  const content = document.getElementById('domainsContent');

  if (!domainIndex || domainList.length === 0) {
    summary.textContent = 'No domain data found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No domain data available.</div>';
    return;
  }

  let filtered = domainList;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = domainList.filter(d => d.domain.toLowerCase().includes(q));
  }

  domainFiltered = filtered;
  domainShown = Math.min(PAGE_SIZE, filtered.length);

  summary.textContent = `${domainList.length.toLocaleString()} unique domains across credentials, cookies, and history`;

  const top10 = domainList.slice(0, 10);
  if (top10.length > 0) {
    const maxCount = top10[0].total;
    stats.innerHTML = top10.map(d => {
      const pct = Math.round((d.total / maxCount) * 100);
      return `<div class="domain-bar-row">
        <span class="domain-bar-label">${escapeHtml(d.domain)}</span>
        <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
        <span class="domain-bar-count">${d.total}</span>
      </div>`;
    }).join('');
  } else {
    stats.innerHTML = '';
  }

  let html = '<div class="data-table-container"><table class="data-table domain-table">';
  html += '<thead><tr><th>Domain</th><th>Credentials</th><th>Cookies</th><th>History</th><th>Subdomains</th></tr></thead><tbody>';
  for (let i = 0; i < domainShown; i++) {
    html += domainRowBuilder(domainFiltered[i]);
  }
  html += '</tbody></table></div>';

  const remaining = domainFiltered.length - domainShown;
  if (remaining > 0) {
    html += `<button class="data-show-more" data-page="domains">Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)</button>`;
  }

  content.innerHTML = html;
}

function handleDomainShowMore() {
  const content = document.getElementById('domainsContent');
  const nextEnd = Math.min(domainShown + PAGE_SIZE, domainFiltered.length);
  let newHtml = '';
  for (let i = domainShown; i < nextEnd; i++) {
    newHtml += domainRowBuilder(domainFiltered[i]);
  }

  const tbody = content.querySelector('tbody');
  if (tbody) tbody.insertAdjacentHTML('beforeend', newHtml);

  domainShown = nextEnd;

  const btn = content.querySelector('.data-show-more');
  const remaining = domainFiltered.length - domainShown;
  if (remaining > 0 && btn) {
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
  } else if (btn) {
    btn.remove();
  }
}

function exportDomainsCSV() {
  if (!domainList || domainList.length === 0) return;
  let csv = 'Domain,Credentials,Cookies,History,Subdomains\n';
  for (const d of domainList) {
    const subs = d._data.subdomains.size > 0 ? [...d._data.subdomains].join('; ') : '';
    csv += [d.domain, d.credentials, d.cookies, d.history, subs].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'domains.csv', 'text/csv');
}

function initDomainExplorer() {
  const searchInput = document.getElementById('domainsSearch');
  let debounce = null;
  searchInput?.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      renderDomainsPage(searchInput.value);
    }, 150);
  });

  document.getElementById('exportDomainsCsv')?.addEventListener('click', exportDomainsCSV);

  document.getElementById('domainsContent')?.addEventListener('click', (e) => {
    const showMoreBtn = e.target.closest('.data-show-more');
    if (showMoreBtn && showMoreBtn.dataset.page === 'domains') {
      handleDomainShowMore();
      return;
    }

    const row = e.target.closest('.domain-row');
    if (!row) return;
    const domain = row.dataset.domain;
    if (!domain) return;

    const wasExpanded = expandedDomain === domain;

    // Collapse previous
    if (expandedDomain) {
      const prevRow = document.querySelector(`.domain-row[data-domain="${CSS.escape(expandedDomain)}"]`);
      if (prevRow) {
        prevRow.classList.remove('domain-row-expanded');
        const icon = prevRow.querySelector('.domain-expand-icon');
        if (icon) icon.innerHTML = '&#9656;';
        const detailRow = prevRow.nextElementSibling;
        if (detailRow && detailRow.classList.contains('domain-detail-row')) {
          detailRow.remove();
        }
      }
      expandedDomain = null;
    }

    if (!wasExpanded) {
      expandedDomain = domain;
      row.classList.add('domain-row-expanded');
      const icon = row.querySelector('.domain-expand-icon');
      if (icon) icon.innerHTML = '&#9662;';

      const item = domainFiltered.find(d => d.domain === domain);
      if (item && item._data) {
        const detailTr = document.createElement('tr');
        detailTr.className = 'domain-detail-row';
        const td = document.createElement('td');
        td.setAttribute('colspan', '5');
        td.innerHTML = renderDomainDetail(item._data, domain);
        detailTr.appendChild(td);
        row.after(detailTr);
      }
    }
  });

  on('data:loaded', () => {
    buildDomainIndex();
    if (domainList.length > 0) {
      document.getElementById('navDomains').disabled = false;
    }
  });

  on('page:domains', () => {
    renderDomainsPage(searchInput?.value || '');
  });

  on('reset', () => {
    domainIndex = null;
    domainList = [];
    domainFiltered = [];
    domainShown = 0;
    expandedDomain = null;
    document.getElementById('navDomains').disabled = true;
    if (searchInput) searchInput.value = '';
  });
}

export { initDomainExplorer };
