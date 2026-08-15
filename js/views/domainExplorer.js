import { on } from '../core/state.js';
import { escapeHtml } from '../core/utils.js';
import { bindDebouncedInput, downloadCsvRows } from '../pages/shared.js';
import { getPasswordsData, getCookiesData, getNotesData } from '../pages/credentials.js';
import { getHistoryData, getBookmarksData } from '../pages/browser.js';
import { getDownloadsData, getDomainDetectionsData } from '../pages/activity.js';
import { extractDomain, extractBaseDomain } from '../core/shared.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';

const PAGE_SIZE = 100;
const SAMPLE = 25;
const SUSPICIOUS_MIN_VALID = 10;

let domainList = [];
let domainFiltered = [];
let domainShown = 0;
let expandedDomain = null;
let domainIndexBuilt = false;
const DOMAIN_PAGE_INPUTS = {
  passwords: 'passwordsSearch',
  cookies: 'cookiesSearch',
  history: 'historySearch',
  bookmarks: 'bookmarksSearch',
  downloads: 'downloadsSearch',
  detections: 'detectionsSearch',
  notes: 'notesSearch',
};

// `android://…@com.app.name/` and `file:///…` rows resolve to a domain that
// appears nowhere in the row text, so the handoff to a data page has to carry a
// literal that page's search can actually hit.
function rawSearchToken(lowerUrl) {
  const android = lowerUrl.match(/^android:\/\/(?:[^@/]*@)?([^/\s?#]+)/);
  if (android) return android[1];
  if (lowerUrl.startsWith('file:')) return 'file://';
  return '';
}

function recordQuery(entry, key, base, url) {
  if (entry.queries[key] === base) return;
  const raw = String(url).toLowerCase();
  if (raw.includes(base)) entry.queries[key] = base;
  else if (!entry.queries[key]) entry.queries[key] = rawSearchToken(raw) || base;
}

function buildDomainIndex() {
  const index = new Map();

  function getEntry(baseDomain) {
    if (!index.has(baseDomain)) {
      index.set(baseDomain, {
        credentials: [],
        cookies: [],
        history: [],
        bookmarks: [],
        downloads: [],
        detections: [],
        notes: [],
        subdomains: new Set(),
        queries: {},
        credentialsCount: 0,
        cookiesCount: 0,
        cookiesValidCount: 0,
        historyCount: 0,
        bookmarksCount: 0,
        downloadsCount: 0,
        detectionsCount: 0,
        notesCount: 0,
      });
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
      recordQuery(entry, 'passwords', base, url);
      entry.credentialsCount++;
      if (entry.credentials.length < SAMPLE) entry.credentials.push({
        url,
        username: userIdx >= 0 ? row[userIdx] : '',
        password: passIdx >= 0 ? row[passIdx] : '',
      });
      if (domain !== base) entry.subdomains.add(domain);
    }
  }

  const ck = getCookiesData();
  if (ck && ck.rows.length > 0) {
    const hostIdx = ck.headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
    const nameIdx = ck.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));
    for (const rowData of ck.rows) {
      const { row, validity, sessionType } = rowData;
      const host = hostIdx >= 0 ? (row[hostIdx] || '') : '';
      if (!host) continue;
      const cleanHost = host.replace(/^\./, '').toLowerCase();
      const base = extractBaseDomain(cleanHost) || cleanHost;
      const entry = getEntry(base);
      entry.cookiesCount++;
      if (validity.status === 'valid') entry.cookiesValidCount++;
      if (entry.cookies.length < SAMPLE) entry.cookies.push({
        host: cleanHost,
        name: nameIdx >= 0 ? (row[nameIdx] || '') : '',
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
      recordQuery(entry, 'history', base, url);
      entry.historyCount++;
      if (entry.history.length < SAMPLE) entry.history.push({ url, title, visitCount });
      if (domain !== base) entry.subdomains.add(domain);
    }
  }

  const bookmarks = getBookmarksData();
  if (bookmarks && bookmarks.entries.length > 0) {
    for (const { url, title, folder } of bookmarks.entries) {
      const domain = extractDomain(url);
      if (!domain) continue;
      const base = extractBaseDomain(domain);
      const entry = getEntry(base);
      entry.bookmarksCount++;
      if (entry.bookmarks.length < SAMPLE) entry.bookmarks.push({ url, title, folder });
      if (domain !== base) entry.subdomains.add(domain);
    }
  }

  const downloads = getDownloadsData();
  if (downloads && downloads.entries.length > 0) {
    for (const { filePath, sourceUrl, domain } of downloads.entries) {
      const resolved = domain || extractDomain(sourceUrl);
      if (!resolved) continue;
      const base = extractBaseDomain(resolved);
      const entry = getEntry(base);
      entry.downloadsCount++;
      if (entry.downloads.length < SAMPLE) entry.downloads.push({ filePath, sourceUrl });
      if (resolved !== base) entry.subdomains.add(resolved);
    }
  }

  const detections = getDomainDetectionsData();
  if (detections && detections.entries.length > 0) {
    for (const { section, label, target, count } of detections.entries) {
      // Detect files also list paths and keywords ("/wp-login", ":2083",
      // "ProtonMail"); only real hosts belong in a domain index.
      const resolved = extractDomain(target);
      if (!resolved) continue;
      const base = extractBaseDomain(resolved);
      const entry = getEntry(base);
      entry.detectionsCount++;
      if (entry.detections.length < SAMPLE) entry.detections.push({ section, label, target, count });
      if (resolved !== base) entry.subdomains.add(resolved);
    }
  }

  const notes = getNotesData();
  if (notes && notes.entries.length > 0) {
    for (const note of notes.entries) {
      const countedBases = new Set();
      for (const domain of note.domains || []) {
        const base = extractBaseDomain(domain);
        const entry = getEntry(base);
        // a note listing several subdomains of one base counts once for that base
        if (!countedBases.has(base)) {
          countedBases.add(base);
          entry.notesCount++;
          if (entry.notes.length < SAMPLE) entry.notes.push({ title: note.title, indicators: note.indicators });
        }
        if (domain !== base) entry.subdomains.add(domain);
      }
    }
  }

  domainList = [];
  for (const [domain, data] of index) {
    const total = data.credentialsCount + data.cookiesCount + data.historyCount +
      data.bookmarksCount + data.downloadsCount + data.detectionsCount + data.notesCount;
    domainList.push({
      domain,
      credentials: data.credentialsCount,
      cookies: data.cookiesCount,
      history: data.historyCount,
      bookmarks: data.bookmarksCount,
      downloads: data.downloadsCount,
      detections: data.detectionsCount,
      notes: data.notesCount,
      subdomains: data.subdomains.size,
      total,
      suspicious: data.cookiesCount >= SUSPICIOUS_MIN_VALID && data.cookiesValidCount === data.cookiesCount,
      _data: data,
    });
  }
  domainList.sort((a, b) => b.total - a.total);
}

function ensureDomainIndex() {
  if (domainIndexBuilt) return;
  buildDomainIndex();
  domainIndexBuilt = true;
}

function hasDomainSourceData() {
  return getPasswordsData().rows.length > 0
    || getCookiesData().rows.length > 0
    || getHistoryData().entries.length > 0
    || getBookmarksData().entries.length > 0
    || getDownloadsData().entries.length > 0
    || getDomainDetectionsData().entries.length > 0
    || getNotesData().entries.length > 0;
}

function domainRowBuilder(item) {
  const suspiciousBadge = item.suspicious
    ? ` <span class="domain-suspicious-badge" title="All ${item.cookies} cookies valid — possible attacker/test host" style="font-family:var(--font-mono);font-size:0.55rem;font-weight:600;text-transform:uppercase;padding:0.05rem 0.3rem;border-radius:3px;background:rgba(220,38,38,0.1);color:var(--error)">suspicious</span>`
    : '';
  return `<tr class="domain-row${item.suspicious ? ' domain-row-suspicious' : ''}" data-domain="${escapeHtml(item.domain)}">
    <td class="domain-name-cell"><span class="domain-expand-icon">&#9656;</span> ${escapeHtml(item.domain)}${suspiciousBadge}</td>
    <td>${item.credentials}</td>
    <td>${item.cookies}</td>
    <td>${item.history}</td>
    <td>${item.bookmarks}</td>
    <td>${item.downloads}</td>
    <td>${item.detections + item.notes}</td>
    <td>${item.subdomains}</td>
  </tr>`;
}

function buildDomainSectionFooter(pageName, searchQuery, totalCount, visibleCount, label) {
  const remaining = Math.max(totalCount - visibleCount, 0);
  const moreText = remaining > 0
    ? `<div class="domain-detail-more">Showing ${visibleCount.toLocaleString()} of ${totalCount.toLocaleString()} ${escapeHtml(label)}.</div>`
    : '';
  return `<div class="domain-detail-footer">
    ${moreText}
    <button class="table-action-btn domain-detail-open-btn" data-domain-open-page="${escapeHtml(pageName)}" data-domain-open-query="${escapeHtml(searchQuery)}">Open full ${escapeHtml(label)} page</button>
  </div>`;
}

function renderDomainDetail(data, baseDomain) {
  const query = (pageName) => data.queries[pageName] || baseDomain;
  let html = '<div class="domain-detail">';

  if (data.subdomains.size > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Subdomains</div>';
    html += '<div class="domain-subdomain-list">';
    for (const sub of [...data.subdomains].sort()) {
      html += `<span class="domain-subdomain-tag">${escapeHtml(sub)}</span>`;
    }
    html += '</div></div>';
  }

  if (data.credentialsCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Credentials (' + data.credentialsCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>URL</th><th>Username</th><th>Password</th></tr></thead><tbody>';
    const showCreds = data.credentials.slice(0, 20);
    for (const c of showCreds) {
      const masked = c.password ? c.password[0] + '\u2022'.repeat(Math.min(c.password.length - 1, 6)) : '';
      html += `<tr><td title="${escapeHtml(c.url)}">${escapeHtml(c.url)}</td><td>${escapeHtml(c.username)}</td><td class="password-cell masked">${escapeHtml(masked)}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('passwords', query('passwords'), data.credentialsCount, showCreds.length, 'credentials');
    html += '</div>';
  }

  if (data.cookiesCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Cookies (' + data.cookiesCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>Host</th><th>Name</th><th>Status</th><th>Type</th></tr></thead><tbody>';
    const showCookies = data.cookies.slice(0, 20);
    for (const c of showCookies) {
      const typeLabel = c.sessionType === 'auth' ? 'Auth'
        : c.sessionType === 'session' ? 'Session'
        : c.sessionType === 'tracking' ? 'Tracking'
        : '';
      html += `<tr><td>${escapeHtml(c.host)}</td><td>${escapeHtml(c.name)}</td>`;
      html += `<td><span class="validity-badge validity-badge-${c.validity.status}">${escapeHtml(c.validity.label)}</span></td>`;
      html += `<td>${typeLabel ? `<span class="session-badge session-badge-${c.sessionType}">${typeLabel}</span>` : ''}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('cookies', query('cookies'), data.cookiesCount, showCookies.length, 'cookies');
    html += '</div>';
  }

  if (data.historyCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">History (' + data.historyCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>URL</th><th>Title</th><th>Visits</th></tr></thead><tbody>';
    const showHistory = data.history.slice(0, 20);
    for (const h of showHistory) {
      html += `<tr><td title="${escapeHtml(h.url)}">${escapeHtml(h.url)}</td><td>${escapeHtml(h.title)}</td><td>${h.visitCount}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('history', query('history'), data.historyCount, showHistory.length, 'history');
    html += '</div>';
  }

  if (data.bookmarksCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Bookmarks (' + data.bookmarksCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>URL</th><th>Title</th><th>Folder</th></tr></thead><tbody>';
    const showBookmarks = data.bookmarks.slice(0, 20);
    for (const bookmark of showBookmarks) {
      html += `<tr><td title="${escapeHtml(bookmark.url)}">${escapeHtml(bookmark.url)}</td><td>${escapeHtml(bookmark.title)}</td><td>${escapeHtml(bookmark.folder)}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('bookmarks', query('bookmarks'), data.bookmarksCount, showBookmarks.length, 'bookmarks');
    html += '</div>';
  }

  if (data.downloadsCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Downloads (' + data.downloadsCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>File Path</th><th>Source URL</th></tr></thead><tbody>';
    const showDownloads = data.downloads.slice(0, 20);
    for (const download of showDownloads) {
      html += `<tr><td title="${escapeHtml(download.filePath)}">${escapeHtml(download.filePath)}</td><td title="${escapeHtml(download.sourceUrl)}">${escapeHtml(download.sourceUrl)}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('downloads', query('downloads'), data.downloadsCount, showDownloads.length, 'downloads');
    html += '</div>';
  }

  if (data.detectionsCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Detections (' + data.detectionsCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>Section</th><th>Label</th><th>Count</th></tr></thead><tbody>';
    const showDetections = data.detections.slice(0, 20);
    for (const detection of showDetections) {
      html += `<tr><td>${escapeHtml(detection.section)}</td><td>${escapeHtml(detection.label || detection.target)}</td><td>${detection.count}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('detections', query('detections'), data.detectionsCount, showDetections.length, 'detections');
    html += '</div>';
  }

  if (data.notesCount > 0) {
    html += '<div class="domain-detail-section"><div class="domain-detail-title">Notes (' + data.notesCount + ')</div>';
    html += '<table class="domain-detail-table"><thead><tr><th>Title</th><th>Indicators</th></tr></thead><tbody>';
    const showNotes = data.notes.slice(0, 20);
    for (const note of showNotes) {
      html += `<tr><td>${escapeHtml(note.title)}</td><td>${escapeHtml(note.indicators)}</td></tr>`;
    }
    html += '</tbody></table>';
    html += buildDomainSectionFooter('notes', query('notes'), data.notesCount, showNotes.length, 'notes');
    html += '</div>';
  }

  html += '</div>';
  return html;
}

function renderDomainsPage(searchQuery = '') {
  const summary = document.getElementById('domainsSummary');
  const stats = document.getElementById('domainsStats');
  const content = document.getElementById('domainsContent');

  if (domainList.length === 0) {
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
  expandedDomain = null;

  let summaryText = filtered.length !== domainList.length
    ? `Showing ${filtered.length.toLocaleString()} of ${domainList.length.toLocaleString()} unique domains across credentials, cookies, history, bookmarks, downloads, detections, and notes`
    : `${domainList.length.toLocaleString()} unique domains across credentials, cookies, history, bookmarks, downloads, detections, and notes`;
  const suspiciousCount = domainList.filter(d => d.suspicious).length;
  if (suspiciousCount > 0) {
    summaryText += ` — ${suspiciousCount} host${suspiciousCount !== 1 ? 's' : ''} with all-valid cookie sets (possible attacker/test infrastructure)`;
  }
  summary.textContent = summaryText;

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
  html += '<thead><tr><th>Domain</th><th>Credentials</th><th>Cookies</th><th>History</th><th>Bookmarks</th><th>Downloads</th><th>Other</th><th>Subdomains</th></tr></thead><tbody>';
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

function openDomainArtifactPage(pageName, searchQuery) {
  const inputId = DOMAIN_PAGE_INPUTS[pageName];
  const searchInput = inputId ? document.getElementById(inputId) : null;
  if (searchInput) {
    searchInput.value = searchQuery;
  }

  if (pageName === 'cookies') {
    const validOnly = document.getElementById('cookiesValidOnly');
    const sessionOnly = document.getElementById('cookiesSessionOnly');
    if (validOnly) validOnly.checked = false;
    if (sessionOnly) sessionOnly.checked = false;
  }

  const navButton = document.querySelector(`.sidebar-nav-item[data-page="${pageName}"]`);
  if (navButton && !navButton.disabled) {
    navButton.click();
  }
}

function exportDomainsCSV() {
  ensureDomainIndex();
  if (!domainList || domainList.length === 0) return;
  downloadCsvRows('domains.csv', ['Domain', 'Credentials', 'Cookies', 'History', 'Bookmarks', 'Downloads', 'Detections', 'Notes', 'Subdomains'], domainList.map((entry) => [
    entry.domain,
    entry.credentials,
    entry.cookies,
    entry.history,
    entry.bookmarks,
    entry.downloads,
    entry.detections,
    entry.notes,
    entry._data.subdomains.size > 0 ? [...entry._data.subdomains].join('; ') : '',
  ]));
}

function initDomainExplorer() {
  const searchInput = document.getElementById('domainsSearch');
  bindDebouncedInput(searchInput, (value) => renderDomainsPage(value));

  document.getElementById('exportDomainsCsv')?.addEventListener('click', exportDomainsCSV);

  document.getElementById('domainsContent')?.addEventListener('click', (e) => {
    const openBtn = e.target.closest('[data-domain-open-page]');
    if (openBtn) {
      e.stopPropagation();
      openDomainArtifactPage(openBtn.dataset.domainOpenPage, openBtn.dataset.domainOpenQuery || '');
      return;
    }

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
        td.setAttribute('colspan', '8');
        td.innerHTML = renderDomainDetail(item._data, domain);
        detailTr.appendChild(td);
        row.after(detailTr);
      }
    }
  });

  on('data:loaded', () => {
    domainIndexBuilt = false;
    document.getElementById('navDomains').disabled = !hasDomainSourceData();
  });

  on('page:domains', () => {
    ensureDomainIndex();
    renderDomainsPage(searchInput?.value || '');
  });

  on('reset', () => {
    domainList = [];
    domainFiltered = [];
    domainShown = 0;
    expandedDomain = null;
    domainIndexBuilt = false;
    document.getElementById('navDomains').disabled = true;
    if (searchInput) searchInput.value = '';
  });
}

export { initDomainExplorer };
