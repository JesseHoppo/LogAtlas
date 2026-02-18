// Data pages, Passwords, Cookies, Autofills, History.

import { state, on, emit } from './state.js';
import { loadFileContent } from './extractor.js';
import { escapeHtml } from './utils.js';
import { parsePasswordFile, parseCookieFile } from './transforms.js';
import { collectHintedNodes, checkCookieValidity, extractDomain, extractBaseDomain, formatRelativeTime, downloadBlob } from './shared.js';
import { classifyCookie } from './sessionCookies.js';
import { FIELD_PATTERNS } from './definitions.js';
import { openColumnMapper } from './columnMapper.js';

// Per-type data stores

let passwordsData = { rows: [], headers: [], fileCount: 0 };
let cookiesData = { rows: [], headers: [], fileCount: 0 };
let autofillsData = { entries: [], fileCount: 0 };
let historyData = { entries: [], fileCount: 0 };

let historySortOrder = 'none';

const PAGE_SIZE = 200;

// Per-page filtered data + visible row count
let passwordsFiltered = [];
let passwordsShown = 0;

let cookiesFiltered = [];
let cookiesShown = 0;

let autofillsFiltered = [];
let autofillsShown = 0;

let historyFiltered = [];
let historyShown = 0;

// Progressive loading helpers

function buildShowMoreButton(remaining, pageId) {
  return `<button class="data-show-more" data-page="${pageId}">Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)</button>`;
}

function buildRowsHtml(rowBuilder, items, start, end) {
  let html = '';
  const limit = Math.min(end, items.length);
  for (let i = start; i < limit; i++) {
    html += rowBuilder(items[i]);
  }
  return html;
}

// Data loading

async function loadPasswordsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_passwordFileHint', rootName, nodes);

  if (nodes.length === 0) {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  const allRows = [];
  let headers = ['URL', 'Username', 'Password'];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        if (parsed.headers.length > headers.length) {
          headers = parsed.headers;
        }
        for (const row of parsed.rows) {
          allRows.push({ row, source: path });
        }
      }
    } catch {
      // skip
    }
  }

  passwordsData = { rows: allRows, headers, fileCount };
}

async function loadCookiesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_cookieFileHint', rootName, nodes);

  if (nodes.length === 0) {
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  const allRows = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseCookieFile(text);
      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const expiresIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
        const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));
        for (const row of parsed.rows) {
          const expiresVal = expiresIdx >= 0 ? row[expiresIdx] : null;
          const validity = checkCookieValidity(expiresVal);
          const cookieName = nameIdx >= 0 ? row[nameIdx] : '';
          const sessionType = classifyCookie(cookieName);
          allRows.push({ row, source: path, validity, sessionType, headers: parsed.headers });
        }
      }
    } catch {
      // skip
    }
  }

  const headers = allRows.length > 0 ? allRows[0].headers : ['Host', 'Name', 'Value', 'Expires'];
  cookiesData = { rows: allRows, headers, fileCount };
}

async function loadAutofillsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_autofillHint', rootName, nodes);

  if (nodes.length === 0) {
    autofillsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      let parsedSome = false;

      const parsed = parsePasswordFile(text);
      if (parsed && parsed.rows.length > 0) {
        const nameIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formField.test(h));
        const valIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.formValue.test(h));

        if (nameIdx >= 0 && valIdx >= 0) {
          for (const row of parsed.rows) {
            const name = (row[nameIdx] || '').trim();
            const value = (row[valIdx] || '').trim();
            if (name && value) {
              entries.push({ name, value, source: path });
              parsedSome = true;
            }
          }
        }
      }

      // Fallback: simple "field value" format
      if (!parsedSome) {
        const lines = text.split('\n').map(l => l.trim()).filter(l => l);
        for (const line of lines) {
          const match = line.match(/^([a-zA-Z_][a-zA-Z0-9_]*)\s+(.+)$/);
          if (match) {
            const name = match[1].trim();
            const value = match[2].trim();
            if (name && value) {
              entries.push({ name, value, source: path });
              parsedSome = true;
            }
          }
        }
      }

      if (parsedSome) fileCount++;
    } catch {
      // skip
    }
  }

  autofillsData = { entries, fileCount };
}

async function loadHistoryData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_historyHint', rootName, nodes);

  if (nodes.length === 0) {
    historyData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const lines = text.split('\n').filter(l => l.trim());
      let parsedSome = false;

      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed) continue;

        // TSV format
        if (trimmed.includes('\t')) {
          const parts = trimmed.split('\t');
          if (parts.length >= 1 && parts[0].match(/^https?:\/\//i)) {
            entries.push({
              url: parts[0], title: parts[1] || '',
              visitCount: parseInt(parts[2], 10) || 1,
              lastVisit: parts[3] || '', source: path
            });
            parsedSome = true;
            continue;
          }
        }

        // Pipe-separated
        if (trimmed.includes('|')) {
          const parts = trimmed.split('|').map(p => p.trim());
          if (parts.length >= 1 && parts[0].match(/^https?:\/\//i)) {
            entries.push({
              url: parts[0], title: parts[1] || '',
              visitCount: parseInt(parts[2], 10) || 1,
              lastVisit: parts[3] || '', source: path
            });
            parsedSome = true;
            continue;
          }
        }

        // Plain URL
        if (trimmed.match(/^https?:\/\//i)) {
          entries.push({
            url: trimmed, title: '', visitCount: 1,
            lastVisit: '', source: path
          });
          parsedSome = true;
        }
      }

      if (parsedSome) fileCount++;
    } catch {
      // skip
    }
  }

  historyData = { entries, fileCount };
}

// Password visibility

let hidePasswords = true;
let passwordColumnIdx = -1;

function maskValue(val) {
  if (!val || val.length === 0) return '';
  if (val.length <= 2) return '\u2022\u2022\u2022\u2022';
  return val[0] + '\u2022'.repeat(Math.min(val.length - 2, 8)) + val[val.length - 1];
}

// Rendering

function passwordRowBuilder({ row }) {
  let html = '<tr>';
  for (let i = 0; i < row.length; i++) {
    const cell = row[i];
    if (hidePasswords && i === passwordColumnIdx) {
      html += `<td class="password-cell masked" title="Click to reveal">${escapeHtml(maskValue(cell))}</td>`;
    } else {
      html += `<td title="${escapeHtml(cell)}">${escapeHtml(cell)}</td>`;
    }
  }
  html += '</tr>';
  return html;
}

async function openMapperForCredentials() {
  const nodes = [];
  collectHintedNodes(state.fileTree, '_passwordFileHint', state.rootZipName, nodes);
  if (nodes.length === 0) return;

  const firstNode = nodes[0].node;
  const content = await loadFileContent(firstNode);
  if (!content) return;
  const text = new TextDecoder('utf-8').decode(content);
  const fileName = nodes[0].path || firstNode.name || 'Unknown file';

  const config = await openColumnMapper(text, fileName);
  if (!config) return;

  // Apply config to all password file nodes
  for (const { node } of nodes) {
    node._parseConfig = config;
  }

  emit('reanalyze');
}

function renderPasswordsPage(searchQuery = '') {
  const summary = document.getElementById('passwordsSummary');
  const content = document.getElementById('passwordsContent');

  if (passwordsData.rows.length === 0) {
    summary.textContent = 'No passwords found';
    content.innerHTML = '<div class="no-data">No password data available.</div>';
    return;
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    passwordsFiltered = passwordsData.rows.filter(({ row }) =>
      row.some(cell => cell.toLowerCase().includes(q))
    );
  } else {
    passwordsFiltered = passwordsData.rows;
  }

  passwordsShown = Math.min(PAGE_SIZE, passwordsFiltered.length);

  const total = passwordsData.rows.length;
  const showing = passwordsFiltered.length;
  summary.textContent = showing !== total
    ? `Showing ${showing.toLocaleString()} of ${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`
    : `${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`;

  // Add "Adjust columns" button in the actions area (only once)
  const actionsArea = summary.parentNode.querySelector('.data-page-actions');
  if (actionsArea && !actionsArea.querySelector('.mapper-adjust-btn')) {
    const adjustBtn = document.createElement('button');
    adjustBtn.className = 'mapper-adjust-btn';
    adjustBtn.textContent = 'Adjust columns\u2026';
    adjustBtn.addEventListener('click', openMapperForCredentials);
    actionsArea.insertBefore(adjustBtn, actionsArea.firstChild);
  }

  // Detect password column index for masking
  passwordColumnIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr>';
  for (const h of passwordsData.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '</tr></thead><tbody>';
  html += buildRowsHtml(passwordRowBuilder, passwordsFiltered, 0, passwordsShown);
  html += '</tbody></table></div>';

  const remaining = passwordsFiltered.length - passwordsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'passwords');
  }

  content.innerHTML = html;
}

function cookieRowBuilder({ row, validity, sessionType }) {
  let html = '<tr>';
  for (const cell of row) {
    html += `<td title="${escapeHtml(cell)}">${escapeHtml(cell)}</td>`;
  }
  html += `<td><span class="validity-badge validity-badge-${validity.status}">${escapeHtml(validity.label)}</span></td>`;
  if (sessionType) {
    const label = sessionType === 'auth' ? 'Auth' : 'Session';
    html += `<td><span class="session-badge session-badge-${sessionType}">${label}</span></td>`;
  } else {
    html += '<td></td>';
  }
  html += '</tr>';
  return html;
}

function renderCookiesPage(validOnly = false, sessionOnly = false, searchQuery = '') {
  const summary = document.getElementById('cookiesSummary');
  const stats = document.getElementById('cookiesStats');
  const content = document.getElementById('cookiesContent');

  if (cookiesData.rows.length === 0) {
    summary.textContent = 'No cookies found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No cookie data available.</div>';
    return;
  }

  let filtered = cookiesData.rows;
  if (validOnly) filtered = filtered.filter(r => r.validity.status === 'valid');
  if (sessionOnly) filtered = filtered.filter(r => r.sessionType);
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(r => r.row.some(cell => cell.toLowerCase().includes(q)));
  }

  cookiesFiltered = filtered;
  cookiesShown = Math.min(PAGE_SIZE, filtered.length);

  const validCount = filtered.filter(r => r.validity.status === 'valid').length;
  const expiredCount = filtered.filter(r => r.validity.status === 'expired').length;
  const browserSessionCount = filtered.filter(r => r.validity.status === 'session').length;
  const authTokenCount = filtered.filter(r => r.sessionType === 'auth').length;
  const sessionTokenCount = filtered.filter(r => r.sessionType === 'session').length;
  const totalSessionTokens = authTokenCount + sessionTokenCount;
  const validAuthCount = filtered.filter(r => r.sessionType && r.validity.status === 'valid').length;

  const totalCookies = cookiesData.rows.length;
  const showingFiltered = filtered.length !== totalCookies;
  summary.textContent = showingFiltered
    ? `Showing ${filtered.length.toLocaleString()} of ${totalCookies.toLocaleString()} cookies from ${cookiesData.fileCount} file(s)`
    : `${totalCookies.toLocaleString()} cookies from ${cookiesData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-valid">${validCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Valid</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-expired">${expiredCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Expired</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-session">${browserSessionCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Browser Session</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth">${totalSessionTokens.toLocaleString()}</div>
      <div class="data-page-stat-label">Session Tokens</div>
    </div>
    ${validAuthCount > 0 ? `<div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth-valid">${validAuthCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Valid Sessions</div>
    </div>` : ''}
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr>';
  for (const h of cookiesData.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '<th>Status</th><th>Type</th></tr></thead><tbody>';
  html += buildRowsHtml(cookieRowBuilder, cookiesFiltered, 0, cookiesShown);
  html += '</tbody></table></div>';

  const remaining = cookiesFiltered.length - cookiesShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'cookies');
  }

  content.innerHTML = html;
}

function autofillRowBuilder({ name, value }) {
  return `<tr><td>${escapeHtml(name)}</td><td title="${escapeHtml(value)}">${escapeHtml(value)}</td></tr>`;
}

function renderAutofillsPage(searchQuery = '') {
  const summary = document.getElementById('autofillsSummary');
  const content = document.getElementById('autofillsContent');

  if (autofillsData.entries.length === 0) {
    summary.textContent = 'No autofill data found';
    content.innerHTML = '<div class="no-data">No autofill data available.</div>';
    return;
  }

  let filtered = autofillsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q) || e.value.toLowerCase().includes(q));
  }

  autofillsFiltered = filtered;
  autofillsShown = Math.min(PAGE_SIZE, filtered.length);

  const total = autofillsData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} entries from ${autofillsData.fileCount} file(s)`
    : `${total.toLocaleString()} entries from ${autofillsData.fileCount} file(s)`;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Field</th><th>Value</th></tr></thead><tbody>';
  html += buildRowsHtml(autofillRowBuilder, autofillsFiltered, 0, autofillsShown);
  html += '</tbody></table></div>';

  const remaining = autofillsFiltered.length - autofillsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'autofills');
  }

  content.innerHTML = html;
}

function historyRowBuilder({ url, title, visitCount }) {
  return `<tr><td title="${escapeHtml(url)}">${escapeHtml(url)}</td><td title="${escapeHtml(title)}">${escapeHtml(title)}</td><td>${visitCount}</td></tr>`;
}

function renderHistoryPage(searchQuery = '') {
  const summary = document.getElementById('historySummary');
  const stats = document.getElementById('historyStats');
  const content = document.getElementById('historyContent');

  if (historyData.entries.length === 0) {
    summary.textContent = 'No history found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No history data available.</div>';
    return;
  }

  let filtered = [...historyData.entries];
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.url.toLowerCase().includes(q) || e.title.toLowerCase().includes(q));
  }

  if (historySortOrder === 'desc') {
    filtered.sort((a, b) => b.visitCount - a.visitCount);
  } else if (historySortOrder === 'asc') {
    filtered.sort((a, b) => a.visitCount - b.visitCount);
  }

  historyFiltered = filtered;
  historyShown = Math.min(PAGE_SIZE, filtered.length);

  const domainCounts = {};
  for (const { url } of historyData.entries) {
    const domain = extractBaseDomain(extractDomain(url));
    domainCounts[domain] = (domainCounts[domain] || 0) + 1;
  }
  const topDomains = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const uniqueDomains = Object.keys(domainCounts).length;

  summary.textContent = `${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueDomains.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Domains</div>
    </div>
  `;

  let html = '';
  if (topDomains.length > 0) {
    const maxCount = topDomains[0][1];
    html += '<div class="domain-bars">';
    for (const [domain, count] of topDomains) {
      const pct = Math.round((count / maxCount) * 100);
      html += `<div class="domain-bar-row">
        <span class="domain-bar-label">${escapeHtml(domain)}</span>
        <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
        <span class="domain-bar-count">${count}</span>
      </div>`;
    }
    html += '</div>';
  }

  const visitsSortClass = historySortOrder === 'desc' ? 'sortable sort-desc' : historySortOrder === 'asc' ? 'sortable sort-asc' : 'sortable';
  html += '<div class="data-table-container"><table class="data-table" id="historyTable">';
  html += `<thead><tr><th>URL</th><th>Title</th><th class="${visitsSortClass}" id="historyVisitsHeader">Visits</th></tr></thead><tbody>`;
  html += buildRowsHtml(historyRowBuilder, historyFiltered, 0, historyShown);
  html += '</tbody></table></div>';

  const remaining = historyFiltered.length - historyShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'history');
  }

  content.innerHTML = html;
}

// CSV export

function escapeCSV(str) {
  if (str == null) return '';
  const s = String(str);
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

function exportPasswordsCSV() {
  if (passwordsData.rows.length === 0) return;
  let csv = passwordsData.headers.map(escapeCSV).join(',') + '\n';
  for (const { row } of passwordsData.rows) {
    csv += row.map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'passwords.csv', 'text/csv');
}

function exportCookiesCSV() {
  if (cookiesData.rows.length === 0) return;
  const headers = [...cookiesData.headers, 'Status', 'Session Type'];
  let csv = headers.map(escapeCSV).join(',') + '\n';
  for (const { row, validity, sessionType } of cookiesData.rows) {
    const typeLabel = sessionType === 'auth' ? 'Auth' : sessionType === 'session' ? 'Session' : '';
    csv += [...row, validity.label, typeLabel].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'cookies.csv', 'text/csv');
}

function exportAutofillsCSV() {
  if (autofillsData.entries.length === 0) return;
  let csv = 'Field,Value\n';
  for (const { name, value } of autofillsData.entries) {
    csv += [name, value].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'autofills.csv', 'text/csv');
}

function exportHistoryCSV() {
  if (historyData.entries.length === 0) return;
  let csv = 'URL,Title,Visits\n';
  for (const { url, title, visitCount } of historyData.entries) {
    csv += [url, title, visitCount].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'history.csv', 'text/csv');
}

// Show-more handler appends rows to existing tbody

function handleShowMore(pageId, contentEl) {
  let filtered, shown, rowBuilder;

  if (pageId === 'passwords') {
    filtered = passwordsFiltered; shown = passwordsShown; rowBuilder = passwordRowBuilder;
  } else if (pageId === 'cookies') {
    filtered = cookiesFiltered; shown = cookiesShown; rowBuilder = cookieRowBuilder;
  } else if (pageId === 'autofills') {
    filtered = autofillsFiltered; shown = autofillsShown; rowBuilder = autofillRowBuilder;
  } else if (pageId === 'history') {
    filtered = historyFiltered; shown = historyShown; rowBuilder = historyRowBuilder;
  } else {
    return;
  }

  const nextEnd = Math.min(shown + PAGE_SIZE, filtered.length);
  const newRowsHtml = buildRowsHtml(rowBuilder, filtered, shown, nextEnd);

  const tbody = contentEl.querySelector('tbody');
  if (tbody) {
    tbody.insertAdjacentHTML('beforeend', newRowsHtml);
  }

  if (pageId === 'passwords') passwordsShown = nextEnd;
  else if (pageId === 'cookies') cookiesShown = nextEnd;
  else if (pageId === 'autofills') autofillsShown = nextEnd;
  else if (pageId === 'history') historyShown = nextEnd;

  const btn = contentEl.querySelector('.data-show-more');
  const remaining = filtered.length - nextEnd;
  if (remaining > 0 && btn) {
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
  } else if (btn) {
    btn.remove();
  }
}

// Init

function initDataPages() {
  const passwordsSearch = document.getElementById('passwordsSearch');
  const passwordsHideCb = document.getElementById('passwordsHidePasswords');
  let pwDebounce = null;
  passwordsSearch?.addEventListener('input', () => {
    clearTimeout(pwDebounce);
    pwDebounce = setTimeout(() => {
      renderPasswordsPage(passwordsSearch.value);
    }, 150);
  });

  passwordsHideCb?.addEventListener('change', () => {
    hidePasswords = passwordsHideCb.checked;
    renderPasswordsPage(passwordsSearch?.value || '');
  });

  // Click-to-reveal individual masked passwords
  document.getElementById('passwordsContent')?.addEventListener('click', (e) => {
    const cell = e.target.closest('.password-cell.masked');
    if (!cell) return;
    // Find which row this is in the table
    const tr = cell.closest('tr');
    if (!tr) return;
    const tbody = tr.closest('tbody');
    if (!tbody) return;
    const rowIdx = Array.from(tbody.rows).indexOf(tr);
    if (rowIdx >= 0 && rowIdx < passwordsFiltered.length) {
      const realValue = passwordsFiltered[rowIdx].row[passwordColumnIdx];
      cell.textContent = realValue;
      cell.title = realValue;
      cell.classList.remove('masked');
      cell.classList.add('revealed');
      // Re-mask after 5 seconds
      setTimeout(() => {
        if (hidePasswords && cell.classList.contains('revealed')) {
          cell.textContent = maskValue(realValue);
          cell.title = 'Click to reveal';
          cell.classList.remove('revealed');
          cell.classList.add('masked');
        }
      }, 5000);
    }
  });

  const cookiesSearch = document.getElementById('cookiesSearch');
  const cookiesValidOnly = document.getElementById('cookiesValidOnly');
  const cookiesSessionOnly = document.getElementById('cookiesSessionOnly');
  let ckDebounce = null;

  const updateCookies = () => {
    clearTimeout(ckDebounce);
    ckDebounce = setTimeout(() => {
      renderCookiesPage(
        cookiesValidOnly?.checked || false,
        cookiesSessionOnly?.checked || false,
        cookiesSearch?.value || ''
      );
    }, 150);
  };

  cookiesSearch?.addEventListener('input', updateCookies);
  cookiesValidOnly?.addEventListener('change', updateCookies);
  cookiesSessionOnly?.addEventListener('change', updateCookies);

  const autofillsSearch = document.getElementById('autofillsSearch');
  let afDebounce = null;
  autofillsSearch?.addEventListener('input', () => {
    clearTimeout(afDebounce);
    afDebounce = setTimeout(() => {
      renderAutofillsPage(autofillsSearch.value);
    }, 150);
  });

  const historySearch = document.getElementById('historySearch');
  let hsDebounce = null;
  historySearch?.addEventListener('input', () => {
    clearTimeout(hsDebounce);
    hsDebounce = setTimeout(() => {
      renderHistoryPage(historySearch.value);
    }, 150);
  });

  // Sort toggle on Visits header
  document.getElementById('historyContent')?.addEventListener('click', (e) => {
    const header = e.target.closest('#historyVisitsHeader');
    if (!header) return;
    if (historySortOrder === 'none') historySortOrder = 'desc';
    else if (historySortOrder === 'desc') historySortOrder = 'asc';
    else historySortOrder = 'none';
    renderHistoryPage(historySearch?.value || '');
  });

  // Delegated show-more handlers
  for (const id of ['passwordsContent', 'cookiesContent', 'autofillsContent', 'historyContent']) {
    const el = document.getElementById(id);
    el?.addEventListener('click', (e) => {
      const btn = e.target.closest('.data-show-more');
      if (!btn) return;
      handleShowMore(btn.dataset.page, el);
    });
  }

  // Export buttons
  document.getElementById('exportPasswordsCsv')?.addEventListener('click', exportPasswordsCSV);
  document.getElementById('exportCookiesCsv')?.addEventListener('click', exportCookiesCSV);
  document.getElementById('exportAutofillsCsv')?.addEventListener('click', exportAutofillsCSV);
  document.getElementById('exportHistoryCsv')?.addEventListener('click', exportHistoryCSV);

  async function reloadData() {
    if (!state.fileTree) return;

    await Promise.all([
      loadPasswordsData(state.fileTree, state.rootZipName),
      loadCookiesData(state.fileTree, state.rootZipName),
      loadAutofillsData(state.fileTree, state.rootZipName),
      loadHistoryData(state.fileTree, state.rootZipName)
    ]);
    emit('data:loaded');

    document.getElementById('navPasswords').disabled = passwordsData.rows.length === 0;
    document.getElementById('navCookies').disabled = cookiesData.rows.length === 0;
    document.getElementById('navAutofills').disabled = autofillsData.entries.length === 0;
    document.getElementById('navHistory').disabled = historyData.entries.length === 0;
  }

  on('extracted', reloadData);
  on('reanalyze', reloadData);

  on('page:passwords', () => renderPasswordsPage(passwordsSearch?.value || ''));
  on('page:cookies', () => renderCookiesPage(cookiesValidOnly?.checked || false, cookiesSessionOnly?.checked || false, cookiesSearch?.value || ''));
  on('page:autofills', () => renderAutofillsPage(autofillsSearch?.value || ''));
  on('page:history', () => renderHistoryPage(historySearch?.value || ''));

  on('reset', () => {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    autofillsData = { entries: [], fileCount: 0 };
    historyData = { entries: [], fileCount: 0 };
    historySortOrder = 'none';
    passwordsFiltered = []; passwordsShown = 0;
    cookiesFiltered = []; cookiesShown = 0;
    autofillsFiltered = []; autofillsShown = 0;
    historyFiltered = []; historyShown = 0;

    document.getElementById('navPasswords').disabled = true;
    document.getElementById('navCookies').disabled = true;
    document.getElementById('navAutofills').disabled = true;
    document.getElementById('navHistory').disabled = true;

    if (passwordsSearch) passwordsSearch.value = '';
    if (cookiesSearch) cookiesSearch.value = '';
    if (autofillsSearch) autofillsSearch.value = '';
    if (historySearch) historySearch.value = '';
    if (cookiesValidOnly) cookiesValidOnly.checked = false;
    if (cookiesSessionOnly) cookiesSessionOnly.checked = false;
    if (passwordsHideCb) passwordsHideCb.checked = true;
    hidePasswords = true;
    passwordColumnIdx = -1;
  });
}

// Getters for cross-module access

function getPasswordsData() { return passwordsData; }
function getCookiesData() { return cookiesData; }
function getAutofillsData() { return autofillsData; }
function getHistoryData() { return historyData; }

export { initDataPages, getPasswordsData, getCookiesData, getAutofillsData, getHistoryData, escapeCSV };
