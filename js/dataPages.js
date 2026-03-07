// Data pages, Passwords, Cookies, Autofills, History.

import { state, on, emit } from './state.js';
import { loadFileContent } from './extractor.js';
import { escapeHtml, getFileExtension, formatBytes } from './utils.js';
import { parsePasswordFile, parseCookieFile, parseAutofillFile, parseHistoryFile, parseDownloadFile } from './transforms.js';
import { collectHintedNodes, checkCookieValidity, extractDomain, extractBaseDomain, downloadBlob, parseTimestampValue } from './shared.js';
import { classifyCookie } from './sessionCookies.js';
import { FIELD_PATTERNS } from './definitions.js';
import { openColumnMapper } from './columnMapper.js';

// Per-type data stores

let passwordsData = { rows: [], headers: [], fileCount: 0 };
let cookiesData = { rows: [], headers: [], fileCount: 0 };
let autofillsData = { entries: [], fileCount: 0 };
let historyData = { entries: [], fileCount: 0 };
let downloadsData = { entries: [], fileCount: 0 };
let softwareData = { entries: [], fileCount: 0, totalCount: 0 };
let processListData = { entries: [], fileCount: 0, uniqueCount: 0 };

let historySort = { key: 'none', order: 'none' };

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

let downloadsFiltered = [];
let downloadsShown = 0;

let softwareFiltered = [];
let softwareShown = 0;

let processesFiltered = [];
let processesShown = 0;

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

function formatTimestampDisplay(date) {
  if (!date) return '';
  return date.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function extractDownloadExtension(filePath, sourceUrl) {
  const candidates = [filePath, sourceUrl];
  for (const candidate of candidates) {
    if (!candidate) continue;
    const clean = candidate.split('?')[0].split('#')[0];
    const segment = clean.split(/[\\/]/).pop() || '';
    const ext = getFileExtension(segment);
    if (ext) return ext;
  }
  return '';
}

function parseDownloadSize(rawValue) {
  if (rawValue == null) return { raw: '', bytes: null, display: '' };

  const raw = String(rawValue).trim();
  if (!raw) return { raw: '', bytes: null, display: '' };

  const normalized = raw.replace(/,/g, '');
  const match = normalized.match(/^(\d+(?:\.\d+)?)\s*(bytes?|b|kb|mb|gb|tb)?$/i);
  if (!match) {
    return { raw, bytes: null, display: raw };
  }

  const value = Number(match[1]);
  if (!Number.isFinite(value) || value < 0) {
    return { raw, bytes: null, display: raw };
  }

  const unit = (match[2] || 'bytes').toLowerCase();
  const multipliers = {
    b: 1,
    byte: 1,
    bytes: 1,
    kb: 1024,
    mb: 1024 ** 2,
    gb: 1024 ** 3,
    tb: 1024 ** 4,
  };
  const bytes = Math.round(value * (multipliers[unit] || 1));
  return { raw, bytes, display: formatBytes(bytes) };
}

// Data loading

async function loadPasswordsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_passwordFileHint', rootName, nodes);

  if (nodes.length === 0) {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  // Pass 1: parse all files and build column mappings
  const canonicalHeaders = ['URL', 'Username', 'Password'];
  const extraHeaders = [];
  const parsedFiles = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) continue;
      fileCount++;

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
      const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

      const colMap = new Map();
      if (urlIdx >= 0)  colMap.set(urlIdx, 0);
      if (userIdx >= 0) colMap.set(userIdx, 1);
      if (passIdx >= 0) colMap.set(passIdx, 2);

      for (let i = 0; i < parsed.headers.length; i++) {
        if (colMap.has(i)) continue;
        const hdr = parsed.headers[i];
        if (/^Column \d+$/.test(hdr)) continue;
        let extraIdx = extraHeaders.indexOf(hdr);
        if (extraIdx < 0) { extraIdx = extraHeaders.length; extraHeaders.push(hdr); }
        colMap.set(i, canonicalHeaders.length + extraIdx);
      }

      parsedFiles.push({ path, parsed, colMap });
    } catch {
      // skip
    }
  }

  // Pass 2: build unified rows with final column count
  const totalCols = canonicalHeaders.length + extraHeaders.length;
  const allRows = [];
  for (const { path, parsed, colMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const unified = new Array(totalCols).fill('');
      for (const [src, dest] of colMap) {
        unified[dest] = row[src] || '';
      }
      allRows.push({ row: unified, source: path });
    }
  }

  const headers = [...canonicalHeaders, ...extraHeaders];
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
      const parsed = parseCookieFile(text, node._parseConfig || null);
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
      const parsed = parseAutofillFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        for (const row of parsed.rows) {
          const name = (row[0] || '').trim();
          const value = (row[1] || '').trim();
          if (name && value) {
            entries.push({ name, value, source: path });
          }
        }
        fileCount++;
      }
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
      const parsed = parseHistoryFile(text, node._parseConfig || null);

      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
        const titleIdx = parsed.headers.findIndex(h => /^(title|page.?title)$/i.test(h));
        const visitsIdx = parsed.headers.findIndex(h => /^(visit.?count|visits?|count)$/i.test(h));
        const lastIdx = parsed.headers.findIndex(h => /^(last.?visit|date|time|timestamp)$/i.test(h));

        for (const row of parsed.rows) {
          const url = urlIdx >= 0 ? (row[urlIdx] || '').trim() : '';
          if (!url) continue;
          const lastVisit = lastIdx >= 0 ? (row[lastIdx] || '').trim() : '';
          entries.push({
            url,
            title: titleIdx >= 0 ? (row[titleIdx] || '').trim() : '',
            visitCount: visitsIdx >= 0 ? (parseInt(row[visitsIdx], 10) || 1) : 1,
            lastVisit,
            lastVisitDate: parseTimestampValue(lastVisit),
            source: path
          });
        }
      }
    } catch {
      // skip
    }
  }

  historyData = { entries, fileCount };
}

async function loadDownloadsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_downloadHint', rootName, nodes);

  if (nodes.length === 0) {
    downloadsData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = new TextDecoder('utf-8').decode(content);
      const parsed = parseDownloadFile(text);
      if (!parsed || parsed.rows.length === 0) continue;

      fileCount++;

      const fileIdx = parsed.headers.findIndex(h => /^(?:file(?:\s*path)?|filename|path|download(?:\s*path)?)$/i.test(h));
      const urlIdx = parsed.headers.findIndex(h => /^(?:source\s*url|url|download\s*url)$/i.test(h));
      const sizeIdx = parsed.headers.findIndex(h => /^(?:file\s*size|size|bytes|received\s*bytes|recived\s*bytes)$/i.test(h));

      for (const row of parsed.rows) {
        const filePath = (fileIdx >= 0 ? row[fileIdx] : row[0]) || '';
        const sourceUrl = (urlIdx >= 0 ? row[urlIdx] : row[1]) || '';
        const sizeInfo = parseDownloadSize(sizeIdx >= 0 ? row[sizeIdx] : '');
        const domain = extractDomain(sourceUrl) || '';
        const extension = extractDownloadExtension(filePath, sourceUrl);

        if (!filePath && !sourceUrl) continue;
        entries.push({
          filePath: filePath.trim(),
          sourceUrl: sourceUrl.trim(),
          fileSizeRaw: sizeInfo.raw,
          fileSizeBytes: sizeInfo.bytes,
          fileSizeDisplay: sizeInfo.display,
          domain,
          extension,
          source: path,
        });
      }
    } catch {
      // skip
    }
  }

  downloadsData = { entries, fileCount };
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

function trimRootPath(path) {
  if (!path) return '';
  if (state.rootZipName && path.startsWith(state.rootZipName + '/')) {
    return path.slice(state.rootZipName.length + 1);
  }
  return path;
}

function chooseMapperNode(nodes, fileType) {
  if (nodes.length === 1) return Promise.resolve(nodes[0]);

  return new Promise((resolve) => {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay visible';
    overlay.innerHTML = `
      <div class="modal modal-filetype">
        <h3>Choose File</h3>
        <p>Select the ${escapeHtml(fileType)} file to remap.</p>
        <div class="filetype-options">
          ${nodes.map(({ node, path }, index) => `
            <button class="filetype-option" data-idx="${index}">
              <span class="filetype-icon">${escapeHtml(node.name || `File ${index + 1}`)}</span>
              <span class="filetype-desc">${escapeHtml(trimRootPath(path))}</span>
            </button>
          `).join('')}
        </div>
        <div class="modal-actions">
          <button class="modal-btn modal-btn-cancel" id="mapperChooseCancel">Cancel</button>
        </div>
      </div>
    `;

    const cleanup = (selection) => {
      overlay.remove();
      resolve(selection);
    };

    overlay.querySelector('.filetype-options').addEventListener('click', (ev) => {
      const btn = ev.target.closest('.filetype-option');
      if (!btn) return;
      cleanup(nodes[parseInt(btn.dataset.idx, 10)] || null);
    });

    overlay.querySelector('#mapperChooseCancel').addEventListener('click', () => cleanup(null));
    overlay.addEventListener('click', (ev) => {
      if (ev.target === overlay) cleanup(null);
    });

    document.body.appendChild(overlay);
  });
}

// Generic column mapper opener for any file type
async function openMapperForHint(hintKey, fileType) {
  const nodes = [];
  collectHintedNodes(state.fileTree, hintKey, state.rootZipName, nodes);
  if (nodes.length === 0) return;

  const selected = await chooseMapperNode(nodes, fileType);
  if (!selected) return;

  const content = await loadFileContent(selected.node);
  if (!content) return;
  const text = new TextDecoder('utf-8').decode(content);
  const fileName = selected.path || selected.node.name || 'Unknown file';

  const config = await openColumnMapper(text, fileName, fileType);
  if (!config) return;

  selected.node._parseConfig = config;
  emit('reanalyze');
}

function addAdjustColumnsBtn(summaryEl, hintKey, fileType) {
  const actionsArea = summaryEl.parentNode.querySelector('.data-page-actions');
  if (actionsArea && !actionsArea.querySelector('.mapper-adjust-btn')) {
    const adjustBtn = document.createElement('button');
    adjustBtn.className = 'mapper-adjust-btn';
    adjustBtn.textContent = 'Adjust columns\u2026';
    adjustBtn.addEventListener('click', () => openMapperForHint(hintKey, fileType));
    actionsArea.insertBefore(adjustBtn, actionsArea.firstChild);
  }
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

  addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');

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

  addAdjustColumnsBtn(summary, '_cookieFileHint', 'cookies');

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

  addAdjustColumnsBtn(summary, '_autofillHint', 'autofill');

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

function historyRowBuilder({ url, title, visitCount, lastVisit, lastVisitDate }) {
  const displayLastVisit = lastVisitDate ? formatTimestampDisplay(lastVisitDate) : lastVisit;
  return `<tr><td title="${escapeHtml(url)}">${escapeHtml(url)}</td><td title="${escapeHtml(title)}">${escapeHtml(title)}</td><td>${visitCount}</td><td title="${escapeHtml(lastVisit || displayLastVisit || '')}">${escapeHtml(displayLastVisit || '')}</td></tr>`;
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
    filtered = filtered.filter(e =>
      e.url.toLowerCase().includes(q) ||
      e.title.toLowerCase().includes(q) ||
      e.lastVisit.toLowerCase().includes(q)
    );
  }

  if (historySort.key === 'visits') {
    filtered.sort((a, b) => historySort.order === 'desc' ? b.visitCount - a.visitCount : a.visitCount - b.visitCount);
  } else if (historySort.key === 'lastVisit') {
    filtered.sort((a, b) => {
      const aTime = a.lastVisitDate ? a.lastVisitDate.getTime() : -Infinity;
      const bTime = b.lastVisitDate ? b.lastVisitDate.getTime() : -Infinity;
      return historySort.order === 'desc' ? bTime - aTime : aTime - bTime;
    });
  }

  historyFiltered = filtered;
  historyShown = Math.min(PAGE_SIZE, filtered.length);

  const domainCounts = {};
  for (const { url } of historyData.entries) {
    const domain = extractBaseDomain(extractDomain(url));
    if (!domain) continue;
    domainCounts[domain] = (domainCounts[domain] || 0) + 1;
  }
  const topDomains = Object.entries(domainCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10);

  const uniqueDomains = Object.keys(domainCounts).length;
  const datedEntries = historyData.entries.filter(entry => entry.lastVisitDate);
  const mostRecent = datedEntries.length > 0
    ? datedEntries.reduce((latest, entry) => !latest || entry.lastVisitDate > latest.lastVisitDate ? entry : latest, null)
    : null;

  summary.textContent = filtered.length !== historyData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`
    : `${historyData.entries.length.toLocaleString()} entries from ${historyData.fileCount} file(s)`;

  addAdjustColumnsBtn(summary, '_historyHint', 'history');

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${uniqueDomains.toLocaleString()}</div>
      <div class="data-page-stat-label">Unique Domains</div>
    </div>
    ${mostRecent ? `<div class="data-page-stat">
      <div class="data-page-stat-value" style="font-size:0.95rem">${escapeHtml(formatTimestampDisplay(mostRecent.lastVisitDate))}</div>
      <div class="data-page-stat-label">Most Recent Visit</div>
    </div>` : ''}
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

  const visitsSortClass = historySort.key === 'visits' ? `sortable sort-${historySort.order}` : 'sortable';
  const lastVisitSortClass = historySort.key === 'lastVisit' ? `sortable sort-${historySort.order}` : 'sortable';
  html += '<div class="data-table-container"><table class="data-table" id="historyTable">';
  html += `<thead><tr><th>URL</th><th>Title</th><th class="${visitsSortClass}" id="historyVisitsHeader">Visits</th><th class="${lastVisitSortClass}" id="historyLastVisitHeader">Last Visit</th></tr></thead><tbody>`;
  html += buildRowsHtml(historyRowBuilder, historyFiltered, 0, historyShown);
  html += '</tbody></table></div>';

  const remaining = historyFiltered.length - historyShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'history');
  }

  content.innerHTML = html;
}

function downloadsRowBuilder({ filePath, sourceUrl, fileSizeDisplay, domain, extension }) {
  return `<tr>
    <td title="${escapeHtml(filePath)}">${escapeHtml(filePath)}</td>
    <td title="${escapeHtml(sourceUrl)}">${escapeHtml(sourceUrl)}</td>
    <td title="${escapeHtml(fileSizeDisplay || '')}">${escapeHtml(fileSizeDisplay || '')}</td>
    <td>${escapeHtml(extension || '')}</td>
    <td>${escapeHtml(domain || '')}</td>
  </tr>`;
}

function renderDownloadsPage(searchQuery = '') {
  const summary = document.getElementById('downloadsSummary');
  const stats = document.getElementById('downloadsStats');
  const content = document.getElementById('downloadsContent');

  if (downloadsData.entries.length === 0) {
    summary.textContent = 'No downloads found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No download data available.</div>';
    return;
  }

  let filtered = downloadsData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e =>
      e.filePath.toLowerCase().includes(q) ||
      e.sourceUrl.toLowerCase().includes(q) ||
      e.fileSizeRaw.toLowerCase().includes(q) ||
      e.fileSizeDisplay.toLowerCase().includes(q) ||
      e.domain.toLowerCase().includes(q) ||
      e.extension.toLowerCase().includes(q)
    );
  }

  downloadsFiltered = filtered;
  downloadsShown = Math.min(PAGE_SIZE, filtered.length);

  const extensionCounts = {};
  let withSourceUrl = 0;
  let withFileSize = 0;
  let totalKnownBytes = 0;
  let knownSizeCount = 0;

  for (const entry of downloadsData.entries) {
    if (entry.extension) extensionCounts[entry.extension] = (extensionCounts[entry.extension] || 0) + 1;
    if (entry.sourceUrl) withSourceUrl++;
    if (entry.fileSizeDisplay) withFileSize++;
    if (entry.fileSizeBytes != null) {
      totalKnownBytes += entry.fileSizeBytes;
      knownSizeCount++;
    }
  }

  const topExtension = Object.entries(extensionCounts).sort((a, b) => b[1] - a[1])[0];
  const totalKnownSizeDisplay = knownSizeCount > 0 ? formatBytes(totalKnownBytes) : '-';

  summary.textContent = filtered.length !== downloadsData.entries.length
    ? `Showing ${filtered.length.toLocaleString()} of ${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`
    : `${downloadsData.entries.length.toLocaleString()} downloads from ${downloadsData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withSourceUrl.toLocaleString()}</div>
      <div class="data-page-stat-label">With Source URL</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withFileSize.toLocaleString()}</div>
      <div class="data-page-stat-label">With File Size</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(topExtension ? topExtension[0] : '-')}</div>
      <div class="data-page-stat-label">Top Extension</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${escapeHtml(totalKnownSizeDisplay)}</div>
      <div class="data-page-stat-label">Known Total Size</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>File Path</th><th>Source URL</th><th>File Size</th><th>Extension</th><th>Domain</th></tr></thead><tbody>';
  html += buildRowsHtml(downloadsRowBuilder, downloadsFiltered, 0, downloadsShown);
  html += '</tbody></table></div>';

  const remaining = downloadsFiltered.length - downloadsShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'downloads');
  }

  content.innerHTML = html;
}

// Software rendering

function softwareRowBuilder({ name, version }) {
  return `<tr><td title="${escapeHtml(name)}">${escapeHtml(name)}</td><td>${escapeHtml(version || '')}</td></tr>`;
}

function renderSoftwarePage(searchQuery = '') {
  const summary = document.getElementById('softwareSummary');
  const content = document.getElementById('softwareContent');

  if (softwareData.entries.length === 0) {
    summary.textContent = 'No software data found';
    content.innerHTML = '<div class="no-data">No software data available.</div>';
    return;
  }

  let filtered = softwareData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q) || (e.version && e.version.toLowerCase().includes(q)));
  }

  softwareFiltered = filtered;
  softwareShown = Math.min(PAGE_SIZE, filtered.length);

  const total = softwareData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} programs from ${softwareData.fileCount} file(s)`
    : `${total.toLocaleString()} programs from ${softwareData.fileCount} file(s)`;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Software Name</th><th>Version</th></tr></thead><tbody>';
  html += buildRowsHtml(softwareRowBuilder, softwareFiltered, 0, softwareShown);
  html += '</tbody></table></div>';

  const remaining = softwareFiltered.length - softwareShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'software');
  }

  content.innerHTML = html;
}

// Process list rendering

function processRowBuilder({ name, pid }) {
  return `<tr><td title="${escapeHtml(name)}">${escapeHtml(name)}</td><td>${pid ? escapeHtml(String(pid)) : ''}</td></tr>`;
}

function renderProcessesPage(searchQuery = '') {
  const summary = document.getElementById('processesSummary');
  const content = document.getElementById('processesContent');

  if (processListData.entries.length === 0) {
    summary.textContent = 'No process data found';
    content.innerHTML = '<div class="no-data">No process data available.</div>';
    return;
  }

  let filtered = processListData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(e => e.name.toLowerCase().includes(q));
  }

  processesFiltered = filtered;
  processesShown = Math.min(PAGE_SIZE, filtered.length);

  const total = processListData.entries.length;
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`
    : `${total.toLocaleString()} processes from ${processListData.fileCount} file(s)`;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Process Name</th><th>PID</th></tr></thead><tbody>';
  html += buildRowsHtml(processRowBuilder, processesFiltered, 0, processesShown);
  html += '</tbody></table></div>';

  const remaining = processesFiltered.length - processesShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'processes');
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
  let csv = 'URL,Title,Visits,Last Visit\n';
  for (const { url, title, visitCount, lastVisit, lastVisitDate } of historyData.entries) {
    csv += [url, title, visitCount, lastVisitDate ? lastVisitDate.toISOString() : lastVisit].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'history.csv', 'text/csv');
}

function exportDownloadsCSV() {
  if (downloadsData.entries.length === 0) return;
  let csv = 'File Path,Source URL,File Size,Extension,Domain\n';
  for (const { filePath, sourceUrl, fileSizeRaw, fileSizeDisplay, extension, domain } of downloadsData.entries) {
    csv += [filePath, sourceUrl, fileSizeRaw || fileSizeDisplay, extension, domain].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'downloads.csv', 'text/csv');
}

function exportSoftwareCSV() {
  if (softwareData.entries.length === 0) return;
  let csv = 'Software Name,Version\n';
  for (const { name, version } of softwareData.entries) {
    csv += [name, version || ''].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'software.csv', 'text/csv');
}

function exportProcessesCSV() {
  if (processListData.entries.length === 0) return;
  let csv = 'Process Name,PID\n';
  for (const { name, pid } of processListData.entries) {
    csv += [name, pid || ''].map(escapeCSV).join(',') + '\n';
  }
  downloadBlob(csv, 'processes.csv', 'text/csv');
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
  } else if (pageId === 'downloads') {
    filtered = downloadsFiltered; shown = downloadsShown; rowBuilder = downloadsRowBuilder;
  } else if (pageId === 'software') {
    filtered = softwareFiltered; shown = softwareShown; rowBuilder = softwareRowBuilder;
  } else if (pageId === 'processes') {
    filtered = processesFiltered; shown = processesShown; rowBuilder = processRowBuilder;
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
  else if (pageId === 'downloads') downloadsShown = nextEnd;
  else if (pageId === 'software') softwareShown = nextEnd;
  else if (pageId === 'processes') processesShown = nextEnd;

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

  const downloadsSearch = document.getElementById('downloadsSearch');
  let dlDebounce = null;
  downloadsSearch?.addEventListener('input', () => {
    clearTimeout(dlDebounce);
    dlDebounce = setTimeout(() => {
      renderDownloadsPage(downloadsSearch.value);
    }, 150);
  });

  // Sort toggle on History headers
  document.getElementById('historyContent')?.addEventListener('click', (e) => {
    const header = e.target.closest('#historyVisitsHeader, #historyLastVisitHeader');
    if (!header) return;
    const nextKey = header.id === 'historyLastVisitHeader' ? 'lastVisit' : 'visits';
    if (historySort.key !== nextKey) {
      historySort = { key: nextKey, order: 'desc' };
    } else if (historySort.order === 'desc') {
      historySort = { key: nextKey, order: 'asc' };
    } else {
      historySort = { key: 'none', order: 'none' };
    }
    renderHistoryPage(historySearch?.value || '');
  });

  // Software search
  const softwareSearch = document.getElementById('softwareSearch');
  let swDebounce = null;
  softwareSearch?.addEventListener('input', () => {
    clearTimeout(swDebounce);
    swDebounce = setTimeout(() => {
      renderSoftwarePage(softwareSearch.value);
    }, 150);
  });

  // Process search
  const processesSearch = document.getElementById('processesSearch');
  let prDebounce = null;
  processesSearch?.addEventListener('input', () => {
    clearTimeout(prDebounce);
    prDebounce = setTimeout(() => {
      renderProcessesPage(processesSearch.value);
    }, 150);
  });

  // Delegated show-more handlers
  for (const id of ['passwordsContent', 'cookiesContent', 'autofillsContent', 'historyContent', 'downloadsContent', 'softwareContent', 'processesContent']) {
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
  document.getElementById('exportDownloadsCsv')?.addEventListener('click', exportDownloadsCSV);
  document.getElementById('exportSoftwareCsv')?.addEventListener('click', exportSoftwareCSV);
  document.getElementById('exportProcessesCsv')?.addEventListener('click', exportProcessesCSV);

  async function reloadData() {
    if (!state.fileTree) return;

    await Promise.all([
      loadPasswordsData(state.fileTree, state.rootZipName),
      loadCookiesData(state.fileTree, state.rootZipName),
      loadAutofillsData(state.fileTree, state.rootZipName),
      loadHistoryData(state.fileTree, state.rootZipName),
      loadDownloadsData(state.fileTree, state.rootZipName)
    ]);
    emit('data:loaded');

    document.getElementById('navPasswords').disabled = passwordsData.rows.length === 0;
    document.getElementById('navCookies').disabled = cookiesData.rows.length === 0;
    document.getElementById('navAutofills').disabled = autofillsData.entries.length === 0;
    document.getElementById('navHistory').disabled = historyData.entries.length === 0;
    document.getElementById('navDownloads').disabled = downloadsData.entries.length === 0;
  }

  on('extracted', reloadData);
  on('reanalyze', reloadData);

  on('page:passwords', () => renderPasswordsPage(passwordsSearch?.value || ''));
  on('page:cookies', () => renderCookiesPage(cookiesValidOnly?.checked || false, cookiesSessionOnly?.checked || false, cookiesSearch?.value || ''));
  on('page:autofills', () => renderAutofillsPage(autofillsSearch?.value || ''));
  on('page:history', () => renderHistoryPage(historySearch?.value || ''));
  on('page:downloads', () => renderDownloadsPage(downloadsSearch?.value || ''));
  on('page:software', () => renderSoftwarePage(softwareSearch?.value || ''));
  on('page:processes', () => renderProcessesPage(processesSearch?.value || ''));

  on('analysis:software', (data) => {
    if (data && data.entries.length > 0) {
      softwareData = data;
      document.getElementById('navSoftware').disabled = false;
    }
  });

  on('analysis:processList', (data) => {
    if (data && data.entries.length > 0) {
      processListData = data;
      document.getElementById('navProcesses').disabled = false;
    }
  });

  on('reset', () => {
    passwordsData = { rows: [], headers: [], fileCount: 0 };
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    autofillsData = { entries: [], fileCount: 0 };
    historyData = { entries: [], fileCount: 0 };
    downloadsData = { entries: [], fileCount: 0 };
    historySort = { key: 'none', order: 'none' };
    passwordsFiltered = []; passwordsShown = 0;
    cookiesFiltered = []; cookiesShown = 0;
    autofillsFiltered = []; autofillsShown = 0;
    historyFiltered = []; historyShown = 0;
    downloadsFiltered = []; downloadsShown = 0;
    softwareData = { entries: [], fileCount: 0, totalCount: 0 };
    processListData = { entries: [], fileCount: 0, uniqueCount: 0 };
    softwareFiltered = []; softwareShown = 0;
    processesFiltered = []; processesShown = 0;

    document.getElementById('navPasswords').disabled = true;
    document.getElementById('navCookies').disabled = true;
    document.getElementById('navAutofills').disabled = true;
    document.getElementById('navHistory').disabled = true;
    document.getElementById('navDownloads').disabled = true;
    document.getElementById('navSoftware').disabled = true;
    document.getElementById('navProcesses').disabled = true;

    if (passwordsSearch) passwordsSearch.value = '';
    if (softwareSearch) softwareSearch.value = '';
    if (processesSearch) processesSearch.value = '';
    if (cookiesSearch) cookiesSearch.value = '';
    if (autofillsSearch) autofillsSearch.value = '';
    if (historySearch) historySearch.value = '';
    if (downloadsSearch) downloadsSearch.value = '';
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
function getDownloadsData() { return downloadsData; }
function getSoftwareData() { return softwareData; }
function getProcessListData() { return processListData; }

export { initDataPages, getPasswordsData, getCookiesData, getAutofillsData, getHistoryData, getDownloadsData, getSoftwareData, getProcessListData, escapeCSV };
