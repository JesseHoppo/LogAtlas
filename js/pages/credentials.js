// Credentials pages: Passwords, Cookies, Autofill, Notes

import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
} from '../transforms/credentials.js';
import { parseNoteArtifact, summariseNotes } from '../analysis/contextArtifacts.js';
import {
  collectHintedNodes,
  checkCookieValidity,
  extractDomain,
  extractBaseDomain,
  SHARED_TEXT_DECODER,
} from '../core/shared.js';
import { classifyCookie } from '../analysis/sessionCookies.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import {
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  bindDebouncedInput,
  createDebounced,
  trimRootPath,
  maskValue,
  addAdjustColumnsBtn,
  downloadCsvRows,
} from './shared.js';

const COOKIE_HEADERS = ['Domain', 'SubDomain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];
const COOKIE_HEADERS_NO_SUBDOMAIN = ['Domain', 'Path', 'Secure', 'Expiration', 'Name', 'Value'];

// Data stores

let passwordsData = { rows: [], headers: [], fileCount: 0, failedFiles: [] };
let cookiesData = { rows: [], headers: [], fileCount: 0 };
let autofillsData = { entries: [], fileCount: 0 };
let notesData = { entries: [], fileCount: 0 };

let passwordsFiltered = [];
let passwordsShown = 0;
let cookiesFiltered = [];
let cookiesShown = 0;
let autofillsFiltered = [];
let autofillsShown = 0;
let notesFiltered = [];
let notesShown = 0;

let hidePasswords = true;
let passwordColumnIdx = -1;

function getCookieColumnMap(headers, columnCount) {
  const map = {
    domain: -1,
    subDomain: -1,
    path: -1,
    secure: -1,
    expires: -1,
    name: -1,
    value: -1,
  };

  for (let i = 0; i < headers.length; i++) {
    const header = headers[i];
    if (map.domain < 0 && /^(domain|host|host_key)$/i.test(header)) map.domain = i;
    else if (map.subDomain < 0 && /^(sub\s*domain|include[_\s-]*subdomains?)$/i.test(header)) map.subDomain = i;
    else if (map.path < 0 && /^path$/i.test(header)) map.path = i;
    else if (map.secure < 0 && /^(secure|is[_\s-]*secure)$/i.test(header)) map.secure = i;
    else if (map.expires < 0 && FIELD_PATTERNS.expires.test(header)) map.expires = i;
    else if (map.name < 0 && /^(name|key)$/i.test(header)) map.name = i;
    else if (map.value < 0 && /^value$/i.test(header)) map.value = i;
  }

  if (map.domain < 0 && columnCount >= 6) map.domain = 0;
  if (map.subDomain < 0 && columnCount >= 7) map.subDomain = 1;
  if (map.path < 0) map.path = columnCount >= 7 ? 2 : columnCount >= 6 ? 1 : -1;
  if (map.secure < 0) map.secure = columnCount >= 7 ? 3 : columnCount >= 6 ? 2 : -1;
  if (map.expires < 0) map.expires = columnCount >= 7 ? 4 : columnCount >= 6 ? 3 : -1;
  if (map.name < 0) map.name = columnCount >= 7 ? 5 : columnCount >= 6 ? 4 : -1;
  if (map.value < 0) map.value = columnCount >= 7 ? 6 : columnCount >= 6 ? 5 : -1;

  return map;
}

function normaliseCookieRow(row, columnMap, includeSubDomain) {
  const normalised = [
    row[columnMap.domain] || '',
    row[columnMap.path] || '',
    row[columnMap.secure] || '',
    row[columnMap.expires] || '',
    row[columnMap.name] || '',
    row[columnMap.value] || '',
  ];

  if (!includeSubDomain) return normalised;

  normalised.splice(1, 0, row[columnMap.subDomain] || '');
  return normalised;
}

// Load functions

async function loadPasswordsData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_passwordFileHint', rootName, nodes);

  if (nodes.length === 0) {
    passwordsData = { rows: [], headers: [], fileCount: 0, failedFiles: [] };
    return;
  }

  const canonicalHeaders = ['URL', 'Username', 'Password'];
  const extraHeaders = [];
  const parsedFiles = [];
  const failedFiles = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    const sourcePath = path || node.name;
    try {
      const content = await loadFileContent(node);
      if (!content) {
        failedFiles.push({ path: sourcePath, reason: 'Unreadable or empty file' });
        continue;
      }
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parsePasswordFile(text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) {
        failedFiles.push({ path: sourcePath, reason: 'No credentials parsed' });
        continue;
      }

      const urlIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
      const userIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
      const passIdx = parsed.headers.findIndex(h => FIELD_PATTERNS.password.test(h));

      if (passIdx < 0 || (urlIdx < 0 && userIdx < 0)) {
        failedFiles.push({ path: sourcePath, reason: 'Missing credential columns after parsing' });
        continue;
      }

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

      fileCount++;
      parsedFiles.push({ path: sourcePath, parsed, colMap });
    } catch (err) {
      failedFiles.push({ path: sourcePath, reason: err?.message || 'Failed to read or parse file' });
    }
  }

  const totalCols = canonicalHeaders.length + extraHeaders.length;
  const dedupedRows = new Map();
  for (const { path, parsed, colMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const unified = new Array(totalCols).fill('');
      for (const [src, dest] of colMap) {
        unified[dest] = row[src] || '';
      }
      const key = [unified[0], unified[1], unified[2]]
        .map(cell => String(cell || '').trim().toLowerCase())
        .join('\u0000');
      if (!key.replace(/\u0000/g, '')) continue;

      if (!dedupedRows.has(key)) {
        dedupedRows.set(key, { row: unified, sources: new Set([path]) });
        continue;
      }

      const existing = dedupedRows.get(key);
      for (let i = 0; i < unified.length; i++) {
        if (!existing.row[i] && unified[i]) existing.row[i] = unified[i];
      }
      existing.sources.add(path);
    }
  }

  const headers = [...canonicalHeaders, ...extraHeaders];
  passwordsData = {
    rows: [...dedupedRows.values()].map(({ row, sources }) => ({
      row,
      source: [...sources].join('; '),
    })),
    headers,
    fileCount,
    failedFiles,
  };
}

async function loadCookiesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_cookieFileHint', rootName, nodes);

  if (nodes.length === 0) {
    cookiesData = { rows: [], headers: [], fileCount: 0 };
    return;
  }

  const parsedFiles = [];
  let includeSubDomain = false;
  let fileCount = 0;

  for (const { node } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parseCookieFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const columnMap = getCookieColumnMap(parsed.headers, parsed.rows[0]?.length || 0);
        if (columnMap.subDomain >= 0) includeSubDomain = true;
        parsedFiles.push({ parsed, columnMap });
      }
    } catch {
      // skip
    }
  }

  const headers = includeSubDomain ? COOKIE_HEADERS : COOKIE_HEADERS_NO_SUBDOMAIN;
  const expiresIdx = headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
  const nameIdx = headers.findIndex(h => FIELD_PATTERNS.cookieName.test(h));
  const rows = [];

  for (const { parsed, columnMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const normalisedRow = normaliseCookieRow(row, columnMap, includeSubDomain);
      const expiresVal = expiresIdx >= 0 ? normalisedRow[expiresIdx] : null;
      const cookieName = nameIdx >= 0 ? normalisedRow[nameIdx] : '';
      rows.push({
        row: normalisedRow,
        validity: checkCookieValidity(expiresVal),
        sessionType: classifyCookie(cookieName),
        headers,
      });
    }
  }

  cookiesData = { rows, headers, fileCount };
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
      const text = SHARED_TEXT_DECODER.decode(content);
      const parsed = parseAutofillFile(text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        for (const row of parsed.rows) {
          const name = (row[0] || '').trim();
          const value = (row[1] || '').trim();
          if (name && value) {
            entries.push({ name, value });
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

async function loadNotesData(fileTree, rootName) {
  const nodes = [];
  collectHintedNodes(fileTree, '_notesHint', rootName, nodes);

  if (nodes.length === 0) {
    notesData = { entries: [], fileCount: 0 };
    return;
  }

  const entries = [];
  let fileCount = 0;

  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const text = SHARED_TEXT_DECODER.decode(content);
      const entry = parseNoteArtifact(text, node.name || '', path, node.lastModified);
      if (!entry) continue;

      entries.push(entry);
      fileCount++;
    } catch {
      // skip
    }
  }

  entries.sort((a, b) => {
    const scoreA = (a.walletHints > 0 ? 2 : 0) + (a.credentialHints > 0 ? 1 : 0);
    const scoreB = (b.walletHints > 0 ? 2 : 0) + (b.credentialHints > 0 ? 1 : 0);
    if (scoreB !== scoreA) return scoreB - scoreA;
    return b.text.length - a.text.length;
  });

  notesData = { entries, fileCount };
}

// Row builders

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

function buildPasswordParseIssuesHtml(failedFiles) {
  if (!failedFiles || failedFiles.length === 0) return '';

  const visible = failedFiles.slice(0, 5);
  const remaining = failedFiles.length - visible.length;
  return `
    <div class="data-page-warning">
      <div class="data-page-warning-title">${failedFiles.length.toLocaleString()} password file(s) could not be parsed cleanly</div>
      <ul class="data-page-warning-list">
        ${visible.map(({ path, reason }) => `<li><strong>${escapeHtml(trimRootPath(path))}</strong>${reason ? ` <span>${escapeHtml(reason)}</span>` : ''}</li>`).join('')}
      </ul>
      ${remaining > 0 ? `<div class="data-page-warning-more">${remaining.toLocaleString()} more file(s) omitted</div>` : ''}
    </div>
  `;
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

function autofillRowBuilder({ name, value }) {
  return `<tr><td>${escapeHtml(name)}</td><td title="${escapeHtml(value)}">${escapeHtml(value)}</td></tr>`;
}

function noteRowBuilder(entry) {
  const indicatorTitle = [
    ...(entry.urls || []),
    ...(entry.emails || []),
    ...(entry.phones || []),
  ].join('\n');

  return `<tr>
    <td title="${escapeHtml(entry.title)}">${escapeHtml(entry.title)}</td>
    <td>${escapeHtml(entry.noteType)}</td>
    <td title="${escapeHtml(indicatorTitle || entry.indicators)}">${escapeHtml(entry.indicators)}</td>
    <td class="note-preview-cell" title="${escapeHtml(entry.text)}">${escapeHtml(entry.preview)}</td>
    <td title="${escapeHtml(entry.source)}">${escapeHtml(trimRootPath(entry.source))}</td>
  </tr>`;
}

// Render functions

function renderPasswordsPage(searchQuery = '') {
  const summary = document.getElementById('passwordsSummary');
  const stats = document.getElementById('passwordsStats');
  const content = document.getElementById('passwordsContent');
  const failedFiles = passwordsData.failedFiles || [];
  const issuesHtml = buildPasswordParseIssuesHtml(failedFiles);

  if (passwordsData.rows.length === 0) {
    summary.textContent = failedFiles.length > 0
      ? `No passwords found — ${failedFiles.length.toLocaleString()} candidate file(s) skipped`
      : 'No passwords found';
    addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');
    stats.innerHTML = '';
    content.innerHTML = `${issuesHtml}<div class="no-data">No password data available.</div>`;
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
  const baseSummary = showing !== total
    ? `Showing ${showing.toLocaleString()} of ${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`
    : `${total.toLocaleString()} credentials from ${passwordsData.fileCount} file(s)`;
  summary.textContent = failedFiles.length > 0
    ? `${baseSummary} — ${failedFiles.length.toLocaleString()} file(s) skipped`
    : baseSummary;

  addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');

  passwordColumnIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.password.test(h));
  const urlIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  const userIdx = passwordsData.headers.findIndex(h => FIELD_PATTERNS.username.test(h));
  const domains = new Set();
  const usernames = new Set();
  let withPasswords = 0;
  for (const { row } of passwordsData.rows) {
    if (passwordColumnIdx >= 0 && row[passwordColumnIdx]) withPasswords++;
    if (urlIdx >= 0) {
      const domain = extractBaseDomain(extractDomain(row[urlIdx] || ''));
      if (domain) domains.add(domain);
    }
    if (userIdx >= 0 && row[userIdx]) usernames.add(row[userIdx].trim().toLowerCase());
  }

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${domains.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Domains</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${usernames.size.toLocaleString()}</div>
      <div class="data-page-stat-label">Usernames</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${withPasswords.toLocaleString()}</div>
      <div class="data-page-stat-label">With Password</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${failedFiles.length.toLocaleString()}</div>
      <div class="data-page-stat-label">Skipped Files</div>
    </div>
  `;

  let html = `${issuesHtml}<div class="data-table-container"><table class="data-table">`;
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
  const validSessionCount = filtered.filter(r => r.sessionType && r.validity.status === 'valid').length;

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
    ${validSessionCount > 0 ? `<div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth-valid">${validSessionCount.toLocaleString()}</div>
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

function renderAutofillsPage(searchQuery = '') {
  const summary = document.getElementById('autofillsSummary');
  const stats = document.getElementById('autofillsStats');
  const content = document.getElementById('autofillsContent');

  if (autofillsData.entries.length === 0) {
    summary.textContent = 'No autofill data found';
    stats.innerHTML = '';
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

  const emailCount = autofillsData.entries.filter(entry => /email|e-mail/i.test(entry.name) || /@/.test(entry.value)).length;
  const phoneCount = autofillsData.entries.filter(entry => /phone|mobile|tel/i.test(entry.name)).length;
  const nameCount = autofillsData.entries.filter(entry => /first\s*name|last\s*name|full\s*name|^name$/i.test(entry.name)).length;
  const addressCount = autofillsData.entries.filter(entry => /address|street|city|postcode|zip|country/i.test(entry.name)).length;
  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${emailCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Email Fields</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${phoneCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Phone Fields</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${nameCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Name Fields</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${addressCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Address Fields</div>
    </div>
  `;

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

function renderNotesPage(searchQuery = '') {
  const summary = document.getElementById('notesSummary');
  const stats = document.getElementById('notesStats');
  const content = document.getElementById('notesContent');

  if (notesData.entries.length === 0) {
    summary.textContent = 'No notes found';
    stats.innerHTML = '';
    content.innerHTML = '<div class="no-data">No note data available.</div>';
    return;
  }

  let filtered = notesData.entries;
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(entry =>
      entry.title.toLowerCase().includes(q) ||
      entry.noteType.toLowerCase().includes(q) ||
      entry.text.toLowerCase().includes(q) ||
      entry.source.toLowerCase().includes(q)
    );
  }

  notesFiltered = filtered;
  notesShown = Math.min(PAGE_SIZE, filtered.length);

  const total = notesData.entries.length;
  const statsData = summariseNotes(filtered);
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} notes from ${notesData.fileCount} file(s)`
    : `${total.toLocaleString()} notes from ${notesData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${statsData.credentialNotes.toLocaleString()}</div>
      <div class="data-page-stat-label">Credential-Like</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${statsData.walletNotes.toLocaleString()}</div>
      <div class="data-page-stat-label">Wallet Hints</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${statsData.totalUrls.toLocaleString()}</div>
      <div class="data-page-stat-label">URLs</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${statsData.totalEmails.toLocaleString()}</div>
      <div class="data-page-stat-label">Emails</div>
    </div>
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr><th>Title</th><th>Type</th><th>Indicators</th><th>Preview</th><th>Source</th></tr></thead><tbody>';
  html += buildRowsHtml(noteRowBuilder, notesFiltered, 0, notesShown);
  html += '</tbody></table></div>';

  const remaining = notesFiltered.length - notesShown;
  if (remaining > 0) {
    html += buildShowMoreButton(remaining, 'notes');
  }

  content.innerHTML = html;
}

// CSV exports

function exportPasswordsCSV() {
  if (passwordsData.rows.length === 0) return;
  downloadCsvRows('passwords.csv', passwordsData.headers, passwordsData.rows.map(({ row }) => row));
}

function exportCookiesCSV() {
  if (cookiesData.rows.length === 0) return;
  const headers = [...cookiesData.headers, 'Status', 'Session Type'];
  downloadCsvRows('cookies.csv', headers, cookiesData.rows.map(({ row, validity, sessionType }) => {
    const typeLabel = sessionType === 'auth' ? 'Auth' : sessionType === 'session' ? 'Session' : '';
    return [...row, validity.label, typeLabel];
  }));
}

function exportAutofillsCSV() {
  if (autofillsData.entries.length === 0) return;
  downloadCsvRows('autofills.csv', ['Field', 'Value'], autofillsData.entries.map(
    ({ name, value }) => [name, value]
  ));
}

function exportNotesCSV() {
  if (notesData.entries.length === 0) return;
  downloadCsvRows('notes.csv', ['Title', 'Type', 'Indicators', 'Preview', 'URLs', 'Emails', 'Phones', 'Credential Hints', 'Wallet Hints', 'Source'], notesData.entries.map(
    (entry) => [
      entry.title,
      entry.noteType,
      entry.indicators,
      entry.preview,
      (entry.urls || []).join('; '),
      (entry.emails || []).join('; '),
      (entry.phones || []).join('; '),
      entry.credentialHints,
      entry.walletHints,
      entry.source,
    ]
  ));
}

// Show-more handler

function handleShowMore(pageId, contentEl) {
  let filtered, shown, rowBuilder;

  if (pageId === 'passwords') {
    filtered = passwordsFiltered; shown = passwordsShown; rowBuilder = passwordRowBuilder;
  } else if (pageId === 'cookies') {
    filtered = cookiesFiltered; shown = cookiesShown; rowBuilder = cookieRowBuilder;
  } else if (pageId === 'autofills') {
    filtered = autofillsFiltered; shown = autofillsShown; rowBuilder = autofillRowBuilder;
  } else if (pageId === 'notes') {
    filtered = notesFiltered; shown = notesShown; rowBuilder = noteRowBuilder;
  } else {
    return false;
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
  else if (pageId === 'notes') notesShown = nextEnd;

  const btn = contentEl.querySelector('.data-show-more');
  const remaining = filtered.length - nextEnd;
  if (remaining > 0 && btn) {
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)`;
  } else if (btn) {
    btn.remove();
  }

  return true;
}

// Reset

function resetCredentials() {
  passwordsData = { rows: [], headers: [], fileCount: 0, failedFiles: [] };
  cookiesData = { rows: [], headers: [], fileCount: 0 };
  autofillsData = { entries: [], fileCount: 0 };
  notesData = { entries: [], fileCount: 0 };
  passwordsFiltered = []; passwordsShown = 0;
  cookiesFiltered = []; cookiesShown = 0;
  autofillsFiltered = []; autofillsShown = 0;
  notesFiltered = []; notesShown = 0;
  hidePasswords = true;
  passwordColumnIdx = -1;
}

// Init

function initCredentials() {
  const passwordsSearch = document.getElementById('passwordsSearch');
  const passwordsHideCb = document.getElementById('passwordsHidePasswords');
  bindDebouncedInput(passwordsSearch, (value) => renderPasswordsPage(value));

  passwordsHideCb?.addEventListener('change', () => {
    hidePasswords = passwordsHideCb.checked;
    renderPasswordsPage(passwordsSearch?.value || '');
  });

  // Click-to-reveal individual masked passwords
  document.getElementById('passwordsContent')?.addEventListener('click', (e) => {
    const cell = e.target.closest('.password-cell.masked');
    if (!cell) return;
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
  const updateCookies = createDebounced(() => {
    renderCookiesPage(
      cookiesValidOnly?.checked || false,
      cookiesSessionOnly?.checked || false,
      cookiesSearch?.value || ''
    );
  });

  cookiesSearch?.addEventListener('input', updateCookies);
  cookiesValidOnly?.addEventListener('change', updateCookies);
  cookiesSessionOnly?.addEventListener('change', updateCookies);

  const autofillsSearch = document.getElementById('autofillsSearch');
  bindDebouncedInput(autofillsSearch, (value) => renderAutofillsPage(value));

  const notesSearch = document.getElementById('notesSearch');
  bindDebouncedInput(notesSearch, (value) => renderNotesPage(value));

  return {
    load: [loadPasswordsData, loadCookiesData, loadAutofillsData, loadNotesData],
    render: {
      passwords: () => renderPasswordsPage(passwordsSearch?.value || ''),
      cookies: () => renderCookiesPage(cookiesValidOnly?.checked || false, cookiesSessionOnly?.checked || false, cookiesSearch?.value || ''),
      autofills: () => renderAutofillsPage(autofillsSearch?.value || ''),
      notes: () => renderNotesPage(notesSearch?.value || ''),
    },
    exports: {
      exportPasswordsCsv: exportPasswordsCSV,
      exportCookiesCsv: exportCookiesCSV,
      exportAutofillsCsv: exportAutofillsCSV,
      exportNotesCsv: exportNotesCSV,
    },
    showMore: handleShowMore,
    reset: () => {
      resetCredentials();
      if (passwordsSearch) passwordsSearch.value = '';
      if (cookiesSearch) cookiesSearch.value = '';
      if (autofillsSearch) autofillsSearch.value = '';
      if (notesSearch) notesSearch.value = '';
      if (cookiesValidOnly) cookiesValidOnly.checked = false;
      if (cookiesSessionOnly) cookiesSessionOnly.checked = false;
      if (passwordsHideCb) passwordsHideCb.checked = true;
    },
    navIds: {
      passwords: () => passwordsData.rows.length === 0 && (passwordsData.failedFiles || []).length === 0,
      cookies: () => cookiesData.rows.length === 0,
      autofills: () => autofillsData.entries.length === 0,
      notes: () => notesData.entries.length === 0,
    },
  };
}

// Getters

function getPasswordsData() { return passwordsData; }
function getCookiesData() { return cookiesData; }
function getAutofillsData() { return autofillsData; }
function getNotesData() { return notesData; }

export {
  initCredentials,
  getPasswordsData,
  getCookiesData,
  getAutofillsData,
  getNotesData,
};
