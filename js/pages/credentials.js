// Credentials pages: Passwords, Cookies, Autofill, Notes

import { on } from '../core/state.js';
import { loadFileContent } from '../files/extractor.js';
import { escapeHtml } from '../core/utils.js';
import {
  parsePasswordFile,
  parseCookieFile,
  parseAutofillFile,
  COOKIE_HEADERS,
  JSON_COOKIE_HEADERS as COOKIE_HEADERS_NO_SUBDOMAIN,
} from '../transforms/credentials.js';
import { parseNoteArtifact, summariseNotes } from '../analysis/contextArtifacts.js';
import {
  collectHintedNodes,
  checkCookieValidity,
  cookieColumnMap,
  cookieDedupeKey,
  credentialColumnIndices,
  getCaptureContext,
  baseDomainFromUrl,
  decodeNodeCached,
  parseNodeCached,
  showNotification,
} from '../core/shared.js';
import { classifyCookie, hasReplayableValue, isLiveSessionToken } from '../analysis/sessionCookies.js';
import { FIELD_PATTERNS } from '../core/definitions/patterns.js';
import { RECOVERED_PASSWORD_FILE } from '../transforms/shared.js';
import { DATA_PAGE_EMPTY_TEXT } from './registry.js';
import {
  buildNoMatchesHtml,
  countLabel,
  datasetSummary,
  PAGE_SIZE,
  buildShowMoreButton,
  buildRowsHtml,
  bindDebouncedInput,
  createDebounced,
  trimRootPath,
  maskValue,
  addAdjustColumnsBtn,
  downloadCsvRows,
  shapeCookiesCsv,
  shapeNotesCsv,
  sessionTypeLabel,
  createTableSort,
  bindTableSort,
} from './shared.js';

// Auth/SSO subdomains whose base domain doesn't name the consumer service.
const AUTH_SUBDOMAIN_SERVICE = [
  { match: /(^|\.)auth\.streamotion\.com\.au$/i, label: 'Kayo / Binge' },
  { match: /(^|\.)auth\.foxtel\.com\.au$/i, label: 'Foxtel' },
  { match: /(^|\.)login\.microsoftonline\.com$/i, label: 'Microsoft 365' },
  { match: /(^|\.)accounts\.google\.com$/i, label: 'Google' },
  { match: /(^|\.)appleid\.apple\.com$/i, label: 'Apple ID' },
];
const AUTH_PREFIX = /^(auth|login|sso|account|accounts|id|signin|secure)\./i;

// Every password set is folded onto these three; anything else a file carries
// is appended after them as an extra column.
const CANONICAL_PASSWORD_HEADERS = ['URL', 'Username', 'Password'];

function titleCaseLabel(value) {
  return String(value || '').split('.')[0].replace(/[-_]+/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}

function friendlyServiceForUrl(url) {
  const host = baseDomainFromUrl(url) ? extractAuthHost(url) : '';
  if (!host) return '';
  for (const { match, label } of AUTH_SUBDOMAIN_SERVICE) {
    if (match.test(host)) return label;
  }
  if (AUTH_PREFIX.test(host)) {
    const base = baseDomainFromUrl(url);
    return base ? titleCaseLabel(base) : '';
  }
  return '';
}

function extractAuthHost(url) {
  const m = String(url || '').match(/^[a-z][\w+.-]*:\/\/([^/?#]+)/i);
  return m ? m[1].replace(/:\d+$/, '').toLowerCase() : '';
}

// Data stores

let passwordsData = { rows: [], headers: [], fileCount: 0, failedFiles: [] };
let cookiesData = { rows: [], headers: [], fileCount: 0 };
let autofillsData = { entries: [], fileCount: 0 };
let notesData = { entries: [], fileCount: 0 };
let credAnalysis = null;

let passwordsFiltered = [];
let passwordsShown = 0;
let cookiesFiltered = [];
let cookiesShown = 0;
let autofillsFiltered = [];
let autofillsShown = 0;
let notesFiltered = [];
let notesShown = 0;

let hidePasswords = true;
let hideCookieValues = true;
let passwordColumnIdx = -1;
let passwordUrlIdx = -1;
let cookieValueIdx = -1;
// Columns come from the parsed file, so the sort keys are resolved on demand:
// `col<N>` reads that cell, `service` the derived service tag.
const passwordsSort = createTableSort((key) => {
  if (key === 'service') return ({ service }) => service || '';
  const match = /^col(\d+)$/.exec(key);
  if (!match) return null;
  const index = Number(match[1]);
  return ({ row }) => row[index];
});
const cookiesSort = createTableSort((key) => {
  if (key === 'status') return ({ validity }) => validity?.label || '';
  if (key === 'sessionType') return ({ sessionType }) => sessionType || '';
  const match = /^col(\d+)$/.exec(key);
  if (!match) return null;
  const index = Number(match[1]);
  return ({ row }) => row[index];
});

const autofillsSort = createTableSort({ name: (e) => e.name, value: (e) => e.value });
const notesSort = createTableSort({
  title: (e) => e.title,
  type: (e) => e.noteType,
  indicators: (e) => e.indicators,
  preview: (e) => e.preview,
  source: (e) => e.source,
});

let passwordShowService = false;
let passwordHiddenCols = new Set();
let passwordConstantNotes = [];

// A duplicate carries no new cookie, but it can carry columns the kept row
// lacks: a CDP export has no subdomain flag, and the same token is often stored
// under two paths. Fold those in rather than losing them with the row.
function foldCookieDuplicate(target, duplicate, pathIdx) {
  for (let i = 0; i < duplicate.length; i++) {
    const value = duplicate[i];
    if (!value || value === target[i]) continue;
    if (!target[i]) target[i] = value;
    else if (i === pathIdx && !target[i].split('; ').includes(value)) target[i] += `; ${value}`;
  }
}

// The Value column sits at a different index depending on whether the set
// carries a subdomain flag, so it is resolved from the headers, never assumed.
function cookieValueIndex(headers) {
  return (headers || []).findIndex(h => /^value$/i.test(h));
}

// Status and Type are rendered columns, so a search has to reach them. Both are
// short derived strings; joining them per row beats caching a second copy of
// every cookie value.
function cookieDerivedText({ validity, sessionType }) {
  return `${validity?.label || ''} ${sessionTypeLabel(sessionType)}`.toLowerCase();
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
    computePasswordDisplay();
    return;
  }

  const extraHeaders = [];
  const parsedFiles = [];
  const failedFiles = [];
  const fileHashes = new Set();
  let fileCount = 0;

  for (const { node, path } of nodes) {
    const sourcePath = path || node.name;
    try {
      const content = await loadFileContent(node);
      if (!content) {
        failedFiles.push({ path: sourcePath, reason: 'Unreadable or empty file' });
        continue;
      }
      const text = decodeNodeCached(node, content);
      const parsed = parseNodeCached(node, 'password', parsePasswordFile, text, node._parseConfig || null);
      if (!parsed || parsed.rows.length === 0) {
        // A bare password dump has no account columns to fail on; analysis
        // reads it as recovered passwords, so listing it here as unparsed
        // contradicted the panel directly below.
        if (!RECOVERED_PASSWORD_FILE.test(node.name || '')) {
          failedFiles.push({ path: sourcePath, reason: 'No credentials parsed' });
        }
        continue;
      }

      const { urlIdx, userIdx, passIdx } = credentialColumnIndices(parsed.headers);

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
        colMap.set(i, CANONICAL_PASSWORD_HEADERS.length + extraIdx);
      }

      // A format twin (passwords.txt + passwords.tsv) is one source of
      // credentials, not two — the same count the analysis pass reports. Its
      // rows are still merged below, for the extra columns and the source path.
      const fileHash = parsed.rows
        .map(r => `${(r[urlIdx] || '')}\t${(r[userIdx] || '')}\t${(r[passIdx] || '')}`)
        .sort()
        .join('\n');
      if (!fileHashes.has(fileHash)) {
        fileHashes.add(fileHash);
        fileCount++;
      }

      parsedFiles.push({ path: sourcePath, parsed, colMap });
    } catch (err) {
      failedFiles.push({ path: sourcePath, reason: err?.message || 'Failed to read or parse file' });
    }
  }

  const totalCols = CANONICAL_PASSWORD_HEADERS.length + extraHeaders.length;
  const dedupedRows = new Map();
  for (const { path, parsed, colMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const unified = new Array(totalCols).fill('');
      for (const [src, dest] of colMap) {
        unified[dest] = row[src] || '';
      }
      const url = String(unified[0] || '').trim();
      const user = String(unified[1] || '').trim();
      const pass = String(unified[2] || '').trim();
      // URL-only saved-site stubs aren't credentials; the dashboard reports them separately.
      if (url && !user && !pass) continue;
      // Case-fold the site and the username only; the password is compared as
      // captured, so `Pass1` and `pass1` stay two credentials.
      const key = [url.toLowerCase(), user.toLowerCase(), pass]
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

  const headers = [...CANONICAL_PASSWORD_HEADERS, ...extraHeaders];
  const rows = [...dedupedRows.values()].map(({ row, sources }) => ({
    row,
    source: [...sources].join('; '),
  }));

  passwordsData = {
    rows,
    headers,
    fileCount,
    failedFiles,
    stats: summarisePasswordRows(rows, headers),
  };

  computePasswordDisplay();
}

function summarisePasswordRows(rows, headers) {
  const { urlIdx, userIdx, passIdx } = credentialColumnIndices(headers);
  const domains = new Set();
  const usernames = new Set();
  let withPasswords = 0;
  for (const { row } of rows) {
    if (passIdx >= 0 && row[passIdx]) withPasswords++;
    if (urlIdx >= 0) {
      const domain = baseDomainFromUrl(row[urlIdx] || '');
      if (domain) domains.add(domain);
    }
    if (userIdx >= 0 && row[userIdx]) usernames.add(row[userIdx].trim().toLowerCase());
  }
  return { domains: domains.size, usernames: usernames.size, withPasswords };
}

// Column layout depends on the whole dataset, not on the current filter, so it
// is settled once here rather than on every search keystroke. Columns whose
// value is identical on every row (e.g. Software = "Google Chrome (Default)")
// cost width and carry no signal: drop them and surface the constant as a
// caption instead.
function computePasswordDisplay() {
  const { headers, rows } = passwordsData;

  passwordColumnIdx = headers.findIndex(h => FIELD_PATTERNS.password.test(h));
  passwordUrlIdx = headers.findIndex(h => FIELD_PATTERNS.url.test(h));
  // Settled once per dataset: the tag is read by the row builder, the sort and
  // the search, and deriving it three times per row per keystroke is waste.
  for (const entry of rows) {
    entry.service = passwordUrlIdx >= 0 ? friendlyServiceForUrl(entry.row[passwordUrlIdx]) : '';
  }
  passwordShowService = rows.some(({ service }) => service);
  passwordHiddenCols = new Set();
  passwordConstantNotes = [];

  if (rows.length === 0) return;

  for (let c = 0; c < headers.length; c++) {
    if (c === passwordColumnIdx || c === passwordUrlIdx) continue;
    let seen = null, constant = true, nonEmpty = 0;
    for (const { row } of rows) {
      const v = (row[c] || '').trim();
      if (!v) continue;
      nonEmpty++;
      if (seen === null) seen = v;
      else if (v !== seen) { constant = false; break; }
    }
    // An extra column empty on every row is a header the export declared and
    // never filled. The three canonical columns stay: an empty Username column
    // is the finding that none of these credentials named an account.
    if (nonEmpty === 0) {
      if (c >= CANONICAL_PASSWORD_HEADERS.length) passwordHiddenCols.add(c);
      continue;
    }
    if (rows.length > 1 && constant && nonEmpty >= rows.length * 0.7) {
      passwordHiddenCols.add(c);
      passwordConstantNotes.push(`${headers[c]}: ${seen}`);
    }
  }
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
      const text = decodeNodeCached(node, content);
      const parsed = parseNodeCached(node, 'cookie', parseCookieFile, text, node._parseConfig || null);
      if (parsed && parsed.rows.length > 0) {
        fileCount++;
        const columnMap = cookieColumnMap(parsed.headers, parsed.rows[0]?.length || 0);
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
  const domainIdx = headers.findIndex(h => FIELD_PATTERNS.cookieDomain.test(h));
  const pathIdx = headers.findIndex(h => /^path$/i.test(h));
  cookieValueIdx = cookieValueIndex(headers);
  const captureDate = getCaptureContext().date;
  const seenCookies = new Map();

  for (const { parsed, columnMap } of parsedFiles) {
    for (const row of parsed.rows) {
      const dedupeKey = cookieDedupeKey(row, columnMap);
      const normalisedRow = normaliseCookieRow(row, columnMap, includeSubDomain);
      const seenRow = seenCookies.get(dedupeKey);
      if (seenRow) foldCookieDuplicate(seenRow, normalisedRow, pathIdx);
      else seenCookies.set(dedupeKey, normalisedRow);
    }
  }

  // Derived once every fold is in, so a badge can't contradict the expiry,
  // name or domain a duplicate filled in.
  const rows = [...seenCookies.values()].map(row => ({
    row,
    validity: checkCookieValidity(expiresIdx >= 0 ? row[expiresIdx] : null, captureDate),
    sessionType: classifyCookie(nameIdx >= 0 ? row[nameIdx] : '', domainIdx >= 0 ? row[domainIdx] : ''),
    headers,
  }));

  cookiesData = { rows, headers, fileCount, captureDate, stats: summariseCookieRows(rows, headers) };
}

// `liveSession` is every token that would still have logged someone in;
// `liveNoValue` is the part of it whose value never made it out of the browser.
// Bulk decryption failure empties the column for whole cookie sets at a time, so
// those rows evidence a logged-in account but hand over nothing replayable.
function summariseCookieRows(rows, headers) {
  const valueIdx = cookieValueIndex(headers);
  let valid = 0, expired = 0, browserSession = 0, auth = 0, session = 0, liveSession = 0, liveNoValue = 0;
  for (const r of rows) {
    if (r.validity.status === 'valid') valid++;
    else if (r.validity.status === 'expired') expired++;
    else if (r.validity.status === 'session') browserSession++;
    if (r.sessionType === 'auth') auth++;
    else if (r.sessionType === 'session') session++;
    if (isLiveSessionToken(r)) {
      liveSession++;
      if (!hasReplayableValue({ value: valueIdx >= 0 ? r.row[valueIdx] : '' })) liveNoValue++;
    }
  }
  return { valid, expired, browserSession, sessionTokens: auth + session, liveSession, liveNoValue };
}

// Expiry is judged against the case's capture instant. The page loaders and the
// analysis pass run concurrently, so a cookie set loaded before analysis
// published the instant is re-judged against it rather than left reading
// expiry against "now".
function applyCaptureDate(captureDate) {
  const { rows, headers } = cookiesData;
  cookiesData.captureDate = captureDate;
  if (rows.length === 0) return;
  const expiresIdx = headers.findIndex(h => FIELD_PATTERNS.expires.test(h));
  for (const entry of rows) {
    entry.validity = checkCookieValidity(expiresIdx >= 0 ? entry.row[expiresIdx] : null, captureDate);
  }
  cookiesData.stats = summariseCookieRows(rows, headers);
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
      const text = decodeNodeCached(node, content);
      const parsed = parseNodeCached(node, 'autofill', parseAutofillFile, text, node._parseConfig || null);
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

  autofillsData = { entries, fileCount, stats: summariseAutofillEntries(entries) };
}

const EMAIL_FIELD = /e-?mail/i;
// `emailAddress` names an email field, not a postal one. Stripping the email
// half before the address test is the only reliable separator: anchoring fails
// because `email_address`, `email-address` and `Email Address` all read as one
// word to a boundary. A field named the other way round
// (`shippingAddress_email`) is genuinely both and stays in the address count.
const EMAIL_ADDRESS_FIELD = /e-?mail[\s_.-]*address/ig;
const ADDRESS_FIELD = /address|street|city|postcode|zip|country/i;
const ID_FIELD = /(date.?of.?birth|\bdob\b|birth\s*date|licen[cs]e|driver|passport|medicare|tax\s*file|\btfn\b)/i;

function summariseAutofillEntries(entries) {
  let emailCount = 0, emailShaped = 0, phoneCount = 0, nameCount = 0, addressCount = 0, idCount = 0;
  for (const { name, value } of entries) {
    if (EMAIL_FIELD.test(name)) emailCount++;
    else if (value.includes('@')) emailShaped++;
    if (/phone|mobile|tel/i.test(name)) phoneCount++;
    if (/first\s*name|last\s*name|full\s*name|^name$/i.test(name)) nameCount++;
    if (ADDRESS_FIELD.test(name.replace(EMAIL_ADDRESS_FIELD, ''))) addressCount++;
    if (ID_FIELD.test(name)) idCount++;
  }
  return { emailCount, emailShaped, phoneCount, nameCount, addressCount, idCount };
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
      const text = decodeNodeCached(node, content);
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

const REVEAL_HINT = 'Click or press Enter to reveal';

function passwordRowBuilder({ row, service }) {
  let html = '<tr>';
  if (passwordShowService) {
    html += `<td>${service ? `<span class="identity-service-tag">${escapeHtml(service)}</span>` : ''}</td>`;
  }
  for (let i = 0; i < row.length; i++) {
    if (passwordHiddenCols.has(i)) continue;
    const cell = row[i];
    if (hidePasswords && i === passwordColumnIdx) {
      html += `<td class="password-cell masked" title="${REVEAL_HINT}">${escapeHtml(maskValue(cell))}</td>`;
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
      <div class="data-page-warning-title">${failedFiles.length.toLocaleString()} password file(s) could not be parsed</div>
      <ul class="data-page-warning-list">
        ${visible.map(({ path, reason }) => `<li><strong>${escapeHtml(trimRootPath(path))}</strong>${reason ? ` <span>${escapeHtml(reason)}</span>` : ''}</li>`).join('')}
      </ul>
      ${remaining > 0 ? `<div class="data-page-warning-more">${remaining.toLocaleString()} more file(s) omitted</div>` : ''}
    </div>
  `;
}

function buildBarList(items) {
  if (!items || items.length === 0) return '';
  const max = items[0].count || 1;
  let html = '<div class="domain-bars">';
  for (const { value, count } of items) {
    const pct = Math.round((count / max) * 100);
    html += `<div class="domain-bar-row">
      <span class="domain-bar-label" title="${escapeHtml(value)}">${escapeHtml(value)}</span>
      <div class="domain-bar-track"><div class="domain-bar-fill" style="width:${pct}%"></div></div>
      <span class="domain-bar-count">${count.toLocaleString()}</span>
    </div>`;
  }
  html += '</div>';
  return html;
}

function buildFootprintCard(title, detail, extra = '') {
  return `<div class="data-page-finding">
    <div class="data-page-finding-title">${escapeHtml(title)}</div>
    <div class="data-page-finding-more">${detail}</div>
    ${extra}
  </div>`;
}

function buildCredentialFootprintHtml() {
  if (!credAnalysis) return '';
  const recovered = credAnalysis.recoveredPasswords;
  const localNetwork = credAnalysis.localNetwork || [];
  const savedOnly = credAnalysis.urlsWithoutCredentials || 0;
  const namedNoPassword = credAnalysis.accountsWithoutPasswords || 0;
  const onion = credAnalysis.onionCredentials || 0;
  const cards = [];

  if (recovered && recovered.total > 0) {
    const sample = (recovered.sample || []).slice(0, 8)
      .map(p => `<span class="identity-service-tag">${escapeHtml(maskValue(p))}</span>`).join('');
    cards.push(buildFootprintCard(
      'Recovered passwords',
      `${recovered.unique.toLocaleString()} unique plaintext password(s) from ${recovered.fileCount.toLocaleString()} bare dump file(s) with no account context.`,
      sample ? `<div class="identity-service-tags">${sample}</div>` : ''
    ));
  }
  if (namedNoPassword > 0) {
    cards.push(buildFootprintCard('Accounts without a captured password',
      `${namedNoPassword.toLocaleString()} site + username pair(s) with no password value in the log.`));
  }
  if (savedOnly > 0) {
    cards.push(buildFootprintCard('Saved-site footprint',
      `${savedOnly.toLocaleString()} site(s) the victim saved with no captured username or password.`));
  }
  if (onion > 0) {
    cards.push(buildFootprintCard('Tor / .onion credentials',
      `${onion.toLocaleString()} credential domain(s) on the Tor network.`));
  }
  if (localNetwork.length > 0) {
    cards.push(buildFootprintCard('Local network',
      'Credentials for router / NAS / intranet hosts.', buildBarList(localNetwork)));
  }

  return cards.join('');
}

function cookieRowBuilder({ row, validity, sessionType }) {
  let html = '<tr>';
  for (let i = 0; i < row.length; i++) {
    // The title carries the masked string too: a raw token in an attribute is
    // still legible on hover and still lands on the clipboard on a cell click.
    if (hideCookieValues && i === cookieValueIdx) {
      const masked = maskValue(row[i]);
      html += `<td class="masked" title="${escapeHtml(masked)}">${escapeHtml(masked)}</td>`;
      continue;
    }
    html += `<td title="${escapeHtml(row[i])}">${escapeHtml(row[i])}</td>`;
  }
  html += `<td><span class="validity-badge validity-badge-${validity.status}">${escapeHtml(validity.label)}</span></td>`;
  if (sessionType === 'auth' || sessionType === 'session') {
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

function buildNotesPiiGroupHtml(entries) {
  const piiNotes = (entries || []).filter(entry => entry.hasStructuredPii);
  if (piiNotes.length === 0) return '';

  const rows = piiNotes.slice(0, 25).map(entry => `<tr>
    <td title="${escapeHtml(entry.title)}">${escapeHtml(entry.title)}</td>
    <td title="${escapeHtml(entry.indicators)}">${escapeHtml(entry.indicators)}</td>
    <td title="${escapeHtml(entry.source)}">${escapeHtml(trimRootPath(entry.source))}</td>
  </tr>`).join('');

  return `<div class="data-page-finding">
    <div class="data-page-finding-title">Notes containing structured PII</div>
    <div class="data-page-finding-more">${piiNotes.length.toLocaleString()} note(s) hold seed phrases, card numbers, IBANs, crypto addresses, or national IDs.</div>
    <div class="data-table-container"><table class="data-table">
      <thead><tr><th>Title</th><th>Indicators</th><th>Source</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
  </div>`;
}

// Render functions

function renderPasswordsPage(searchQuery = '') {
  const summary = document.getElementById('passwordsSummary');
  const stats = document.getElementById('passwordsStats');
  const content = document.getElementById('passwordsContent');
  const failedFiles = passwordsData.failedFiles || [];
  const issuesHtml = buildPasswordParseIssuesHtml(failedFiles);

  if (passwordsData.rows.length === 0) {
    const footprintHtml = buildCredentialFootprintHtml();
    summary.textContent = failedFiles.length > 0
      ? `No account credentials · ${countLabel(failedFiles.length, 'candidate file')} skipped`
      : footprintHtml ? 'Recovered artifacts only, no account credentials' : '';
    addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');
    stats.innerHTML = '';
    content.innerHTML = footprintHtml
      ? `${issuesHtml}${footprintHtml}`
      : `${issuesHtml}<div class="no-data">${DATA_PAGE_EMPTY_TEXT.passwords}</div>`;
    return;
  }

  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    passwordsFiltered = passwordsData.rows.filter(({ row, service }) =>
      row.some(cell => cell.toLowerCase().includes(q)) ||
      (passwordShowService && service.toLowerCase().includes(q))
    );
  } else {
    passwordsFiltered = passwordsData.rows;
  }
  passwordsFiltered = passwordsSort.apply(passwordsFiltered);

  passwordsShown = Math.min(PAGE_SIZE, passwordsFiltered.length);

  const total = passwordsData.rows.length;
  const showing = passwordsFiltered.length;
  // Rows here are per site + username + password and include accounts with no
  // captured password; unique credentials is the dashboard's narrower count.
  const unique = credAnalysis?.uniqueCredentials || 0;
  const uniquePart = unique > 0 ? ` (${unique.toLocaleString()} unique credentials)` : '';
  const baseSummary = showing !== total
    ? `Showing ${showing.toLocaleString()} of ${total.toLocaleString()} rows${uniquePart} from ${passwordsData.fileCount} file(s)`
    : `${total.toLocaleString()} rows${uniquePart} from ${passwordsData.fileCount} file(s)`;
  summary.textContent = failedFiles.length > 0
    ? `${baseSummary} (${failedFiles.length.toLocaleString()} file(s) skipped)`
    : baseSummary;

  addAdjustColumnsBtn(summary, '_passwordFileHint', 'credentials');

  const constantCaption = passwordConstantNotes.length
    ? `<div class="data-table-caption">${escapeHtml(passwordConstantNotes.join('   ·   '))}</div>`
    : '';

  const cached = passwordsData.stats || { domains: 0, usernames: 0, withPasswords: 0 };

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.domains.toLocaleString()}</div>
      <div class="data-page-stat-label">Domains</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.usernames.toLocaleString()}</div>
      <div class="data-page-stat-label">Usernames</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${cached.withPasswords.toLocaleString()}</div>
      <div class="data-page-stat-label">With Password</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${failedFiles.length.toLocaleString()}</div>
      <div class="data-page-stat-label">Skipped Files</div>
    </div>
  `;

  let html = `${issuesHtml}${buildCredentialFootprintHtml()}${constantCaption}<div class="data-table-container"><table class="data-table">`;
  html += '<thead><tr>';
  if (passwordShowService) html += passwordsSort.th('service', 'Service');
  for (let c = 0; c < passwordsData.headers.length; c++) {
    if (passwordHiddenCols.has(c)) continue;
    html += passwordsSort.th(`col${c}`, passwordsData.headers[c]);
  }
  html += '</tr></thead><tbody data-page-rows>';
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
  if (sessionOnly) filtered = filtered.filter(r => r.sessionType === 'auth' || r.sessionType === 'session');
  if (searchQuery) {
    const q = searchQuery.toLowerCase();
    filtered = filtered.filter(r =>
      r.row.some(cell => cell.toLowerCase().includes(q)) || cookieDerivedText(r).includes(q)
    );
  }

  cookiesFiltered = cookiesSort.apply(filtered);
  cookiesShown = Math.min(PAGE_SIZE, filtered.length);

  const filterActive = validOnly || sessionOnly || !!searchQuery;
  const cached = cookiesData.stats || { valid: 0, expired: 0, browserSession: 0, sessionTokens: 0, liveSession: 0, liveNoValue: 0 };
  const shown = filterActive ? summariseCookieRows(filtered, cookiesData.headers) : cached;
  const replayable = shown.liveSession - shown.liveNoValue;

  const totalCookies = cookiesData.rows.length;
  summary.textContent = datasetSummary({ shown: filtered.length, total: totalCookies, singular: 'cookie', fileCount: cookiesData.fileCount });

  addAdjustColumnsBtn(summary, '_cookieFileHint', 'cookies');

  if (cookiesFiltered.length === 0) {
    stats.innerHTML = '';
    content.innerHTML = buildNoMatchesHtml('cookies');
    return;
  }

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-valid">${shown.valid.toLocaleString()}</div>
      <div class="data-page-stat-label">Valid</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-expired">${shown.expired.toLocaleString()}</div>
      <div class="data-page-stat-label">Expired</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-session">${shown.browserSession.toLocaleString()}</div>
      <div class="data-page-stat-label">Browser session</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value cookie-auth">${shown.sessionTokens.toLocaleString()}</div>
      <div class="data-page-stat-label">Session tokens</div>
    </div>
    ${shown.liveSession > 0 ? `<div class="data-page-stat" title="Session tokens live at capture — unexpired, or browser-session cookies carrying no expiry — whose value was captured, so they could be replayed.">
      <div class="data-page-stat-value cookie-auth-valid">${replayable.toLocaleString()}</div>
      <div class="data-page-stat-label">Live sessions</div>
    </div>` : ''}
    ${shown.liveNoValue > 0 ? `<div class="data-page-stat" title="Live session tokens whose value was not captured: evidence the account was logged in, but nothing that can be replayed.">
      <div class="data-page-stat-value">${shown.liveNoValue.toLocaleString()}</div>
      <div class="data-page-stat-label">Live, no value</div>
    </div>` : ''}
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += '<thead><tr>';
  for (let c = 0; c < cookiesData.headers.length; c++) {
    html += cookiesSort.th(`col${c}`, cookiesData.headers[c]);
  }
  html += `${cookiesSort.th('status', 'Status')}${cookiesSort.th('sessionType', 'Type')}</tr></thead><tbody data-page-rows>`;
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

  autofillsFiltered = autofillsSort.apply(filtered);
  autofillsShown = Math.min(PAGE_SIZE, filtered.length);

  const total = autofillsData.entries.length;
  summary.textContent = datasetSummary({ shown: filtered.length, total, singular: 'entry', plural: 'entries', fileCount: autofillsData.fileCount });

  addAdjustColumnsBtn(summary, '_autofillHint', 'autofill');

  if (autofillsFiltered.length === 0) {
    stats.innerHTML = '';
    content.innerHTML = buildNoMatchesHtml('autofill entries');
    return;
  }

  // Counted over the rows on screen, not the whole dataset.
  const shown = searchQuery
    ? summariseAutofillEntries(filtered)
    : (autofillsData.stats || { emailCount: 0, emailShaped: 0, phoneCount: 0, nameCount: 0, addressCount: 0, idCount: 0 });
  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${shown.emailCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Email fields</div>
    </div>
    ${shown.emailShaped > 0 ? `<div class="data-page-stat" title="Fields not named for email whose stored value is an address — sign-in boxes named loginfmt, identifier or username.">
      <div class="data-page-stat-value">${shown.emailShaped.toLocaleString()}</div>
      <div class="data-page-stat-label">Email-shaped values</div>
    </div>` : ''}
    <div class="data-page-stat">
      <div class="data-page-stat-value">${shown.phoneCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Phone fields</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${shown.nameCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Name fields</div>
    </div>
    <div class="data-page-stat">
      <div class="data-page-stat-value">${shown.addressCount.toLocaleString()}</div>
      <div class="data-page-stat-label">Address fields</div>
    </div>
    ${shown.idCount > 0 ? `<div class="data-page-stat">
      <div class="data-page-stat-value">${shown.idCount.toLocaleString()}</div>
      <div class="data-page-stat-label">ID / DOB fields</div>
    </div>` : ''}
  `;

  let html = '<div class="data-table-container"><table class="data-table">';
  html += `<thead><tr>${autofillsSort.th('name', 'Field')}${autofillsSort.th('value', 'Value')}</tr></thead><tbody data-page-rows>`;
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

  notesFiltered = notesSort.apply(filtered);
  notesShown = Math.min(PAGE_SIZE, filtered.length);

  const total = notesData.entries.length;
  const statsData = summariseNotes(filtered);
  summary.textContent = filtered.length !== total
    ? `Showing ${filtered.length.toLocaleString()} of ${total.toLocaleString()} notes from ${notesData.fileCount} file(s)`
    : `${total.toLocaleString()} notes from ${notesData.fileCount} file(s)`;

  stats.innerHTML = `
    <div class="data-page-stat">
      <div class="data-page-stat-value">${statsData.structuredPiiNotes.toLocaleString()}</div>
      <div class="data-page-stat-label">Structured PII</div>
    </div>
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

  let html = buildNotesPiiGroupHtml(filtered);
  html += '<div class="data-table-container"><table class="data-table">';
  html += `<thead><tr>${notesSort.th('title', 'Title')}${notesSort.th('type', 'Type')}${notesSort.th('indicators', 'Indicators')}${notesSort.th('preview', 'Preview')}${notesSort.th('source', 'Source')}</tr></thead><tbody data-page-rows>`;
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
  const { headers, rows } = shapeCookiesCsv(cookiesData);
  downloadCsvRows('cookies.csv', headers, rows);
}

function exportAutofillsCSV() {
  if (autofillsData.entries.length === 0) return;
  downloadCsvRows('autofills.csv', ['Field', 'Value'], autofillsData.entries.map(
    ({ name, value }) => [name, value]
  ));
}

function exportNotesCSV() {
  if (notesData.entries.length === 0) return;
  const { headers, rows } = shapeNotesCsv(notesData);
  downloadCsvRows('notes.csv', headers, rows);
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

  // The paged table isn't always the first one on the page — the notes page
  // renders a structured-PII group above it.
  const tbody = contentEl.querySelector('tbody[data-page-rows]');
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
    btn.textContent = `Show ${Math.min(remaining, PAGE_SIZE).toLocaleString()} more (${remaining.toLocaleString()} remaining)`;
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
  credAnalysis = null;
  passwordsFiltered = []; passwordsShown = 0;
  cookiesFiltered = []; cookiesShown = 0;
  passwordsSort.reset();
  cookiesSort.reset();
  autofillsFiltered = []; autofillsShown = 0;
  notesFiltered = []; notesShown = 0;
  autofillsSort.reset();
  notesSort.reset();
  hidePasswords = true;
  hideCookieValues = true;
  passwordColumnIdx = -1;
  passwordUrlIdx = -1;
  cookieValueIdx = -1;
  passwordShowService = false;
  passwordHiddenCols = new Set();
  passwordConstantNotes = [];
}

// Init

function initCredentials() {
  const passwordsSearch = document.getElementById('passwordsSearch');
  const passwordsHideCb = document.getElementById('passwordsHidePasswords');
  bindDebouncedInput(passwordsSearch, (value) => renderPasswordsPage(value));

  on('analysis:credentials', (payload) => {
    credAnalysis = payload || null;
    if (document.getElementById('pagePasswords')?.classList.contains('active')) {
      renderPasswordsPage(passwordsSearch?.value || '');
    }
  });

  passwordsHideCb?.addEventListener('change', () => {
    hidePasswords = passwordsHideCb.checked;
    renderPasswordsPage(passwordsSearch?.value || '');
  });

  // Reveal one masked password: click it, or focus it with the arrow keys and
  // press Enter or Space.
  const revealPassword = (e) => {
    if (e.type === 'keydown' && e.key !== 'Enter' && e.key !== ' ') return;
    const cell = e.target.closest('.password-cell.masked');
    if (!cell) return;
    // The event is spent on the reveal; without this the cell-copy handler sees
    // an unmasked cell a moment later and puts the password on the clipboard.
    e.stopPropagation();
    if (e.type === 'keydown') e.preventDefault();
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
          cell.title = REVEAL_HINT;
          cell.classList.remove('revealed');
          cell.classList.add('masked');
        }
      }, 5000);
    }
  };

  const passwordsContent = document.getElementById('passwordsContent');
  passwordsContent?.addEventListener('click', revealPassword);
  passwordsContent?.addEventListener('keydown', revealPassword);

  const cookiesSearch = document.getElementById('cookiesSearch');
  const cookiesValidOnly = document.getElementById('cookiesValidOnly');
  const cookiesSessionOnly = document.getElementById('cookiesSessionOnly');
  const cookiesHideValuesCb = document.getElementById('cookiesHideValues');
  const renderCookies = () => renderCookiesPage(
    cookiesValidOnly?.checked || false,
    cookiesSessionOnly?.checked || false,
    cookiesSearch?.value || ''
  );
  const updateCookies = createDebounced(renderCookies);

  cookiesSearch?.addEventListener('input', updateCookies);
  cookiesValidOnly?.addEventListener('change', updateCookies);
  cookiesSessionOnly?.addEventListener('change', updateCookies);
  cookiesHideValuesCb?.addEventListener('change', () => {
    hideCookieValues = cookiesHideValuesCb.checked;
    renderCookies();
  });

  bindTableSort('passwordsContent', passwordsSort, () => renderPasswordsPage(passwordsSearch?.value || ''));
  bindTableSort('cookiesContent', cookiesSort, renderCookies);

  on('analysis:capture', ({ date }) => {
    const loaded = cookiesData.captureDate;
    if ((loaded ? loaded.getTime() : null) === (date ? date.getTime() : null)) return;
    applyCaptureDate(date);
    if (document.getElementById('pageCookies')?.classList.contains('active')) {
      renderCookies();
    }
  });

  const autofillsSearch = document.getElementById('autofillsSearch');
  bindDebouncedInput(autofillsSearch, (value) => renderAutofillsPage(value));

  const notesSearch = document.getElementById('notesSearch');
  bindDebouncedInput(notesSearch, (value) => renderNotesPage(value));

  bindTableSort('autofillsContent', autofillsSort, () => renderAutofillsPage(autofillsSearch?.value || ''));
  bindTableSort('notesContent', notesSort, () => renderNotesPage(notesSearch?.value || ''));

  for (const [id, handler] of Object.entries({
    exportPasswordsCsv: exportPasswordsCSV,
    exportCookiesCsv: exportCookiesCSV,
    exportAutofillsCsv: exportAutofillsCSV,
    exportNotesCsv: exportNotesCSV,
  })) {
    document.getElementById(id)?.addEventListener('click', handler);
  }

  return {
    load: [loadPasswordsData, loadCookiesData, loadAutofillsData, loadNotesData],
    render: {
      passwords: () => renderPasswordsPage(passwordsSearch?.value || ''),
      cookies: renderCookies,
      autofills: () => renderAutofillsPage(autofillsSearch?.value || ''),
      notes: () => renderNotesPage(notesSearch?.value || ''),
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
      if (cookiesHideValuesCb) cookiesHideValuesCb.checked = true;
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
