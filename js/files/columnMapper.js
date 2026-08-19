// Interactive column mapper modal for files with non-standard formats.
// Roles are configurable per file type (credentials, cookies, history, autofill).

import { escapeHtml } from '../core/utils.js';
import {
  detectFormat,
  inferColumnRoles,
  makeSplitFn,
  maxColumnCount,
  splitLines,
} from '../transforms/delimited.js';
import { normaliseSeparators, normaliseText } from '../transforms/shared.js';
import { parseAutofillFile, parseCookieFile, parsePasswordFile } from '../transforms/credentials.js';
import { parseHistoryFile } from '../transforms/structured.js';
import { countLabel } from '../pages/shared.js';
import { openModal, closeModal } from '../core/modal.js';

const ROLE_SETS = {
  credentials: [
    { value: 'url', label: 'URL' },
    { value: 'username', label: 'Username' },
    { value: 'password', label: 'Password' },
    { value: 'email', label: 'Email' },
    { value: 'notes', label: 'Notes' },
  ],
  cookies: [
    { value: 'domain', label: 'Domain' },
    { value: 'name', label: 'Name' },
    { value: 'value', label: 'Value' },
    { value: 'path', label: 'Path' },
    { value: 'secure', label: 'Secure' },
    { value: 'expiration', label: 'Expiration' },
  ],
  history: [
    { value: 'url', label: 'URL' },
    { value: 'title', label: 'Title' },
    { value: 'visitCount', label: 'Visits' },
    { value: 'lastVisit', label: 'Last Visit' },
  ],
  autofill: [
    { value: 'field', label: 'Field Name' },
    { value: 'value', label: 'Value' },
  ],
};

// Each consumer of a mapping normalises the text its own way before parsing.
// The preview, the inference and the parse have to index one line list, or a
// header toggle silently drops a record the analyst just read in the preview.
const CONFIG_NORMALISERS = {
  credentials: text => normaliseSeparators(normaliseText(text)),
  cookies: text => normaliseText(text),
  history: text => normaliseText(text),
  autofill: text => normaliseSeparators(normaliseText(text)),
};

const PARSERS = {
  credentials: parsePasswordFile,
  cookies: parseCookieFile,
  history: parseHistoryFile,
  autofill: parseAutofillFile,
};

const HEADER_ALIASES = {
  url: ['url', 'uri', 'link', 'origin', 'originurl', 'host', 'hostname', 'site', 'website', 'webaddress', 'page', 'loginpage', 'address'],
  username: ['username', 'user', 'login', 'loginname', 'loginid', 'account', 'accountname', 'userid'],
  password: ['password', 'pass', 'passwd', 'pwd', 'passcode', 'pin'],
  email: ['email', 'emailaddress', 'mail'],
  notes: ['notes', 'note', 'comment', 'comments'],
  domain: ['domain', 'host', 'hostkey', 'hostname', 'site'],
  name: ['name', 'cookiename', 'key'],
  value: ['value', 'cookievalue', 'content'],
  path: ['path'],
  secure: ['secure', 'issecure', 'httponly'],
  expiration: ['expiration', 'expirationdate', 'expires', 'expiresutc', 'expiry', 'expirydate'],
  title: ['title', 'pagetitle'],
  visitCount: ['visitcount', 'visits', 'count'],
  lastVisit: ['lastvisit', 'lastvisited', 'lastvisittime', 'visittime', 'date', 'time', 'timestamp'],
  field: ['field', 'fieldname', 'name', 'key'],
};

const BOOL_VALUE = /^(?:true|false)$/i;
const HOST_VALUE = /^\.?[a-z0-9-]+(?:\.[a-z0-9-]+)+\.?$/i;
const URL_VALUE = /^(?:[a-z][a-z0-9+.-]*:\/\/|www\.)/i;
const DATE_VALUE = /^(?:\d{4}-\d{2}-\d{2}|\d{1,2}[./-]\d{1,2}[./-]\d{2,4})/;
const SMALL_INTEGER = /^\d{1,6}$/;
const DESCRIPTOR_LIMIT = 40;
// A dropdown per column stops being a way to read a file long before this, and
// a JSON export read as comma-delimited runs to tens of thousands of columns —
// enough table to lock the tab up while it builds. Columns past the limit keep
// whatever the parse makes of them.
const PREVIEW_COLUMN_LIMIT = 64;

let mapperResolver = null;
let currentText = '';
let currentFileType = 'credentials';
let currentRoles = ROLE_SETS.credentials;
let detectedDelimiter = '\t';
let detectedTrimLines = true;
let detectedDropColumns = [];
const manualRoles = new Map();
let manualDelimiter = null;
let previewTruncated = false;

let elModal, elRawPreview, elTableContainer, elHasHeader, elCustomInput, elFileName, elApply, elStatus;

function getSelectedDelimiter() {
  const checked = elModal.querySelector('input[name="mapperDelimiter"]:checked');
  if (!checked) return '\t';
  if (checked.value === 'custom') return elCustomInput.value;
  return checked.value;
}

function setDelimiterRadio(delimiter) {
  const radios = elModal.querySelectorAll('input[name="mapperDelimiter"]');
  let matched = false;
  for (const r of radios) {
    if (r.value === delimiter) { r.checked = true; matched = true; break; }
  }
  if (!matched) {
    const customRadio = elModal.querySelector('input[name="mapperDelimiter"][value="custom"]');
    if (customRadio) {
      customRadio.checked = true;
      elCustomInput.value = delimiter;
    }
  }
}

function setStatus(message, tone = '') {
  if (!elStatus) return;
  elStatus.textContent = message || '';
  elStatus.classList.toggle('mapper-status-error', tone === 'error');
}

// Only the detected delimiter carries the index space the detector settled on;
// any other choice is read in the trimmed space parseWithConfig defaults to.
function activeTrimLines(delimiter) {
  return delimiter === detectedDelimiter ? detectedTrimLines : true;
}

function normaliseHeaderCell(value) {
  return String(value || '').trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function rolesFromHeader(cells, roles) {
  const map = {};
  const taken = new Set();
  for (let i = 0; i < cells.length; i++) {
    const cell = normaliseHeaderCell(cells[i]);
    if (!cell) continue;
    const role = roles.find(r => !taken.has(r.value) && HEADER_ALIASES[r.value]?.includes(cell));
    if (!role) continue;
    map[i] = role.value;
    taken.add(role.value);
  }
  return map;
}

function columnStats(rows, colCount) {
  const stats = Array.from({ length: colCount }, () => ({
    total: 0, chars: 0, bool: 0, path: 0, host: 0, urlLike: 0, time: 0, smallInt: 0,
  }));

  for (const cells of rows) {
    for (let i = 0; i < colCount && i < cells.length; i++) {
      const val = cells[i].trim();
      if (!val) continue;
      const s = stats[i];
      s.total++;
      s.chars += val.length;
      if (BOOL_VALUE.test(val)) s.bool++;
      if (val.startsWith('/')) s.path++;
      if (!val.includes('@') && HOST_VALUE.test(val)) s.host++;
      if (URL_VALUE.test(val) || (!val.includes('@') && HOST_VALUE.test(val))) s.urlLike++;
      if (DATE_VALUE.test(val) || (/^\d+$/.test(val) && (val.length >= 9 || val === '0'))) s.time++;
      else if (SMALL_INTEGER.test(val)) s.smallInt++;
    }
  }

  return stats;
}

function share(stat, key) {
  return stat.total > 0 ? stat[key] / stat.total : 0;
}

function meanLength(stat) {
  return stat.total > 0 ? stat.chars / stat.total : 0;
}

function findColumn(stats, predicate) {
  for (let i = 0; i < stats.length; i++) {
    if (stats[i].total > 0 && predicate(stats[i], i)) return i;
  }
  return -1;
}

// Netscape cookie exports: host, [include subdomains], path, secure, expiry,
// name, value. The subdomain flag has no role of its own, so the secure flag is
// the last boolean column rather than the first.
function inferCookieRoles(stats) {
  const map = {};
  const bools = [];
  for (let i = 0; i < stats.length; i++) {
    if (stats[i].total > 0 && share(stats[i], 'bool') > 0.8) bools.push(i);
  }

  const taken = new Set(bools);
  const pathCol = findColumn(stats, (s, i) => !taken.has(i) && share(s, 'path') > 0.8);
  if (pathCol >= 0) taken.add(pathCol);
  const domainCol = findColumn(stats, (s, i) => !taken.has(i) && share(s, 'host') > 0.6);
  if (domainCol >= 0) taken.add(domainCol);
  const expiryCol = findColumn(stats, (s, i) => !taken.has(i) && share(s, 'time') > 0.8);
  if (expiryCol >= 0) taken.add(expiryCol);

  if (domainCol >= 0) map[domainCol] = 'domain';
  if (pathCol >= 0) map[pathCol] = 'path';
  if (bools.length) map[bools[bools.length - 1]] = 'secure';
  if (expiryCol >= 0) map[expiryCol] = 'expiration';

  const rest = [];
  for (let i = 0; i < stats.length; i++) {
    if (!taken.has(i) && stats[i].total > 0) rest.push(i);
  }
  if (rest.length === 1) {
    map[rest[0]] = 'value';
  } else if (rest.length > 1) {
    // The value is the wide column; the name sits beside it.
    const valueCol = rest.reduce((a, b) => (meanLength(stats[b]) > meanLength(stats[a]) ? b : a));
    map[valueCol] = 'value';
    map[rest.find(i => i !== valueCol)] = 'name';
  }

  return map;
}

function inferHistoryRoles(stats) {
  const map = {};
  const taken = new Set();

  const urlCol = findColumn(stats, s => share(s, 'urlLike') > 0.6);
  if (urlCol >= 0) { map[urlCol] = 'url'; taken.add(urlCol); }
  const visitCol = findColumn(stats, (s, i) => !taken.has(i) && share(s, 'time') > 0.8);
  if (visitCol >= 0) { map[visitCol] = 'lastVisit'; taken.add(visitCol); }
  const countCol = findColumn(stats, (s, i) => !taken.has(i) && share(s, 'smallInt') > 0.8);
  if (countCol >= 0) { map[countCol] = 'visitCount'; taken.add(countCol); }
  const titleCol = findColumn(stats, (s, i) => !taken.has(i));
  if (titleCol >= 0) map[titleCol] = 'title';

  return map;
}

function inferAutofillRoles(stats) {
  const populated = [];
  for (let i = 0; i < stats.length; i++) {
    if (stats[i].total > 0) populated.push(i);
  }
  if (populated.length < 2) return {};

  const valueCol = populated.slice(1).reduce((a, b) => (meanLength(stats[b]) > meanLength(stats[a]) ? b : a));
  return { [populated[0]]: 'field', [valueCol]: 'value' };
}

function inferRoles(lines, delimiter, hasHeader) {
  const splitFn = makeSplitFn(delimiter);
  if (hasHeader && lines.length) {
    const byHeader = rolesFromHeader(splitFn(lines[0]), currentRoles);
    if (Object.keys(byHeader).length >= 2) return byHeader;
  }

  if (currentFileType === 'credentials') {
    return inferColumnRoles(lines, delimiter, hasHeader).columnMap;
  }

  const sample = (hasHeader ? lines.slice(1) : lines).slice(0, 200).map(l => splitFn(l));
  if (sample.length === 0) return {};
  const stats = columnStats(sample, Math.max(...sample.map(r => r.length)));

  if (currentFileType === 'cookies') return inferCookieRoles(stats);
  if (currentFileType === 'history') return inferHistoryRoles(stats);
  return inferAutofillRoles(stats);
}

// Every column the parse will emit needs a role here. Where inference finds
// nothing the roles are laid down in order: an untouched Apply is then at worst
// wrong-order, never an empty table.
function defaultColumnMap(inferred, dropColumns, colCount) {
  const valid = new Set(currentRoles.map(r => r.value));
  const map = {};
  let matched = 0;

  for (let i = 0; i < colCount; i++) {
    const role = inferred[i];
    if (dropColumns.has(i) || !valid.has(role)) continue;
    map[i] = role;
    matched++;
  }
  if (matched > 0) return map;

  let slot = 0;
  for (let i = 0; i < colCount; i++) {
    if (dropColumns.has(i)) continue;
    if (currentRoles[slot]) map[i] = currentRoles[slot].value;
    slot++;
  }
  return map;
}

// Screen reader users get one dropdown per column with nothing but its position
// to tell them apart, so name each after the content it governs. Banner lines
// carry no columns, so a word from one would name the wrong thing.
function columnDescriptor(rows, index) {
  let fallback = '';
  for (const row of rows) {
    const cell = (row[index] || '').trim();
    if (!cell) continue;
    if (/[a-z0-9]/i.test(cell)) return truncateDescriptor(cell);
    if (!fallback) fallback = cell;
  }
  return truncateDescriptor(fallback);
}

function truncateDescriptor(value) {
  return value.length > DESCRIPTOR_LIMIT ? `${value.slice(0, DESCRIPTOR_LIMIT)}…` : value;
}

// A role the analyst picked belongs to the columns it was picked in. Another
// delimiter is another set of columns, so the choices go with it — but the
// header toggle leaves them standing.
function applyManualRoles(columnMap, delimiter, colCount) {
  if (manualRoles.size === 0) return false;
  if (delimiter !== manualDelimiter) {
    manualRoles.clear();
    return true;
  }

  let dropped = false;
  for (const [col, role] of manualRoles) {
    if (col < colCount) columnMap[col] = role;
    else { manualRoles.delete(col); dropped = true; }
  }
  return dropped;
}

// announce: the redraw came from the analyst changing the delimiter or the
// header toggle, which rebuilds every dropdown under them without a word.
function renderPreviewTable(announce = false) {
  const delimiter = getSelectedDelimiter();
  if (elApply) elApply.disabled = !delimiter;
  previewTruncated = false;
  setStatus('');
  if (!delimiter) {
    elTableContainer.innerHTML = '<div class="no-data">Enter a custom delimiter</div>';
    return;
  }

  const hasHeader = elHasHeader.checked;
  const trimLines = activeTrimLines(delimiter);
  const splitFn = makeSplitFn(delimiter);
  const lines = splitLines(currentText, trimLines);
  const previewLines = lines.slice(0, 15);

  if (previewLines.length === 0) {
    if (elApply) elApply.disabled = true;
    elTableContainer.innerHTML = '<div class="no-data">No data to preview</div>';
    return;
  }

  const allRows = previewLines.map(l => splitFn(l));
  // The parse sizes itself off a wider sample than the preview shows; take the
  // same width so every emitted column gets a dropdown.
  const colCount = Math.max(maxColumnCount(currentText, delimiter, trimLines), ...allRows.map(r => r.length));
  const shownCols = Math.min(colCount, PREVIEW_COLUMN_LIMIT);
  previewTruncated = shownCols < colCount;

  const inferred = inferRoles(lines, delimiter, hasHeader);
  const dropColumns = new Set(delimiter === detectedDelimiter ? detectedDropColumns : []);
  const columnMap = defaultColumnMap(inferred, dropColumns, colCount);
  const rolesReset = applyManualRoles(columnMap, delimiter, colCount);
  const fullRows = allRows.filter(r => r.length === colCount);
  const descriptorRows = fullRows.length ? fullRows : allRows;

  const notes = [];
  if (colCount < 2) notes.push('One column: this delimiter does not split the file.');
  else if (announce) notes.push(`${countLabel(colCount, 'column')}.`);
  if (shownCols < colCount) notes.push(`Roles are shown for the first ${countLabel(shownCols, 'column')}; the rest are kept as the parse reads them.`);
  if (rolesReset) notes.push('Column roles re-detected.');
  setStatus(notes.join(' '));

  let html = '<table class="data-table mapper-preview-table" aria-label="Column role mapping preview"><thead><tr>';

  for (let i = 0; i < shownCols; i++) {
    const selected = columnMap[i] || 'skip';
    const descriptor = columnDescriptor(descriptorRows, i);
    const label = `Role for column ${i + 1}${descriptor ? `: ${descriptor}` : ''}`;

    html += `<th scope="col"><select class="mapper-role-select" data-col="${i}" aria-label="${escapeHtml(label)}">`;
    for (const role of currentRoles) {
      const sel = selected === role.value ? ' selected' : '';
      html += `<option value="${role.value}"${sel}>${escapeHtml(role.label)}</option>`;
    }
    html += `<option value="skip"${selected === 'skip' ? ' selected' : ''}>(Skip)</option>`;
    html += '</select></th>';
  }
  html += '</tr>';

  // Show original header row if toggled on
  if (hasHeader && allRows.length > 0) {
    html += '<tr class="mapper-original-header">';
    for (let i = 0; i < shownCols; i++) {
      html += `<td class="mapper-orig-th">${escapeHtml((allRows[0][i] || '').trim())}</td>`;
    }
    html += '</tr>';
  }
  html += '</thead><tbody>';

  const startIdx = hasHeader ? 1 : 0;
  const dataRows = allRows.slice(startIdx, startIdx + 10);
  for (const row of dataRows) {
    html += '<tr>';
    for (let i = 0; i < shownCols; i++) {
      html += `<td>${escapeHtml((row[i] || '').trim())}</td>`;
    }
    html += '</tr>';
  }

  html += '</tbody></table>';
  elTableContainer.innerHTML = html;
}

function handleApply() {
  const delimiter = getSelectedDelimiter();
  if (!delimiter) return;
  const hasHeaderRow = elHasHeader.checked;
  const selects = elTableContainer.querySelectorAll('.mapper-role-select');
  const columnMap = {};

  selects.forEach(sel => {
    const col = parseInt(sel.dataset.col, 10);
    columnMap[col] = sel.value;
  });

  closeMapper({ delimiter, hasHeaderRow, columnMap });
}

function closeMapper(result) {
  elModal.classList.remove('visible');
  if (mapperResolver) {
    mapperResolver(result);
    mapperResolver = null;
  }
  currentText = '';
}

// fileType: 'credentials' | 'cookies' | 'history' | 'autofill'
function openColumnMapper(text, fileName, fileType) {
  // A second open before the first resolves would orphan the prior awaiter:
  // settle it as cancelled and tear down the modal before reopening.
  if (mapperResolver) closeMapper(null);
  return new Promise((resolve) => {
    mapperResolver = resolve;
    currentFileType = ROLE_SETS[fileType] ? fileType : 'credentials';
    currentRoles = ROLE_SETS[currentFileType];
    currentText = CONFIG_NORMALISERS[currentFileType](text || '');
    manualRoles.clear();
    manualDelimiter = null;

    if (elFileName) elFileName.textContent = fileName || 'Unknown file';

    const rawLines = currentText.split('\n').slice(0, 10);
    elRawPreview.textContent = rawLines.join('\n');

    const format = detectFormat(currentText);
    if (format && format.type === 'delimited') {
      detectedDelimiter = format.delimiter;
      detectedTrimLines = format.trimLines !== false;
      detectedDropColumns = format.dropColumns || [];
      setDelimiterRadio(format.delimiter);
      elHasHeader.checked = format.hasHeaderRow || false;
    } else {
      detectedDelimiter = '\t';
      detectedTrimLines = true;
      detectedDropColumns = [];
      setDelimiterRadio('\t');
      elHasHeader.checked = false;
    }

    renderPreviewTable();
    openModal(elModal, { onDismiss: () => closeMapper(null) });
  });
}

function initColumnMapper() {
  elModal = document.getElementById('columnMapperModal');
  if (!elModal) return;

  elRawPreview = document.getElementById('mapperRawPreview');
  elTableContainer = document.getElementById('mapperTableContainer');
  elHasHeader = document.getElementById('mapperHasHeader');
  elCustomInput = document.getElementById('mapperCustomDelimiter');
  elFileName = document.getElementById('mapperFileName');
  elApply = document.getElementById('mapperApply');

  elStatus = document.createElement('div');
  elStatus.className = 'mapper-status';
  elStatus.setAttribute('role', 'alert');
  elApply.parentNode.insertBefore(elStatus, elApply.parentNode.firstChild);

  elModal.querySelectorAll('input[name="mapperDelimiter"]').forEach(radio => {
    radio.addEventListener('change', () => renderPreviewTable(true));
  });
  elCustomInput.addEventListener('input', () => {
    const customRadio = elModal.querySelector('input[name="mapperDelimiter"][value="custom"]');
    if (customRadio) customRadio.checked = true;
    renderPreviewTable(true);
  });

  elHasHeader.addEventListener('change', () => renderPreviewTable(true));

  elTableContainer.addEventListener('change', (event) => {
    const select = event.target.closest('.mapper-role-select');
    if (select) {
      manualRoles.set(Number(select.dataset.col), select.value);
      manualDelimiter = getSelectedDelimiter();
    }
    if (elStatus.classList.contains('mapper-status-error')) setStatus('');
  });

  // The preview wears the data-table look and inherits click-to-copy with it.
  // These cells are a picture of how the file splits, not values to take.
  elTableContainer.addEventListener('click', (event) => {
    if (event.target.closest('td, th')) event.stopPropagation();
  });

  elApply.addEventListener('click', handleApply);
  document.getElementById('mapperCancel').addEventListener('click', () => closeMapper(null));

  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closeMapper(null);
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && elModal.classList.contains('visible')) {
      e.preventDefault();
      closeMapper(null);
    }
  });
}

export { openColumnMapper, initColumnMapper };
