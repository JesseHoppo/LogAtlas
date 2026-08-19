// Shared utilities used across all data page modules.

import { state, emit } from '../core/state.js';
import { loadFileContent, getNodeAtPath } from '../files/extractor.js';
import { escapeHtml, getFileExtension, formatBytes } from '../core/utils.js';
import {
  collectHintedNodes,
  copyToClipboard,
  downloadBlob,
  showNotification,
  SHARED_TEXT_DECODER,
} from '../core/shared.js';
import { openColumnMapper } from '../files/columnMapper.js';
import { parseStructuredFile } from '../files/structuredTransforms.js';
import { openTransientModal, topModal } from '../core/modal.js';

export { formatBytes, openTransientModal };

export const PAGE_SIZE = 200;

export function createDebounced(fn, delay = 150) {
  let timeoutId = null;
  return (...args) => {
    clearTimeout(timeoutId);
    timeoutId = setTimeout(() => fn(...args), delay);
  };
}

export function bindDebouncedInput(input, onValue, delay = 150) {
  if (!input) return;
  input.addEventListener('input', createDebounced(() => onValue(input.value), delay));
}

export function buildShowMoreButton(remaining, pageId) {
  return `<button class="data-show-more" data-page="${pageId}">Show ${Math.min(remaining, PAGE_SIZE)} more (${remaining.toLocaleString()} remaining)</button>`;
}

export function buildRowsHtml(rowBuilder, items, start, end) {
  let html = '';
  const limit = Math.min(end, items.length);
  for (let i = start; i < limit; i++) {
    html += rowBuilder(items[i], i);
  }
  return html;
}

// Blanks sink to the bottom in both directions: an empty cell is absence of
// data, not a value belonging at one end of the range.
const BLANK = Symbol('blank');

function sortValue(raw) {
  if (raw == null) return BLANK;
  if (raw instanceof Date) return isNaN(raw.getTime()) ? BLANK : raw.getTime();
  if (typeof raw === 'number') return Number.isFinite(raw) ? raw : BLANK;
  const text = String(raw).trim();
  return text === '' ? BLANK : text.toLowerCase();
}

function compareSortValues(a, b) {
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
}

// Header sorting for the data tables. `columns` is a map of sort key to
// accessor, or — where the columns come from the parsed file and aren't known
// up front — a function resolving a key to one. Clicking cycles desc -> asc ->
// unsorted, so the file's own order stays reachable: it is evidence too.
export function createTableSort(columns) {
  const resolve = typeof columns === 'function' ? columns : (name) => columns[name];
  let key = 'none';
  let order = 'none';

  return {
    get key() { return key; },
    get order() { return order; },
    reset() { key = 'none'; order = 'none'; },
    cycle(nextKey) {
      if (!nextKey || !resolve(nextKey)) return false;
      if (key !== nextKey) { key = nextKey; order = 'desc'; }
      else if (order === 'desc') { order = 'asc'; }
      else { key = 'none'; order = 'none'; }
      return true;
    },
    th(columnKey, label) {
      const active = key === columnKey && order !== 'none';
      const classes = active ? `sortable sort-${order}` : 'sortable';
      const aria = active ? (order === 'asc' ? 'ascending' : 'descending') : 'none';
      return `<th class="${classes}" data-sort-key="${escapeHtml(columnKey)}" tabindex="0" aria-sort="${aria}">${escapeHtml(label)}</th>`;
    },
    apply(rows) {
      const accessor = key === 'none' ? null : resolve(key);
      if (!accessor) return rows;
      const direction = order === 'asc' ? 1 : -1;
      // Decorated with the source index so the sort is stable: rows that tie
      // keep the order they were parsed in.
      return rows
        .map((row, index) => ({ row, index, value: sortValue(accessor(row)) }))
        .sort((a, b) => {
          // Blank last in both directions, so reversing the sort never floats
          // the rows with nothing in that column to the top.
          const aBlank = a.value === BLANK;
          const bBlank = b.value === BLANK;
          if (aBlank || bBlank) {
            if (aBlank && bBlank) return a.index - b.index;
            return aBlank ? 1 : -1;
          }
          return compareSortValues(a.value, b.value) * direction || a.index - b.index;
        })
        .map((entry) => entry.row);
    },
  };
}

// One delegated listener per table container; the header cells carry the key.
export function bindTableSort(container, sort, rerender) {
  const el = typeof container === 'string' ? document.getElementById(container) : container;
  if (!el) return;

  const activate = (event) => {
    const header = event.target.closest('th[data-sort-key]');
    if (!header || !el.contains(header)) return;
    if (event.type === 'keydown') {
      if (event.key !== 'Enter' && event.key !== ' ') return;
      event.preventDefault();
    }
    const focused = document.activeElement === header;
    const sortKey = header.dataset.sortKey;
    if (!sort.cycle(sortKey)) return;
    rerender();
    // The rerender replaces the header that was just operated, so keyboard
    // focus has to be put back on its replacement.
    if (focused) el.querySelector(`th[data-sort-key="${CSS.escape(sortKey)}"]`)?.focus();
  };

  el.addEventListener('click', activate);
  el.addEventListener('keydown', activate);
}

// A click on a cell does what a click does everywhere else — it puts a caret
// down and starts a selection. Copying is its own control: one button, moved
// into whichever cell the pointer or the keyboard is on, so a page of two
// hundred rows carries exactly one of them and nothing is copied by accident.
// Columns truncate what they show, so the title attribute carries the
// untruncated text and wins over the visible label.
const COPYABLE_CELL = '.data-table td, .domain-detail-table td, .lab-creds-table td';
const COPY_HINT_ID = 'cellCopyHint';
// Drawn with its own stroke rather than left to the sheet: the control is
// useless if it is invisible.
const COPY_ICON = '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.3" stroke-linejoin="round" aria-hidden="true" focusable="false"><rect x="5.9" y="5.9" width="8.2" height="8.2" rx="1.4"/><path d="M11 4V2.8A1.3 1.3 0 0 0 9.7 1.5H2.8A1.3 1.3 0 0 0 1.5 2.8v6.9A1.3 1.3 0 0 0 2.8 11H4"/></svg>';

let flashTimer = null;

function flashCopied(cell) {
  clearTimeout(flashTimer);
  document.querySelector('.cell-copied')?.classList.remove('cell-copied');
  void cell.offsetWidth;  // restart the flash on a repeat click
  cell.classList.add('cell-copied');
  flashTimer = setTimeout(() => cell.classList.remove('cell-copied'), 600);
}

function cellValue(cell) {
  // A cell spanning the table is an opened detail panel, not a value: copying
  // it would take the whole panel's text.
  if (cell.hasAttribute('colspan')) return '';
  // The em dash stands for a value the log never recorded; there is nothing to
  // take, and the placeholder on the clipboard would pass for one.
  if (cell.querySelector('.cell-empty')) return '';
  return (cell.title || cell.textContent || '').trim();
}

function rowCells(row) {
  return [...row.children].filter((el) => el.tagName === 'TD');
}

function tableRows(table) {
  const body = table?.querySelector('tbody');
  return body ? [...body.children].filter((el) => el.tagName === 'TR') : [];
}

// A masked cell belongs to its reveal control, the em dash placeholder stands
// for a value the log never held, and a cell that is only a button holds an
// action rather than evidence. None of the three has anything to take.
// A table inside a dialog that is not the top of the modal stack is behind
// something else, so it is not what a click or a keystroke is aimed at.
function isCopyable(cell) {
  if (!cell || !cell.isConnected || cell.classList.contains('masked')) return false;
  if (cell.querySelector('button:not(.cell-copy-btn)')) return false;
  const overlay = cell.closest('.modal-overlay');
  if (overlay && overlay !== topModal()) return false;
  return cellValue(cell) !== '';
}

// The heading the cell sits under. It names what went to the clipboard without
// putting the value itself anywhere.
function columnLabel(cell) {
  const headers = cell.closest('table')?.querySelectorAll('thead th');
  const label = headers?.[rowCells(cell.parentNode).indexOf(cell)]?.textContent.trim() || '';
  return label.length <= 32 ? label : '';
}

let copyBtn = null;
let hoveredCell = null;
let focusedCell = null;

async function copyCell(cell) {
  if (!isCopyable(cell)) return;
  const label = columnLabel(cell);

  if (await copyToClipboard(cellValue(cell))) {
    flashCopied(cell);
    // The value itself never goes into the banner: the tables hold cookie
    // values, autofill entries and revealed passwords, and a copy is often made
    // while presenting. The column name and the cell's own flash say which one
    // was taken without repeating it.
    showNotification(label ? `Copied ${label} to clipboard` : 'Copied to clipboard');
  } else {
    showNotification('Could not copy to clipboard', 'error');
  }
}

function copyButton() {
  if (copyBtn) return copyBtn;
  copyBtn = document.createElement('button');
  copyBtn.type = 'button';
  copyBtn.className = 'cell-copy-btn';
  copyBtn.innerHTML = COPY_ICON;
  // Taking focus on press would collapse a selection the analyst is part-way
  // through making and drop the caret somewhere they did not put it.
  copyBtn.addEventListener('mousedown', (event) => event.preventDefault());
  copyBtn.addEventListener('click', (event) => {
    // Some of these rows open on a click anywhere in them. This is not that.
    event.stopPropagation();
    const cell = copyBtn.closest(COPYABLE_CELL);
    copyCell(cell);
    // Reached by keyboard, the button holds focus afterwards and the arrow keys
    // can no longer walk the table; hand it back to the cell it lives in.
    if (cell && document.activeElement === copyBtn) focusCell(cell);
  });
  return copyBtn;
}

// Rerenders take the cell the button was sitting in with them, so the two
// references are checked rather than trusted.
function liveCell(cell) {
  return cell?.isConnected ? cell : null;
}

function syncCopyButton() {
  const cell = liveCell(focusedCell) || liveCell(hoveredCell);
  if (!isCopyable(cell)) {
    copyBtn?.remove();
    return;
  }
  if (copyBtn?.parentNode === cell) return;

  const button = copyButton();
  const label = columnLabel(cell);
  button.setAttribute('aria-label', label ? `Copy ${label} to clipboard` : 'Copy this cell to clipboard');
  cell.appendChild(button);
}

// One description node for the whole app, pointed at whichever cell currently
// holds focus, so the copy action has a name without every cell carrying a
// label that would be read out during ordinary table navigation.
function copyHint() {
  let hint = document.getElementById(COPY_HINT_ID);
  if (!hint) {
    hint = document.createElement('span');
    hint.id = COPY_HINT_ID;
    hint.className = 'sr-only';
    hint.textContent = 'Press Tab for the copy button, or use the arrow keys to move.';
    document.body.appendChild(hint);
  }
  return hint;
}

let describedCell = null;

function releaseCell() {
  describedCell?.removeAttribute('aria-describedby');
  describedCell = null;
  focusedCell = null;
  syncCopyButton();
}

function focusCell(cell) {
  if (!cell) return false;
  releaseCell();
  cell.tabIndex = -1;
  if (isCopyable(cell)) {
    copyHint();
    cell.setAttribute('aria-describedby', COPY_HINT_ID);
    describedCell = cell;
  }
  focusedCell = cell;
  syncCopyButton();
  cell.focus();
  return true;
}

// The sortable headers are already in the tab order, so the body is entered
// from one of them rather than by making every cell tabbable — a page of 200
// rows would otherwise cost a thousand tab stops.
function navigateCells(event) {
  const { key } = event;
  if (key !== 'ArrowUp' && key !== 'ArrowDown' && key !== 'ArrowLeft' && key !== 'ArrowRight' && key !== 'Escape') return false;

  const header = event.target.closest('thead th');
  if (header) {
    if (key !== 'ArrowDown') return false;
    const rows = tableRows(header.closest('table'));
    const column = [...header.parentNode.children].indexOf(header);
    if (rows.length === 0) return false;
    const cells = rowCells(rows[0]);
    return focusCell(cells[Math.min(column, cells.length - 1)]);
  }

  // The copy control sits inside the cell, so the arrow keys keep working while
  // focus is on it.
  const cell = event.target.closest(COPYABLE_CELL);
  if (!cell || !cell.contains(document.activeElement)) return false;

  const row = cell.parentNode;
  const cells = rowCells(row);
  const column = cells.indexOf(cell);
  // Only a header that can hold focus is somewhere to go back to.
  const headerCell = () => {
    const headers = cell.closest('table')?.querySelectorAll('thead th[tabindex]');
    return headers?.length ? headers[Math.min(column, headers.length - 1)] : null;
  };

  if (key === 'Escape') {
    const back = headerCell();
    if (!back) return false;
    releaseCell();
    back.focus();
    return true;
  }

  if (key === 'ArrowLeft' || key === 'ArrowRight') {
    return focusCell(cells[column + (key === 'ArrowRight' ? 1 : -1)]);
  }

  const rows = tableRows(cell.closest('table'));
  const next = rows[rows.indexOf(row) + (key === 'ArrowDown' ? 1 : -1)];
  if (next) {
    const target = rowCells(next);
    return focusCell(target[Math.min(column, target.length - 1)]);
  }
  if (key === 'ArrowUp') {
    const back = headerCell();
    if (back) { releaseCell(); back.focus(); return true; }
  }
  return false;
}

export function initCellCopy() {
  document.addEventListener('mouseover', (event) => {
    const cell = event.target.closest?.(COPYABLE_CELL) || null;
    if (cell === hoveredCell) return;
    hoveredCell = cell;
    // A held button means a selection is being dragged out, and moving the
    // control between cells would shift the DOM under it. It settles on release.
    if (!event.buttons) syncCopyButton();
  });
  document.addEventListener('mouseup', syncCopyButton);

  // Cells are focused through the navigation above, which claims the control as
  // it goes. Focus reaching anything outside the cell — the button inside it
  // excepted — gives it up again.
  document.addEventListener('focusin', (event) => {
    if (focusedCell && !focusedCell.contains(event.target)) releaseCell();
  });

  document.addEventListener('keydown', (event) => {
    if (navigateCells(event)) event.preventDefault();
  });
}

// `3 cookies` / `1 cookie`, with a thousands separator. Named counts read as
// English rather than as "1 file(s)".
export function countLabel(value, singular, plural = singular + 's') {
  return `${value.toLocaleString()} ${value === 1 ? singular : plural}`;
}

// One shape for every dataset page's summary line: what is on screen, out of
// what, and how many files it came from, joined by middots rather than written
// as a sentence.
export function datasetSummary({ shown, total, singular, plural = singular + 's', fileCount = 0, extra = [] }) {
  const counted = shown !== total && shown != null
    ? `${shown.toLocaleString()} of ${countLabel(total, singular, plural)}`
    : countLabel(total, singular, plural);
  return [counted, fileCount > 0 ? countLabel(fileCount, 'file') : '', ...extra]
    .filter(Boolean)
    .join(' \u00B7 ');
}

// Zero matches is a result, not a failure. A table drawn as bare column
// headings over an empty body reads as the page having failed to render.
export function buildNoMatchesHtml(noun) {
  return `<div class="no-data">No ${escapeHtml(noun)} match the current search and filters.</div>`;
}

// Where the capture instant came from, and — when a sysinfo timezone let the
// victim's wall clock be turned into a real instant — which offset was applied.
export function captureProvenance({ source, detail, offsetMinutes } = {}) {
  if (!source) return '';
  const parts = [source === 'sysinfo' && detail ? `sysinfo: ${detail}` : source];
  if (offsetMinutes != null) {
    const sign = offsetMinutes < 0 ? '-' : '+';
    const abs = Math.abs(offsetMinutes);
    parts.push(`UTC${sign}${String(Math.floor(abs / 60)).padStart(2, '0')}:${String(abs % 60).padStart(2, '0')}`);
  }
  return parts.join(', ');
}

function isValidDate(value) {
  return value instanceof Date && !isNaN(value.getTime());
}

// Every instant in a case is built as UTC: epoch values are absolute, and a
// wall-clock string from a log carries no zone, so it is read as UTC and shown
// back unchanged. Rendering in the machine's zone would move both — the same
// evidence would read differently on two analysts' screens, and a log written
// at 17:59 would be reported as some other hour entirely.
function pad(value, width = 2) {
  return String(value).padStart(width, '0');
}

// Date only, e.g. "2026-03-05".
export function formatDateLabel(value) {
  if (!isValidDate(value)) return '';
  return `${value.getUTCFullYear()}-${pad(value.getUTCMonth() + 1)}-${pad(value.getUTCDate())}`;
}

// Date + time, e.g. "2026-03-05 14:30 UTC".
export function formatDateTimeLabel(value) {
  if (!isValidDate(value)) return '';
  return `${formatDateLabel(value)} ${pad(value.getUTCHours())}:${pad(value.getUTCMinutes())} UTC`;
}

// Seconds included, for the capture instant and other single-value readouts
// where the log's own precision matters.
export function formatInstantLabel(value) {
  if (!isValidDate(value)) return '';
  return `${formatDateLabel(value)} ${pad(value.getUTCHours())}:${pad(value.getUTCMinutes())}:${pad(value.getUTCSeconds())} UTC`;
}

export function formatOptionalDate(value) {
  return formatDateTimeLabel(value);
}

export function resolveSourcePathSegments(sourcePath) {
  const parts = String(sourcePath || '').split('/').filter(Boolean);
  if (parts.length > 0 && parts[0] === state.rootZipName) return parts.slice(1);
  return parts;
}

export function emitPreview(node, folderSegments) {
  emit('preview:open', {
    name: node.name,
    size: node.size || 0,
    path: folderSegments,
  });
}

export function openSourcePreview(sourcePath) {
  const segments = resolveSourcePathSegments(sourcePath);
  const node = segments.length > 0 ? getNodeAtPath(segments) : null;
  if (!node) {
    showNotification('Source file is no longer available in the current session.', 'error');
    return;
  }

  emitPreview(node, segments.slice(0, -1));
}

export function getImageMimeFromName(name) {
  const ext = getFileExtension(name);
  const mimeMap = {
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    png: 'image/png',
    bmp: 'image/bmp',
    gif: 'image/gif',
    webp: 'image/webp',
  };
  return mimeMap[ext] || 'image/png';
}

export function measureImage(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.onload = () => resolve({ width: img.naturalWidth, height: img.naturalHeight });
    img.onerror = () => resolve({ width: null, height: null });
    img.src = url;
  });
}

export function revokeScreenshotUrls(screenshotsData) {
  for (const entry of screenshotsData.entries) {
    if (entry.blobUrl) URL.revokeObjectURL(entry.blobUrl);
  }
}

export function extractCardLast4(cardNumber) {
  return String(cardNumber || '').replace(/\D/g, '').slice(-4);
}

export function maskValue(val) {
  if (!val || val.length === 0) return '';
  if (val.length <= 2) return '\u2022\u2022\u2022\u2022';
  return val[0] + '\u2022'.repeat(Math.min(val.length - 2, 8)) + val[val.length - 1];
}

export function maskCardNumber(cardNumber) {
  const raw = String(cardNumber || '').trim();
  if (!raw) return '';
  const last4 = extractCardLast4(raw);
  if (last4) return `\u2022\u2022\u2022\u2022 ${last4}`;
  if (raw.length <= 4) return raw;
  return `${raw[0]}\u2022\u2022\u2022${raw[raw.length - 1]}`;
}

export function maskTokenValue(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  if (raw.length <= 10) return '\u2022'.repeat(raw.length);
  return `${raw.slice(0, 4)}\u2022\u2022\u2022\u2022${raw.slice(-4)}`;
}

export function inferMetadataCategory(pathText) {
  const value = String(pathText || '');
  if (/\/path\//i.test(value)) return 'Path';
  if (/\/ua\//i.test(value)) return 'User Agent';
  if (/\/version\//i.test(value)) return 'Version';
  if (/debug\.txt$/i.test(value)) return 'Debug';
  return 'Metadata';
}

export function inferServiceArtifactType(pathText) {
  const value = String(pathText || '');
  if (/leveldb/i.test(value)) return 'Local Storage';
  if (/accounts\.txt$/i.test(value)) return 'Accounts';
  if (/usersettings\.json$/i.test(value)) return 'Settings';
  if (/token\.txt$/i.test(value)) return 'Token Config';
  if (/\.(?:conf|cfg|ini)$/i.test(value)) return 'Config';
  return 'Artifact';
}

export function extractDownloadExtension(filePath, sourceUrl) {
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

export function parseDownloadSize(rawValue) {
  if (rawValue == null) return { raw: '', bytes: null, display: '' };

  const raw = String(rawValue).trim();
  if (!raw) return { raw: '', bytes: null, display: '' };

  const normalised = raw.replace(/,/g, '');
  const match = normalised.match(/^(\d+(?:\.\d+)?)\s*(bytes?|b|kb|mb|gb|tb)?$/i);
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

function escapeCSV(str) {
  if (str == null) return '';
  let s = String(str);
  // Neutralise spreadsheet formula/DDE injection: log values are attacker-controlled.
  // Spreadsheets strip leading whitespace before evaluating, so test the trimmed value.
  if (/^[=+\-@]/.test(s.trimStart()) || s[0] === '\t' || s[0] === '\r') s = "'" + s;
  if (s.includes(',') || s.includes('"') || s.includes('\n')) {
    return '"' + s.replace(/"/g, '""') + '"';
  }
  return s;
}

export function buildCsvText(headers, rows) {
  return [headers, ...(rows || [])]
    .map((row) => (row || []).map(escapeCSV).join(','))
    .join('\n');
}

export function downloadCsvRows(filename, headers, rows) {
  downloadBlob(buildCsvText(headers, rows), filename, 'text/csv');
}

export function sessionTypeLabel(t) {
  if (t === 'auth') return 'Auth';
  if (t === 'session') return 'Session';
  if (t === 'tracking') return 'Tracking';
  return '';
}

export function shapeCookiesCsv(cookiesData) {
  return {
    headers: [...cookiesData.headers, 'Status', 'Session Type'],
    rows: cookiesData.rows.map(({ row, validity, sessionType }) =>
      [...row, validity.label, sessionTypeLabel(sessionType)]),
  };
}

export function shapeNotesCsv(notesData) {
  return {
    headers: ['Title', 'Type', 'Indicators', 'Preview', 'URLs', 'Emails', 'Phones', 'Credential Hints', 'Wallet Hints', 'Source'],
    rows: notesData.entries.map((entry) => [
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
    ]),
  };
}

export function trimRootPath(path) {
  if (!path) return '';
  if (state.rootZipName && path.startsWith(state.rootZipName + '/')) {
    return path.slice(state.rootZipName.length + 1);
  }
  return path;
}

// Walk a hint, load each file, and parse it. parseFn(textOrBytes, node, path)
// returns the row(s) to keep: an array (possibly empty), a single entry, or
// null/undefined to skip the file entirely. A non-null return counts the file
// even when it yields zero entries (e.g. all rows filtered out). With
// decode:false parseFn receives the raw bytes instead of decoded text.
export async function collectAndParse(fileTree, rootName, hintKey, parseFn, { decode = true } = {}) {
  const nodes = [];
  collectHintedNodes(fileTree, hintKey, rootName, nodes);
  const entries = [];
  let fileCount = 0;
  for (const { node, path } of nodes) {
    try {
      const content = await loadFileContent(node);
      if (!content) continue;
      const input = decode ? SHARED_TEXT_DECODER.decode(content) : content;
      const result = parseFn(input, node, path);
      if (result == null) continue;
      fileCount++;
      if (Array.isArray(result)) entries.push(...result);
      else entries.push(result);
    } catch { /* skip */ }
  }
  return { entries, fileCount };
}

export function createPagedCollectionRegistry(definitions) {
  return {
    handleShowMore(pageId) {
      const definition = definitions[pageId];
      if (!definition) return null;
      return {
        filtered: definition.getFiltered(),
        shown: definition.getShown(),
        builder: definition.rowBuilder,
      };
    },
    updateShown(pageId, newShown) {
      definitions[pageId]?.setShown(newShown);
    },
    updateNav() {
      for (const definition of Object.values(definitions)) {
        if (!definition.navId) continue;
        const navEl = document.getElementById(definition.navId);
        if (navEl) navEl.disabled = definition.isEmpty();
      }
    },
    reset() {
      for (const definition of Object.values(definitions)) {
        definition.reset?.();
      }
    },
  };
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

async function openMapperForHint(hintKey, fileType) {
  const nodes = [];
  collectHintedNodes(state.fileTree, hintKey, state.rootZipName, nodes);
  if (nodes.length === 0) return;

  const selected = await chooseMapperNode(nodes, fileType);
  if (!selected) return;

  const content = await loadFileContent(selected.node);
  if (!content) return;
  const text = SHARED_TEXT_DECODER.decode(content);
  const fileName = selected.path || selected.node.name || 'Unknown file';

  const config = await openColumnMapper(text, fileName, fileType);
  if (!config) return;

  selected.node._parseConfig = config;
  emit('reanalyze');
}

export function addAdjustColumnsBtn(summaryEl, hintKey, fileType) {
  const actionsArea = summaryEl.parentNode.querySelector('.data-page-actions');
  if (actionsArea && !actionsArea.querySelector('.mapper-adjust-btn')) {
    const adjustBtn = document.createElement('button');
    adjustBtn.className = 'mapper-adjust-btn';
    adjustBtn.textContent = 'Adjust columns\u2026';
    adjustBtn.addEventListener('click', () => openMapperForHint(hintKey, fileType));
    actionsArea.insertBefore(adjustBtn, actionsArea.firstChild);
  }
}
