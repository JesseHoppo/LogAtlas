// Shared utilities used across all data page modules.

import { state, emit } from '../core/state.js';
import { loadFileContent, getNodeAtPath } from '../files/extractor.js';
import { escapeHtml, getFileExtension, formatBytes } from '../core/utils.js';
import {
  collectHintedNodes,
  downloadBlob,
  showNotification,
  SHARED_TEXT_DECODER,
} from '../core/shared.js';
import { openColumnMapper } from '../files/columnMapper.js';

export { formatBytes };

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

// Look up a cell value in a row by matching the column header against a regex.
// Tabular data shapes here are always `{ row, headers }`.
export function getFieldByPattern({ row, headers }, pattern) {
  const index = headers.findIndex((header) => pattern.test(header));
  return index >= 0 ? (row[index] || '') : '';
}

export function buildRowsHtml(rowBuilder, items, start, end) {
  let html = '';
  const limit = Math.min(end, items.length);
  for (let i = start; i < limit; i++) {
    html += rowBuilder(items[i], i);
  }
  return html;
}

export function formatOptionalDate(value) {
  return value instanceof Date && !isNaN(value.getTime()) ? value.toLocaleString() : '';
}

function isValidDate(value) {
  return value instanceof Date && !isNaN(value.getTime());
}

// Date only, e.g. "Mar 5, 2026".
export function formatDateLabel(value) {
  if (!isValidDate(value)) return '';
  return value.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// Date + time, e.g. "Mar 5, 2026, 02:30 PM".
export function formatDateTimeLabel(value) {
  if (!isValidDate(value)) return '';
  return value.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function resolveSourcePathSegments(sourcePath) {
  const parts = String(sourcePath || '').split('/').filter(Boolean);
  if (parts.length > 0 && parts[0] === state.rootZipName) return parts.slice(1);
  return parts;
}

export function openSourcePreview(sourcePath) {
  const segments = resolveSourcePathSegments(sourcePath);
  const node = segments.length > 0 ? getNodeAtPath(segments) : null;
  if (!node) {
    showNotification('Source file is no longer available in the current session.', 'error');
    return;
  }

  emit('preview:open', {
    name: node.name,
    size: node.size || 0,
    path: segments.slice(0, -1),
  });
}

export const formatTimestampDisplay = formatDateTimeLabel;

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
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
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

export function trimRootPath(path) {
  if (!path) return '';
  if (state.rootZipName && path.startsWith(state.rootZipName + '/')) {
    return path.slice(state.rootZipName.length + 1);
  }
  return path;
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

export async function openMapperForHint(hintKey, fileType) {
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
