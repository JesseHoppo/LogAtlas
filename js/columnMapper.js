// Interactive column mapper modal for credential files with non-standard formats.

import { escapeHtml } from './utils.js';
import { detectFormat, splitCSVLine, inferColumnRoles, makeSplitFn } from './transforms.js';

let mapperResolver = null;
let currentText = '';

let elModal, elRawPreview, elTableContainer, elHasHeader, elCustomInput, elFileName;

function getSelectedDelimiter() {
  const checked = elModal.querySelector('input[name="mapperDelimiter"]:checked');
  if (!checked) return '\t';
  if (checked.value === 'custom') return elCustomInput.value || '\t';
  return checked.value;
}

function setDelimiterRadio(delimiter) {
  const radios = elModal.querySelectorAll('input[name="mapperDelimiter"]');
  let matched = false;
  for (const r of radios) {
    if (r.value === delimiter) { r.checked = true; matched = true; break; }
  }
  if (!matched) {
    // Set custom
    const customRadio = elModal.querySelector('input[name="mapperDelimiter"][value="custom"]');
    if (customRadio) {
      customRadio.checked = true;
      elCustomInput.value = delimiter;
    }
  }
}

function renderPreviewTable() {
  const delimiter = getSelectedDelimiter();
  const hasHeader = elHasHeader.checked;
  const splitFn = makeSplitFn(delimiter);
  const lines = currentText.split('\n').map(l => l.trim()).filter(l => l);
  const previewLines = lines.slice(0, 15);

  if (previewLines.length === 0) {
    elTableContainer.innerHTML = '<div class="no-data">No data to preview</div>';
    return;
  }

  const allRows = previewLines.map(l => splitFn(l));
  const colCount = Math.max(...allRows.map(r => r.length));

  // Infer roles for dropdown defaults
  const inference = inferColumnRoles(lines, delimiter, hasHeader);

  let html = '<table class="data-table mapper-preview-table"><thead><tr>';

  for (let i = 0; i < colCount; i++) {
    const inferred = inference.columnMap[i] || '';
    const isSkip = !inferred;
    html += `<th><select class="mapper-role-select" data-col="${i}">
      <option value="url"${inferred === 'url' ? ' selected' : ''}>URL</option>
      <option value="username"${inferred === 'username' ? ' selected' : ''}>Username</option>
      <option value="password"${inferred === 'password' ? ' selected' : ''}>Password</option>
      <option value="email"${inferred === 'email' ? ' selected' : ''}>Email</option>
      <option value="notes"${inferred === 'notes' ? ' selected' : ''}>Notes</option>
      <option value="skip"${isSkip ? ' selected' : ''}>(Skip)</option>
    </select></th>`;
  }
  html += '</tr>';

  // Show original header row if toggled on
  if (hasHeader && allRows.length > 0) {
    html += '<tr class="mapper-original-header">';
    for (let i = 0; i < colCount; i++) {
      html += `<td class="mapper-orig-th">${escapeHtml((allRows[0][i] || '').trim())}</td>`;
    }
    html += '</tr>';
  }
  html += '</thead><tbody>';

  const startIdx = hasHeader ? 1 : 0;
  const dataRows = allRows.slice(startIdx, startIdx + 10);
  for (const row of dataRows) {
    html += '<tr>';
    for (let i = 0; i < colCount; i++) {
      html += `<td>${escapeHtml((row[i] || '').trim())}</td>`;
    }
    html += '</tr>';
  }

  html += '</tbody></table>';
  elTableContainer.innerHTML = html;
}

function handleApply() {
  const delimiter = getSelectedDelimiter();
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

function openColumnMapper(text, fileName) {
  return new Promise((resolve) => {
    mapperResolver = resolve;
    currentText = text;

    // Show filename
    if (elFileName) elFileName.textContent = fileName || 'Unknown file';

    // Show raw preview
    const rawLines = text.split('\n').slice(0, 10);
    elRawPreview.textContent = rawLines.join('\n');

    // Auto-detect initial delimiter
    const format = detectFormat(text);
    if (format && format.type === 'delimited') {
      setDelimiterRadio(format.delimiter);
      elHasHeader.checked = format.hasHeaderRow || false;
    } else {
      setDelimiterRadio('\t');
      elHasHeader.checked = false;
    }

    renderPreviewTable();
    elModal.classList.add('visible');
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

  // Delimiter radio changes
  elModal.querySelectorAll('input[name="mapperDelimiter"]').forEach(radio => {
    radio.addEventListener('change', renderPreviewTable);
  });
  elCustomInput.addEventListener('input', () => {
    const customRadio = elModal.querySelector('input[name="mapperDelimiter"][value="custom"]');
    if (customRadio) customRadio.checked = true;
    renderPreviewTable();
  });

  // Header checkbox
  elHasHeader.addEventListener('change', renderPreviewTable);

  // Apply / Cancel
  document.getElementById('mapperApply').addEventListener('click', handleApply);
  document.getElementById('mapperCancel').addEventListener('click', () => closeMapper(null));

  // Backdrop click
  elModal.addEventListener('click', (e) => {
    if (e.target === elModal) closeMapper(null);
  });

  // Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && elModal.classList.contains('visible')) {
      e.preventDefault();
      closeMapper(null);
    }
  });
}

export { openColumnMapper, initColumnMapper };
