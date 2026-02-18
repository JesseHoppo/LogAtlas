// Interactive column mapper modal for files with non-standard formats.
// Roles are configurable per file type (credentials, cookies, history, autofill).

import { escapeHtml } from './utils.js';
import { detectFormat, splitCSVLine, inferColumnRoles, makeSplitFn } from './transforms.js';

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

let mapperResolver = null;
let currentText = '';
let currentRoles = ROLE_SETS.credentials;

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

  // Infer roles for dropdown defaults (credential-style inference)
  const inference = inferColumnRoles(lines, delimiter, hasHeader);

  let html = '<table class="data-table mapper-preview-table"><thead><tr>';

  for (let i = 0; i < colCount; i++) {
    const inferred = inference.columnMap[i] || '';
    // Check if inferred role exists in current role set
    const inferredValid = currentRoles.some(r => r.value === inferred);
    const isSkip = !inferred || !inferredValid;

    html += '<th><select class="mapper-role-select" data-col="' + i + '">';
    for (const role of currentRoles) {
      const sel = (inferredValid && inferred === role.value) ? ' selected' : '';
      html += `<option value="${role.value}"${sel}>${escapeHtml(role.label)}</option>`;
    }
    html += `<option value="skip"${isSkip ? ' selected' : ''}>(Skip)</option>`;
    html += '</select></th>';
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

// fileType: 'credentials' | 'cookies' | 'history' | 'autofill'
function openColumnMapper(text, fileName, fileType) {
  return new Promise((resolve) => {
    mapperResolver = resolve;
    currentText = text;
    currentRoles = ROLE_SETS[fileType] || ROLE_SETS.credentials;

    if (elFileName) elFileName.textContent = fileName || 'Unknown file';

    const rawLines = text.split('\n').slice(0, 10);
    elRawPreview.textContent = rawLines.join('\n');

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

  elModal.querySelectorAll('input[name="mapperDelimiter"]').forEach(radio => {
    radio.addEventListener('change', renderPreviewTable);
  });
  elCustomInput.addEventListener('input', () => {
    const customRadio = elModal.querySelector('input[name="mapperDelimiter"][value="custom"]');
    if (customRadio) customRadio.checked = true;
    renderPreviewTable();
  });

  elHasHeader.addEventListener('change', renderPreviewTable);

  document.getElementById('mapperApply').addEventListener('click', handleApply);
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

export { openColumnMapper, initColumnMapper, ROLE_SETS };
