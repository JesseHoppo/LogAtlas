// File preview modal 

import { state, on, emit } from './state.js';
import { getNodeAtPath, loadFileContent, applyManualType, flattenTree } from './extractor.js';
import {
  escapeHtml,
  formatBytes,
  getFileIcon,
  getFileExtension,
  getMimeType,
  isTextFile,
  isImageFile,
  looksLikeText,
  syntaxHighlightJSON,
  MAX_PREVIEW_SIZE,
} from './utils.js';
import { parsePasswordFile, parseCookieFile, toCSV } from './transforms.js';
import { downloadBlob, copyToClipboard, showNotification } from './shared.js';
import { openColumnMapper } from './columnMapper.js';

let elOverlay;
let elBody;
let elActions;
let elSearchBar;
let elSearchInput;
let elSearchCount;
let elSearchPrev;
let elSearchNext;
let currentFile = null;
let currentContent = null;
let currentNode = null;
let currentDecodedText = null;
let currentParsedData = null;
let activeBlobUrls = [];

let searchMatches = [];
let currentMatchIndex = -1;

const ROW_CAP = 500;
const LINE_CAP = 5000;

// Blob URL lifecycle

function trackBlobUrl(url) {
  activeBlobUrls.push(url);
}

function revokeAllBlobUrls() {
  for (const url of activeBlobUrls) {
    URL.revokeObjectURL(url);
  }
  activeBlobUrls = [];
}

// Type label for the Set Type button

function getNodeTypeLabel(node) {
  if (!node) return null;
  if (node._passwordFileHint) return 'credentials';
  if (node._cookieFileHint) return 'cookies';
  if (node._autofillHint) return 'autofill';
  if (node._historyHint) return 'history';
  return null;
}

function updateTypeButton() {
  const btn = document.getElementById('previewSetType');
  if (!btn) return;
  const label = getNodeTypeLabel(currentNode);
  if (label) {
    btn.textContent = label.charAt(0).toUpperCase() + label.slice(1);
    btn.className = 'preview-btn preview-type-btn preview-type-' + label;
  } else {
    btn.textContent = 'Set Type';
    btn.className = 'preview-btn preview-type-btn';
  }
}

function showPreviewTypeMenu() {
  if (!currentNode) return;

  const overlay = document.createElement('div');
  overlay.className = 'modal-overlay visible';
  overlay.innerHTML = `
    <div class="modal modal-filetype">
      <h3>Set File Type</h3>
      <div class="filetype-options">
        <button class="filetype-option" data-type="credentials" data-key="1">
          <span class="filetype-icon">Credentials</span>
        </button>
        <button class="filetype-option" data-type="cookies" data-key="2">
          <span class="filetype-icon">Cookies</span>
        </button>
        <button class="filetype-option" data-type="autofill" data-key="3">
          <span class="filetype-icon">Autofill</span>
        </button>
        <button class="filetype-option" data-type="history" data-key="4">
          <span class="filetype-icon">History</span>
        </button>
        <button class="filetype-option filetype-option-remove" data-type="none" data-key="5">
          <span class="filetype-icon">Remove Label</span>
        </button>
      </div>
    </div>
  `;
  document.body.appendChild(overlay);

  overlay.querySelector('.filetype-options').addEventListener('click', (ev) => {
    const btn = ev.target.closest('.filetype-option');
    if (!btn) return;
    applyManualType(currentNode, btn.dataset.type);
    if (state.fileTree) {
      state.flatFiles = flattenTree(state.fileTree, state.rootZipName);
    }
    overlay.remove();
    updateTypeButton();
    emit('reanalyze');
  });

  overlay.addEventListener('click', (ev) => {
    if (ev.target === overlay) overlay.remove();
  });
}

// In-preview text search

function showSearchBar(show) {
  if (elSearchBar) {
    elSearchBar.classList.toggle('hidden', !show);
    if (show) {
      elSearchInput.value = '';
      elSearchCount.textContent = '';
      searchMatches = [];
      currentMatchIndex = -1;
    }
  }
}

function performSearch(query) {
  const textContent = elBody.querySelector('.preview-text-content');
  if (!textContent || !currentDecodedText) return;

  searchMatches = [];
  currentMatchIndex = -1;

  if (!query || query.length < 1) {
    const fileName = currentFile?.name || '';
    const ext = getFileExtension(fileName);
    let formattedContent = escapeHtml(currentDecodedText);
    if (ext === 'json') {
      try {
        const parsed = JSON.parse(currentDecodedText);
        formattedContent = syntaxHighlightJSON(escapeHtml(JSON.stringify(parsed, null, 2)));
      } catch (_) {
        formattedContent = syntaxHighlightJSON(formattedContent);
      }
    }
    textContent.innerHTML = formattedContent;
    elSearchCount.textContent = '';
    return;
  }

  const lowerText = currentDecodedText.toLowerCase();
  const lowerQuery = query.toLowerCase();
  let idx = 0;
  const matchPositions = [];
  while ((idx = lowerText.indexOf(lowerQuery, idx)) !== -1) {
    matchPositions.push(idx);
    idx += 1;
  }

  if (matchPositions.length === 0) {
    elSearchCount.textContent = '0 / 0';
    const fileName = currentFile?.name || '';
    const ext = getFileExtension(fileName);
    let formattedContent = escapeHtml(currentDecodedText);
    if (ext === 'json') {
      try {
        const parsed = JSON.parse(currentDecodedText);
        formattedContent = syntaxHighlightJSON(escapeHtml(JSON.stringify(parsed, null, 2)));
      } catch (_) {
        formattedContent = syntaxHighlightJSON(formattedContent);
      }
    }
    textContent.innerHTML = formattedContent;
    return;
  }

  let html = '';
  let lastEnd = 0;
  for (let i = 0; i < matchPositions.length; i++) {
    const start = matchPositions[i];
    const end = start + query.length;
    html += escapeHtml(currentDecodedText.substring(lastEnd, start));
    const matchClass = i === 0 ? 'preview-search-match preview-search-match-current' : 'preview-search-match';
    html += `<span class="${matchClass}" data-match-idx="${i}">${escapeHtml(currentDecodedText.substring(start, end))}</span>`;
    lastEnd = end;
  }
  html += escapeHtml(currentDecodedText.substring(lastEnd));

  textContent.innerHTML = html;
  searchMatches = textContent.querySelectorAll('.preview-search-match');
  currentMatchIndex = 0;
  elSearchCount.textContent = `1 / ${matchPositions.length}`;
  scrollToCurrentMatch();
}

function scrollToCurrentMatch() {
  if (searchMatches.length === 0 || currentMatchIndex < 0) return;
  searchMatches.forEach(el => el.classList.remove('preview-search-match-current'));
  const currentEl = searchMatches[currentMatchIndex];
  if (currentEl) {
    currentEl.classList.add('preview-search-match-current');
    currentEl.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
  elSearchCount.textContent = `${currentMatchIndex + 1} / ${searchMatches.length}`;
}

function navigateMatch(direction) {
  if (searchMatches.length === 0) return;
  if (direction === 'next') {
    currentMatchIndex = (currentMatchIndex + 1) % searchMatches.length;
  } else {
    currentMatchIndex = (currentMatchIndex - 1 + searchMatches.length) % searchMatches.length;
  }
  scrollToCurrentMatch();
}

// Renderers

function renderTextPreview(content, fileName, showAll = false) {
  const allLines = content.split('\n');
  const totalLines = allLines.length;
  const capped = !showAll && totalLines > LINE_CAP;
  const displayContent = capped ? allLines.slice(0, LINE_CAP).join('\n') : content;
  const displayLineCount = capped ? LINE_CAP : totalLines;

  const lineNumbers = Array.from({ length: displayLineCount }, (_, i) => i + 1).join('\n');
  const ext = getFileExtension(fileName);

  let formattedContent = escapeHtml(displayContent);
  if (ext === 'json') {
    try {
      const formatted = JSON.stringify(JSON.parse(content), null, 2);
      formattedContent = syntaxHighlightJSON(showAll ? escapeHtml(formatted) : escapeHtml(formatted.split('\n').slice(0, LINE_CAP).join('\n')));
    } catch (_) {
      formattedContent = syntaxHighlightJSON(escapeHtml(displayContent));
    }
  }

  let html = '';
  if (capped) {
    html += `<div class="preview-line-cap">Showing first ${LINE_CAP.toLocaleString()} of ${totalLines.toLocaleString()} lines ` +
      `<button class="btn preview-show-all-lines" id="showAllLines">Show all</button></div>`;
  }
  html += `<div class="preview-text-wrapper">` +
    `<div class="preview-line-numbers">${lineNumbers}</div>` +
    `<pre class="preview-text-content">${formattedContent}</pre></div>`;
  return html;
}

function renderImagePreview(data, fileName) {
  const blob = new Blob([data], { type: getMimeType(fileName) });
  const url = URL.createObjectURL(blob);
  trackBlobUrl(url);
  return `<div class="preview-image-container">` +
    `<img src="${url}" class="preview-image" alt="${escapeHtml(fileName)}" ` +
    `style="opacity:0; transition: opacity 0.3s"></div>`;
}

function attachShowAllLinesHandler() {
  const btn = document.getElementById('showAllLines');
  if (btn && currentDecodedText && currentFile) {
    btn.addEventListener('click', () => {
      elBody.innerHTML = renderTextPreview(currentDecodedText, currentFile.name, true);
    });
  }
}

function attachImageLoadHandler() {
  const img = elBody.querySelector('.preview-image');
  if (img) img.addEventListener('load', () => { img.style.opacity = '1'; });
}

function renderUnsupported(fileName) {
  const ext = getFileExtension(fileName);
  return `<div class="preview-unsupported">` +
    `<div class="preview-unsupported-icon">?</div>` +
    `<h3>Preview not available</h3>` +
    `<p>${ext ? `".${escapeHtml(ext)}" files` : 'This file type'} cannot be previewed in the browser.</p>` +
    `<p style="margin-top: 1rem; font-size: 0.8rem;">You can download the file to view it.</p></div>`;
}

function renderLoading() {
  return `<div class="preview-loading"><div class="spinner"></div><div>Loading preview...</div></div>`;
}

function renderError(message) {
  return `<div class="preview-error">` +
    `<div class="preview-error-icon">!</div>` +
    `<p>${escapeHtml(message)}</p></div>`;
}

// CSV table renderer

function renderCSVTable(parsed, showAll) {
  const totalRows = parsed.rows.length;
  const capped = !showAll && totalRows > ROW_CAP;
  const displayRows = capped ? parsed.rows.slice(0, ROW_CAP) : parsed.rows;

  let html = '<div class="preview-csv-wrapper">';
  html += '<div class="preview-csv-stats">';
  html += `<span>${totalRows} records / ${parsed.headers.length} columns`;
  if (capped) html += ` / showing first ${ROW_CAP}`;
  html += '</span>';
  html += '<span class="preview-csv-controls">';
  html += '<button class="mapper-adjust-btn" id="csvAdjustColumns">Adjust columns\u2026</button>';
  html += '<button class="mapper-adjust-btn" id="csvBackToText">Back to Text</button>';
  html += '<button class="mapper-adjust-btn" id="csvDownloadCsv">Download CSV</button>';
  html += '</span>';
  html += '</div>';
  html += '<div class="preview-csv-table-container">';
  html += '<table class="preview-csv-table">';
  html += '<thead><tr>';
  for (const h of parsed.headers) {
    html += `<th>${escapeHtml(h)}</th>`;
  }
  html += '</tr></thead><tbody>';
  for (const row of displayRows) {
    html += '<tr>';
    for (const cell of row) {
      html += `<td>${escapeHtml(cell)}</td>`;
    }
    html += '</tr>';
  }
  html += '</tbody></table></div>';

  if (capped) {
    html += `<button class="btn preview-csv-show-all" id="csvShowAll">Show all ${totalRows} records</button>`;
  }

  html += '</div>';
  return html;
}

// Transform buttons

function clearTransformButtons() {
  const btns = elActions.querySelectorAll('.preview-btn-transform, .preview-btn-try-transform, .preview-btn-back-text, .preview-btn-download-csv');
  btns.forEach(b => b.remove());
}

function addTransformButton(prominent) {
  clearTransformButtons();
  const btn = document.createElement('button');
  btn.className = `preview-btn ${prominent ? 'preview-btn-transform' : 'preview-btn-try-transform'}`;
  btn.textContent = prominent ? 'Transform to CSV' : 'Try Transform';
  btn.addEventListener('click', () => {
    if (!currentParsedData && currentDecodedText) {
      let parsed = null;
      if (currentNode && currentNode._cookieFileHint) {
        parsed = parseCookieFile(currentDecodedText);
      }
      if (!parsed) parsed = parsePasswordFile(currentDecodedText, (currentNode && currentNode._parseConfig) || null);
      if (!parsed) parsed = parseCookieFile(currentDecodedText);
      if (parsed && parsed.rows.length > 0) {
        currentParsedData = parsed;
      } else {
        showTransformError();
        return;
      }
    }
    if (currentParsedData) showCSVView(false);
  });
  elActions.insertBefore(btn, elActions.firstChild);
}

function addCSVViewButtons() {
  clearTransformButtons();
  document.getElementById('previewDownload').textContent = 'Download TXT';
}

// View switching

function showCSVView(showAll) {
  if (!currentParsedData) return;
  showSearchBar(false);
  elBody.innerHTML = renderCSVTable(currentParsedData, showAll);
  addCSVViewButtons();

  const showAllBtn = document.getElementById('csvShowAll');
  if (showAllBtn) {
    showAllBtn.addEventListener('click', () => showCSVView(true));
  }

  const backBtn = document.getElementById('csvBackToText');
  if (backBtn) backBtn.addEventListener('click', () => showTextView());

  const dlBtn = document.getElementById('csvDownloadCsv');
  if (dlBtn) dlBtn.addEventListener('click', downloadCurrentCSV);

  const adjustBtn = document.getElementById('csvAdjustColumns');
  if (adjustBtn && currentNode && currentDecodedText) {
    adjustBtn.addEventListener('click', async () => {
      const fileName = currentFile ? currentFile.name : 'Unknown file';
      const config = await openColumnMapper(currentDecodedText, fileName);
      if (!config) return;
      if (currentNode) currentNode._parseConfig = config;
      const parsed = parsePasswordFile(currentDecodedText, config);
      if (parsed && parsed.rows.length > 0) {
        currentParsedData = parsed;
        showCSVView(false);
      }
      emit('reanalyze');
    });
  }
}

function showTextView() {
  if (!currentDecodedText || !currentFile) return;
  showSearchBar(true);
  elBody.innerHTML = renderTextPreview(currentDecodedText, currentFile.name);
  attachShowAllLinesHandler();

  document.getElementById('previewDownload').textContent = 'Download';

  if (currentParsedData || (currentNode && (currentNode._passwordFileHint || currentNode._cookieFileHint))) {
    addTransformButton(true);
  } else if (getFileExtension(currentFile.name) === 'txt' || getFileExtension(currentFile.name) === 'tsv') {
    addTransformButton(false);
  }
}

function showTransformError() {
  const existing = document.querySelector('.preview-transform-error');
  if (existing) existing.remove();

  const el = document.createElement('div');
  el.className = 'preview-transform-error';
  el.textContent = 'No structured credential data detected in this file.';
  elBody.insertBefore(el, elBody.firstChild);
  setTimeout(() => el.remove(), 4000);
}

function downloadCurrentCSV() {
  if (!currentParsedData || !currentFile) return;
  const csvText = toCSV(currentParsedData);
  const baseName = currentFile.name.replace(/\.[^.]+$/, '');
  downloadBlob(csvText, `${baseName}_transformed.csv`, 'text/csv');
}

// Show / Close

async function showPreview(name, size, pathSegments) {
  revokeAllBlobUrls();
  clearTransformButtons();
  showSearchBar(false);

  currentFile = { name, size, path: pathSegments };
  currentDecodedText = null;
  currentParsedData = null;
  currentNode = null;

  document.getElementById('previewIcon').textContent = getFileIcon(name, false, false);
  document.getElementById('previewName').textContent = name;
  document.getElementById('previewSize').textContent = formatBytes(size);

  elBody.innerHTML = renderLoading();
  elOverlay.classList.add('visible');

  const fullPath = [...pathSegments, name];
  const node = getNodeAtPath(fullPath);
  currentNode = node;
  updateTypeButton();

  if (!node) {
    elBody.innerHTML = renderError('File not found in archive.');
    return;
  }

  if (node.size > MAX_PREVIEW_SIZE) {
    elBody.innerHTML = renderError(`File is too large to preview (${formatBytes(node.size)}). Maximum preview size is ${formatBytes(MAX_PREVIEW_SIZE)}. Use the download button instead.`);
    return;
  }

  const content = await loadFileContent(node);
  currentContent = content;

  if (!content) {
    elBody.innerHTML = renderError('File content not available for preview. This may be due to encryption or file size limits.');
    return;
  }

  const copyBtn = document.getElementById('previewCopy');

  if (isImageFile(name)) {
    elBody.innerHTML = renderImagePreview(content, name);
    attachImageLoadHandler();
    copyBtn.classList.add('hidden');
  } else if (isTextFile(name)) {
    try {
      const text = new TextDecoder('utf-8').decode(content);
      currentDecodedText = text;
      elBody.innerHTML = renderTextPreview(text, name);
      attachShowAllLinesHandler();
      showSearchBar(true);
      copyBtn.classList.remove('hidden');

      if (node._passwordFileHint) {
        const parsed = parsePasswordFile(text, node._parseConfig || null);
        if (parsed && parsed.rows.length > 0) {
          currentParsedData = parsed;
          addTransformButton(true);
        } else {
          addTransformButton(false);
        }
      } else if (node._cookieFileHint) {
        const parsed = parseCookieFile(text);
        if (parsed && parsed.rows.length > 0) {
          currentParsedData = parsed;
          addTransformButton(true);
        } else {
          addTransformButton(false);
        }
      } else {
        const ext = getFileExtension(name);
        if (ext === 'txt' || ext === 'tsv') {
          addTransformButton(false);
        }
      }
    } catch (_) {
      elBody.innerHTML = renderError('Failed to decode file content.');
    }
  } else if (looksLikeText(content)) {
    // Extension not recognized but content looks like text
    try {
      const text = new TextDecoder('utf-8').decode(content);
      currentDecodedText = text;
      elBody.innerHTML = renderTextPreview(text, name);
      attachShowAllLinesHandler();
      showSearchBar(true);
      copyBtn.classList.remove('hidden');
      addTransformButton(false);
    } catch (_) {
      elBody.innerHTML = renderUnsupported(name);
    }
  } else {
    elBody.innerHTML = renderUnsupported(name);
    copyBtn.classList.add('hidden');
  }
}

function closePreview() {
  elOverlay.classList.remove('visible');
  revokeAllBlobUrls();
  clearTransformButtons();
  showSearchBar(false);

  document.getElementById('previewDownload').textContent = 'Download';
  document.getElementById('previewCopy').classList.add('hidden');
  document.getElementById('previewCopy').textContent = 'Copy';

  searchMatches = [];
  currentMatchIndex = -1;
  currentFile = null;
  currentContent = null;
  currentNode = null;
  currentDecodedText = null;
  currentParsedData = null;
}

function downloadCurrentFile() {
  if (!currentFile || !currentContent) return;
  downloadBlob(currentContent, currentFile.name, getMimeType(currentFile.name));
}

// Init

function initPreview() {
  elOverlay = document.getElementById('previewOverlay');
  elBody = document.getElementById('previewBody');
  elActions = document.querySelector('.preview-actions');

  elSearchBar = document.getElementById('previewSearch');
  elSearchInput = document.getElementById('previewSearchInput');
  elSearchCount = document.getElementById('previewSearchCount');
  elSearchPrev = document.getElementById('previewSearchPrev');
  elSearchNext = document.getElementById('previewSearchNext');

  document.getElementById('previewClose').addEventListener('click', closePreview);
  document.getElementById('previewDownload').addEventListener('click', downloadCurrentFile);
  document.getElementById('previewSetType').addEventListener('click', showPreviewTypeMenu);

  document.getElementById('previewCopy').addEventListener('click', () => {
    if (!currentDecodedText) return;
    copyToClipboard(currentDecodedText).then(ok => {
      const btn = document.getElementById('previewCopy');
      if (ok) {
        btn.textContent = 'Copied';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      }
    });
  });

  let searchDebounce = null;
  elSearchInput.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    searchDebounce = setTimeout(() => {
      performSearch(elSearchInput.value);
    }, 150);
  });

  elSearchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      navigateMatch(e.shiftKey ? 'prev' : 'next');
    }
    if (e.key === 'Escape') {
      elSearchInput.value = '';
      performSearch('');
    }
  });

  elSearchPrev.addEventListener('click', () => navigateMatch('prev'));
  elSearchNext.addEventListener('click', () => navigateMatch('next'));

  elOverlay.addEventListener('click', (e) => {
    if (e.target === elOverlay) closePreview();
  });

  on('preview:open', ({ name, size, path }) => {
    showPreview(name, size, path);
  });

  on('reset', () => {
    closePreview();
  });
}

export { initPreview, closePreview };
